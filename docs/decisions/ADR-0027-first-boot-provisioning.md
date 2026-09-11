# ADR-0027 — First-boot provisioning and the WardOS account lifecycle

## Status
Accepted. **Supersedes the account-creation decision in [ADR-0026](ADR-0026-first-run-calibrate.md)**
(its "account creation stays with the installer" §Context): first-boot provisioning is now
the canonical way a WardOS machine gets its human account. ADR-0026's CALIBRATE settings
(language/keyboard/timezone) stand and become part of provisioning.

## Decision
The **real human account is created at first boot, not baked into the image.** The immutable
bootc image ships **unprovisioned** — with *no* human account and *no* shipped password. The
first boot of an unprovisioned machine runs a **provisioning session** (CALIBRATE, extended)
that collects language, keyboard, timezone, the person's full name, a username, and a
password, **creates the real local user** (its home, `wheel`/admin per WardOS policy), marks
the machine provisioned, and hands off to the normal greeter. Every subsequent boot goes
straight to the greeter and a normal login.

This is machine/runtime state, so it does **not** mutate the immutable image: provisioning
writes only `/etc` (accounts, locale, keymap, timezone), `/var` (the provisioned marker),
and `/home` (the new user). The bootc image stays byte-identical across machines.

The pre-created `wardos` account is demoted to a **build-time development/test escape hatch**,
never the production default (see §Dev escape hatch).

### Canonical account lifecycle
```
unprovisioned image
   → boot → detect "unprovisioned" → provisioning session (CALIBRATE)
   → broker creates the real user + applies locale/keyboard/timezone
   → machine marked provisioned → provisioning path permanently disabled
   → greeter → user login → WardOS desktop
subsequent boots: boot → greeter → user login → desktop
```

## The bootstrap mechanism (determined before implementation)
The gating question — "the smallest reliable mechanism that allows a graphical first-run
before any human account exists" — resolves to **greetd, marker-gated**, because greetd
already runs a graphical, unprivileged, locked kiosk (`cage` hosting `gtkgreet` as the
`greeter` system user, `/usr/sbin/nologin`, no password) and only enters a real user's
session after PAM auth. Reusing it avoids a second display manager, an autologin of any real
user, and any default-password account.

- **Marker**: `/var/lib/wardos/provisioned` (mutable `/var`, absent in the image).
- **Session selector**: greetd's session `command` becomes a small wrapper,
  `wardos-greetd-session`. Marker **absent** → it execs the **provisioning UI** under cage;
  marker **present** → it execs the normal `gtkgreet` greeter (today's #116 command, verbatim).
  greetd's `user` stays the unprivileged, locked bootstrap identity throughout; no real user
  is ever autologged-in.
- **Provisioning UI** (`wardos-provision-ui`, **unprivileged**): the keyboard-first CALIBRATE
  flow — keyboard, language, timezone, full name, username, password (+confirm), review —
  running as the locked bootstrap identity inside the cage kiosk. It performs **no** privileged
  operation itself; it hands validated choices to the broker.
  - **Implementation amendment (owner-approved, after the T480s hardware boot):** the UI is a
    **foot-hosted terminal UI (xdg-shell), not fuzzel.** cage supports xdg-shell only
    (wlr-layer-shell is an open upstream PR), so fuzzel — a layer-shell client — aborts under
    cage and the provisioning UI never renders. The bootstrap therefore runs `cage -s -- foot …
    wardos-provision-ui`, a self-contained bash TUI. The keyboard is asked **first** and the
    chosen layout is re-established as the compositor's live input layout (the session relaunches
    cage with `XKB_DEFAULT_LAYOUT` from the recorded choice) **before** any password is typed, so
    a non-US password is entered under the intended layout. A future graphical (E-10 toolkit)
    surface remains a follow-up; the desktop's post-login fuzzel is unaffected.
- **Provisioning broker** (`wardos-provisiond`, **root, socket-activated**): a systemd
  service exposing a Unix socket with a **narrow, validated verb set** — `set-locale`,
  `set-keymap`, `set-timezone`, `create-account`, `complete`. It performs `useradd`/`chpasswd`/
  `localectl`/`timedatectl`, writes the marker, and refuses everything once the marker exists.
  The UI cannot ask it for anything outside those verbs; the broker validates every field
  (username policy, non-empty password) and never trusts the UI beyond them.

This is the precedent the user named: **UI components request narrowly-scoped system actions
through a broker rather than running privileged.** It generalises to later WardOS surfaces.

## Security invariants (each mapped to its mechanism)
- **No shipped universal production password** — no human account exists in the image at all;
  the bootstrap identity is passwordless and `nologin`.
- **No normal shell/login to any bootstrap identity** — the bootstrap user has `/usr/sbin/nologin`
  and no password; its only reachable program is the cage-hosted provisioning UI (kiosk,
  single window). VT-switch still reaches a text console for recovery, but it offers only a
  `nologin` prompt — never a session (belt-and-braces, as today's greeter).
- **Bootstrap privilege exists only as needed** — the UI is unprivileged; only the broker is
  root, and only for its five verbs, with validated inputs, reachable only over a socket whose
  access is confined to the provisioning session.
- **After successful account creation the bootstrap path is disabled** — `complete` writes the
  marker; the selector then only ever runs the greeter, and the broker self-refuses when the
  marker is present. There is no second provisioning.
- **Interrupted provisioning is safely resumable** — the marker is written **only** on full
  success, last, after the account exists; a crash before it re-enters provisioning cleanly on
  the next boot. Each broker step is idempotent (re-creating an existing user updates rather
  than errors).
- **Transactional against power loss** — `create-account` creates the user and sets its
  password as one broker operation that rolls the half-created user back on failure; the marker
  (the commit point) is `fsync`'d and renamed into place last, so a power cut leaves the machine
  either unprovisioned (re-runs) or fully provisioned (usable), never a login-less half-state.
- **Password material is never logged** — the UI never echoes it; it crosses the socket once and
  is fed to `chpasswd` on **stdin**, never as an argv or environment value, and no code path
  writes it to a log, the journal, or the marker.
- **First-run cannot be bypassed into an unlocked desktop** — while the marker is absent greetd
  runs *only* the provisioning UI; there is no getty autologin (removed in #116) and no real
  account to log into, so there is no desktop to reach until provisioning completes.

## Dev / test escape hatch
CI and hardware iteration need a machine that skips provisioning. A **build-time** Containerfile
arg (default off) — `WARDOS_DEV_SEED_USER=<name>` — bakes only a *username* (never a secret) so
`wardos-dev-seed.service` seeds that development user (in `wheel`) **locked** and writes the
marker **at first boot** (not at build time, where bootc does not persist `/var` or `/home`).
The account's password is **never baked into an image layer**: it is delivered, if wanted, as a
**first-boot systemd credential** `wardos-dev-seed.password`
(`systemd.set_credential=…` on the kernel command line, or a credentials file); with none, the
account stays locked. The image build asserts no `dev-seed-password` file exists in any layer.
The `disk` workflow's `user` input is blank by default (release disks are unprovisioned) and,
when a dev sets it, the password comes from the `WARDOS_DEV_SEED_PASSWORD` **repo secret** (into
the disk's own `/etc/shadow`, not a shared OCI layer), never a plaintext workflow input. This
escape hatch must never be the production default.

## Relationship to the installer
Anaconda / bootc-image-builder MAY still create users for specialised or unattended deployment
scenarios, and `image/disk.sh --user` stays for those and for producing dev images. But the
**canonical consumer flow is first-boot CALIBRATE**, not an installer-created account; the
default consumer image is unprovisioned regardless of install medium.

## Consequences
- New components: `wardos-provisiond` (root broker + socket unit), `wardos-provision-ui`
  (unprivileged provisioning CALIBRATE), `wardos-greetd-session` (marker-gated selector), the
  `/var/lib/wardos/provisioned` marker, and the bootstrap sysuser. `wardos-calibrate` (ADR-0026)
  keeps its in-session role (re-running locale/keyboard/timezone later) and shares its pickers
  with the provisioning UI via `desktop/lib`.
- Reopening the boot path is accepted, per the explicit product call, to establish the correct
  long-term account model — done so the marker-present path is byte-identical to today's #116
  greeter command, so a provisioned machine boots exactly as it does now.
- The image stays immutable; provisioning writes only mutable machine state.
- Tests: broker verb/validation/refuse-when-provisioned and the transactional create with
  mocked `useradd`/`chpasswd`/`localectl`/`timedatectl`; the selector's marker gating; the UI
  flow (mocked broker); an image assertion that the default image is unprovisioned. Final
  validation is a hardware boot (CI builds the image but never runs the compositor).
- No `docs/security-model.md` guarantee is weakened; this strengthens the account posture. The
  broker is a new privileged surface and is written to the same bar as the rest of the host
  (narrow, validated, refusing).

## Follow-ups (named, not in this slice)
Friendly language **names** in the picker; a graphical (non-fuzzel) provisioning surface once
the E-10 toolkit lands (the fuzzel flow is the interim, exactly as ADR-0016 for the rest of the
shell); disk-encryption passphrase enrolment during provisioning for the raw-image path.
