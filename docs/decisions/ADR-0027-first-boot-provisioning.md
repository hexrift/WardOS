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
    chosen layout is re-established as the compositor's live input layout **before** any password
    is typed, so a non-US password is entered under the intended layout. The mechanism: when the
    pick differs from cage's running layout the UI records the non-secret carry-over (never the
    password) to a stage file and exits `75`; `wardos-greetd-session` relaunches cage with
    `XKB_DEFAULT_LAYOUT` from the recorded choice, and the UI then sees its choice already live
    and proceeds to the password. The stage file lives in its **own greeter-owned runtime
    directory** — `/run/wardos-provision`, created `0700 greeter greeter` by an image
    `tmpfiles.d` entry, **not** the broker's root-owned `/run/wardos` (the greeter cannot write
    there). A `0700` greeter-owned directory inside root-owned `/run` is non-symlinkable by
    another user, the write is atomic (temp → rename), and a persistence failure is surfaced
    visibly and bounds the relaunch loop rather than re-showing the picker forever. A future
    graphical (E-10 toolkit) surface remains a follow-up; the desktop's post-login fuzzel is
    unaffected.
- **Provisioning broker** (`wardos-provisiond`, **root, socket-activated**): a systemd
  service exposing a Unix socket with a **narrow, validated verb set** — `STATUS` (read-only),
  `LOCALE`, `KEYMAP`, `TIMEZONE`, and `ACCOUNT`. `ACCOUNT` is the **transactional commit**: it
  creates the user, sets the password, and writes the marker **last**, as one operation — there
  is **no** separate `complete` verb. It performs `useradd`/`chpasswd`/`localectl`/`timedatectl`,
  writes the marker, and refuses every mutating verb once the marker exists. The UI cannot ask it
  for anything outside those verbs; the broker validates every field (username policy, non-empty
  password) and never trusts the UI beyond them. **Every mutating verb** (`LOCALE`/`KEYMAP`/
  `TIMEZONE`/`ACCOUNT`) is serialized under one exclusive lock (`/run/wardos/provisiond.lock`,
  root-writable) and **re-checks the marker after acquiring it** — a cheap pre-lock reject keeps
  the common case fast, but the authoritative check is post-acquisition — so a setting request
  that passed its pre-lock check cannot race the `ACCOUNT` that commits the marker and then
  mutate an already-provisioned machine. `STATUS` only reads the marker and stays lock-free.

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
- **After successful account creation the bootstrap path is disabled** — `ACCOUNT` writes the
  marker last; the selector then only ever runs the greeter, and the broker self-refuses every
  mutating verb (re-checked under the lock) when the marker is present. There is no second
  provisioning.
- **No adoption of an existing account** — `ACCOUNT` refuses any username already in use, human
  **or** system (e.g. `nobody=65534`), and refuses reserved/system names outright (`root`,
  `greeter`, the bootstrap identity, …); it never elevates or mutates an existing account. On an
  unprovisioned machine there is no human account to adopt, and an adopted one could not be
  rolled back cleanly.
- **Interrupted provisioning recovers via a durable journal + rollback, not idempotent
  re-creation** — the marker is written **only** on full success, last, after the account exists.
  `ACCOUNT` records a transaction **journal** (naming the intended user) durably **before**
  `useradd`; on any mid-transaction failure it rolls the account back and clears the journal only
  if that rollback succeeds. The next `ACCOUNT` runs `reconcile_pending` under the lock first: if
  the journalled account still exists it is removed **before** anything new is created, so a
  crash or a failed rollback can never leave two administrators. A marker that was renamed into
  place but whose directory `fsync` cannot be confirmed (even after one retry) is treated as
  **indeterminate** — the journal is kept and the connection replies *recovery-required* rather
  than acknowledging success, so a later power loss that drops the not-yet-durable marker is
  reconciled (the orphan removed) on the next boot.
- **Transactional against power loss** — `ACCOUNT` creates the user and sets its password as one
  broker operation that rolls the half-created user back on failure. Every durable write uses the
  same ordering — write a **temp** file, **`fsync`** it, **`rename`** it into place, then
  **`fsync` the containing directory** so the rename survives a power cut — and the marker,
  written this way **last**, is the commit point. A failed durability barrier is **reported,
  never acknowledged OK** (a lost `fsync` fails the write closed). So a power cut leaves the
  machine either unprovisioned (re-runs) or fully provisioned (usable), never a login-less
  half-state.
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
when a dev sets it, it is passed as `image/build.sh --dev-seed-user NAME` (the
`WARDOS_DEV_SEED_USER` build-arg), **not** a disk-build `--user`; the password is never baked
into a layer or the disk and is delivered at first boot as the `wardos-dev-seed.password`
systemd credential (else the account stays locked and the machine runs first-boot provisioning).
This escape hatch must never be the production default.

## Relationship to the installer
Anaconda / bootc-image-builder MAY still create users for specialised or unattended deployment
scenarios via their own kickstart/config. `image/disk.sh` itself **no longer pre-creates any
account** — its `--user`/`--password`/`--ssh-key` flags were removed, so every disk it builds is
**unprovisioned**. A development account is baked instead through
`image/build.sh --dev-seed-user NAME`, which `wardos-dev-seed` seeds (locked) and marks
provisioned at first boot. The **canonical consumer flow is first-boot provisioning**, not an
installer-created account; the default consumer image is unprovisioned regardless of install
medium.

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
Friendly language **names** in the picker; a graphical provisioning surface once the E-10
toolkit lands. The **interim provisioning UI is the foot-hosted TUI** — an xdg-shell client
under cage, chosen precisely because a layer-shell client like fuzzel aborts under cage — so the
future replacement is that graphical surface, **not** fuzzel (fuzzel remains the rest of the
shell's interim surface per ADR-0016, but was never viable for provisioning). Disk-encryption
passphrase enrolment during provisioning for the raw-image path.
