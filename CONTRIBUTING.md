# Contributing to WardOS

WardOS is built in the open. Issues, pull requests and design findings are welcome.

## Before you start

* Read [`docs/architecture.md`](docs/architecture.md) and the decision records in
  [`docs/decisions/`](docs/decisions/). A change that alters a decision comes with a new
  ADR, or an amendment to the one it changes, in the same pull request.
* Read [`docs/development-under-tamperward.md`](docs/development-under-tamperward.md).
  The tests, the verification scripts, CI and the TamperWard configuration are
  *protected surfaces*: changing them to make a check pass is the one thing a pull
  request must never do. The paths in [`.github/CODEOWNERS`](.github/CODEOWNERS) get a
  human review.

## Building and verifying

```bash
cargo build --workspace
scripts/verify/tamperward.sh        # fmt, clippy, tests, security checks; what CI runs
desktop/tests/run.sh                # the desktop command family, no compositor needed
image/check-packages.sh --dry-run   # every package name exists on the target Fedora
image/build.sh                      # the bootc image (podman or docker)
```

`scripts/verify/tamperward.sh` is the merge gate. Run it before opening a pull request;
the same script runs in CI, so a green run locally is a green run there.

## Pull requests

* One change per pull request, with a title that says what the change does.
* Fill in the template: summary, changes, how it was verified, security impact.
  "None" is a fine answer for the last one when it is true.
* Tests come with the code. A bug fix starts with the test that reproduces the bug.
* Keep the documentation current in the same pull request: `README.md`, the relevant
  `docs/*.md`, and an ADR when a decision changes.
* Squash merge; the pull request title becomes the commit subject.

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md). Do not open a public issue for an unfixed vulnerability.

## License

By contributing you agree that your contribution is licensed under
[Apache-2.0](LICENSE), like the rest of WardOS.
