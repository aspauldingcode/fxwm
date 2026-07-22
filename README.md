# Doorman

[![CI](https://github.com/aspauldingcode/fxwm/actions/workflows/ci.yml/badge.svg)](https://github.com/aspauldingcode/fxwm/actions/workflows/ci.yml)
[![Release](https://github.com/aspauldingcode/fxwm/actions/workflows/release.yml/badge.svg)](https://github.com/aspauldingcode/fxwm/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A macOS user authentication & account-management framework.**

Doorman lets any program authenticate a macOS user, launch their session, and
create/manage accounts — using a Linux-shaped API. It is a port of the Linux
login model (PAM-style transactions, a conversation callback, `getpwent`/
`getgrouplist`, `.desktop` sessions, `useradd`/`passwd`-style tooling) onto
macOS's native substrate (Open Directory, OpenPAM, `dscl`/`dseditgroup`/
`createhomedir`). It is **macOS-only** by design: the macOS account store and
filesystem differ from Linux, and Doorman's whole purpose is to bridge that gap
so you can log in and manage accounts on macOS the way you would on Linux.

> ⚠️ Experimental software that authenticates and provisions **real** macOS
> accounts. Review it before using anywhere that matters.

## What it does

- **Authenticate** via a PAM-style transaction with a conversation callback,
  backed by OpenDirectory, the local dsLocal `ShadowHashData` (PBKDF2), or the
  native OpenPAM stack (`/etc/pam.d`). Backends: `AUTO`, `OPENDIRECTORY`,
  `DSLOCAL`, `PAM`.
- **Enumerate** users (`getpwent`), supplementary groups (`getgrouplist`), and
  login sessions (freedesktop `.desktop` files + a built-in `aqua` session).
- **Open a session** for the authenticated user (fork → setgid/initgroups/
  setuid → login environment → exec), the way a display manager does.
- **Provision** accounts: create/delete users and groups, set passwords, manage
  membership, and create home directories from the macOS user template. Written
  through the native store, so the stock tools (`passwd`, `id`, `dscl`) fully
  interoperate.
- **CLI**: a `doorman` command that also answers to `useradd`, `userdel`,
  `passwd`, `groupadd`, `groupdel`, `usermod`, and `gpasswd`, so Linux account
  scripts work.

## Layout

- **`doorman/`** — the framework: public header (`include/doorman.h`) and
  implementation (`src/`). See [`doorman/README.md`](doorman/README.md).
- **`cli/`** — the `doorman` command-line tool and Linux-tool shims.
- **`examples/macdm/`** — a console "display manager" showing how to consume the
  library.
- **`tests/`** — unprivileged unit tests and a privileged end-to-end test.
- **`docs/`** — the Linux↔macOS design docs (see below).
- **`Makefile`** / **`flake.nix`** — plain and Nix builds.

## Documentation

- [`docs/LINUX_AUTH.md`](docs/LINUX_AUTH.md) — how Linux authenticates users and
  how Doorman ports that model.
- [`docs/AUTH_DIFFERENCES.md`](docs/AUTH_DIFFERENCES.md) — the exhaustive
  macOS-vs-Linux difference map with a per-area bridge scorecard.
- [`docs/CLI_AND_PROVISIONING.md`](docs/CLI_AND_PROVISIONING.md) — the CLI,
  provisioning API, and why the stock Unix tools interoperate.
- [`docs/API.md`](docs/API.md) — the complete API reference: every type and
  function, installation, linking, and worked usage for each capability.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and the hardening in the
  auth and provisioning paths.

**For LLMs / coding agents:** [`llms.txt`](llms.txt) (index, follows the
[llmstxt.org](https://llmstxt.org) convention) and [`llms-full.txt`](llms-full.txt)
— a single self-contained context file with the full API surface, semantic
contracts, memory-ownership rules, and copy-paste recipes. Paste `llms-full.txt`
into an agent's context and it has everything needed to integrate Doorman.

## Install a release (no build required)

Every tagged release publishes a prebuilt **universal** (Apple Silicon + Intel)
archive on the [Releases page](../../releases). Download and unpack:

```sh
tar xzf doorman-<version>-macos-universal.tar.gz
# contains: lib/libdoorman.{a,dylib}, include/doorman.h, bin/doorman (+ tool
# symlinks), bin/macdm, share/doc/...
```

## Build from source

With Nix flakes (recommended; builds universal binaries):

```sh
nix build .#doorman          # static + dylib + header  -> ./result
nix build .#doorman-cli      # the doorman CLI + tool symlinks
nix build .#dist             # the full distributable tree (what releases ship)
nix run  .                   # run the doorman CLI
```

Or with the plain Makefile (host architecture), which also runs the tests:

```sh
make                         # libdoorman + CLI + example + tests
make test                    # unprivileged unit tests
sudo tests/integration.sh    # full create/login/delete + interop test
sudo make install            # into /usr/local (lib, header, bin + tool symlinks)
```

## Using the library

```c
#include <doorman.h>

/* one-shot verify (directory backends) */
if (doorman_authenticate_password(user, pass, DOORMAN_BACKEND_AUTO) == DOORMAN_SUCCESS) { /* ok */ }

/* full transaction with a conversation (works with every backend incl. PAM) */
doorman_conv_t conv = { my_conv_fn, appdata };
doorman_handle_t *h;
doorman_start("login", user, &conv, DOORMAN_BACKEND_PAM, &h);
doorman_authenticate(h);
doorman_acct_mgmt(h);
doorman_setcred(h, DOORMAN_CRED_ESTABLISH);
doorman_open_session(h, &session, &pid);
doorman_end(h);
```

Link with:

```sh
cc app.c -I<doorman>/include <doorman>/lib/libdoorman.a \
   -framework Foundation -framework OpenDirectory -framework Security -lpam -lobjc
```

The complete reference — every function with parameters, ownership rules, and a
worked example — is in [`docs/API.md`](docs/API.md).

## CI & releases

- **CI** (`.github/workflows/ci.yml`) builds the library, CLI, example, and
  tests on a macOS 26 runner, runs the unit + privileged integration tests, and
  builds the Nix flake. The badge at the top of this README reflects the latest
  run. The unit suite touches every public `doorman_*` entry point; the
  integration test exercises the privileged create → login → passwd → groups →
  delete paths end to end.
- **Releases** (`.github/workflows/release.yml`) build the flake and publish a
  universal artifact to a GitHub Release automatically when a `v*` tag is pushed.

## License

[MIT](LICENSE). Doorman is a library meant to be embedded — in display
managers, greeters, account tooling, or proprietary apps — and linked from any
language over its C ABI, so it uses the most permissive mainstream license:
no copyleft obligations for static or dynamic linking, just attribution. Its
only third-party dependencies are Apple's system frameworks and macOS's
BSD-licensed OpenPAM, so nothing upstream constrains this choice.
