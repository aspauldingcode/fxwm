# Doorman (`libdoorman`)

A PAM-inspired **macOS user authentication framework**, extracted from fxwm so
that any project can sign a user in to macOS through one stable C ABI.

The name says what it does: Doorman checks a user's credentials at the door and
admits them into a session — the authentication backend a login screen or
display manager relies on to decide who gets in and to hand them their session.

It exposes the same conceptual flow a Linux login stack uses — start a
transaction, run a *conversation* to collect credentials, authenticate,
validate the account, establish credentials, open a session — and backs each
step with a native macOS mechanism.

- [`../docs/LINUX_AUTH.md`](../docs/LINUX_AUTH.md) — how Linux authenticates
  users, and the Linux→macOS mapping that motivates the design.
- [`../docs/AUTH_DIFFERENCES.md`](../docs/AUTH_DIFFERENCES.md) — the exhaustive
  macOS-vs-Linux difference map with a per-area "bridge scorecard" showing what
  the framework hides and the few macOS realities it can only surface.

The intended consumers are login programs that were not written for macOS —
for example a port of a Wayland display manager, which wants to present a user
list, a session picker, and a password prompt, then launch the selected
session as the authenticated user.

## Backends

Credential verification can use any of:

| Backend | Mechanism | Use it when |
|---------|-----------|-------------|
| `DOORMAN_BACKEND_AUTO` | OpenDirectory, falling back to dsLocal | default; most robust |
| `DOORMAN_BACKEND_OPENDIRECTORY` | `ODRecord verifyPassword:` via opendirectoryd | production; supports local + network/mobile accounts |
| `DOORMAN_BACKEND_DSLOCAL` | Parse `ShadowHashData` `SALTED-SHA512-PBKDF2` directly | restricted/early contexts without opendirectoryd (fxwm's original method) |
| `DOORMAN_BACKEND_PAM` | Drive macOS's OpenPAM stack (`/etc/pam.d/<service>`) | you want administrator-configurable policy, closest to the Linux method |

## API at a glance

```c
#include <doorman.h>

/* One-shot (directory backends), a drop-in for the old DoLogon(): */
if (doorman_authenticate_password(user, pass, DOORMAN_BACKEND_AUTO) == DOORMAN_SUCCESS) { ... }

/* Full transaction with a conversation (works with every backend, incl. PAM): */
doorman_conv_t conv = { my_conv_fn, appdata };
doorman_handle_t *h;
doorman_start("login", user, &conv, DOORMAN_BACKEND_PAM, &h);
doorman_authenticate(h);      /* prompts via my_conv_fn                    */
doorman_acct_mgmt(h);         /* account allowed to log in?                */
doorman_setcred(h, DOORMAN_CRED_ESTABLISH);          /* pam_setcred parity     */

/* Display-manager helpers: */
doorman_user_t *users; size_t nu;
doorman_enumerate_users(true, &users, &nu);          /* login-eligible users   */

gid_t *gids; size_t ng;
doorman_get_groups(user, &gids, &ng);                /* getgrouplist parity    */

doorman_session_t *sessions; size_t ns;
doorman_enumerate_sessions(&sessions, &ns);          /* .desktop + aqua        */

pid_t pid;
doorman_open_session(h, &sessions[i], &pid);         /* fork/setuid/exec       */

doorman_end(h);
```

The conversation callback mirrors `struct pam_conv` (styles map 1:1 to
`PAM_PROMPT_ECHO_OFF` etc.), so a Linux PAM conversation function ports almost
verbatim. Full documentation is in the header, [`include/doorman.h`](include/doorman.h).

## Account management & CLI

Beyond authentication, Doorman can **create and manage accounts** the way Linux
does — `doorman_create_user`/`doorman_delete_user`/`doorman_set_password`/
`doorman_create_group`/`doorman_add_user_to_group`/`doorman_create_home` — and
ships a `doorman` CLI that also answers to `useradd`, `userdel`, `passwd`,
`groupadd`, `groupdel`, and `usermod`. It writes through the native macOS store
(`dscl`/`dseditgroup`/`createhomedir`), so the stock tools (`passwd`, `id`,
`dscl`) fully interoperate. See
[`../docs/CLI_AND_PROVISIONING.md`](../docs/CLI_AND_PROVISIONING.md).

## Building

The plain (non-Nix) build for normal use and CI, via the top-level `Makefile`:

```bash
make            # libdoorman.a + .dylib, the doorman CLI, macdm, and tests
make test       # run the unprivileged unit tests
sudo tests/integration.sh   # full create/login/delete + interop test
sudo make install           # into /usr/local (lib, header, bin + tool symlinks)
```

Doorman is also exposed as Nix flake packages (arm64e, to match the
WindowServer ABI that fxwm injects into):

```bash
nix build .#doorman          # static + dylib + header in ./result
nix build .#doorman-cli      # the doorman CLI + Linux-tool symlinks
nix build .#doorman-example  # the console demo, ./result/bin/macdm
```

Or compile against it directly on macOS:

```sh
cc yourapp.c -I<doorman>/include \
   <doorman>/lib/libdoorman.a \
   -framework Foundation -framework OpenDirectory -framework Security \
   -lpam -lobjc
```

Produces `libdoorman.a` (for embedding, as fxwm does) and `libdoorman.dylib`
(for dynamic consumers), plus the installed public header.

## Example

[`../examples/macdm`](../examples/macdm) is a minimal terminal "display
manager" that lists users and sessions, authenticates through a conversation
callback, and launches the selected session — the reference for how a real
display-manager port should consume the framework.

## Security notes

- Password buffers collected internally are zeroed before being freed, and the
  dsLocal backend compares derived keys in constant time.
- The directory backends need read access to the local store (run as root) for
  the dsLocal path; OpenDirectory enforces its own access via opendirectoryd.
- `doorman_open_session` only drops privileges when the caller is root; other-
  wise it can launch a session for the current user (handy for development).
- This is experimental software that authenticates real macOS accounts. Review
  it before using it anywhere that matters.
