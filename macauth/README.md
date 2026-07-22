# libmacauth

A PAM-inspired **macOS user authentication framework**, extracted from fxwm so
that any project can sign a user in to macOS through one stable C ABI.

It exposes the same conceptual flow a Linux login stack uses — start a
transaction, run a *conversation* to collect credentials, authenticate,
validate the account, open a session — and backs each step with a native macOS
mechanism. See [`../docs/LINUX_AUTH.md`](../docs/LINUX_AUTH.md) for the full
Linux→macOS mapping that motivates the design.

The intended consumers are login programs that were not written for macOS —
for example a port of a Wayland display manager, which wants to present a user
list, a session picker, and a password prompt, then launch the selected
session as the authenticated user.

## Backends

Credential verification can use any of:

| Backend | Mechanism | Use it when |
|---------|-----------|-------------|
| `MACAUTH_BACKEND_AUTO` | OpenDirectory, falling back to dsLocal | default; most robust |
| `MACAUTH_BACKEND_OPENDIRECTORY` | `ODRecord verifyPassword:` via opendirectoryd | production; supports local + network/mobile accounts |
| `MACAUTH_BACKEND_DSLOCAL` | Parse `ShadowHashData` `SALTED-SHA512-PBKDF2` directly | restricted/early contexts without opendirectoryd (fxwm's original method) |
| `MACAUTH_BACKEND_PAM` | Drive macOS's OpenPAM stack (`/etc/pam.d/<service>`) | you want administrator-configurable policy, closest to the Linux method |

## API at a glance

```c
#include <macauth.h>

/* One-shot (directory backends), a drop-in for the old DoLogon(): */
if (macauth_authenticate_password(user, pass, MACAUTH_BACKEND_AUTO) == MACAUTH_SUCCESS) { ... }

/* Full transaction with a conversation (works with every backend, incl. PAM): */
macauth_conv_t conv = { my_conv_fn, appdata };
macauth_handle_t *h;
macauth_start("login", user, &conv, MACAUTH_BACKEND_PAM, &h);
macauth_authenticate(h);      /* prompts via my_conv_fn                    */
macauth_acct_mgmt(h);         /* account allowed to log in?                */

/* Display-manager helpers: */
macauth_user_t *users; size_t nu;
macauth_enumerate_users(true, &users, &nu);          /* login-eligible users   */

macauth_session_t *sessions; size_t ns;
macauth_enumerate_sessions(&sessions, &ns);          /* .desktop + aqua        */

pid_t pid;
macauth_open_session(h, &sessions[i], &pid);         /* fork/setuid/exec       */

macauth_end(h);
```

The conversation callback mirrors `struct pam_conv` (styles map 1:1 to
`PAM_PROMPT_ECHO_OFF` etc.), so a Linux PAM conversation function ports almost
verbatim. Full documentation is in the header, [`include/macauth.h`](include/macauth.h).

## Building

macauth is exposed as a Nix flake package (arm64e, to match the WindowServer
ABI that fxwm injects into):

```bash
nix build .#macauth          # static + dylib + header in ./result
nix build .#macauth-example  # the console demo, ./result/bin/macdm
```

Or compile against it directly on macOS:

```sh
cc yourapp.c -I<macauth>/include \
   <macauth>/lib/libmacauth.a \
   -framework Foundation -framework OpenDirectory -framework Security \
   -lpam -lobjc
```

Produces `libmacauth.a` (for embedding, as fxwm does) and `libmacauth.dylib`
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
- `macauth_open_session` only drops privileges when the caller is root; other-
  wise it can launch a session for the current user (handy for development).
- This is experimental software that authenticates real macOS accounts. Review
  it before using it anywhere that matters.
