# How Linux authenticates users (and how doorman maps it to macOS)

This document answers the design question behind `libdoorman`: *how does Linux
actually authenticate a user at login, and what is the equivalent on macOS?*
The library is a port of the Linux model, so understanding the Linux side is
the specification for the macOS side.

## The Linux login stack, end to end

When you type a username and password into a Linux console login, `sshd`, or a
graphical display manager (GDM, SDDM, LightDM), roughly this happens:

1. **Identity lookup (NSS).** The program resolves the username to an account
   via the Name Service Switch. `getpwnam()`/`getpwent()` consult the sources
   listed in `/etc/nsswitch.conf` (`files`, `systemd`, `ldap`, `sss`, ...).
   The `files` source reads `/etc/passwd`, which holds the login name, UID,
   GID, GECOS (full name), home directory and login shell — but **not** the
   password.

2. **Credential verification (PAM).** The actual password check is *not* done
   by the login program. It is delegated to **PAM — Pluggable Authentication
   Modules**. The program is a "PAM-aware application"; it links `libpam` and
   calls a small API. PAM loads a stack of modules according to a per-service
   policy file and runs them in order.

3. **Session establishment.** After authentication and account checks pass, the
   program asks PAM to open a session, drops privileges to the target user
   (`setgid` → `initgroups` → `setuid`), sets up the environment, and `exec`s
   the user's shell or the chosen desktop session.

### The password store: `/etc/shadow` and `crypt`

The `files` backend for passwords is `/etc/shadow` (readable only by root).
Each line stores the username and a hashed password field of the form:

```
$id$salt$hash
```

where `id` selects the hashing scheme — `$6$` = SHA-512 crypt, `$y$` =
yescrypt (the modern default on many distros), `$2b$` = bcrypt. Verification
means running the same one-way `crypt(3)` function over the entered password
with the stored salt and parameters, then comparing in constant time. Nobody
"decrypts" the stored value; you re-derive and compare.

macOS is structurally identical here: there is no `/etc/shadow`, but the local
directory stores a per-user `ShadowHashData` blob whose `SALTED-SHA512-PBKDF2`
entry is exactly a salt + iteration count + derived key. Verifying a password
is the same "re-derive with PBKDF2-HMAC-SHA512 and compare" operation. That is
what `doorman`'s `dslocal` backend does.

## PAM in detail (the part doorman ports)

PAM is the piece worth porting because it is the abstraction every Linux login
program shares. Its value is that the *application* does not know or care how a
credential is verified — that is policy, configured by the administrator.

### Configuration

Policy lives in `/etc/pam.d/<service>`, one file per service name
(`login`, `sshd`, `gdm-password`, `sudo`, ...). Each line is:

```
<type>   <control>   <module>   [args]
```

- **type** — which phase the rule belongs to:
  - `auth` — prove identity (verify a password, token, biometric).
  - `account` — is this account allowed to log in *now*? (not expired,
    within allowed hours, not locked).
  - `password` — update the authentication token (change password).
  - `session` — set up / tear down the session (mount home, set limits,
    register with `logind`, write `wtmp`).
- **control** — how the result affects the stack: `required`, `requisite`,
  `sufficient`, `optional`, or the richer `[success=1 default=ignore]` form.
- **module** — a `.so` such as `pam_unix.so` (shadow passwords),
  `pam_systemd.so` (session/seat registration), `pam_faillock.so`,
  `pam_google_authenticator.so`, etc.

Because the stack is data, an administrator can add MFA or switch to LDAP with
no change to the login program.

### The application API

A PAM-aware program uses a very small surface:

```c
#include <security/pam_appl.h>

struct pam_conv conv = { my_conversation_fn, appdata };
pam_handle_t *pamh;

pam_start("login", username, &conv, &pamh);   /* begin transaction         */
pam_authenticate(pamh, 0);                     /* run the auth stack        */
pam_acct_mgmt(pamh, 0);                         /* run the account stack     */
pam_setcred(pamh, PAM_ESTABLISH_CRED);          /* establish credentials     */
pam_open_session(pamh, 0);                      /* run the session stack     */
/* ... user is logged in; run their session ... */
pam_close_session(pamh, 0);
pam_end(pamh, status);                          /* finish transaction        */
```

### The conversation function

PAM never touches the terminal or GUI itself. When a module needs input (a
password, a one-time code) or wants to display a message, it calls back into
the application through the **conversation function** the app supplied:

```c
int conv(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata);
```

For each message the app either prints it (`PAM_TEXT_INFO`, `PAM_ERROR_MSG`) or
prompts for input (`PAM_PROMPT_ECHO_OFF` for passwords, `PAM_PROMPT_ECHO_ON`
for usernames) and returns the answer. This indirection is what lets the same
PAM stack serve a text console, an SSH session, and a graphical greeter.

## How a Linux display manager ties it together

A greeter such as GDM/SDDM/LightDM combines all of the above:

1. **Enumerate users** with `getpwent()` (filtered to "human" accounts, usually
   UID ≥ 1000 and a real login shell) to draw the user list.
2. **Enumerate sessions** by reading freedesktop *desktop entries*:
   - `/usr/share/xsessions/*.desktop` for X11 sessions,
   - `/usr/share/wayland-sessions/*.desktop` for Wayland sessions.
   Each file's `Name=`, `Comment=`, and `Exec=` populate the session picker.
3. **Authenticate** the selected user through PAM using a conversation function
   wired to the greeter's password field.
4. **Open a session and launch it**: `pam_open_session`, then fork, drop to the
   user, export `HOME`, `USER`, `SHELL`, `PATH`, `XDG_RUNTIME_DIR`,
   `XDG_SESSION_TYPE`, `WAYLAND_DISPLAY`, etc., and `exec` the session `Exec=`
   command.

## Linux → macOS mapping

`libdoorman` reproduces each stage with a native macOS mechanism:

| Linux concept                         | macOS equivalent                                   | doorman surface |
|---------------------------------------|----------------------------------------------------|-----------------|
| `getpwnam` / `getpwent` over NSS      | `getpwnam` / `getpwent` serviced by opendirectoryd | `doorman_enumerate_users`, `doorman_lookup_user` |
| `/etc/passwd`                         | dsLocal user records (`/var/db/dslocal/...`)       | user fields (uid/gid/home/shell/gecos) |
| `/etc/shadow` + `crypt`               | `ShadowHashData` → `SALTED-SHA512-PBKDF2`          | `DOORMAN_BACKEND_DSLOCAL` |
| PAM stack (`pam_unix`, `pam_ldap`...) | OpenDirectory (`ODRecord verifyPassword`)          | `DOORMAN_BACKEND_OPENDIRECTORY` |
| PAM API + `/etc/pam.d`                | OpenPAM (macOS ships it!) + `/etc/pam.d`           | `DOORMAN_BACKEND_PAM` |
| `struct pam_conv` conversation        | `doorman_conv_t` conversation                      | `doorman_authenticate` |
| `pam_start`/`authenticate`/`acct_mgmt`| same phases                                        | `doorman_start` / `doorman_authenticate` / `doorman_acct_mgmt` |
| `.desktop` session discovery          | same `.desktop` discovery + built-in `aqua`        | `doorman_enumerate_sessions` |
| `pam_open_session` + fork/setuid/exec | fork/setgid/initgroups/setuid/exec                 | `doorman_open_session` |

Two facts make the port clean rather than an emulation:

- **macOS ships OpenPAM.** `security/pam_appl.h`, `libpam`, and `/etc/pam.d/`
  all exist on macOS. A program written against PAM on Linux can, in principle,
  keep using PAM on macOS. `doorman`'s PAM backend simply drives that stack.
- **macOS password hashing is the same shape as Linux's.** A salted,
  iterated, one-way KDF verified by re-derivation. Only the storage location
  and container format differ, and the `dslocal` backend hides that.

The result: a login program (for example a Wayland display manager being
ported to macOS) can keep its PAM-style structure and its `.desktop` session
model, and only swap `libpam`/NSS calls for the equivalent `libdoorman` calls.

For the *complete* enumeration of every place the two platforms diverge — and
exactly which differences the framework bridges versus surfaces — see
[`AUTH_DIFFERENCES.md`](AUTH_DIFFERENCES.md).
