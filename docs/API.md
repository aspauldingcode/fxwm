# Doorman API reference

`libdoorman` is a C ABI. This document covers installation, linking, the core
concepts, and every public type and function, with a worked example for each
capability. The single header to include is [`doorman.h`](../doorman/include/doorman.h).

> Working with an LLM or coding agent? [`llms-full.txt`](../llms-full.txt) at
> the repository root is a single self-contained version of this reference
> (full signatures, contracts, ownership rules, recipes) designed to be pasted
> into an agent's context; [`llms.txt`](../llms.txt) is the index.

- [Installation](#installation)
- [Linking](#linking)
- [Core concepts](#core-concepts)
- [Result codes](#result-codes)
- [Transaction lifecycle](#transaction-lifecycle)
- [Items](#items)
- [Authentication](#authentication)
- [One-shot authentication](#one-shot-authentication)
- [Groups](#groups)
- [User enumeration](#user-enumeration)
- [Session discovery and launch](#session-discovery-and-launch)
- [Account provisioning](#account-provisioning)
- [Memory and ownership rules](#memory-and-ownership-rules)
- [Threading](#threading)
- [Command-line tool](#command-line-tool)

---

## Installation

Doorman is macOS-only (it links OpenDirectory, Security, and the system
OpenPAM). You need macOS with the Command Line Tools / Xcode.

### Option A — download a prebuilt release (no build)

Every tagged release publishes a prebuilt **universal** (Apple Silicon + Intel)
archive on the [Releases page](https://github.com/aspauldingcode/fxwm/releases):

```sh
tar xzf doorman-<version>-macos-universal.tar.gz
# lib/libdoorman.a, lib/libdoorman.dylib, include/doorman.h,
# bin/doorman (+ useradd/passwd/... symlinks), bin/macdm, share/doc/...
```

Copy `lib/` and `include/` where you want them, or install system-wide.

### Option B — build with Nix (universal)

```sh
nix build .#doorman          # static + dylib + header -> ./result
nix build .#doorman-cli      # the CLI + tool symlinks
nix build .#dist             # the full distributable tree (what releases ship)
nix run  .                   # run the CLI
```

### Option C — build with make (host arch), run the tests

```sh
make                         # libdoorman.a + .dylib, CLI, example, tests
make test                    # unprivileged unit tests
sudo tests/integration.sh    # privileged end-to-end test
sudo make install PREFIX=/usr/local
```

Both build systems compile with strict **warnings-as-errors**; the library is
expected to build clean under `-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wsign-conversion -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes
-Wformat=2 -Werror`.

## Linking

Link the static archive (or the dylib) plus the frameworks Doorman uses:

```sh
cc app.c -I<prefix>/include <prefix>/lib/libdoorman.a \
   -framework Foundation -framework OpenDirectory -framework Security \
   -lpam -lobjc
```

Only the `doorman_*` symbols are exported (the library is built with
`-fvisibility=hidden`). The header is plain C and compiles as **C11** and
**C++17**; from Swift, expose it through a bridging header or a module map.

---

## Core concepts

**Backends** (`doorman_backend_t`) choose how a password is verified:

| Backend | Mechanism | Use when |
|---|---|---|
| `DOORMAN_BACKEND_AUTO` | OpenDirectory, then the offline dsLocal reader for lookup/system faults only | default |
| `DOORMAN_BACKEND_OPENDIRECTORY` | `ODRecord verifyPassword:` via opendirectoryd | production; local + network/mobile accounts |
| `DOORMAN_BACKEND_DSLOCAL` | parse `ShadowHashData` and verify PBKDF2 directly (root) | no opendirectoryd (recovery/early boot) |
| `DOORMAN_BACKEND_PAM` | drive `/etc/pam.d/<service>` | administrator-configurable policy |

**Conversation** — instead of taking a password parameter, the transaction API
calls back into your `doorman_conv_fn` to collect credentials, exactly like a
PAM conversation. This lets one code path serve a TTY prompt, a GUI field, or a
canned secret.

**Transaction** — the PAM-shaped flow: `doorman_start` → `doorman_authenticate`
→ `doorman_acct_mgmt` → `doorman_setcred` → `doorman_open_session` →
`doorman_close_session` → `doorman_end`.

---

## Result codes

```c
typedef enum doorman_result {
    DOORMAN_SUCCESS = 0,
    DOORMAN_ERR_AUTH,          /* credentials rejected                 */
    DOORMAN_ERR_USER_UNKNOWN,  /* no such user                         */
    DOORMAN_ERR_ACCT_DISABLED, /* exists but cannot log in             */
    DOORMAN_ERR_PERM,          /* caller lacks privilege               */
    DOORMAN_ERR_CONV,          /* conversation failed/aborted          */
    DOORMAN_ERR_ABORT,         /* transaction is dead                  */
    DOORMAN_ERR_NO_SESSION,    /* session id not found                 */
    DOORMAN_ERR_SYSTEM,        /* underlying OS/directory error        */
    DOORMAN_ERR_INVALID_ARG,   /* NULL/invalid argument                */
    DOORMAN_ERR_UNSUPPORTED,   /* backend does not support this        */
} doorman_result_t;

const char *doorman_strerror(doorman_result_t result);
```

`doorman_strerror` never returns NULL and never returns freeable memory.

```c
if (r != DOORMAN_SUCCESS)
    fprintf(stderr, "doorman: %s\n", doorman_strerror(r));
```

---

## Transaction lifecycle

```c
doorman_result_t doorman_start(const char *service, const char *user,
                               const doorman_conv_t *conv,
                               doorman_backend_t backend,
                               doorman_handle_t **out);
void             doorman_end(doorman_handle_t *handle);
```

- `service` — PAM service name (`/etc/pam.d/<service>`) for the PAM backend,
  recorded otherwise; `NULL` defaults to `"login"`.
- `user` — target login name, or `NULL` to let the conversation prompt for it.
- `conv` — conversation used to collect credentials; may be `NULL` if you only
  ever call the one-shot helpers.
- `backend` — verification mechanism.
- `out` — receives the handle on success; free it with `doorman_end` (which is
  a no-op on `NULL`).

```c
doorman_conv_t conv = { my_conv_fn, my_appdata };
doorman_handle_t *h = NULL;
if (doorman_start("login", "alice", &conv, DOORMAN_BACKEND_AUTO, &h) != DOORMAN_SUCCESS)
    return;
/* ... use h ... */
doorman_end(h);
```

## Items

```c
typedef enum doorman_item {
    DOORMAN_ITEM_SERVICE = 1,
    DOORMAN_ITEM_USER    = 2,
    DOORMAN_ITEM_RHOST   = 3, /* remote host, informational */
    DOORMAN_ITEM_TTY     = 4, /* controlling tty / seat     */
} doorman_item_t;

doorman_result_t doorman_set_item(doorman_handle_t *h, doorman_item_t item, const char *value);
doorman_result_t doorman_get_item(doorman_handle_t *h, doorman_item_t item, const char **value);
```

`doorman_get_item` returns a borrowed pointer valid until the item changes or
the handle is freed; it is `NULL` if never set. RHOST/TTY are forwarded to PAM
(`PAM_RHOST`/`PAM_TTY`) so a networked policy can see them.

```c
doorman_set_item(h, DOORMAN_ITEM_RHOST, "10.0.0.5");
const char *svc = NULL;
doorman_get_item(h, DOORMAN_ITEM_SERVICE, &svc);   /* "login" */
```

## Authentication

```c
doorman_result_t doorman_authenticate(doorman_handle_t *h);
doorman_result_t doorman_acct_mgmt(doorman_handle_t *h);
doorman_result_t doorman_setcred(doorman_handle_t *h, doorman_cred_flag_t flag);
```

- `doorman_authenticate` runs the conversation to obtain the password (and the
  username if it was `NULL`) and verifies it against the backend.
- `doorman_acct_mgmt` validates the account may log in now (not disabled or
  expired). Must follow a successful authenticate (else `DOORMAN_ERR_ABORT`).
- `doorman_setcred` establishes/tears down credentials. With PAM it calls the
  real `pam_setcred`; with the directory backends it is a documented no-op
  returning `DOORMAN_SUCCESS` (you cannot unlock another user's keychain from
  outside their session — see [`AUTH_DIFFERENCES.md`](AUTH_DIFFERENCES.md)).

```c
typedef enum doorman_cred_flag {
    DOORMAN_CRED_ESTABLISH = 1, DOORMAN_CRED_DELETE = 2,
    DOORMAN_CRED_REINITIALIZE = 3, DOORMAN_CRED_REFRESH = 4,
} doorman_cred_flag_t;

doorman_result_t r = doorman_authenticate(h);
if (r == DOORMAN_SUCCESS) r = doorman_acct_mgmt(h);
if (r == DOORMAN_SUCCESS) r = doorman_setcred(h, DOORMAN_CRED_ESTABLISH);
```

### The conversation callback

```c
typedef enum doorman_msg_style {
    DOORMAN_PROMPT_ECHO_OFF = 1, /* password */
    DOORMAN_PROMPT_ECHO_ON  = 2, /* username */
    DOORMAN_ERROR_MSG       = 3,
    DOORMAN_TEXT_INFO       = 4,
} doorman_msg_style_t;

typedef struct doorman_message  { doorman_msg_style_t style; const char *msg; } doorman_message_t;
typedef struct doorman_response { char *resp; int resp_retcode; } doorman_response_t;

typedef int (*doorman_conv_fn)(int num_msg, const doorman_message_t **msg,
                               doorman_response_t **resp, void *appdata);
typedef struct doorman_conv { doorman_conv_fn conv; void *appdata; } doorman_conv_t;
```

For each input-style message the callback allocates `resp[i]->resp` with
`malloc`/`strdup`; **Doorman takes ownership and scrubs then frees it** (so it
can wipe password memory). Return `0` on success, non-zero to abort with
`DOORMAN_ERR_CONV`.

```c
static int my_conv_fn(int num_msg, const doorman_message_t **msg,
                      doorman_response_t **resp, void *appdata) {
    (void)appdata;
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->style) {
            case DOORMAN_PROMPT_ECHO_OFF: resp[i]->resp = read_password(msg[i]->msg); break;
            case DOORMAN_PROMPT_ECHO_ON:  resp[i]->resp = read_line(msg[i]->msg);     break;
            case DOORMAN_ERROR_MSG:       fprintf(stderr, "%s\n", msg[i]->msg);        break;
            case DOORMAN_TEXT_INFO:       printf("%s\n", msg[i]->msg);                 break;
        }
        if ((msg[i]->style == DOORMAN_PROMPT_ECHO_OFF ||
             msg[i]->style == DOORMAN_PROMPT_ECHO_ON) && !resp[i]->resp)
            return 1; /* abort */
    }
    return 0;
}
```

## One-shot authentication

```c
doorman_result_t doorman_authenticate_password(const char *user,
                                                const char *password,
                                                doorman_backend_t backend);
```

Verifies a name/password pair without a transaction or conversation. Does not
open a session. `DOORMAN_BACKEND_PAM` returns `DOORMAN_ERR_UNSUPPORTED` (PAM
needs its own conversation — use the transaction API).

```c
if (doorman_authenticate_password("alice", pw, DOORMAN_BACKEND_AUTO) == DOORMAN_SUCCESS)
    grant();
```

## Groups

```c
doorman_result_t doorman_get_groups(const char *user, gid_t **gids, size_t *count);
```

Resolves the supplementary group list (primary gid included first) via
`getgrouplist`, the way a login program does before `initgroups`. On success
`*gids` is a heap array of `*count` — free it with `free()`.

```c
gid_t *g = NULL; size_t n = 0;
if (doorman_get_groups("alice", &g, &n) == DOORMAN_SUCCESS) {
    for (size_t i = 0; i < n; i++) printf("%u\n", (unsigned)g[i]);
    free(g);
}
```

## User enumeration

```c
typedef struct doorman_user {
    char *name, *full_name, *home, *shell;
    uid_t uid; gid_t gid; bool hidden;
} doorman_user_t;

doorman_result_t doorman_enumerate_users(bool interactive_only,
                                         doorman_user_t **out, size_t *count);
void             doorman_free_users(doorman_user_t *users, size_t count);
doorman_result_t doorman_lookup_user(const char *name, doorman_user_t *out);
void             doorman_free_user_fields(doorman_user_t *user);
```

`interactive_only` filters out service accounts (uid < 500, `_`-prefixed names,
non-login shells), matching what a login screen shows. `doorman_lookup_user`
fills a caller-owned struct whose fields are released with
`doorman_free_user_fields`.

```c
doorman_user_t *u = NULL; size_t n = 0;
doorman_enumerate_users(true, &u, &n);
for (size_t i = 0; i < n; i++) printf("%s (uid %u)\n", u[i].name, (unsigned)u[i].uid);
doorman_free_users(u, n);

doorman_user_t one;
if (doorman_lookup_user("alice", &one) == DOORMAN_SUCCESS) {
    printf("home=%s shell=%s\n", one.home, one.shell);
    doorman_free_user_fields(&one);
}
```

## Session discovery and launch

```c
typedef struct doorman_session {
    char *id, *name, *comment, *exec, *type; /* type: "wayland" | "x11" | "aqua" */
} doorman_session_t;

doorman_result_t doorman_enumerate_sessions(doorman_session_t **out, size_t *count);
void             doorman_free_sessions(doorman_session_t *sessions, size_t count);
doorman_result_t doorman_open_session(doorman_handle_t *h,
                                      const doorman_session_t *session, pid_t *out_pid);
doorman_result_t doorman_close_session(doorman_handle_t *h);
```

`doorman_enumerate_sessions` reads the freedesktop `wayland-sessions`/`xsessions`
directories under `$XDG_DATA_DIRS` and always appends the built-in `aqua`
session. `doorman_open_session` must follow a successful authenticate; running
as root it drops privileges (`setgid`/`initgroups`/`setuid`), builds a minimal
login environment, and `fork`/`exec`s the session, writing the child pid to
`*out_pid`. Wait on the pid, then call `doorman_close_session`.

```c
doorman_session_t *s = NULL; size_t n = 0;
doorman_enumerate_sessions(&s, &n);
pid_t pid = 0;
if (doorman_open_session(h, &s[0], &pid) == DOORMAN_SUCCESS) {
    int status = 0; waitpid(pid, &status, 0);
    doorman_close_session(h);
}
doorman_free_sessions(s, n);
```

## Account provisioning

All provisioning mutates the local directory and requires **root**
(`DOORMAN_ERR_PERM` otherwise). Names are validated before use; passwords are
written through the OpenDirectory API (never on a command line).

```c
typedef struct doorman_user_spec {
    const char *name;       /* required: login name                            */
    const char *full_name;  /* RealName; defaults to name                      */
    const char *password;   /* initial password; NULL leaves it unset          */
    const char *home;       /* NFSHomeDirectory; defaults to /Users/<name>     */
    const char *shell;      /* UserShell; defaults to /bin/zsh                 */
    uid_t uid;              /* 0 => auto-assign next free >= 501                */
    gid_t gid;              /* 0 => 20 (staff)                                 */
    bool admin, hidden, create_home;
} doorman_user_spec_t;

doorman_result_t doorman_create_user(const doorman_user_spec_t *spec);
doorman_result_t doorman_delete_user(const char *name, bool remove_home);
doorman_result_t doorman_set_password(const char *name, const char *new_password);
doorman_result_t doorman_create_home(const char *name);
doorman_result_t doorman_create_group(const char *name, gid_t gid, const char *full_name);
doorman_result_t doorman_delete_group(const char *name);
doorman_result_t doorman_add_user_to_group(const char *user, const char *group);
doorman_result_t doorman_remove_user_from_group(const char *user, const char *group);
```

```c
doorman_user_spec_t spec = {
    .name = "alice", .full_name = "Alice", .password = "S3cret!",
    .shell = "/bin/zsh", .create_home = true, .admin = false,
};
if (doorman_create_user(&spec) == DOORMAN_SUCCESS) {
    doorman_create_group("designers", 0, "Designers");
    doorman_add_user_to_group("alice", "designers");
    doorman_set_password("alice", "N3wSecret!");
    doorman_remove_user_from_group("alice", "designers");
    doorman_delete_user("alice", /*remove_home=*/true);
}
```

Accounts created this way are ordinary macOS accounts — `id`, `dscl`, `passwd`,
System Settings, and the Login Window all interoperate with them. See
[`CLI_AND_PROVISIONING.md`](CLI_AND_PROVISIONING.md).

---

## Memory and ownership rules

- Handles from `doorman_start` are freed with `doorman_end`.
- Arrays from `doorman_enumerate_users` / `doorman_enumerate_sessions` are freed
  with `doorman_free_users` / `doorman_free_sessions`.
- A struct filled by `doorman_lookup_user` is released with
  `doorman_free_user_fields`.
- The gid array from `doorman_get_groups` is released with `free()`.
- `doorman_get_item` returns a **borrowed** pointer; do not free it.
- `doorman_strerror` returns a static string; do not free it.
- Conversation response buffers are owned by Doorman after the callback returns
  and are scrubbed before being freed.

## Threading

Each `doorman_handle_t` is a single-threaded object: do not drive one handle
from multiple threads concurrently. Independent handles on different threads are
fine. The read-only calls (`enumerate_*`, `lookup_user`, `get_groups`,
`strerror`) are reentrant. `doorman_open_session` calls `fork`; the child uses
only async-safe operations before `exec`.

## Command-line tool

The `doorman` CLI exposes the framework from the shell and doubles as Linux
account tools when symlinked under those names.

```
doorman authenticate <user>            verify a password (reads stdin)
doorman login <user> [--exec CMD] [--session ID]
doorman useradd [-m -u -g -s -c -d -p -G --admin --hidden] <name>
doorman userdel [-r] <name>
doorman passwd [--stdin] <user>
doorman groupadd [-g gid] <name>
doorman groupdel <name>
doorman usermod -aG <group> <user>
doorman gpasswd -a|-d <user> <group>
doorman users | sessions | groups <user>
```

Installed symlinks `useradd userdel passwd groupadd groupdel usermod gpasswd`
dispatch to the matching subcommand, so existing Linux account scripts work
unchanged on macOS. See [`CLI_AND_PROVISIONING.md`](CLI_AND_PROVISIONING.md).
