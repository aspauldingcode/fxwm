/*
 * SPDX-License-Identifier: MIT
 *
 * doorman.h - Doorman, a macOS user authentication framework
 *
 * Doorman checks a user's credentials at the door and admits them into a
 * session: it is the authentication backend a login screen or display manager
 * relies on to decide who gets in and to launch their session.
 *
 * A PAM-inspired authentication library for macOS. It exposes the same
 * conceptual flow that Linux login stacks use (start a transaction, run a
 * conversation to collect credentials, authenticate, validate the account,
 * then open a session) but backs it with native macOS mechanisms:
 * OpenDirectory, the local dsLocal ShadowHashData store, or the OpenPAM
 * implementation that ships in macOS.
 *
 * The goal is to let non-macOS-native login software (for example a port of a
 * Wayland display manager) authenticate a user and start a session on macOS
 * through one stable C ABI, without each project re-implementing shadow-hash
 * parsing or shelling out to `dscl . -authonly`.
 *
 * The API is intentionally C so it can be consumed from C, Objective-C, C++,
 * Swift (via a bridging header/module map) or through FFI from other runtimes.
 */

#ifndef DOORMAN_H
#define DOORMAN_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The whole public surface is exported with default ELF/Mach-O visibility even
 * when the library is compiled with -fvisibility=hidden. Hidden-by-default lets
 * the build keep every `_dm_*` internal out of the dynamic symbol table, which
 * shrinks the dylib, speeds up dyld binding, and frees the optimizer to inline
 * internal calls. Only the symbols between the push/pop below are exported.
 */
#pragma GCC visibility push(default)

#define DOORMAN_VERSION_MAJOR 0
#define DOORMAN_VERSION_MINOR 1
#define DOORMAN_VERSION_PATCH 0

/* ------------------------------------------------------------------------- */
/* MARK: - Result codes                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Result codes returned by every doorman call. These mirror the semantic
 * distinctions PAM makes (PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN,
 * PAM_ACCT_EXPIRED, ...) so that a caller ported from a Linux login stack can
 * map return values one-to-one.
 */
typedef enum doorman_result {
    DOORMAN_SUCCESS = 0,       /* operation completed successfully            */
    DOORMAN_ERR_AUTH,          /* credentials were rejected                   */
    DOORMAN_ERR_USER_UNKNOWN,  /* no such user in the directory               */
    DOORMAN_ERR_ACCT_DISABLED, /* account exists but cannot log in            */
    DOORMAN_ERR_PERM,          /* caller lacks privileges for the operation   */
    DOORMAN_ERR_CONV,          /* the conversation callback failed/aborted    */
    DOORMAN_ERR_ABORT,         /* unrecoverable error, transaction is dead    */
    DOORMAN_ERR_NO_SESSION,    /* requested session id was not found          */
    DOORMAN_ERR_SYSTEM,        /* underlying OS/directory error               */
    DOORMAN_ERR_INVALID_ARG,   /* a required argument was NULL/invalid        */
    DOORMAN_ERR_UNSUPPORTED,   /* backend does not support the operation      */
} doorman_result_t;

/*
 * Human-readable, static description of a result code. Never returns NULL and
 * the returned string must not be freed. Analogous to pam_strerror().
 */
const char *doorman_strerror(doorman_result_t result);

/* ------------------------------------------------------------------------- */
/* MARK: - Backends                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Selects the mechanism used to verify credentials.
 *
 *  - AUTO          Try OpenDirectory first (works for local + network/mobile
 *                  accounts), then fall back to the direct dsLocal reader.
 *  - OPENDIRECTORY Use the OpenDirectory framework (ODRecord verifyPassword).
 *                  This is the recommended production backend.
 *  - DSLOCAL       Parse /var/db/dslocal ShadowHashData and verify the
 *                  SALTED-SHA512-PBKDF2 entry directly. No opendirectoryd
 *                  round-trip; useful in restricted/early-boot contexts.
 *  - PAM           Drive macOS's OpenPAM stack (/etc/pam.d/<service>). This is
 *                  the closest analogue to a Linux login and lets an
 *                  administrator reconfigure policy without recompiling.
 */
typedef enum doorman_backend {
    DOORMAN_BACKEND_AUTO = 0,
    DOORMAN_BACKEND_OPENDIRECTORY,
    DOORMAN_BACKEND_DSLOCAL,
    DOORMAN_BACKEND_PAM,
} doorman_backend_t;

/* ------------------------------------------------------------------------- */
/* MARK: - Conversation (credential collection)                              */
/* ------------------------------------------------------------------------- */

/*
 * Message styles handed to the conversation callback. Values intentionally
 * match Linux-PAM's PAM_PROMPT_ECHO_* / PAM_*_MSG so a PAM conversation
 * function can be reused almost verbatim.
 */
typedef enum doorman_msg_style {
    DOORMAN_PROMPT_ECHO_OFF = 1, /* ask for input, do not echo (password)     */
    DOORMAN_PROMPT_ECHO_ON  = 2, /* ask for input, echo it (username)         */
    DOORMAN_ERROR_MSG       = 3, /* display an error message, no input        */
    DOORMAN_TEXT_INFO       = 4, /* display informational text, no input      */
} doorman_msg_style_t;

typedef struct doorman_message {
    doorman_msg_style_t style;
    const char *msg;             /* NUL-terminated prompt/message text        */
} doorman_message_t;

typedef struct doorman_response {
    char *resp;                  /* heap string owned by doorman after return */
    int   resp_retcode;          /* reserved, set to 0                        */
} doorman_response_t;

/*
 * Conversation callback. Mirrors struct pam_conv's conv().
 *
 * The library calls this to prompt for credentials. For each of the `num_msg`
 * messages the callback must, when the style requests input, allocate a
 * response string with malloc() and store it in resp[i].resp. doorman takes
 * ownership of those strings and frees them (so it can zero password memory).
 *
 * On success return 0; any non-zero value aborts the transaction with
 * DOORMAN_ERR_CONV.
 */
typedef int (*doorman_conv_fn)(int num_msg,
                               const doorman_message_t **msg,
                               doorman_response_t **resp,
                               void *appdata);

typedef struct doorman_conv {
    doorman_conv_fn conv;
    void *appdata;               /* opaque pointer passed back to conv()      */
} doorman_conv_t;

/* ------------------------------------------------------------------------- */
/* MARK: - Transaction lifecycle                                             */
/* ------------------------------------------------------------------------- */

/* Opaque authentication transaction handle. */
typedef struct doorman_handle doorman_handle_t;

/*
 * Begin an authentication transaction. Mirrors pam_start().
 *
 *   service  Policy/service name. Used as the PAM service (/etc/pam.d/<service>)
 *            for the PAM backend, and recorded for logging otherwise. May be
 *            NULL to default to "login".
 *   user     Target username, or NULL if not yet known (the conversation may
 *            prompt for it). Can be set later with doorman_set_item().
 *   conv     Conversation used to collect credentials. May be NULL if you only
 *            ever call the *_password convenience helpers.
 *   backend  Which verification mechanism to use.
 *   out      Receives the new handle on DOORMAN_SUCCESS.
 *
 * Free the handle with doorman_end().
 */
doorman_result_t doorman_start(const char *service,
                               const char *user,
                               const doorman_conv_t *conv,
                               doorman_backend_t backend,
                               doorman_handle_t **out);

/* Tear down a transaction and release all associated memory (mirrors pam_end).
 * Passing NULL is a no-op. */
void doorman_end(doorman_handle_t *handle);

/* Items that can be inspected/updated on a live handle (subset of PAM items). */
typedef enum doorman_item {
    DOORMAN_ITEM_SERVICE = 1,
    DOORMAN_ITEM_USER    = 2,
    DOORMAN_ITEM_RHOST   = 3, /* remote host, informational                   */
    DOORMAN_ITEM_TTY     = 4, /* controlling tty / seat, informational        */
} doorman_item_t;

doorman_result_t doorman_set_item(doorman_handle_t *handle,
                                  doorman_item_t item,
                                  const char *value);

/* Returns a borrowed pointer valid until the item changes or the handle is
 * freed. *value is set to NULL if the item was never set. */
doorman_result_t doorman_get_item(doorman_handle_t *handle,
                                  doorman_item_t item,
                                  const char **value);

/*
 * Verify the user's credentials. Mirrors pam_authenticate(). Runs the
 * conversation to obtain the password (and the username, if it was NULL) and
 * checks it against the selected backend.
 */
doorman_result_t doorman_authenticate(doorman_handle_t *handle);

/*
 * Validate that the authenticated account is allowed to log in right now
 * (not disabled, not expired). Mirrors pam_acct_mgmt(). For the directory
 * backends this checks the account's authentication authority / disabled
 * state; for PAM it calls pam_acct_mgmt().
 */
doorman_result_t doorman_acct_mgmt(doorman_handle_t *handle);

/*
 * Credential establishment flags, mirroring pam_setcred()'s flags.
 */
typedef enum doorman_cred_flag {
    DOORMAN_CRED_ESTABLISH    = 1, /* set up user credentials                 */
    DOORMAN_CRED_DELETE       = 2, /* tear down credentials                   */
    DOORMAN_CRED_REINITIALIZE = 3, /* fully refresh credentials               */
    DOORMAN_CRED_REFRESH      = 4, /* extend the lifetime of credentials      */
} doorman_cred_flag_t;

/*
 * Establish (or tear down) the authenticated user's credentials. Mirrors
 * pam_setcred(). This is the phase that, on Linux, acquires a Kerberos ticket
 * or joins the kernel keyring; on macOS the analogue is establishing the
 * OpenDirectory/Kerberos credential and unlocking the login keychain.
 *
 * With the PAM backend this calls the real pam_setcred() and therefore runs
 * whatever the configured stack does. With the directory backends it is a
 * safe no-op returning DOORMAN_SUCCESS: there is no supported way to unlock a
 * *different* user's login keychain from outside that user's security session,
 * so credential material that depends on the plaintext password must be
 * established inside the launched session. See docs/AUTH_DIFFERENCES.md §5, §9.
 *
 * Must be called after a successful doorman_authenticate().
 */
doorman_result_t doorman_setcred(doorman_handle_t *handle,
                                 doorman_cred_flag_t flag);

/*
 * Resolve the supplementary group id list for a user, the way a login program
 * does before initgroups(). Wraps getgrouplist(), which is serviced by
 * opendirectoryd on macOS and NSS on Linux, so the result matches across
 * platforms for the common (non-nested) case. See docs/AUTH_DIFFERENCES.md §6.
 *
 * On success *gids points to a heap array of *count gid_t values (the primary
 * gid is included first); free it with free(). If the user has more groups
 * than a reasonable buffer, the list is still returned fully.
 */
doorman_result_t doorman_get_groups(const char *user,
                                    gid_t **gids,
                                    size_t *count);

/* ------------------------------------------------------------------------- */
/* MARK: - Convenience one-shot authentication                               */
/* ------------------------------------------------------------------------- */

/*
 * Authenticate a username/password pair without setting up a conversation.
 * Handy for callers that already have the password in hand. Does not open a
 * session.
 */
doorman_result_t doorman_authenticate_password(const char *user,
                                                const char *password,
                                                doorman_backend_t backend);

/* ------------------------------------------------------------------------- */
/* MARK: - User enumeration                                                  */
/* ------------------------------------------------------------------------- */

/*
 * A directory user, analogous to a struct passwd entry a Linux DM would read
 * from getpwent(). All strings are heap-owned and freed by doorman_free_users.
 */
typedef struct doorman_user {
    char  *name;      /* short/record name (login name)                       */
    char  *full_name; /* display / GECOS name, may be NULL                    */
    char  *home;      /* home directory, may be NULL                          */
    char  *shell;     /* login shell, may be NULL                             */
    uid_t  uid;
    gid_t  gid;
    bool   hidden;    /* system/service account not normally shown at login   */
} doorman_user_t;

/*
 * Enumerate directory users. If `interactive_only` is true, hidden/system
 * accounts (uid < 500, names starting with '_', /usr/bin/false shells, etc.)
 * are filtered out, matching what a login screen would display.
 *
 * On success *out points to a heap array of `*count` entries; free it with
 * doorman_free_users().
 */
doorman_result_t doorman_enumerate_users(bool interactive_only,
                                         doorman_user_t **out,
                                         size_t *count);

void doorman_free_users(doorman_user_t *users, size_t count);

/* Look up a single user by name. Fills a caller-provided struct whose members
 * must be released with doorman_free_user_fields(). */
doorman_result_t doorman_lookup_user(const char *name, doorman_user_t *out);
void doorman_free_user_fields(doorman_user_t *user);

/* ------------------------------------------------------------------------- */
/* MARK: - Session discovery and launch                                      */
/* ------------------------------------------------------------------------- */

/*
 * A selectable session, analogous to the freedesktop .desktop entries a Linux
 * display manager reads from /usr/share/xsessions and
 * /usr/share/wayland-sessions. doorman discovers these same directories so a
 * ported display manager keeps working, and also synthesizes a built-in
 * "aqua" entry for the stock macOS session.
 */
typedef struct doorman_session {
    char *id;      /* stable id (desktop file basename, or "aqua")           */
    char *name;    /* human-readable Name= from the desktop entry            */
    char *comment; /* Comment= description, may be NULL                      */
    char *exec;    /* Exec= command line to launch the session               */
    char *type;    /* "wayland", "x11", or "aqua"                            */
} doorman_session_t;

/*
 * Discover available sessions. Reads the standard freedesktop session
 * directories (honoring $XDG_DATA_DIRS) plus the built-in aqua session.
 * Free with doorman_free_sessions().
 */
doorman_result_t doorman_enumerate_sessions(doorman_session_t **out,
                                            size_t *count);

void doorman_free_sessions(doorman_session_t *sessions, size_t count);

/*
 * Open a session for the authenticated user and launch `session`. Mirrors
 * pam_open_session() followed by the display manager fork/exec.
 *
 * This must be called after a successful doorman_authenticate(). When the
 * caller is running as root it drops privileges to the target user (setgid,
 * initgroups, setuid), establishes a minimal login environment (HOME, USER,
 * LOGNAME, SHELL, PATH and the XDG_* variables a Wayland session expects) and
 * execs the session command in a forked child.
 *
 * On success the child pid is written to *out_pid (if non-NULL) and the
 * function returns immediately; the caller is expected to wait on the pid and
 * later call doorman_close_session().
 */
doorman_result_t doorman_open_session(doorman_handle_t *handle,
                                      const doorman_session_t *session,
                                      pid_t *out_pid);

/* Mirrors pam_close_session(); tears down session bookkeeping. */
doorman_result_t doorman_close_session(doorman_handle_t *handle);

/* ------------------------------------------------------------------------- */
/* MARK: - Account provisioning (users and groups)                           */
/* ------------------------------------------------------------------------- */

/*
 * Account creation/management. This is the macOS analogue of Linux's
 * useradd/userdel/groupadd/passwd, letting a caller create and manage accounts
 * with a Linux-shaped API. It writes through macOS's native account substrate
 * (Open Directory local node via `dscl`, groups via `dseditgroup`) and creates
 * home directories from the macOS user template via `createhomedir`, so the
 * result is a fully valid macOS account that the stock tools (`passwd`, `id`,
 * `dscl`, Login Window) all see and interoperate with.
 *
 * All of these operations modify the local directory and therefore require
 * root privileges; they return DOORMAN_ERR_PERM otherwise. See
 * docs/CLI_AND_PROVISIONING.md.
 */

/* Description of an account to create. Zero/NULL fields take sane defaults. */
typedef struct doorman_user_spec {
    const char *name;       /* required: short (login) name                    */
    const char *full_name;  /* RealName; defaults to name                      */
    const char *password;   /* initial password; NULL leaves it unset/disabled */
    const char *home;       /* NFSHomeDirectory; defaults to /Users/<name>     */
    const char *shell;      /* UserShell; defaults to /bin/zsh                 */
    uid_t uid;              /* UniqueID; 0 => auto-assign next free >= 501      */
    gid_t gid;              /* PrimaryGroupID; 0 => 20 (staff)                 */
    bool admin;            /* also add to the 'admin' group                    */
    bool hidden;           /* set IsHidden (service/hidden account)            */
    bool create_home;      /* create the home directory from the macOS template*/
} doorman_user_spec_t;

/* Create a user account (Linux `useradd`). */
doorman_result_t doorman_create_user(const doorman_user_spec_t *spec);

/* Delete a user account (Linux `userdel`); optionally remove its home dir. */
doorman_result_t doorman_delete_user(const char *name, bool remove_home);

/* Set/reset a user's password (Linux `passwd`). As root no old password is
 * required; this writes the same ShadowHashData the system `passwd` writes. */
doorman_result_t doorman_set_password(const char *name, const char *new_password);

/* Ensure a user's home directory exists, created from the macOS user template
 * (wraps `createhomedir`). Idempotent. */
doorman_result_t doorman_create_home(const char *name);

/* Create a group (Linux `groupadd`). gid 0 => auto-assign. full_name optional. */
doorman_result_t doorman_create_group(const char *name, gid_t gid,
                                      const char *full_name);

/* Delete a group (Linux `groupdel`). */
doorman_result_t doorman_delete_group(const char *name);

/* Add/remove a user to/from a group (Linux `usermod -aG` / `gpasswd -d`). */
doorman_result_t doorman_add_user_to_group(const char *user, const char *group);
doorman_result_t doorman_remove_user_from_group(const char *user, const char *group);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DOORMAN_H */
