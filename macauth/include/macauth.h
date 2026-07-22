/*
 * macauth.h - macOS user authentication framework
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

#ifndef MACAUTH_H
#define MACAUTH_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MACAUTH_VERSION_MAJOR 0
#define MACAUTH_VERSION_MINOR 1
#define MACAUTH_VERSION_PATCH 0

/* ------------------------------------------------------------------------- */
/* MARK: - Result codes                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Result codes returned by every macauth call. These mirror the semantic
 * distinctions PAM makes (PAM_SUCCESS, PAM_AUTH_ERR, PAM_USER_UNKNOWN,
 * PAM_ACCT_EXPIRED, ...) so that a caller ported from a Linux login stack can
 * map return values one-to-one.
 */
typedef enum macauth_result {
    MACAUTH_SUCCESS = 0,       /* operation completed successfully            */
    MACAUTH_ERR_AUTH,          /* credentials were rejected                   */
    MACAUTH_ERR_USER_UNKNOWN,  /* no such user in the directory               */
    MACAUTH_ERR_ACCT_DISABLED, /* account exists but cannot log in            */
    MACAUTH_ERR_PERM,          /* caller lacks privileges for the operation   */
    MACAUTH_ERR_CONV,          /* the conversation callback failed/aborted    */
    MACAUTH_ERR_ABORT,         /* unrecoverable error, transaction is dead    */
    MACAUTH_ERR_NO_SESSION,    /* requested session id was not found          */
    MACAUTH_ERR_SYSTEM,        /* underlying OS/directory error               */
    MACAUTH_ERR_INVALID_ARG,   /* a required argument was NULL/invalid        */
    MACAUTH_ERR_UNSUPPORTED,   /* backend does not support the operation      */
} macauth_result_t;

/*
 * Human-readable, static description of a result code. Never returns NULL and
 * the returned string must not be freed. Analogous to pam_strerror().
 */
const char *macauth_strerror(macauth_result_t result);

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
 *                  round-trip; useful in restricted/early-boot contexts (this
 *                  is the mechanism fxwm originally used).
 *  - PAM           Drive macOS's OpenPAM stack (/etc/pam.d/<service>). This is
 *                  the closest analogue to a Linux login and lets an
 *                  administrator reconfigure policy without recompiling.
 */
typedef enum macauth_backend {
    MACAUTH_BACKEND_AUTO = 0,
    MACAUTH_BACKEND_OPENDIRECTORY,
    MACAUTH_BACKEND_DSLOCAL,
    MACAUTH_BACKEND_PAM,
} macauth_backend_t;

/* ------------------------------------------------------------------------- */
/* MARK: - Conversation (credential collection)                              */
/* ------------------------------------------------------------------------- */

/*
 * Message styles handed to the conversation callback. Values intentionally
 * match Linux-PAM's PAM_PROMPT_ECHO_* / PAM_*_MSG so a PAM conversation
 * function can be reused almost verbatim.
 */
typedef enum macauth_msg_style {
    MACAUTH_PROMPT_ECHO_OFF = 1, /* ask for input, do not echo (password)     */
    MACAUTH_PROMPT_ECHO_ON  = 2, /* ask for input, echo it (username)         */
    MACAUTH_ERROR_MSG       = 3, /* display an error message, no input        */
    MACAUTH_TEXT_INFO       = 4, /* display informational text, no input      */
} macauth_msg_style_t;

typedef struct macauth_message {
    macauth_msg_style_t style;
    const char *msg;             /* NUL-terminated prompt/message text        */
} macauth_message_t;

typedef struct macauth_response {
    char *resp;                  /* heap string owned by macauth after return */
    int   resp_retcode;          /* reserved, set to 0                        */
} macauth_response_t;

/*
 * Conversation callback. Mirrors struct pam_conv's conv().
 *
 * The library calls this to prompt for credentials. For each of the `num_msg`
 * messages the callback must, when the style requests input, allocate a
 * response string with malloc() and store it in resp[i].resp. macauth takes
 * ownership of those strings and frees them (so it can zero password memory).
 *
 * On success return 0; any non-zero value aborts the transaction with
 * MACAUTH_ERR_CONV.
 */
typedef int (*macauth_conv_fn)(int num_msg,
                               const macauth_message_t **msg,
                               macauth_response_t **resp,
                               void *appdata);

typedef struct macauth_conv {
    macauth_conv_fn conv;
    void *appdata;               /* opaque pointer passed back to conv()      */
} macauth_conv_t;

/* ------------------------------------------------------------------------- */
/* MARK: - Transaction lifecycle                                             */
/* ------------------------------------------------------------------------- */

/* Opaque authentication transaction handle. */
typedef struct macauth_handle macauth_handle_t;

/*
 * Begin an authentication transaction. Mirrors pam_start().
 *
 *   service  Policy/service name. Used as the PAM service (/etc/pam.d/<service>)
 *            for the PAM backend, and recorded for logging otherwise. May be
 *            NULL to default to "login".
 *   user     Target username, or NULL if not yet known (the conversation may
 *            prompt for it). Can be set later with macauth_set_item().
 *   conv     Conversation used to collect credentials. May be NULL if you only
 *            ever call the *_password convenience helpers.
 *   backend  Which verification mechanism to use.
 *   out      Receives the new handle on MACAUTH_SUCCESS.
 *
 * Free the handle with macauth_end().
 */
macauth_result_t macauth_start(const char *service,
                               const char *user,
                               const macauth_conv_t *conv,
                               macauth_backend_t backend,
                               macauth_handle_t **out);

/* Tear down a transaction and release all associated memory (mirrors pam_end).
 * Passing NULL is a no-op. */
void macauth_end(macauth_handle_t *handle);

/* Items that can be inspected/updated on a live handle (subset of PAM items). */
typedef enum macauth_item {
    MACAUTH_ITEM_SERVICE = 1,
    MACAUTH_ITEM_USER    = 2,
    MACAUTH_ITEM_RHOST   = 3, /* remote host, informational                   */
    MACAUTH_ITEM_TTY     = 4, /* controlling tty / seat, informational        */
} macauth_item_t;

macauth_result_t macauth_set_item(macauth_handle_t *handle,
                                  macauth_item_t item,
                                  const char *value);

/* Returns a borrowed pointer valid until the item changes or the handle is
 * freed. *value is set to NULL if the item was never set. */
macauth_result_t macauth_get_item(macauth_handle_t *handle,
                                  macauth_item_t item,
                                  const char **value);

/*
 * Verify the user's credentials. Mirrors pam_authenticate(). Runs the
 * conversation to obtain the password (and the username, if it was NULL) and
 * checks it against the selected backend.
 */
macauth_result_t macauth_authenticate(macauth_handle_t *handle);

/*
 * Validate that the authenticated account is allowed to log in right now
 * (not disabled, not expired). Mirrors pam_acct_mgmt(). For the directory
 * backends this checks the account's authentication authority / disabled
 * state; for PAM it calls pam_acct_mgmt().
 */
macauth_result_t macauth_acct_mgmt(macauth_handle_t *handle);

/* ------------------------------------------------------------------------- */
/* MARK: - Convenience one-shot authentication                               */
/* ------------------------------------------------------------------------- */

/*
 * Authenticate a username/password pair without setting up a conversation.
 * This is the direct replacement for fxwm's old DoLogon() and is handy for
 * callers that already have the password in hand. Does not open a session.
 */
macauth_result_t macauth_authenticate_password(const char *user,
                                                const char *password,
                                                macauth_backend_t backend);

/* ------------------------------------------------------------------------- */
/* MARK: - User enumeration                                                  */
/* ------------------------------------------------------------------------- */

/*
 * A directory user, analogous to a struct passwd entry a Linux DM would read
 * from getpwent(). All strings are heap-owned and freed by macauth_free_users.
 */
typedef struct macauth_user {
    char  *name;      /* short/record name (login name)                       */
    char  *full_name; /* display / GECOS name, may be NULL                    */
    char  *home;      /* home directory, may be NULL                          */
    char  *shell;     /* login shell, may be NULL                             */
    uid_t  uid;
    gid_t  gid;
    bool   hidden;    /* system/service account not normally shown at login   */
} macauth_user_t;

/*
 * Enumerate directory users. If `interactive_only` is true, hidden/system
 * accounts (uid < 500, names starting with '_', /usr/bin/false shells, etc.)
 * are filtered out, matching what a login screen would display.
 *
 * On success *out points to a heap array of `*count` entries; free it with
 * macauth_free_users().
 */
macauth_result_t macauth_enumerate_users(bool interactive_only,
                                         macauth_user_t **out,
                                         size_t *count);

void macauth_free_users(macauth_user_t *users, size_t count);

/* Look up a single user by name. Fills a caller-provided struct whose members
 * must be released with macauth_free_user_fields(). */
macauth_result_t macauth_lookup_user(const char *name, macauth_user_t *out);
void macauth_free_user_fields(macauth_user_t *user);

/* ------------------------------------------------------------------------- */
/* MARK: - Session discovery and launch                                      */
/* ------------------------------------------------------------------------- */

/*
 * A selectable session, analogous to the freedesktop .desktop entries a Linux
 * display manager reads from /usr/share/xsessions and
 * /usr/share/wayland-sessions. macauth discovers these same directories so a
 * ported display manager keeps working, and also synthesizes a built-in
 * "aqua" entry for the stock macOS session.
 */
typedef struct macauth_session {
    char *id;      /* stable id (desktop file basename, or "aqua")           */
    char *name;    /* human-readable Name= from the desktop entry            */
    char *comment; /* Comment= description, may be NULL                      */
    char *exec;    /* Exec= command line to launch the session               */
    char *type;    /* "wayland", "x11", or "aqua"                            */
} macauth_session_t;

/*
 * Discover available sessions. Reads the standard freedesktop session
 * directories (honoring $XDG_DATA_DIRS) plus the built-in aqua session.
 * Free with macauth_free_sessions().
 */
macauth_result_t macauth_enumerate_sessions(macauth_session_t **out,
                                            size_t *count);

void macauth_free_sessions(macauth_session_t *sessions, size_t count);

/*
 * Open a session for the authenticated user and launch `session`. Mirrors
 * pam_open_session() followed by the display manager fork/exec.
 *
 * This must be called after a successful macauth_authenticate(). When the
 * caller is running as root it drops privileges to the target user (setgid,
 * initgroups, setuid), establishes a minimal login environment (HOME, USER,
 * LOGNAME, SHELL, PATH and the XDG_* variables a Wayland session expects) and
 * execs the session command in a forked child.
 *
 * On success the child pid is written to *out_pid (if non-NULL) and the
 * function returns immediately; the caller is expected to wait on the pid and
 * later call macauth_close_session().
 */
macauth_result_t macauth_open_session(macauth_handle_t *handle,
                                      const macauth_session_t *session,
                                      pid_t *out_pid);

/* Mirrors pam_close_session(); tears down session bookkeeping. */
macauth_result_t macauth_close_session(macauth_handle_t *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MACAUTH_H */
