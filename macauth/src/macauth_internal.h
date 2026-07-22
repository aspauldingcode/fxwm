/*
 * macauth_internal.h - private declarations shared across macauth sources.
 * Not installed; not part of the public ABI.
 */

#ifndef MACAUTH_INTERNAL_H
#define MACAUTH_INTERNAL_H

#import <Foundation/Foundation.h>
#include "macauth.h"

/* The opaque handle definition. */
struct macauth_handle {
    char *service;
    char *user;
    char *rhost;
    char *tty;
    macauth_backend_t backend;
    macauth_conv_t conv;

    bool authenticated;   /* macauth_authenticate() succeeded                 */
    bool session_open;    /* macauth_open_session() succeeded                 */
    pid_t session_pid;    /* pid of the launched session child, or 0          */

    /* Opaque backend-owned state (e.g. a retained pam handle box). */
    void *backend_state;
};

/*
 * Backend password verification entry points. Each verifies `password` for
 * `user` and returns a macauth_result_t. They do not run the conversation;
 * the core is responsible for collecting credentials first.
 */
macauth_result_t _macauth_verify_dslocal(const char *user, const char *password);
macauth_result_t _macauth_verify_opendirectory(const char *user, const char *password);

/*
 * PAM backend. Because PAM owns its own conversation, the PAM path receives the
 * handle so it can bridge macauth's conversation into a struct pam_conv.
 */
macauth_result_t _macauth_pam_authenticate(macauth_handle_t *handle);
macauth_result_t _macauth_pam_acct_mgmt(macauth_handle_t *handle);

/* Account validity checks for the directory backends. */
macauth_result_t _macauth_acct_mgmt_directory(const char *user);

/* Helpers implemented in users.m, reused by session launch. */
BOOL _macauth_copy_passwd(const char *name, macauth_user_t *out);

/* Zero and free a heap string that may hold secret material. */
static inline void _macauth_secure_free(char **p, size_t len) {
    if (p && *p) {
        if (len) memset(*p, 0, len);
        free(*p);
        *p = NULL;
    }
}

#endif /* MACAUTH_INTERNAL_H */
