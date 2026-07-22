/*
 * doorman_internal.h - private declarations shared across doorman sources.
 * Not installed; not part of the public ABI.
 */

#ifndef DOORMAN_INTERNAL_H
#define DOORMAN_INTERNAL_H

#import <Foundation/Foundation.h>
#include "doorman.h"

/* The opaque handle definition. */
struct doorman_handle {
    char *service;
    char *user;
    char *rhost;
    char *tty;
    doorman_backend_t backend;
    doorman_conv_t conv;

    bool authenticated;   /* doorman_authenticate() succeeded                 */
    bool session_open;    /* doorman_open_session() succeeded                 */
    pid_t session_pid;    /* pid of the launched session child, or 0          */

    /* Opaque backend-owned state (e.g. a retained pam handle box). */
    void *backend_state;
};

/*
 * Backend password verification entry points. Each verifies `password` for
 * `user` and returns a doorman_result_t. They do not run the conversation;
 * the core is responsible for collecting credentials first.
 */
doorman_result_t _doorman_verify_dslocal(const char *user, const char *password);
doorman_result_t _doorman_verify_opendirectory(const char *user, const char *password);

/*
 * PAM backend. Because PAM owns its own conversation, the PAM path receives the
 * handle so it can bridge doorman's conversation into a struct pam_conv.
 */
doorman_result_t _doorman_pam_authenticate(doorman_handle_t *handle);
doorman_result_t _doorman_pam_acct_mgmt(doorman_handle_t *handle);
doorman_result_t _doorman_pam_setcred(doorman_handle_t *handle, int flag);

/* Account validity checks for the directory backends. */
doorman_result_t _doorman_acct_mgmt_directory(const char *user);

/* Helpers implemented in users.m, reused by session launch. */
BOOL _doorman_copy_passwd(const char *name, doorman_user_t *out);

/* Zero and free a heap string that may hold secret material. */
static inline void _doorman_secure_free(char **p, size_t len) {
    if (p && *p) {
        if (len) memset(*p, 0, len);
        free(*p);
        *p = NULL;
    }
}

#endif /* DOORMAN_INTERNAL_H */
