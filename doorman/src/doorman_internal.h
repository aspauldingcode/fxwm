/*
 * doorman_internal.h - private declarations shared across the Doorman sources.
 *
 * Nothing here is installed or part of the public ABI; symbols carry the `_dm_`
 * prefix to keep them clearly separate from the exported `doorman_*` surface.
 */

#ifndef DOORMAN_INTERNAL_H
#define DOORMAN_INTERNAL_H

#import <Foundation/Foundation.h>
#include <string.h>
#include <stdlib.h>
#include "doorman.h"

/*
 * Private transaction state behind the opaque doorman_handle_t. Kept small and
 * POD-ish: everything owned here is either a malloc'd C string or a backend box.
 */
struct doorman_handle {
    char *service;
    char *user;
    char *rhost;
    char *tty;
    doorman_backend_t backend;
    doorman_conv_t conv;

    bool authenticated;   /* set once doorman_authenticate() has succeeded     */
    bool session_open;    /* set once doorman_open_session() has succeeded     */
    pid_t session_pid;    /* pid of the launched session child, or 0           */

    void *backend_state;  /* backend-owned box (e.g. a retained PAM handle)    */
};

/* ------------------------------------------------------------------------- */
/* Secret hygiene                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Overwrite a buffer through a volatile pointer so the store cannot be elided
 * by dead-store elimination. Used to scrub plaintext passwords and derived key
 * material as soon as they are no longer needed.
 */
static inline void _dm_scrub(void *buf, size_t len) {
    if (!buf || len == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
}

/* Scrub, free, and NULL a heap string that may have held a secret. */
static inline void _dm_scrub_free(char **slot, size_t len) {
    if (slot && *slot) {
        _dm_scrub(*slot, len);
        free(*slot);
        *slot = NULL;
    }
}

/* Constant-time equality for two byte buffers of equal length. Returns true
 * only when the lengths match and every byte is identical, without leaking a
 * mismatch position through timing. */
bool _dm_consttime_equal(const void *a, const void *b, size_t len);

/* ------------------------------------------------------------------------- */
/* Input validation                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Validate a short account or group name before it is ever interpolated into a
 * filesystem path or handed to a system tool. Accepts only a conservative
 * portable set ([A-Za-z0-9] plus '_', '-', '.'), forbids a leading '-' or '.'
 * (which could be misread as an option or a path component), rejects '/' and
 * control characters outright, and caps the length. This is the primary guard
 * against path traversal in the dsLocal reader and against argument smuggling
 * in the provisioning tools.
 */
bool _dm_name_ok(const char *name);

/* ------------------------------------------------------------------------- */
/* Backend verification entry points                                         */
/* ------------------------------------------------------------------------- */

/* Verify `password` for `user`; neither runs the conversation (the core layer
 * collects credentials first). */
doorman_result_t _dm_verify_dslocal(const char *user, const char *password);
doorman_result_t _dm_verify_opendirectory(const char *user, const char *password);

/* Account validity check for the directory backends (disabled/expired). */
doorman_result_t _dm_account_is_enabled(const char *user);

/* Set a user's password through the OpenDirectory local node. Runs as root and
 * writes the same ShadowHashData the system tools do, without ever exposing the
 * plaintext on a command line. */
doorman_result_t _dm_od_set_password(const char *user, const char *new_password);

/* ------------------------------------------------------------------------- */
/* PAM backend (owns its own conversation, so it takes the handle)           */
/* ------------------------------------------------------------------------- */

doorman_result_t _dm_pam_authenticate(doorman_handle_t *handle);
doorman_result_t _dm_pam_check_account(doorman_handle_t *handle);
doorman_result_t _dm_pam_setcred(doorman_handle_t *handle, int flag);

/* Fill a doorman_user_t from the passwd database (implemented in users.m). */
BOOL _dm_fill_user_from_passwd(const char *name, doorman_user_t *out);

#endif /* DOORMAN_INTERNAL_H */
