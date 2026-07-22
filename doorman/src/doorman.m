/*
 * doorman.m - transaction lifecycle and the credential-collection core.
 *
 * This file owns the public transaction surface (start/end/items/authenticate/
 * acct_mgmt) and the convenience one-shot helper. Backend verification and the
 * PAM bridge live in their own translation units.
 */

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include "doorman_internal.h"

const char *doorman_strerror(doorman_result_t result) {
    switch (result) {
        case DOORMAN_SUCCESS:           return "success";
        case DOORMAN_ERR_AUTH:          return "authentication failed";
        case DOORMAN_ERR_USER_UNKNOWN:  return "unknown user";
        case DOORMAN_ERR_ACCT_DISABLED: return "account is disabled or expired";
        case DOORMAN_ERR_PERM:          return "insufficient privileges";
        case DOORMAN_ERR_CONV:          return "conversation error";
        case DOORMAN_ERR_ABORT:         return "transaction aborted";
        case DOORMAN_ERR_NO_SESSION:    return "no such session";
        case DOORMAN_ERR_SYSTEM:        return "system error";
        case DOORMAN_ERR_INVALID_ARG:   return "invalid argument";
        case DOORMAN_ERR_UNSUPPORTED:   return "operation not supported";
    }
    return "unknown error";
}

static char *dup_or_null(const char *s) {
    return s ? strdup(s) : NULL;
}

doorman_result_t doorman_start(const char *service,
                               const char *user,
                               const doorman_conv_t *conv,
                               doorman_backend_t backend,
                               doorman_handle_t **out) {
    if (!out) return DOORMAN_ERR_INVALID_ARG;
    *out = NULL;

    doorman_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return DOORMAN_ERR_SYSTEM;

    h->service = dup_or_null(service ? service : "login");
    h->user = dup_or_null(user);
    h->backend = backend;
    if (conv) h->conv = *conv;

    *out = h;
    return DOORMAN_SUCCESS;
}

void doorman_end(doorman_handle_t *handle) {
    if (!handle) return;

    /* Release any live PAM handle stashed by the PAM backend. */
    if (handle->backend == DOORMAN_BACKEND_PAM && handle->backend_state) {
        /* pam_state_t begins with a pam_handle_t*; end it. */
        pam_handle_t **pamh = (pam_handle_t **)handle->backend_state;
        if (*pamh) pam_end(*pamh, PAM_SUCCESS);
        free(handle->backend_state);
        handle->backend_state = NULL;
    }

    free(handle->service);
    free(handle->user);
    free(handle->rhost);
    free(handle->tty);
    free(handle);
}

static char **item_slot(doorman_handle_t *handle, doorman_item_t item) {
    switch (item) {
        case DOORMAN_ITEM_SERVICE: return &handle->service;
        case DOORMAN_ITEM_USER:    return &handle->user;
        case DOORMAN_ITEM_RHOST:   return &handle->rhost;
        case DOORMAN_ITEM_TTY:     return &handle->tty;
    }
    return NULL;
}

doorman_result_t doorman_set_item(doorman_handle_t *handle,
                                  doorman_item_t item,
                                  const char *value) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    char **slot = item_slot(handle, item);
    if (!slot) return DOORMAN_ERR_INVALID_ARG;
    char *copy = dup_or_null(value);
    if (value && !copy) return DOORMAN_ERR_SYSTEM;
    free(*slot);
    *slot = copy;
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_get_item(doorman_handle_t *handle,
                                  doorman_item_t item,
                                  const char **value) {
    if (!handle || !value) return DOORMAN_ERR_INVALID_ARG;
    char **slot = item_slot(handle, item);
    if (!slot) return DOORMAN_ERR_INVALID_ARG;
    *value = *slot;
    return DOORMAN_SUCCESS;
}

/*
 * Run the conversation to obtain (optionally) the username and the password.
 * Returns the collected password via *out_password (heap, caller frees) and,
 * if the handle had no user, sets it from the echoed response.
 */
static doorman_result_t collect_credentials(doorman_handle_t *handle,
                                             char **out_password) {
    *out_password = NULL;
    if (!handle->conv.conv) return DOORMAN_ERR_CONV;

    bool need_user = (handle->user == NULL);

    /* One message for the username (if unknown) and one for the password. */
    int num_msg = need_user ? 2 : 1;
    doorman_message_t msgs[2];
    const doorman_message_t *msg_ptrs[2];
    doorman_response_t resps[2];
    doorman_response_t *resp_ptrs[2];
    memset(resps, 0, sizeof(resps));

    int idx = 0;
    if (need_user) {
        msgs[idx].style = DOORMAN_PROMPT_ECHO_ON;
        msgs[idx].msg = "login: ";
        idx++;
    }
    msgs[idx].style = DOORMAN_PROMPT_ECHO_OFF;
    msgs[idx].msg = "Password: ";
    idx++;

    for (int i = 0; i < num_msg; i++) {
        msg_ptrs[i] = &msgs[i];
        resp_ptrs[i] = &resps[i];
    }

    int rc = handle->conv.conv(num_msg, msg_ptrs, resp_ptrs, handle->conv.appdata);
    if (rc != 0) {
        for (int i = 0; i < num_msg; i++)
            if (resps[i].resp) { size_t l = strlen(resps[i].resp); _doorman_secure_free(&resps[i].resp, l); }
        return DOORMAN_ERR_CONV;
    }

    idx = 0;
    if (need_user) {
        if (resps[idx].resp) {
            free(handle->user);
            handle->user = strdup(resps[idx].resp);
            free(resps[idx].resp);
            resps[idx].resp = NULL;
        }
        idx++;
    }
    *out_password = resps[idx].resp; /* transfer ownership to caller */
    resps[idx].resp = NULL;

    if (!handle->user) return DOORMAN_ERR_USER_UNKNOWN;
    if (!*out_password) return DOORMAN_ERR_CONV;
    return DOORMAN_SUCCESS;
}

/* Dispatch a username/password check to the selected directory backend. */
static doorman_result_t verify_with_backend(doorman_backend_t backend,
                                            const char *user,
                                            const char *password) {
    switch (backend) {
        case DOORMAN_BACKEND_OPENDIRECTORY:
            return _doorman_verify_opendirectory(user, password);
        case DOORMAN_BACKEND_DSLOCAL:
            return _doorman_verify_dslocal(user, password);
        case DOORMAN_BACKEND_AUTO: {
            doorman_result_t r = _doorman_verify_opendirectory(user, password);
            /* Fall back to the on-disk reader only for system/lookup faults,
             * never to turn a rejected password into a second attempt. */
            if (r == DOORMAN_ERR_SYSTEM || r == DOORMAN_ERR_USER_UNKNOWN) {
                doorman_result_t r2 = _doorman_verify_dslocal(user, password);
                if (r2 == DOORMAN_SUCCESS || r2 == DOORMAN_ERR_AUTH) return r2;
            }
            return r;
        }
        case DOORMAN_BACKEND_PAM:
            /* Handled by the PAM-specific path, not here. */
            return DOORMAN_ERR_UNSUPPORTED;
    }
    return DOORMAN_ERR_INVALID_ARG;
}

doorman_result_t doorman_authenticate(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;

    if (handle->backend == DOORMAN_BACKEND_PAM) {
        doorman_result_t r = _doorman_pam_authenticate(handle);
        handle->authenticated = (r == DOORMAN_SUCCESS);
        return r;
    }

    char *password = NULL;
    doorman_result_t r = collect_credentials(handle, &password);
    if (r != DOORMAN_SUCCESS) return r;

    r = verify_with_backend(handle->backend, handle->user, password);

    size_t plen = password ? strlen(password) : 0;
    _doorman_secure_free(&password, plen);

    handle->authenticated = (r == DOORMAN_SUCCESS);
    return r;
}

doorman_result_t doorman_acct_mgmt(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;

    if (handle->backend == DOORMAN_BACKEND_PAM)
        return _doorman_pam_acct_mgmt(handle);

    return _doorman_acct_mgmt_directory(handle->user);
}

doorman_result_t doorman_setcred(doorman_handle_t *handle,
                                 doorman_cred_flag_t flag) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;

    if (handle->backend == DOORMAN_BACKEND_PAM)
        return _doorman_pam_setcred(handle, (int)flag);

    /* Directory backends: establishing keychain/Kerberos credentials for
     * another user from outside their security session is not supported by
     * macOS, so this is a documented no-op. See docs/AUTH_DIFFERENCES.md §5. */
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_get_groups(const char *user,
                                    gid_t **gids,
                                    size_t *count) {
    if (!user || !gids || !count) return DOORMAN_ERR_INVALID_ARG;
    *gids = NULL;
    *count = 0;

    doorman_user_t u;
    if (doorman_lookup_user(user, &u) != DOORMAN_SUCCESS)
        return DOORMAN_ERR_USER_UNKNOWN;
    gid_t primary = u.gid;
    doorman_free_user_fields(&u);

    /* macOS's getgrouplist() takes an int* buffer (glibc uses gid_t*); we use
     * int here to match the platform and convert to gid_t for the caller.
     * The buffer may need to grow to report the full membership. We guarantee
     * forward progress and cap the attempts: some macOS versions return -1
     * without enlarging *ngroups, which would otherwise spin forever. */
    int ngroups = 32;
    int *buf = NULL;
    bool ok = false;
    for (int attempt = 0; attempt < 12; attempt++) {
        int *tmp = realloc(buf, (size_t)ngroups * sizeof(*buf));
        if (!tmp) { free(buf); return DOORMAN_ERR_SYSTEM; }
        buf = tmp;
        int prev = ngroups;
        if (getgrouplist(user, (int)primary, buf, &ngroups) != -1) { ok = true; break; }
        if (ngroups <= prev) ngroups = prev * 2; /* ensure the buffer grows */
    }
    if (!ok) { free(buf); return DOORMAN_ERR_SYSTEM; }

    gid_t *out = malloc((size_t)ngroups * sizeof(*out));
    if (!out) { free(buf); return DOORMAN_ERR_SYSTEM; }
    for (int i = 0; i < ngroups; i++) out[i] = (gid_t)buf[i];
    free(buf);

    *gids = out;
    *count = (size_t)ngroups;
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_authenticate_password(const char *user,
                                               const char *password,
                                               doorman_backend_t backend) {
    if (!user || !password) return DOORMAN_ERR_INVALID_ARG;
    if (backend == DOORMAN_BACKEND_PAM) {
        /* PAM insists on driving its own conversation; the one-shot helper is
         * for the directory backends. Callers wanting PAM should use the full
         * transaction API with a conversation callback. */
        return DOORMAN_ERR_UNSUPPORTED;
    }
    return verify_with_backend(backend, user, password);
}
