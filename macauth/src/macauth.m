/*
 * macauth.m - transaction lifecycle and the credential-collection core.
 *
 * This file owns the public transaction surface (start/end/items/authenticate/
 * acct_mgmt) and the convenience one-shot helper. Backend verification and the
 * PAM bridge live in their own translation units.
 */

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include "macauth_internal.h"

const char *macauth_strerror(macauth_result_t result) {
    switch (result) {
        case MACAUTH_SUCCESS:           return "success";
        case MACAUTH_ERR_AUTH:          return "authentication failed";
        case MACAUTH_ERR_USER_UNKNOWN:  return "unknown user";
        case MACAUTH_ERR_ACCT_DISABLED: return "account is disabled or expired";
        case MACAUTH_ERR_PERM:          return "insufficient privileges";
        case MACAUTH_ERR_CONV:          return "conversation error";
        case MACAUTH_ERR_ABORT:         return "transaction aborted";
        case MACAUTH_ERR_NO_SESSION:    return "no such session";
        case MACAUTH_ERR_SYSTEM:        return "system error";
        case MACAUTH_ERR_INVALID_ARG:   return "invalid argument";
        case MACAUTH_ERR_UNSUPPORTED:   return "operation not supported";
    }
    return "unknown error";
}

static char *dup_or_null(const char *s) {
    return s ? strdup(s) : NULL;
}

macauth_result_t macauth_start(const char *service,
                               const char *user,
                               const macauth_conv_t *conv,
                               macauth_backend_t backend,
                               macauth_handle_t **out) {
    if (!out) return MACAUTH_ERR_INVALID_ARG;
    *out = NULL;

    macauth_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return MACAUTH_ERR_SYSTEM;

    h->service = dup_or_null(service ? service : "login");
    h->user = dup_or_null(user);
    h->backend = backend;
    if (conv) h->conv = *conv;

    *out = h;
    return MACAUTH_SUCCESS;
}

void macauth_end(macauth_handle_t *handle) {
    if (!handle) return;

    /* Release any live PAM handle stashed by the PAM backend. */
    if (handle->backend == MACAUTH_BACKEND_PAM && handle->backend_state) {
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

static char **item_slot(macauth_handle_t *handle, macauth_item_t item) {
    switch (item) {
        case MACAUTH_ITEM_SERVICE: return &handle->service;
        case MACAUTH_ITEM_USER:    return &handle->user;
        case MACAUTH_ITEM_RHOST:   return &handle->rhost;
        case MACAUTH_ITEM_TTY:     return &handle->tty;
    }
    return NULL;
}

macauth_result_t macauth_set_item(macauth_handle_t *handle,
                                  macauth_item_t item,
                                  const char *value) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;
    char **slot = item_slot(handle, item);
    if (!slot) return MACAUTH_ERR_INVALID_ARG;
    char *copy = dup_or_null(value);
    if (value && !copy) return MACAUTH_ERR_SYSTEM;
    free(*slot);
    *slot = copy;
    return MACAUTH_SUCCESS;
}

macauth_result_t macauth_get_item(macauth_handle_t *handle,
                                  macauth_item_t item,
                                  const char **value) {
    if (!handle || !value) return MACAUTH_ERR_INVALID_ARG;
    char **slot = item_slot(handle, item);
    if (!slot) return MACAUTH_ERR_INVALID_ARG;
    *value = *slot;
    return MACAUTH_SUCCESS;
}

/*
 * Run the conversation to obtain (optionally) the username and the password.
 * Returns the collected password via *out_password (heap, caller frees) and,
 * if the handle had no user, sets it from the echoed response.
 */
static macauth_result_t collect_credentials(macauth_handle_t *handle,
                                             char **out_password) {
    *out_password = NULL;
    if (!handle->conv.conv) return MACAUTH_ERR_CONV;

    bool need_user = (handle->user == NULL);

    /* One message for the username (if unknown) and one for the password. */
    int num_msg = need_user ? 2 : 1;
    macauth_message_t msgs[2];
    const macauth_message_t *msg_ptrs[2];
    macauth_response_t resps[2];
    macauth_response_t *resp_ptrs[2];
    memset(resps, 0, sizeof(resps));

    int idx = 0;
    if (need_user) {
        msgs[idx].style = MACAUTH_PROMPT_ECHO_ON;
        msgs[idx].msg = "login: ";
        idx++;
    }
    msgs[idx].style = MACAUTH_PROMPT_ECHO_OFF;
    msgs[idx].msg = "Password: ";
    idx++;

    for (int i = 0; i < num_msg; i++) {
        msg_ptrs[i] = &msgs[i];
        resp_ptrs[i] = &resps[i];
    }

    int rc = handle->conv.conv(num_msg, msg_ptrs, resp_ptrs, handle->conv.appdata);
    if (rc != 0) {
        for (int i = 0; i < num_msg; i++)
            if (resps[i].resp) { size_t l = strlen(resps[i].resp); _macauth_secure_free(&resps[i].resp, l); }
        return MACAUTH_ERR_CONV;
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

    if (!handle->user) return MACAUTH_ERR_USER_UNKNOWN;
    if (!*out_password) return MACAUTH_ERR_CONV;
    return MACAUTH_SUCCESS;
}

/* Dispatch a username/password check to the selected directory backend. */
static macauth_result_t verify_with_backend(macauth_backend_t backend,
                                            const char *user,
                                            const char *password) {
    switch (backend) {
        case MACAUTH_BACKEND_OPENDIRECTORY:
            return _macauth_verify_opendirectory(user, password);
        case MACAUTH_BACKEND_DSLOCAL:
            return _macauth_verify_dslocal(user, password);
        case MACAUTH_BACKEND_AUTO: {
            macauth_result_t r = _macauth_verify_opendirectory(user, password);
            /* Fall back to the on-disk reader only for system/lookup faults,
             * never to turn a rejected password into a second attempt. */
            if (r == MACAUTH_ERR_SYSTEM || r == MACAUTH_ERR_USER_UNKNOWN) {
                macauth_result_t r2 = _macauth_verify_dslocal(user, password);
                if (r2 == MACAUTH_SUCCESS || r2 == MACAUTH_ERR_AUTH) return r2;
            }
            return r;
        }
        case MACAUTH_BACKEND_PAM:
            /* Handled by the PAM-specific path, not here. */
            return MACAUTH_ERR_UNSUPPORTED;
    }
    return MACAUTH_ERR_INVALID_ARG;
}

macauth_result_t macauth_authenticate(macauth_handle_t *handle) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;

    if (handle->backend == MACAUTH_BACKEND_PAM) {
        macauth_result_t r = _macauth_pam_authenticate(handle);
        handle->authenticated = (r == MACAUTH_SUCCESS);
        return r;
    }

    char *password = NULL;
    macauth_result_t r = collect_credentials(handle, &password);
    if (r != MACAUTH_SUCCESS) return r;

    r = verify_with_backend(handle->backend, handle->user, password);

    size_t plen = password ? strlen(password) : 0;
    _macauth_secure_free(&password, plen);

    handle->authenticated = (r == MACAUTH_SUCCESS);
    return r;
}

macauth_result_t macauth_acct_mgmt(macauth_handle_t *handle) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;
    if (!handle->authenticated) return MACAUTH_ERR_ABORT;

    if (handle->backend == MACAUTH_BACKEND_PAM)
        return _macauth_pam_acct_mgmt(handle);

    return _macauth_acct_mgmt_directory(handle->user);
}

macauth_result_t macauth_authenticate_password(const char *user,
                                               const char *password,
                                               macauth_backend_t backend) {
    if (!user || !password) return MACAUTH_ERR_INVALID_ARG;
    if (backend == MACAUTH_BACKEND_PAM) {
        /* PAM insists on driving its own conversation; the one-shot helper is
         * for the directory backends. Callers wanting PAM should use the full
         * transaction API with a conversation callback. */
        return MACAUTH_ERR_UNSUPPORTED;
    }
    return verify_with_backend(backend, user, password);
}
