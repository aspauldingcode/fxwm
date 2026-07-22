/*
 * doorman.m - the transaction core: lifecycle, item accessors, credential
 * collection, and the authenticate/acct/setcred verbs. Backend verification
 * and the PAM bridge live in their own translation units; this file only
 * orchestrates them.
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

static char *dm_strdup_opt(const char *s) {
    return s ? strdup(s) : NULL;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

doorman_result_t doorman_start(const char *service,
                               const char *user,
                               const doorman_conv_t *conv,
                               doorman_backend_t backend,
                               doorman_handle_t **out) {
    if (!out) return DOORMAN_ERR_INVALID_ARG;
    *out = NULL;

    doorman_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return DOORMAN_ERR_SYSTEM;

    h->service = dm_strdup_opt(service ? service : "login");
    h->user = dm_strdup_opt(user);
    h->backend = backend;
    if (conv) h->conv = *conv;

    *out = h;
    return DOORMAN_SUCCESS;
}

void doorman_end(doorman_handle_t *handle) {
    if (!handle) return;

    /* The PAM backend stashes a box whose first member is the live pam handle;
     * release it before dropping our own state. */
    if (handle->backend == DOORMAN_BACKEND_PAM && handle->backend_state) {
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

/* ------------------------------------------------------------------------- */
/* Items                                                                     */
/* ------------------------------------------------------------------------- */

static char **slot_for_item(doorman_handle_t *handle, doorman_item_t item) {
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
    char **slot = slot_for_item(handle, item);
    if (!slot) return DOORMAN_ERR_INVALID_ARG;
    char *copy = dm_strdup_opt(value);
    if (value && !copy) return DOORMAN_ERR_SYSTEM;
    free(*slot);
    *slot = copy;
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_get_item(doorman_handle_t *handle,
                                  doorman_item_t item,
                                  const char **value) {
    if (!handle || !value) return DOORMAN_ERR_INVALID_ARG;
    char **slot = slot_for_item(handle, item);
    if (!slot) return DOORMAN_ERR_INVALID_ARG;
    *value = *slot;
    return DOORMAN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Credential collection                                                     */
/* ------------------------------------------------------------------------- */

/* Free every response string a conversation produced, scrubbing each first
 * (any of them may be a password). */
static void discard_responses(doorman_response_t *resps, int n) {
    for (int i = 0; i < n; i++) {
        if (resps[i].resp) {
            _dm_scrub_free(&resps[i].resp, strlen(resps[i].resp));
        }
    }
}

/*
 * Drive the conversation to obtain the password and, if the handle did not
 * already carry a username, the login name too. Ownership of the collected
 * password is transferred to the caller via *out_secret (heap, must be
 * scrubbed and freed).
 */
static doorman_result_t run_credential_conversation(doorman_handle_t *handle,
                                                    char **out_secret) {
    *out_secret = NULL;
    if (!handle->conv.conv) return DOORMAN_ERR_CONV;

    const bool ask_user = (handle->user == NULL);
    const int count = ask_user ? 2 : 1;

    doorman_message_t prompts[2];
    const doorman_message_t *prompt_ptrs[2];
    doorman_response_t answers[2];
    doorman_response_t *answer_ptrs[2];
    memset(answers, 0, sizeof(answers));

    int at = 0;
    if (ask_user) {
        prompts[at].style = DOORMAN_PROMPT_ECHO_ON;
        prompts[at].msg = "login: ";
        at++;
    }
    prompts[at].style = DOORMAN_PROMPT_ECHO_OFF;
    prompts[at].msg = "Password: ";
    at++;

    for (int i = 0; i < count; i++) {
        prompt_ptrs[i] = &prompts[i];
        answer_ptrs[i] = &answers[i];
    }

    if (handle->conv.conv(count, prompt_ptrs, answer_ptrs, handle->conv.appdata) != 0) {
        discard_responses(answers, count);
        return DOORMAN_ERR_CONV;
    }

    at = 0;
    if (ask_user) {
        if (answers[at].resp) {
            free(handle->user);
            handle->user = strdup(answers[at].resp);
            free(answers[at].resp);
            answers[at].resp = NULL;
        }
        at++;
    }
    *out_secret = answers[at].resp;   /* hand ownership to the caller */
    answers[at].resp = NULL;

    if (!handle->user) return DOORMAN_ERR_USER_UNKNOWN;
    if (!*out_secret) return DOORMAN_ERR_CONV;
    return DOORMAN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Authentication                                                            */
/* ------------------------------------------------------------------------- */

/* Route a name/secret pair to the requested directory backend. PAM has its own
 * path and is rejected here. */
static doorman_result_t dispatch_directory_verify(doorman_backend_t backend,
                                                  const char *user,
                                                  const char *secret) {
    switch (backend) {
        case DOORMAN_BACKEND_OPENDIRECTORY:
            return _dm_verify_opendirectory(user, secret);
        case DOORMAN_BACKEND_DSLOCAL:
            return _dm_verify_dslocal(user, secret);
        case DOORMAN_BACKEND_AUTO: {
            doorman_result_t primary = _dm_verify_opendirectory(user, secret);
            /* Only fall through to the on-disk reader for lookup/system faults,
             * never to give a rejected password a second bite. */
            if (primary == DOORMAN_ERR_SYSTEM || primary == DOORMAN_ERR_USER_UNKNOWN) {
                doorman_result_t offline = _dm_verify_dslocal(user, secret);
                if (offline == DOORMAN_SUCCESS || offline == DOORMAN_ERR_AUTH)
                    return offline;
            }
            return primary;
        }
        case DOORMAN_BACKEND_PAM:
            return DOORMAN_ERR_UNSUPPORTED;
    }
    return DOORMAN_ERR_INVALID_ARG;
}

doorman_result_t doorman_authenticate(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;

    if (handle->backend == DOORMAN_BACKEND_PAM) {
        doorman_result_t r = _dm_pam_authenticate(handle);
        handle->authenticated = (r == DOORMAN_SUCCESS);
        return r;
    }

    char *secret = NULL;
    doorman_result_t r = run_credential_conversation(handle, &secret);
    if (r != DOORMAN_SUCCESS) return r;

    r = dispatch_directory_verify(handle->backend, handle->user, secret);
    _dm_scrub_free(&secret, secret ? strlen(secret) : 0);

    handle->authenticated = (r == DOORMAN_SUCCESS);
    return r;
}

doorman_result_t doorman_acct_mgmt(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;

    if (handle->backend == DOORMAN_BACKEND_PAM)
        return _dm_pam_check_account(handle);

    return _dm_account_is_enabled(handle->user);
}

doorman_result_t doorman_setcred(doorman_handle_t *handle,
                                 doorman_cred_flag_t flag) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;

    if (handle->backend == DOORMAN_BACKEND_PAM)
        return _dm_pam_setcred(handle, (int)flag);

    /* Directory backends: there is no supported way to establish another user's
     * keychain/Kerberos credentials from outside their security session, so
     * this is a documented no-op. See docs/AUTH_DIFFERENCES.md §5. */
    return DOORMAN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Group resolution                                                          */
/* ------------------------------------------------------------------------- */

doorman_result_t doorman_get_groups(const char *user,
                                    gid_t **gids,
                                    size_t *count) {
    if (!user || !gids || !count) return DOORMAN_ERR_INVALID_ARG;
    *gids = NULL;
    *count = 0;

    doorman_user_t info;
    if (doorman_lookup_user(user, &info) != DOORMAN_SUCCESS)
        return DOORMAN_ERR_USER_UNKNOWN;
    gid_t primary = info.gid;
    doorman_free_user_fields(&info);

    /* macOS getgrouplist() wants an int* buffer (glibc uses gid_t*); we work in
     * int and convert for the caller. The buffer may have to grow; some macOS
     * builds return -1 without enlarging *slots, so we force forward progress
     * and cap the retries to avoid an unbounded spin. */
    int slots = 32;
    int *scratch = NULL;
    bool done = false;
    for (int attempt = 0; attempt < 12; attempt++) {
        int *grown = realloc(scratch, (size_t)slots * sizeof(*scratch));
        if (!grown) { free(scratch); return DOORMAN_ERR_SYSTEM; }
        scratch = grown;
        int before = slots;
        if (getgrouplist(user, (int)primary, scratch, &slots) != -1) { done = true; break; }
        if (slots <= before) slots = before * 2;
    }
    if (!done) { free(scratch); return DOORMAN_ERR_SYSTEM; }

    gid_t *result = malloc((size_t)slots * sizeof(*result));
    if (!result) { free(scratch); return DOORMAN_ERR_SYSTEM; }
    for (int i = 0; i < slots; i++) result[i] = (gid_t)scratch[i];
    free(scratch);

    *gids = result;
    *count = (size_t)slots;
    return DOORMAN_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* One-shot convenience                                                      */
/* ------------------------------------------------------------------------- */

doorman_result_t doorman_authenticate_password(const char *user,
                                               const char *password,
                                               doorman_backend_t backend) {
    if (!user || !password) return DOORMAN_ERR_INVALID_ARG;
    if (backend == DOORMAN_BACKEND_PAM) {
        /* PAM must drive its own conversation; the one-shot helper is for the
         * directory backends only. */
        return DOORMAN_ERR_UNSUPPORTED;
    }
    return dispatch_directory_verify(backend, user, password);
}
