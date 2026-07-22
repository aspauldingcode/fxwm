/*
 * backend_pam.m - drive macOS's OpenPAM stack.
 *
 * macOS ships OpenPAM (since 10.6) with policy files under /etc/pam.d/. This
 * backend is the most faithful "port of the Linux method": it hands control to
 * the PAM stack configured for the service name, so behaviour is whatever the
 * administrator declared in /etc/pam.d/<service> (pam_opendirectory,
 * pam_unix, smartcard modules, etc.).
 *
 * We bridge macauth's conversation to a struct pam_conv so the same credential
 * prompts flow through unchanged.
 */

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include "macauth_internal.h"

/* Translate a PAM message style into a macauth style. */
static macauth_msg_style_t pam_style_to_macauth(int pam_style) {
    switch (pam_style) {
        case PAM_PROMPT_ECHO_OFF: return MACAUTH_PROMPT_ECHO_OFF;
        case PAM_PROMPT_ECHO_ON:  return MACAUTH_PROMPT_ECHO_ON;
        case PAM_ERROR_MSG:       return MACAUTH_ERROR_MSG;
        case PAM_TEXT_INFO:
        default:                  return MACAUTH_TEXT_INFO;
    }
}

/*
 * PAM conversation shim. appdata_ptr is the macauth_handle_t*. We forward each
 * PAM message to the macauth conversation and copy responses back into
 * PAM-allocated storage (PAM frees resp with free()).
 */
static int pam_conv_shim(int num_msg,
                         const struct pam_message **msg,
                         struct pam_response **resp,
                         void *appdata_ptr) {
    macauth_handle_t *handle = (macauth_handle_t *)appdata_ptr;
    if (!handle || !handle->conv.conv || num_msg <= 0) return PAM_CONV_ERR;

    struct pam_response *replies = calloc((size_t)num_msg, sizeof(*replies));
    if (!replies) return PAM_BUF_ERR;

    /* Build macauth-shaped messages. */
    macauth_message_t *mmsgs = calloc((size_t)num_msg, sizeof(*mmsgs));
    const macauth_message_t **mmsg_ptrs = calloc((size_t)num_msg, sizeof(*mmsg_ptrs));
    macauth_response_t *mresp = calloc((size_t)num_msg, sizeof(*mresp));
    macauth_response_t **mresp_ptrs = calloc((size_t)num_msg, sizeof(*mresp_ptrs));
    if (!mmsgs || !mmsg_ptrs || !mresp || !mresp_ptrs) {
        free(replies); free(mmsgs); free(mmsg_ptrs); free(mresp); free(mresp_ptrs);
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        mmsgs[i].style = pam_style_to_macauth(msg[i]->msg_style);
        mmsgs[i].msg = msg[i]->msg;
        mmsg_ptrs[i] = &mmsgs[i];
        mresp_ptrs[i] = &mresp[i];
    }

    int rc = handle->conv.conv(num_msg, mmsg_ptrs, mresp_ptrs, handle->conv.appdata);
    if (rc != 0) {
        for (int i = 0; i < num_msg; i++) {
            if (mresp[i].resp) { memset(mresp[i].resp, 0, strlen(mresp[i].resp)); free(mresp[i].resp); }
        }
        free(replies); free(mmsgs); free(mmsg_ptrs); free(mresp); free(mresp_ptrs);
        return PAM_CONV_ERR;
    }

    /* Copy macauth responses into PAM-owned storage. */
    for (int i = 0; i < num_msg; i++) {
        if (mresp[i].resp) {
            replies[i].resp = strdup(mresp[i].resp);
            replies[i].resp_retcode = 0;
            memset(mresp[i].resp, 0, strlen(mresp[i].resp));
            free(mresp[i].resp);
        } else {
            replies[i].resp = NULL;
            replies[i].resp_retcode = 0;
        }
    }

    free(mmsgs); free(mmsg_ptrs); free(mresp); free(mresp_ptrs);
    *resp = replies;
    return PAM_SUCCESS;
}

/* Box holding the live pam handle so acct_mgmt can reuse the auth transaction. */
typedef struct {
    pam_handle_t *pamh;
    struct pam_conv conv;
} pam_state_t;

static macauth_result_t pam_status_to_macauth(int status) {
    switch (status) {
        case PAM_SUCCESS:         return MACAUTH_SUCCESS;
        case PAM_AUTH_ERR:
        case PAM_CRED_INSUFFICIENT:
        case PAM_MAXTRIES:        return MACAUTH_ERR_AUTH;
        case PAM_USER_UNKNOWN:    return MACAUTH_ERR_USER_UNKNOWN;
        case PAM_ACCT_EXPIRED:
        case PAM_NEW_AUTHTOK_REQD:
        case PAM_PERM_DENIED:     return MACAUTH_ERR_ACCT_DISABLED;
        case PAM_CONV_ERR:        return MACAUTH_ERR_CONV;
        case PAM_ABORT:           return MACAUTH_ERR_ABORT;
        default:                  return MACAUTH_ERR_SYSTEM;
    }
}

macauth_result_t _macauth_pam_authenticate(macauth_handle_t *handle) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;
    if (!handle->conv.conv) return MACAUTH_ERR_CONV;

    pam_state_t *state = calloc(1, sizeof(*state));
    if (!state) return MACAUTH_ERR_SYSTEM;

    state->conv.conv = pam_conv_shim;
    state->conv.appdata_ptr = handle;

    const char *service = handle->service ? handle->service : "login";
    int rc = pam_start(service, handle->user, &state->conv, &state->pamh);
    if (rc != PAM_SUCCESS) {
        free(state);
        return pam_status_to_macauth(rc);
    }

    if (handle->rhost) pam_set_item(state->pamh, PAM_RHOST, handle->rhost);
    if (handle->tty)   pam_set_item(state->pamh, PAM_TTY, handle->tty);

    rc = pam_authenticate(state->pamh, 0);

    /* If the user was learned during the conversation, sync it back. */
    const char *pam_user = NULL;
    if (pam_get_item(state->pamh, PAM_USER, (const void **)&pam_user) == PAM_SUCCESS &&
        pam_user && !handle->user) {
        handle->user = strdup(pam_user);
    }

    if (rc == PAM_SUCCESS) {
        /* Keep the pam handle alive so acct_mgmt/session can reuse it. */
        handle->backend_state = state;
    } else {
        pam_end(state->pamh, rc);
        free(state);
    }
    return pam_status_to_macauth(rc);
}

macauth_result_t _macauth_pam_acct_mgmt(macauth_handle_t *handle) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;
    pam_state_t *state = (pam_state_t *)handle->backend_state;
    if (!state || !state->pamh) return MACAUTH_ERR_ABORT;

    int rc = pam_acct_mgmt(state->pamh, 0);
    return pam_status_to_macauth(rc);
}
