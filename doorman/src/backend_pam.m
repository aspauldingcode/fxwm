/*
 * backend_pam.m - drive the OpenPAM stack that ships with macOS.
 *
 * This is the most faithful "port of the Linux method": control is handed to
 * whatever /etc/pam.d/<service> declares (pam_opendirectory, pam_unix,
 * smartcard modules, ...), so behaviour is administrator-configurable without
 * recompiling. Doorman's conversation is bridged onto a struct pam_conv so the
 * same credential prompts flow through unchanged.
 */

#import <Foundation/Foundation.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include "doorman_internal.h"

/* The live PAM transaction, kept alive between authenticate/acct/setcred.
 * pamh MUST be the first member: doorman_end() treats the box as a
 * pam_handle_t** to release it without knowing this layout. */
typedef struct {
    pam_handle_t *pamh;
    struct pam_conv conv;
} dm_pam_box;

static doorman_msg_style_t style_from_pam(int pam_style) {
    switch (pam_style) {
        case PAM_PROMPT_ECHO_OFF: return DOORMAN_PROMPT_ECHO_OFF;
        case PAM_PROMPT_ECHO_ON:  return DOORMAN_PROMPT_ECHO_ON;
        case PAM_ERROR_MSG:       return DOORMAN_ERROR_MSG;
        case PAM_TEXT_INFO:
        default:                  return DOORMAN_TEXT_INFO;
    }
}

static doorman_result_t result_from_pam(int status) {
    switch (status) {
        case PAM_SUCCESS:          return DOORMAN_SUCCESS;
        case PAM_AUTH_ERR:
        case PAM_CRED_INSUFFICIENT:
        case PAM_MAXTRIES:         return DOORMAN_ERR_AUTH;
        case PAM_USER_UNKNOWN:     return DOORMAN_ERR_USER_UNKNOWN;
        case PAM_ACCT_EXPIRED:
        case PAM_NEW_AUTHTOK_REQD:
        case PAM_PERM_DENIED:      return DOORMAN_ERR_ACCT_DISABLED;
        case PAM_CONV_ERR:         return DOORMAN_ERR_CONV;
        case PAM_ABORT:            return DOORMAN_ERR_ABORT;
        default:                   return DOORMAN_ERR_SYSTEM;
    }
}

/*
 * PAM -> doorman conversation bridge. appdata_ptr is the doorman_handle_t. Each
 * PAM message is translated, forwarded to the application's conversation, and
 * the replies are copied into PAM-owned storage (PAM frees them with free()).
 * Every intermediate secret is scrubbed before its buffer is released.
 */
static int conversation_bridge(int num_msg,
                               const struct pam_message **msg,
                               struct pam_response **resp,
                               void *appdata_ptr) {
    doorman_handle_t *handle = (doorman_handle_t *)appdata_ptr;
    if (!handle || !handle->conv.conv || num_msg <= 0) return PAM_CONV_ERR;

    struct pam_response *out = calloc((size_t)num_msg, sizeof(*out));
    doorman_message_t *dmsg = calloc((size_t)num_msg, sizeof(*dmsg));
    const doorman_message_t **dmsg_ptrs = calloc((size_t)num_msg, sizeof(*dmsg_ptrs));
    doorman_response_t *dresp = calloc((size_t)num_msg, sizeof(*dresp));
    doorman_response_t **dresp_ptrs = calloc((size_t)num_msg, sizeof(*dresp_ptrs));
    if (!out || !dmsg || !dmsg_ptrs || !dresp || !dresp_ptrs) {
        free(out); free(dmsg); free(dmsg_ptrs); free(dresp); free(dresp_ptrs);
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        dmsg[i].style = style_from_pam(msg[i]->msg_style);
        dmsg[i].msg = msg[i]->msg;
        dmsg_ptrs[i] = &dmsg[i];
        dresp_ptrs[i] = &dresp[i];
    }

    int rc = handle->conv.conv(num_msg, dmsg_ptrs, dresp_ptrs, handle->conv.appdata);
    if (rc != 0) {
        for (int i = 0; i < num_msg; i++)
            if (dresp[i].resp) _dm_scrub_free(&dresp[i].resp, strlen(dresp[i].resp));
        free(out); free(dmsg); free(dmsg_ptrs); free(dresp); free(dresp_ptrs);
        return PAM_CONV_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        if (dresp[i].resp) {
            out[i].resp = strdup(dresp[i].resp);
            out[i].resp_retcode = 0;
            _dm_scrub_free(&dresp[i].resp, strlen(dresp[i].resp));
        }
    }

    free(dmsg); free(dmsg_ptrs); free(dresp); free(dresp_ptrs);
    *resp = out;
    return PAM_SUCCESS;
}

doorman_result_t _dm_pam_authenticate(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->conv.conv) return DOORMAN_ERR_CONV;

    dm_pam_box *box = calloc(1, sizeof(*box));
    if (!box) return DOORMAN_ERR_SYSTEM;

    box->conv.conv = conversation_bridge;
    box->conv.appdata_ptr = handle;

    const char *service = handle->service ? handle->service : "login";
    int rc = pam_start(service, handle->user, &box->conv, &box->pamh);
    if (rc != PAM_SUCCESS) {
        free(box);
        return result_from_pam(rc);
    }

    if (handle->rhost) pam_set_item(box->pamh, PAM_RHOST, handle->rhost);
    if (handle->tty)   pam_set_item(box->pamh, PAM_TTY, handle->tty);

    rc = pam_authenticate(box->pamh, 0);

    /* Sync back a username that the stack may have learned. */
    const void *pam_user = NULL;
    if (pam_get_item(box->pamh, PAM_USER, &pam_user) == PAM_SUCCESS &&
        pam_user && !handle->user) {
        handle->user = strdup((const char *)pam_user);
    }

    if (rc == PAM_SUCCESS) {
        handle->backend_state = box;   /* keep alive for acct_mgmt/setcred */
    } else {
        pam_end(box->pamh, rc);
        free(box);
    }
    return result_from_pam(rc);
}

doorman_result_t _dm_pam_check_account(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    dm_pam_box *box = (dm_pam_box *)handle->backend_state;
    if (!box || !box->pamh) return DOORMAN_ERR_ABORT;
    return result_from_pam(pam_acct_mgmt(box->pamh, 0));
}

doorman_result_t _dm_pam_setcred(doorman_handle_t *handle, int flag) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    dm_pam_box *box = (dm_pam_box *)handle->backend_state;
    if (!box || !box->pamh) return DOORMAN_ERR_ABORT;

    int pam_flag;
    switch (flag) {
        case DOORMAN_CRED_DELETE:       pam_flag = PAM_DELETE_CRED; break;
        case DOORMAN_CRED_REINITIALIZE: pam_flag = PAM_REINITIALIZE_CRED; break;
        case DOORMAN_CRED_REFRESH:      pam_flag = PAM_REFRESH_CRED; break;
        case DOORMAN_CRED_ESTABLISH:
        default:                        pam_flag = PAM_ESTABLISH_CRED; break;
    }
    return result_from_pam(pam_setcred(box->pamh, pam_flag));
}
