/*
 * test_doorman.m - unprivileged unit tests for libdoorman.
 *
 * These run without root on any macOS builder and touch every public entry
 * point at least once: the read-only / verification surface via its real
 * behaviour, and the privileged provisioning surface via its argument-
 * validation and permission guards (which return before doing anything).
 * The privileged happy paths (create/login/passwd/groups/delete) are covered
 * end-to-end by tests/integration.sh.
 */

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "doorman.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do { \
    g_checks++; \
    if (cond) { printf("ok   - %s\n", msg); } \
    else { printf("FAIL - %s\n", msg); g_failures++; } \
} while (0)

/* A conversation that refuses to supply input. */
static int conv_refuse(int n, const doorman_message_t **m, doorman_response_t **r, void *a) {
    (void)n; (void)m; (void)r; (void)a; return 1;
}

/* A conversation that answers every prompt with fixed, wrong credentials. */
static int conv_wrong(int n, const doorman_message_t **m, doorman_response_t **r, void *a) {
    (void)a;
    for (int i = 0; i < n; i++) {
        if (m[i]->style == DOORMAN_PROMPT_ECHO_OFF)
            r[i]->resp = strdup("definitely-not-the-password-000");
        else if (m[i]->style == DOORMAN_PROMPT_ECHO_ON)
            r[i]->resp = strdup("root");
    }
    return 0;
}

int main(void) {
    @autoreleasepool {
        doorman_result_t r;

        /* ---- doorman_strerror: total, specific, never NULL ---- */
        CHECK(doorman_strerror(DOORMAN_SUCCESS) != NULL, "strerror(SUCCESS) non-null");
        CHECK(strcmp(doorman_strerror(DOORMAN_ERR_AUTH), "unknown error") != 0,
              "strerror(ERR_AUTH) is specific");
        CHECK(strcmp(doorman_strerror((doorman_result_t)999), "unknown error") == 0,
              "strerror(bogus) falls back to 'unknown error'");

        /* ---- doorman_enumerate_users / free_users ---- */
        doorman_user_t *users = NULL; size_t nu = 0;
        r = doorman_enumerate_users(false, &users, &nu);
        CHECK(r == DOORMAN_SUCCESS && nu > 0, "enumerate_users returns users");
        bool sawRoot = false;
        for (size_t i = 0; i < nu; i++)
            if (users[i].name && strcmp(users[i].name, "root") == 0) sawRoot = true;
        CHECK(sawRoot, "enumerate_users includes root");
        doorman_free_users(users, nu);

        CHECK(doorman_enumerate_users(true, NULL, &nu) == DOORMAN_ERR_INVALID_ARG,
              "enumerate_users(NULL out) => INVALID_ARG");

        doorman_user_t *iusers = NULL; size_t ni = 0;
        doorman_enumerate_users(true, &iusers, &ni);
        bool sawUnderscore = false;
        for (size_t i = 0; i < ni; i++)
            if (iusers[i].name && iusers[i].name[0] == '_') sawUnderscore = true;
        CHECK(!sawUnderscore, "interactive_only hides _-prefixed accounts");
        doorman_free_users(iusers, ni);

        /* ---- doorman_lookup_user / free_user_fields ---- */
        doorman_user_t one;
        r = doorman_lookup_user("root", &one);
        CHECK(r == DOORMAN_SUCCESS && one.uid == 0, "lookup_user(root) uid==0");
        if (r == DOORMAN_SUCCESS) doorman_free_user_fields(&one);

        CHECK(doorman_lookup_user("definitely_no_such_user_xyz", &one) == DOORMAN_ERR_USER_UNKNOWN,
              "lookup_user(missing) => USER_UNKNOWN");
        CHECK(doorman_lookup_user(NULL, &one) == DOORMAN_ERR_INVALID_ARG,
              "lookup_user(NULL) => INVALID_ARG");

        /* ---- doorman_get_groups ---- */
        gid_t *gids = NULL; size_t ng = 0;
        r = doorman_get_groups("root", &gids, &ng);
        CHECK(r == DOORMAN_SUCCESS && ng >= 1, "get_groups(root) returns >=1 gid");
        free(gids);
        CHECK(doorman_get_groups(NULL, &gids, &ng) == DOORMAN_ERR_INVALID_ARG,
              "get_groups(NULL) => INVALID_ARG");

        /* ---- doorman_enumerate_sessions / free_sessions ---- */
        doorman_session_t *sessions = NULL; size_t ns = 0;
        r = doorman_enumerate_sessions(&sessions, &ns);
        bool sawAqua = false;
        for (size_t i = 0; i < ns; i++)
            if (sessions[i].id && strcmp(sessions[i].id, "aqua") == 0) sawAqua = true;
        CHECK(r == DOORMAN_SUCCESS && sawAqua, "enumerate_sessions includes aqua");
        doorman_free_sessions(sessions, ns);
        CHECK(doorman_enumerate_sessions(NULL, &ns) == DOORMAN_ERR_INVALID_ARG,
              "enumerate_sessions(NULL) => INVALID_ARG");

        /* ---- doorman_authenticate_password (directory backends) ---- */
        CHECK(doorman_authenticate_password("root", "wrong-pw-000", DOORMAN_BACKEND_OPENDIRECTORY)
              != DOORMAN_SUCCESS, "authenticate_password(root, wrong) fails");
        CHECK(doorman_authenticate_password("definitely_no_such_user_xyz", "x", DOORMAN_BACKEND_OPENDIRECTORY)
              != DOORMAN_SUCCESS, "authenticate_password(missing) fails");
        CHECK(doorman_authenticate_password("root", "x", DOORMAN_BACKEND_PAM) == DOORMAN_ERR_UNSUPPORTED,
              "PAM one-shot returns UNSUPPORTED");
        CHECK(doorman_authenticate_password(NULL, "x", DOORMAN_BACKEND_AUTO) == DOORMAN_ERR_INVALID_ARG,
              "authenticate_password(NULL) => INVALID_ARG");
        /* Path-traversal-shaped name must not be treated as a real user. */
        CHECK(doorman_authenticate_password("../../etc/passwd", "x", DOORMAN_BACKEND_DSLOCAL)
              == DOORMAN_ERR_USER_UNKNOWN, "dslocal rejects a traversal-shaped name");

        /* ---- Transaction lifecycle: start / items / authenticate / guards ---- */
        CHECK(doorman_start("login", "root", NULL, DOORMAN_BACKEND_AUTO, NULL) == DOORMAN_ERR_INVALID_ARG,
              "start(NULL out) => INVALID_ARG");
        CHECK(doorman_authenticate(NULL) == DOORMAN_ERR_INVALID_ARG, "authenticate(NULL) => INVALID_ARG");

        doorman_conv_t refuse = { conv_refuse, NULL };
        doorman_handle_t *h = NULL;
        r = doorman_start("login", "root", &refuse, DOORMAN_BACKEND_OPENDIRECTORY, &h);
        CHECK(r == DOORMAN_SUCCESS && h != NULL, "doorman_start creates a handle");

        const char *svc = NULL;
        doorman_get_item(h, DOORMAN_ITEM_SERVICE, &svc);
        CHECK(svc && strcmp(svc, "login") == 0, "get_item(SERVICE) == login");

        doorman_set_item(h, DOORMAN_ITEM_RHOST, "host.example");
        doorman_set_item(h, DOORMAN_ITEM_TTY, "ttys000");
        const char *rh = NULL, *tty = NULL;
        doorman_get_item(h, DOORMAN_ITEM_RHOST, &rh);
        doorman_get_item(h, DOORMAN_ITEM_TTY, &tty);
        CHECK(rh && strcmp(rh, "host.example") == 0, "set/get_item(RHOST) round-trips");
        CHECK(tty && strcmp(tty, "ttys000") == 0, "set/get_item(TTY) round-trips");

        /* A conversation that refuses input aborts with ERR_CONV. */
        CHECK(doorman_authenticate(h) == DOORMAN_ERR_CONV, "authenticate(refusing conv) => CONV");

        /* Guards that require prior successful auth. */
        CHECK(doorman_acct_mgmt(h) == DOORMAN_ERR_ABORT, "acct_mgmt before auth => ABORT");
        CHECK(doorman_setcred(h, DOORMAN_CRED_ESTABLISH) == DOORMAN_ERR_ABORT, "setcred before auth => ABORT");
        doorman_session_t dummy = {0};
        dummy.id = "t"; dummy.name = "t"; dummy.exec = "/usr/bin/true"; dummy.type = "tty";
        CHECK(doorman_open_session(h, &dummy, NULL) == DOORMAN_ERR_ABORT, "open_session before auth => ABORT");
        CHECK(doorman_close_session(h) == DOORMAN_ERR_NO_SESSION, "close_session with no session => NO_SESSION");
        doorman_end(h);

        /* A full conversation-driven authenticate with wrong credentials must be
         * rejected (exercises collect + verify + scrub). */
        doorman_conv_t wrong = { conv_wrong, NULL };
        doorman_handle_t *hw = NULL;
        doorman_start("login", NULL, &wrong, DOORMAN_BACKEND_OPENDIRECTORY, &hw);
        r = doorman_authenticate(hw);
        CHECK(r != DOORMAN_SUCCESS, "authenticate(conv wrong) does not succeed");
        doorman_end(hw);

        /* ---- Provisioning: argument validation (safe unprivileged) ---- */
        CHECK(doorman_create_user(NULL) == DOORMAN_ERR_INVALID_ARG, "create_user(NULL) => INVALID_ARG");
        doorman_user_spec_t bad = {0}; bad.name = "bad/name";
        CHECK(doorman_create_user(&bad) == DOORMAN_ERR_INVALID_ARG, "create_user(bad name) => INVALID_ARG");
        CHECK(doorman_delete_user("bad/name", false) == DOORMAN_ERR_INVALID_ARG, "delete_user(bad name) => INVALID_ARG");
        CHECK(doorman_set_password("bad/name", "x") == DOORMAN_ERR_INVALID_ARG, "set_password(bad name) => INVALID_ARG");
        CHECK(doorman_create_home("bad/name") == DOORMAN_ERR_INVALID_ARG, "create_home(bad name) => INVALID_ARG");
        CHECK(doorman_create_group("bad/name", 0, NULL) == DOORMAN_ERR_INVALID_ARG, "create_group(bad name) => INVALID_ARG");
        CHECK(doorman_delete_group("bad/name") == DOORMAN_ERR_INVALID_ARG, "delete_group(bad name) => INVALID_ARG");
        CHECK(doorman_add_user_to_group("bad/name", "staff") == DOORMAN_ERR_INVALID_ARG, "add_user_to_group(bad user) => INVALID_ARG");
        CHECK(doorman_remove_user_from_group("root", "bad/name") == DOORMAN_ERR_INVALID_ARG, "remove_user_from_group(bad group) => INVALID_ARG");

        /* ---- Provisioning: permission guard (only meaningful unprivileged) ---- */
        if (geteuid() != 0) {
            doorman_user_spec_t sp = {0}; sp.name = "doorman_perm_probe";
            CHECK(doorman_create_user(&sp) == DOORMAN_ERR_PERM, "create_user without root => PERM");
            CHECK(doorman_delete_user("doorman_perm_probe", false) == DOORMAN_ERR_PERM, "delete_user without root => PERM");
            CHECK(doorman_set_password("doorman_perm_probe", "x") == DOORMAN_ERR_PERM, "set_password without root => PERM");
            CHECK(doorman_create_home("doorman_perm_probe") == DOORMAN_ERR_PERM, "create_home without root => PERM");
            CHECK(doorman_create_group("doorman_perm_grp", 0, NULL) == DOORMAN_ERR_PERM, "create_group without root => PERM");
            CHECK(doorman_delete_group("doorman_perm_grp") == DOORMAN_ERR_PERM, "delete_group without root => PERM");
            CHECK(doorman_add_user_to_group("doorman_perm_probe", "staff") == DOORMAN_ERR_PERM, "add_user_to_group without root => PERM");
            CHECK(doorman_remove_user_from_group("doorman_perm_probe", "staff") == DOORMAN_ERR_PERM, "remove_user_from_group without root => PERM");
        }

        printf("\n%d checks, %d failures\n", g_checks, g_failures);
        return g_failures == 0 ? 0 : 1;
    }
}
