/*
 * test_doorman.m - unprivileged unit tests for libdoorman.
 *
 * These run without root on any macOS builder and validate the read-only /
 * verification surface of the framework. Privileged provisioning + login is
 * covered separately by tests/integration.sh.
 */

#import <Foundation/Foundation.h>
#include <stdio.h>
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

static int no_conv(int n, const doorman_message_t **m, doorman_response_t **r, void *a) {
    (void)n; (void)m; (void)r; (void)a; return 1; /* refuse: no interactive input */
}

int main(void) {
    @autoreleasepool {
        /* strerror is total and never NULL. */
        CHECK(doorman_strerror(DOORMAN_SUCCESS) != NULL, "strerror(SUCCESS) non-null");
        CHECK(strcmp(doorman_strerror(DOORMAN_ERR_AUTH), "unknown error") != 0,
              "strerror(ERR_AUTH) is specific");

        /* User enumeration returns something and includes root. */
        doorman_user_t *users = NULL; size_t nu = 0;
        doorman_result_t r = doorman_enumerate_users(false, &users, &nu);
        CHECK(r == DOORMAN_SUCCESS && nu > 0, "enumerate_users returns users");
        bool sawRoot = false;
        for (size_t i = 0; i < nu; i++) if (users[i].name && strcmp(users[i].name, "root") == 0) sawRoot = true;
        CHECK(sawRoot, "enumerate_users includes root");
        doorman_free_users(users, nu);

        /* Interactive-only filtering hides the '_'-prefixed service accounts. */
        doorman_user_t *iusers = NULL; size_t ni = 0;
        doorman_enumerate_users(true, &iusers, &ni);
        bool sawUnderscore = false;
        for (size_t i = 0; i < ni; i++) if (iusers[i].name && iusers[i].name[0] == '_') sawUnderscore = true;
        CHECK(!sawUnderscore, "interactive_only hides _-prefixed accounts");
        doorman_free_users(iusers, ni);

        /* lookup_user(root) => uid 0. */
        doorman_user_t root;
        r = doorman_lookup_user("root", &root);
        CHECK(r == DOORMAN_SUCCESS && root.uid == 0, "lookup_user(root) uid==0");
        if (r == DOORMAN_SUCCESS) doorman_free_user_fields(&root);

        r = doorman_lookup_user("definitely_no_such_user_xyz", &root);
        CHECK(r == DOORMAN_ERR_USER_UNKNOWN, "lookup_user(missing) => USER_UNKNOWN");

        /* Group resolution returns the primary group at least. */
        gid_t *gids = NULL; size_t ng = 0;
        r = doorman_get_groups("root", &gids, &ng);
        CHECK(r == DOORMAN_SUCCESS && ng >= 1, "get_groups(root) returns >=1 gid");
        free(gids);

        /* Session discovery always includes the built-in aqua session. */
        doorman_session_t *sessions = NULL; size_t ns = 0;
        r = doorman_enumerate_sessions(&sessions, &ns);
        bool sawAqua = false;
        for (size_t i = 0; i < ns; i++) if (sessions[i].id && strcmp(sessions[i].id, "aqua") == 0) sawAqua = true;
        CHECK(r == DOORMAN_SUCCESS && sawAqua, "enumerate_sessions includes aqua");
        doorman_free_sessions(sessions, ns);

        /* A wrong password must never succeed (root is a real account). */
        r = doorman_authenticate_password("root", "this-is-not-the-root-password-000", DOORMAN_BACKEND_OPENDIRECTORY);
        CHECK(r != DOORMAN_SUCCESS, "authenticate_password(root, wrong) fails");

        /* Unknown user must not authenticate. */
        r = doorman_authenticate_password("definitely_no_such_user_xyz", "x", DOORMAN_BACKEND_OPENDIRECTORY);
        CHECK(r != DOORMAN_SUCCESS, "authenticate_password(missing) fails");

        /* PAM one-shot is unsupported (needs a conversation) - verify contract. */
        r = doorman_authenticate_password("root", "x", DOORMAN_BACKEND_PAM);
        CHECK(r == DOORMAN_ERR_UNSUPPORTED, "PAM one-shot returns UNSUPPORTED");

        /* Provisioning without root must be denied, not silently succeed. */
        if (geteuid() != 0) {
            doorman_user_spec_t spec = {0};
            spec.name = "doorman_should_not_exist";
            r = doorman_create_user(&spec);
            CHECK(r == DOORMAN_ERR_PERM, "create_user without root => PERM");
        }

        /* Transaction lifecycle basics. */
        doorman_conv_t conv = { no_conv, NULL };
        doorman_handle_t *h = NULL;
        r = doorman_start("login", "root", &conv, DOORMAN_BACKEND_OPENDIRECTORY, &h);
        CHECK(r == DOORMAN_SUCCESS && h != NULL, "doorman_start creates a handle");
        const char *svc = NULL;
        doorman_get_item(h, DOORMAN_ITEM_SERVICE, &svc);
        CHECK(svc && strcmp(svc, "login") == 0, "get_item(SERVICE) == login");
        doorman_end(h);

        printf("\n%d checks, %d failures\n", g_checks, g_failures);
        return g_failures == 0 ? 0 : 1;
    }
}
