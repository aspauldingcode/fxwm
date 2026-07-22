/*
 * users.m - directory user enumeration and lookup.
 *
 * On macOS getpwent()/getpwnam() are backed by opendirectoryd, so they surface
 * the same local + cached network accounts the login window shows. This is the
 * macOS analogue of a Linux DM walking getpwent() over /etc/passwd + NSS.
 * Interactive filtering follows Apple's convention: hide service accounts
 * (uid < 500), names beginning with '_', and non-login shells.
 */

#import <Foundation/Foundation.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include "doorman_internal.h"

static const uid_t kFirstInteractiveUID = 500;

static bool account_is_hidden(const struct passwd *pw) {
    if (!pw || !pw->pw_name) return true;
    if (pw->pw_uid != 0 && pw->pw_uid < kFirstInteractiveUID) return true;
    if (pw->pw_name[0] == '_') return true;
    if (pw->pw_shell) {
        static const char *const nologin_shells[] = {
            "/usr/bin/false", "/sbin/nologin", "/usr/bin/nologin", NULL
        };
        for (int i = 0; nologin_shells[i]; i++)
            if (strcmp(pw->pw_shell, nologin_shells[i]) == 0) return true;
    }
    return false;
}

static void populate_user(const struct passwd *pw, doorman_user_t *u) {
    u->name = pw->pw_name ? strdup(pw->pw_name) : NULL;
    u->full_name = (pw->pw_gecos && pw->pw_gecos[0]) ? strdup(pw->pw_gecos) : NULL;
    u->home = pw->pw_dir ? strdup(pw->pw_dir) : NULL;
    u->shell = pw->pw_shell ? strdup(pw->pw_shell) : NULL;
    u->uid = pw->pw_uid;
    u->gid = pw->pw_gid;
    u->hidden = account_is_hidden(pw);
}

doorman_result_t doorman_enumerate_users(bool interactive_only,
                                         doorman_user_t **out,
                                         size_t *count) {
    if (!out || !count) return DOORMAN_ERR_INVALID_ARG;
    *out = NULL;
    *count = 0;

    size_t cap = 16, n = 0;
    doorman_user_t *list = calloc(cap, sizeof(*list));
    if (!list) return DOORMAN_ERR_SYSTEM;

    setpwent();
    struct passwd *pw;
    while ((pw = getpwent()) != NULL) {
        if (interactive_only && account_is_hidden(pw)) continue;
        if (n == cap) {
            size_t next = cap * 2;
            doorman_user_t *grown = realloc(list, next * sizeof(*list));
            if (!grown) { endpwent(); doorman_free_users(list, n); return DOORMAN_ERR_SYSTEM; }
            list = grown;
            cap = next;
        }
        populate_user(pw, &list[n]);
        n++;
    }
    endpwent();

    *out = list;
    *count = n;
    return DOORMAN_SUCCESS;
}

void doorman_free_users(doorman_user_t *users, size_t count) {
    if (!users) return;
    for (size_t i = 0; i < count; i++) doorman_free_user_fields(&users[i]);
    free(users);
}

void doorman_free_user_fields(doorman_user_t *user) {
    if (!user) return;
    free(user->name);
    free(user->full_name);
    free(user->home);
    free(user->shell);
    memset(user, 0, sizeof(*user));
}

BOOL _dm_fill_user_from_passwd(const char *name, doorman_user_t *out) {
    if (!name || !out) return NO;
    struct passwd *pw = getpwnam(name);
    if (!pw) return NO;
    populate_user(pw, out);
    return YES;
}

doorman_result_t doorman_lookup_user(const char *name, doorman_user_t *out) {
    if (!name || !out) return DOORMAN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (!_dm_fill_user_from_passwd(name, out)) return DOORMAN_ERR_USER_UNKNOWN;
    return DOORMAN_SUCCESS;
}
