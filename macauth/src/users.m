/*
 * users.m - directory user enumeration and lookup.
 *
 * On macOS getpwent()/getpwnam() are serviced by opendirectoryd, so they
 * return the same local + cached network accounts the login window would show.
 * This is the macOS analogue of a Linux DM walking getpwent() over
 * /etc/passwd + NSS. Interactive filtering matches Apple's convention of
 * hiding uid < 500 service accounts and names beginning with '_'.
 */

#import <Foundation/Foundation.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include "macauth_internal.h"

static const uid_t kMinInteractiveUID = 500;

static bool is_hidden_account(const struct passwd *pw) {
    if (!pw || !pw->pw_name) return true;
    if (pw->pw_uid != 0 && pw->pw_uid < kMinInteractiveUID) return true;
    if (pw->pw_name[0] == '_') return true;
    if (pw->pw_shell) {
        if (strcmp(pw->pw_shell, "/usr/bin/false") == 0) return true;
        if (strcmp(pw->pw_shell, "/sbin/nologin") == 0) return true;
        if (strcmp(pw->pw_shell, "/usr/bin/nologin") == 0) return true;
    }
    return false;
}

static void fill_from_passwd(const struct passwd *pw, macauth_user_t *u) {
    u->name = pw->pw_name ? strdup(pw->pw_name) : NULL;
    u->full_name = (pw->pw_gecos && pw->pw_gecos[0]) ? strdup(pw->pw_gecos) : NULL;
    u->home = pw->pw_dir ? strdup(pw->pw_dir) : NULL;
    u->shell = pw->pw_shell ? strdup(pw->pw_shell) : NULL;
    u->uid = pw->pw_uid;
    u->gid = pw->pw_gid;
    u->hidden = is_hidden_account(pw);
}

macauth_result_t macauth_enumerate_users(bool interactive_only,
                                         macauth_user_t **out,
                                         size_t *count) {
    if (!out || !count) return MACAUTH_ERR_INVALID_ARG;
    *out = NULL;
    *count = 0;

    size_t cap = 16, n = 0;
    macauth_user_t *arr = calloc(cap, sizeof(*arr));
    if (!arr) return MACAUTH_ERR_SYSTEM;

    setpwent();
    struct passwd *pw;
    while ((pw = getpwent()) != NULL) {
        if (interactive_only && is_hidden_account(pw)) continue;
        if (n == cap) {
            size_t ncap = cap * 2;
            macauth_user_t *tmp = realloc(arr, ncap * sizeof(*arr));
            if (!tmp) { endpwent(); macauth_free_users(arr, n); return MACAUTH_ERR_SYSTEM; }
            arr = tmp;
            cap = ncap;
        }
        fill_from_passwd(pw, &arr[n]);
        n++;
    }
    endpwent();

    *out = arr;
    *count = n;
    return MACAUTH_SUCCESS;
}

void macauth_free_users(macauth_user_t *users, size_t count) {
    if (!users) return;
    for (size_t i = 0; i < count; i++) macauth_free_user_fields(&users[i]);
    free(users);
}

void macauth_free_user_fields(macauth_user_t *user) {
    if (!user) return;
    free(user->name);
    free(user->full_name);
    free(user->home);
    free(user->shell);
    memset(user, 0, sizeof(*user));
}

BOOL _macauth_copy_passwd(const char *name, macauth_user_t *out) {
    if (!name || !out) return NO;
    struct passwd *pw = getpwnam(name);
    if (!pw) return NO;
    fill_from_passwd(pw, out);
    return YES;
}

macauth_result_t macauth_lookup_user(const char *name, macauth_user_t *out) {
    if (!name || !out) return MACAUTH_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (!_macauth_copy_passwd(name, out)) return MACAUTH_ERR_USER_UNKNOWN;
    return MACAUTH_SUCCESS;
}
