/*
 * sessions.m - session discovery and launch.
 *
 * Discovery mirrors a Linux display manager: read freedesktop ".desktop"
 * entries from the wayland-sessions and xsessions directories under every
 * $XDG_DATA_DIRS root, so a ported Wayland DM's session catalog "just works".
 * A synthetic "aqua" entry for the stock macOS session is always appended.
 *
 * Launch mirrors pam_open_session() followed by a DM's fork/exec: when running
 * as root we drop to the target user (setgid, initgroups, setuid), start a new
 * session, install a minimal login environment, and exec the Exec= command.
 *
 * Fork safety: the entire environment is assembled in the parent and handed to
 * the child via execle(), so the post-fork path performs no heap allocation of
 * its own (no setenv/getenv churn) beyond what libc's credential calls do.
 */

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "doorman_internal.h"

/* ------------------------------------------------------------------------- */
/* .desktop discovery                                                        */
/* ------------------------------------------------------------------------- */

static NSDictionary *read_desktop_entry(NSString *path) {
    NSError *err = nil;
    NSString *text = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:&err];
    if (!text) return nil;

    NSMutableDictionary *fields = [NSMutableDictionary dictionary];
    BOOL inEntry = NO;
    for (NSString *raw in [text componentsSeparatedByString:@"\n"]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        if ([line hasPrefix:@"["]) {
            inEntry = [line isEqualToString:@"[Desktop Entry]"];
            continue;
        }
        if (!inEntry) continue;

        NSRange eq = [line rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        NSString *key = [[line substringToIndex:eq.location]
                         stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *val = [[line substringFromIndex:eq.location + 1]
                         stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        /* Skip locale-qualified keys such as Name[de]; keep the plain key. */
        if ([key rangeOfString:@"["].location != NSNotFound) continue;
        if (!fields[key]) fields[key] = val;
    }
    return fields;
}

static NSArray<NSString *> *xdg_data_roots(void) {
    const char *env = getenv("XDG_DATA_DIRS");
    NSString *value = (env && env[0]) ? [NSString stringWithUTF8String:env]
                                      : @"/usr/local/share:/usr/share";
    return [value componentsSeparatedByString:@":"];
}

static char *copy_cstr(NSString *s) {
    return s ? strdup(s.UTF8String) : NULL;
}

doorman_result_t doorman_enumerate_sessions(doorman_session_t **out,
                                            size_t *count) {
    if (!out || !count) return DOORMAN_ERR_INVALID_ARG;
    *out = NULL;
    *count = 0;

    @autoreleasepool {
        NSMutableArray *discovered = [NSMutableArray array];
        NSMutableSet *seen = [NSMutableSet set];

        const struct { NSString *sub; const char *type; } kinds[] = {
            { @"wayland-sessions", "wayland" },
            { @"xsessions", "x11" },
        };

        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *root in xdg_data_roots()) {
            for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
                NSString *dir = [root stringByAppendingPathComponent:kinds[k].sub];
                for (NSString *file in [fm contentsOfDirectoryAtPath:dir error:nil]) {
                    if (![file hasSuffix:@".desktop"]) continue;
                    NSString *ident = [file stringByDeletingPathExtension];
                    if ([seen containsObject:ident]) continue;

                    NSDictionary *entry =
                        read_desktop_entry([dir stringByAppendingPathComponent:file]);
                    if (!entry || !entry[@"Exec"]) continue;

                    [seen addObject:ident];
                    NSString *displayName = entry[@"Name"] ? entry[@"Name"] : ident;
                    id comment = entry[@"Comment"] ? entry[@"Comment"] : [NSNull null];
                    [discovered addObject:@{
                        @"id": ident,
                        @"name": displayName,
                        @"comment": comment,
                        @"exec": entry[@"Exec"],
                        @"type": [NSString stringWithUTF8String:kinds[k].type],
                    }];
                }
            }
        }

        [discovered addObject:@{
            @"id": @"aqua",
            @"name": @"macOS (Aqua)",
            @"comment": @"Stock macOS desktop session",
            @"exec": @"/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            @"type": @"aqua",
        }];

        size_t n = discovered.count;
        doorman_session_t *arr = calloc(n, sizeof(*arr));
        if (!arr) return DOORMAN_ERR_SYSTEM;

        for (size_t i = 0; i < n; i++) {
            NSDictionary *e = discovered[i];
            arr[i].id = copy_cstr(e[@"id"]);
            arr[i].name = copy_cstr(e[@"name"]);
            arr[i].comment = (e[@"comment"] == [NSNull null]) ? NULL : copy_cstr(e[@"comment"]);
            arr[i].exec = copy_cstr(e[@"exec"]);
            arr[i].type = copy_cstr(e[@"type"]);
        }

        *out = arr;
        *count = n;
        return DOORMAN_SUCCESS;
    }
}

void doorman_free_sessions(doorman_session_t *sessions, size_t count) {
    if (!sessions) return;
    for (size_t i = 0; i < count; i++) {
        free(sessions[i].id);
        free(sessions[i].name);
        free(sessions[i].comment);
        free(sessions[i].exec);
        free(sessions[i].type);
    }
    free(sessions);
}

/* ------------------------------------------------------------------------- */
/* Session launch                                                            */
/* ------------------------------------------------------------------------- */

/* Append "KEY=VALUE" to a NULL-terminated env vector at *n, growing nothing:
 * the caller sizes the array up front. */
static void env_put(char **env, size_t *n, const char *key, const char *value) {
    char *entry = NULL;
    if (asprintf(&entry, "%s=%s", key, value ? value : "") >= 0 && entry)
        env[(*n)++] = entry;
}

static void env_free(char **env) {
    if (!env) return;
    for (size_t i = 0; env[i]; i++) free(env[i]);
    free(env);
}

/* Assemble the login environment for the target user in the parent, so the
 * child never has to allocate it after fork(). Returns a NULL-terminated
 * vector to be freed with env_free(). */
static char **build_login_env(const doorman_user_t *u,
                              const doorman_session_t *session,
                              const char *runtime_dir) {
    char **env = calloc(16, sizeof(*env));
    if (!env) return NULL;
    size_t n = 0;

    env_put(env, &n, "USER", u->name);
    env_put(env, &n, "LOGNAME", u->name);
    if (u->home) env_put(env, &n, "HOME", u->home);
    env_put(env, &n, "SHELL", u->shell ? u->shell : "/bin/sh");
    env_put(env, &n, "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin");
    env_put(env, &n, "XDG_RUNTIME_DIR", runtime_dir);
    env_put(env, &n, "XDG_SESSION_TYPE", session->type);
    env_put(env, &n, "XDG_SESSION_DESKTOP", session->id);
    if (session->type && strcmp(session->type, "wayland") == 0)
        env_put(env, &n, "WAYLAND_DISPLAY", "wayland-0");

    env[n] = NULL;
    return env;
}

doorman_result_t doorman_open_session(doorman_handle_t *handle,
                                      const doorman_session_t *session,
                                      pid_t *out_pid) {
    if (!handle || !session || !session->exec || !session->type)
        return DOORMAN_ERR_INVALID_ARG;
    if (!handle->authenticated) return DOORMAN_ERR_ABORT;
    if (!handle->user) return DOORMAN_ERR_USER_UNKNOWN;

    doorman_user_t u;
    if (doorman_lookup_user(handle->user, &u) != DOORMAN_SUCCESS)
        return DOORMAN_ERR_USER_UNKNOWN;

    /* Dropping privileges needs root; without it we may still launch a session
     * for the current user (handy for development/testing). */
    const bool privileged = (geteuid() == 0);
    if (!privileged && u.uid != getuid()) {
        doorman_free_user_fields(&u);
        return DOORMAN_ERR_PERM;
    }

    /* Everything the child needs is prepared here, in the parent. */
    char runtime_dir[64];
    snprintf(runtime_dir, sizeof(runtime_dir), "/private/tmp/doorman-%u", (unsigned)u.uid);

    char **child_env = build_login_env(&u, session, runtime_dir);
    const char *shell = (u.shell && u.shell[0]) ? u.shell : "/bin/sh";
    char *shell_dup = strdup(shell);
    char *home_dup = u.home ? strdup(u.home) : NULL;
    char *exec_dup = strdup(session->exec);
    char *name_dup = u.name ? strdup(u.name) : NULL;
    uid_t uid = u.uid;
    gid_t gid = u.gid;
    doorman_free_user_fields(&u);

    if (!child_env || !shell_dup || !exec_dup || (name_dup == NULL)) {
        env_free(child_env);
        free(shell_dup); free(home_dup); free(exec_dup); free(name_dup);
        return DOORMAN_ERR_SYSTEM;
    }

    pid_t pid = fork();
    if (pid < 0) {
        env_free(child_env);
        free(shell_dup); free(home_dup); free(exec_dup); free(name_dup);
        return DOORMAN_ERR_SYSTEM;
    }

    if (pid == 0) {
        /* --- child: POSIX-only from here to exec --- */
        if (privileged) {
            if (setgid(gid) != 0) _exit(127);
            if (initgroups(name_dup, (int)gid) != 0) _exit(127);
            if (setuid(uid) != 0) _exit(127);
            /* Defence in depth: if we dropped to a non-root uid, regaining root
             * must be impossible; bail out if it somehow is not. */
            if (uid != 0 && setuid(0) == 0) _exit(127);
        }

        setsid();
        if (home_dup) { if (chdir(home_dup) != 0) { /* fall back below */ } }
        mkdir(runtime_dir, 0700);

        execle(shell_dup, shell_dup, "-l", "-c", exec_dup, (char *)NULL, child_env);
        _exit(127);
    }

    /* --- parent --- */
    env_free(child_env);
    free(shell_dup); free(home_dup); free(exec_dup); free(name_dup);

    handle->session_open = true;
    handle->session_pid = pid;
    if (out_pid) *out_pid = pid;
    return DOORMAN_SUCCESS;
}

doorman_result_t doorman_close_session(doorman_handle_t *handle) {
    if (!handle) return DOORMAN_ERR_INVALID_ARG;
    if (!handle->session_open) return DOORMAN_ERR_NO_SESSION;
    handle->session_open = false;
    handle->session_pid = 0;
    return DOORMAN_SUCCESS;
}
