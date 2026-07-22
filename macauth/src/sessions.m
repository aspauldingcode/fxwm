/*
 * sessions.m - session discovery and launch.
 *
 * Discovery mirrors what a Linux display manager does: read freedesktop
 * ".desktop" entries from the wayland-sessions and xsessions directories under
 * every $XDG_DATA_DIRS root. This is exactly the mechanism a ported Wayland
 * display manager expects, so its session catalog "just works" on macOS. A
 * synthetic "aqua" entry for the stock macOS session is always included.
 *
 * Launch mirrors pam_open_session() followed by a display manager's
 * fork/setuid/exec: when running as root we drop to the target user (setgid,
 * initgroups, setuid), build a minimal login environment, and exec the
 * session's Exec= command.
 */

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <sys/stat.h>
#include "macauth_internal.h"

/* ------------------------------------------------------------------------- */
/* Minimal .desktop parser                                                   */
/* ------------------------------------------------------------------------- */

static NSDictionary *parse_desktop_entry(NSString *path) {
    NSError *err = nil;
    NSString *contents = [NSString stringWithContentsOfFile:path
                                                   encoding:NSUTF8StringEncoding
                                                      error:&err];
    if (!contents) return nil;

    NSMutableDictionary *entry = [NSMutableDictionary dictionary];
    BOOL inSection = NO;
    for (NSString *rawLine in [contents componentsSeparatedByString:@"\n"]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        if ([line hasPrefix:@"["]) {
            inSection = [line isEqualToString:@"[Desktop Entry]"];
            continue;
        }
        if (!inSection) continue;
        NSRange eq = [line rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        NSString *key = [[line substringToIndex:eq.location]
                         stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *val = [[line substringFromIndex:eq.location + 1]
                         stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        /* Ignore locale-qualified keys like Name[de]; keep the plain key. */
        if ([key rangeOfString:@"["].location != NSNotFound) continue;
        if (!entry[key]) entry[key] = val;
    }
    return entry;
}

static NSArray<NSString *> *xdg_data_dirs(void) {
    const char *env = getenv("XDG_DATA_DIRS");
    NSString *value = (env && env[0]) ? [NSString stringWithUTF8String:env]
                                      : @"/usr/local/share:/usr/share";
    return [value componentsSeparatedByString:@":"];
}

static char *dup_nsstring(NSString *s) {
    return s ? strdup(s.UTF8String) : NULL;
}

macauth_result_t macauth_enumerate_sessions(macauth_session_t **out,
                                            size_t *count) {
    if (!out || !count) return MACAUTH_ERR_INVALID_ARG;
    *out = NULL;
    *count = 0;

    @autoreleasepool {
        NSMutableArray *found = [NSMutableArray array];
        NSMutableSet *seenIds = [NSMutableSet set];

        struct { NSString *sub; const char *type; } kinds[] = {
            { @"wayland-sessions", "wayland" },
            { @"xsessions", "x11" },
        };

        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *root in xdg_data_dirs()) {
            for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
                NSString *dir = [root stringByAppendingPathComponent:kinds[k].sub];
                NSArray *files = [fm contentsOfDirectoryAtPath:dir error:nil];
                for (NSString *file in files) {
                    if (![file hasSuffix:@".desktop"]) continue;
                    NSString *sessionId = [file stringByDeletingPathExtension];
                    if ([seenIds containsObject:sessionId]) continue;

                    NSDictionary *entry = parse_desktop_entry(
                        [dir stringByAppendingPathComponent:file]);
                    if (!entry || !entry[@"Exec"]) continue;

                    [seenIds addObject:sessionId];
                    [found addObject:@{
                        @"id": sessionId,
                        @"name": entry[@"Name"] ?: sessionId,
                        @"comment": entry[@"Comment"] ?: [NSNull null],
                        @"exec": entry[@"Exec"],
                        @"type": [NSString stringWithUTF8String:kinds[k].type],
                    }];
                }
            }
        }

        /* Always offer the stock macOS session. */
        [found addObject:@{
            @"id": @"aqua",
            @"name": @"macOS (Aqua)",
            @"comment": @"Stock macOS desktop session",
            @"exec": @"/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            @"type": @"aqua",
        }];

        size_t n = found.count;
        macauth_session_t *arr = calloc(n, sizeof(*arr));
        if (!arr) return MACAUTH_ERR_SYSTEM;

        for (size_t i = 0; i < n; i++) {
            NSDictionary *e = found[i];
            arr[i].id = dup_nsstring(e[@"id"]);
            arr[i].name = dup_nsstring(e[@"name"]);
            arr[i].comment = (e[@"comment"] == [NSNull null]) ? NULL : dup_nsstring(e[@"comment"]);
            arr[i].exec = dup_nsstring(e[@"exec"]);
            arr[i].type = dup_nsstring(e[@"type"]);
        }

        *out = arr;
        *count = n;
        return MACAUTH_SUCCESS;
    }
}

void macauth_free_sessions(macauth_session_t *sessions, size_t count) {
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

macauth_result_t macauth_open_session(macauth_handle_t *handle,
                                      const macauth_session_t *session,
                                      pid_t *out_pid) {
    if (!handle || !session || !session->exec) return MACAUTH_ERR_INVALID_ARG;
    if (!handle->authenticated) return MACAUTH_ERR_ABORT;
    if (!handle->user) return MACAUTH_ERR_USER_UNKNOWN;

    macauth_user_t u;
    if (macauth_lookup_user(handle->user, &u) != MACAUTH_SUCCESS)
        return MACAUTH_ERR_USER_UNKNOWN;

    /* Dropping privileges requires root; without it we can still launch a
     * session for the current user (useful for development/testing). */
    bool amRoot = (geteuid() == 0);
    if (!amRoot && u.uid != getuid()) {
        macauth_free_user_fields(&u);
        return MACAUTH_ERR_PERM;
    }

    pid_t pid = fork();
    if (pid < 0) {
        macauth_free_user_fields(&u);
        return MACAUTH_ERR_SYSTEM;
    }

    if (pid == 0) {
        /* --- child ---
         * Deliberately POSIX-only from here on: Foundation/Objective-C is not
         * safe to use after fork() in a process that may be multithreaded, so
         * we rely solely on async-signal-safe-ish libc calls. */
        if (amRoot) {
            if (setgid(u.gid) != 0) _exit(127);
            if (initgroups(u.name, u.gid) != 0) _exit(127);
            if (setuid(u.uid) != 0) _exit(127);
        }

        if (u.home) chdir(u.home);

        char runtimeDir[64];
        snprintf(runtimeDir, sizeof(runtimeDir), "/private/tmp/macauth-%u", (unsigned)u.uid);
        mkdir(runtimeDir, 0700);

        /* Start from an empty environment and build a minimal login session. */
        extern char **environ;
        static char *empty_env[1] = { NULL };
        environ = empty_env;
        setenv("USER", u.name, 1);
        setenv("LOGNAME", u.name, 1);
        if (u.home) setenv("HOME", u.home, 1);
        setenv("SHELL", u.shell ? u.shell : "/bin/sh", 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin", 1);
        setenv("XDG_RUNTIME_DIR", runtimeDir, 1);
        setenv("XDG_SESSION_TYPE", session->type, 1);
        setenv("XDG_SESSION_DESKTOP", session->id, 1);
        if (strcmp(session->type, "wayland") == 0) setenv("WAYLAND_DISPLAY", "wayland-0", 1);

        /* exec through the login shell so Exec= is parsed like a DM would. */
        const char *shell = u.shell ? u.shell : "/bin/sh";
        execl(shell, shell, "-l", "-c", session->exec, (char *)NULL);
        _exit(127);
    }

    /* --- parent --- */
    handle->session_open = true;
    handle->session_pid = pid;
    if (out_pid) *out_pid = pid;
    macauth_free_user_fields(&u);
    return MACAUTH_SUCCESS;
}

macauth_result_t macauth_close_session(macauth_handle_t *handle) {
    if (!handle) return MACAUTH_ERR_INVALID_ARG;
    if (!handle->session_open) return MACAUTH_ERR_NO_SESSION;
    handle->session_open = false;
    handle->session_pid = 0;
    return MACAUTH_SUCCESS;
}
