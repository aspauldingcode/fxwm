/*
 * provision.m - account and group provisioning.
 *
 * The macOS analogue of Linux's useradd/userdel/groupadd/passwd. It writes
 * through macOS's native account substrate rather than editing flat files:
 *
 *   - users:  Open Directory local node, driven via `dscl .` (the same store
 *             `getpwnam`, `passwd`, and Login Window use);
 *   - groups: `dseditgroup` (handles nested/computed OD membership correctly);
 *   - homes:  `createhomedir`, which materializes the macOS user template so
 *             new accounts get the standard ~/Desktop, ~/Library, etc.
 *
 * Because it uses the canonical macOS tools, accounts created here are
 * indistinguishable from ones created by System Settings, and the stock Unix
 * tools (`passwd`, `id`, `dscl`, `dscacheutil`) fully interoperate with them.
 *
 * Everything here mutates the local directory and needs root.
 */

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <pwd.h>
#include "doorman_internal.h"

static NSString *const kDSCL          = @"/usr/bin/dscl";
static NSString *const kDSEditGroup   = @"/usr/sbin/dseditgroup";
static NSString *const kCreateHomeDir = @"/usr/sbin/createhomedir";

/* Run a tool, capturing stdout. Returns the tool's exit status, or -1 if it
 * could not be launched. */
static int run_capture(NSString *launchPath, NSArray<NSString *> *args,
                       NSString **stdoutStr) {
    @try {
        NSTask *task = [[NSTask alloc] init];
        task.launchPath = launchPath;
        task.arguments = args;
        NSPipe *outPipe = [NSPipe pipe];
        task.standardOutput = outPipe;
        task.standardError = [NSPipe pipe];
        [task launch];
        NSData *data = [[outPipe fileHandleForReading] readDataToEndOfFile];
        [task waitUntilExit];
        if (stdoutStr) {
            *stdoutStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        }
        return task.terminationStatus;
    } @catch (NSException *e) {
        NSLog(@"[doorman] provision: failed to run %@: %@", launchPath, e.reason);
        return -1;
    }
}

static int run(NSString *launchPath, NSArray<NSString *> *args) {
    return run_capture(launchPath, args, NULL);
}

static bool require_root(void) {
    return geteuid() == 0;
}

/* Find the next free UniqueID at or above 501 by scanning existing users. */
static uid_t next_free_uid(void) {
    NSString *out = nil;
    if (run_capture(kDSCL, @[@".", @"-list", @"/Users", @"UniqueID"], &out) != 0 || !out) {
        return 501;
    }
    long maxUid = 500;
    for (NSString *line in [out componentsSeparatedByString:@"\n"]) {
        NSArray *tokens = [line componentsSeparatedByCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
        NSString *last = [tokens lastObject];
        if (last.length == 0) continue;
        long uid = [last longLongValue];
        /* Ignore huge sentinel/system ids so we assign a tidy human uid. */
        if (uid > maxUid && uid < 100000) maxUid = uid;
    }
    return (uid_t)(maxUid + 1);
}

static NSString *user_record_path(const char *name) {
    return [NSString stringWithFormat:@"/Users/%@", [NSString stringWithUTF8String:name]];
}

doorman_result_t doorman_create_user(const doorman_user_spec_t *spec) {
    if (!spec || !spec->name) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:spec->name];

        /* Refuse to clobber an existing account. */
        if (getpwnam(spec->name) != NULL) return DOORMAN_ERR_SYSTEM;

        NSString *recPath = user_record_path(spec->name);
        NSString *fullName = spec->full_name ? [NSString stringWithUTF8String:spec->full_name] : name;
        NSString *home = spec->home ? [NSString stringWithUTF8String:spec->home]
                                    : [@"/Users" stringByAppendingPathComponent:name];
        NSString *shell = spec->shell ? [NSString stringWithUTF8String:spec->shell] : @"/bin/zsh";
        uid_t uid = spec->uid ? spec->uid : next_free_uid();
        gid_t gid = spec->gid ? spec->gid : 20; /* staff */

        /* Build the OD record with dscl, mirroring the canonical recipe. */
        struct { NSArray<NSString *> *args; } steps[] = {
            {@[@".", @"-create", recPath]},
            {@[@".", @"-create", recPath, @"RealName", fullName]},
            {@[@".", @"-create", recPath, @"UniqueID", [@(uid) stringValue]]},
            {@[@".", @"-create", recPath, @"PrimaryGroupID", [@(gid) stringValue]]},
            {@[@".", @"-create", recPath, @"NFSHomeDirectory", home]},
            {@[@".", @"-create", recPath, @"UserShell", shell]},
        };
        for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
            if (run(kDSCL, steps[i].args) != 0) {
                /* Roll back a partial record so we don't leave junk behind. */
                run(kDSCL, @[@".", @"-delete", recPath]);
                return DOORMAN_ERR_SYSTEM;
            }
        }

        if (spec->hidden) {
            run(kDSCL, @[@".", @"-create", recPath, @"IsHidden", @"1"]);
        }

        if (spec->password) {
            NSString *pw = [NSString stringWithUTF8String:spec->password];
            if (run(kDSCL, @[@".", @"-passwd", recPath, pw]) != 0) {
                run(kDSCL, @[@".", @"-delete", recPath]);
                return DOORMAN_ERR_SYSTEM;
            }
        }

        if (spec->admin) {
            run(kDSEditGroup, @[@"-o", @"edit", @"-a", name, @"-t", @"user", @"admin"]);
        }

        if (spec->create_home) {
            doorman_result_t hr = doorman_create_home(spec->name);
            if (hr != DOORMAN_SUCCESS) return hr;
        }

        return DOORMAN_SUCCESS;
    }
}

doorman_result_t doorman_delete_user(const char *name, bool remove_home) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        struct passwd *pw = getpwnam(name);
        if (!pw) return DOORMAN_ERR_USER_UNKNOWN;
        NSString *home = pw->pw_dir ? [NSString stringWithUTF8String:pw->pw_dir] : nil;

        if (run(kDSCL, @[@".", @"-delete", user_record_path(name)]) != 0) {
            return DOORMAN_ERR_SYSTEM;
        }

        if (remove_home && home && [home hasPrefix:@"/Users/"]) {
            [[NSFileManager defaultManager] removeItemAtPath:home error:nil];
        }
        return DOORMAN_SUCCESS;
    }
}

doorman_result_t doorman_set_password(const char *name, const char *new_password) {
    if (!name || !new_password) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        if (getpwnam(name) == NULL) return DOORMAN_ERR_USER_UNKNOWN;
        NSString *pw = [NSString stringWithUTF8String:new_password];
        int rc = run(kDSCL, @[@".", @"-passwd", user_record_path(name), pw]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_create_home(const char *name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        /* Note: no getpwnam() guard here on purpose. createhomedir consults
         * Open Directory directly, and just after doorman_create_user() the
         * libc passwd cache may not yet reflect the new record. */
        NSString *nsName = [NSString stringWithUTF8String:name];
        int rc = run(kCreateHomeDir, @[@"-c", @"-u", nsName]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_create_group(const char *name, gid_t gid,
                                      const char *full_name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        NSString *nsName = [NSString stringWithUTF8String:name];
        NSMutableArray *args = [NSMutableArray arrayWithArray:@[@"-o", @"create"]];
        if (gid != 0) { [args addObject:@"-i"]; [args addObject:[@(gid) stringValue]]; }
        if (full_name) { [args addObject:@"-r"]; [args addObject:[NSString stringWithUTF8String:full_name]]; }
        [args addObject:nsName];
        int rc = run(kDSEditGroup, args);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_delete_group(const char *name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        NSString *nsName = [NSString stringWithUTF8String:name];
        int rc = run(kDSEditGroup, @[@"-o", @"delete", nsName]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

static doorman_result_t edit_membership(const char *user, const char *group, BOOL add) {
    if (!user || !group) return DOORMAN_ERR_INVALID_ARG;
    if (!require_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        if (getpwnam(user) == NULL) return DOORMAN_ERR_USER_UNKNOWN;
        NSString *nsUser = [NSString stringWithUTF8String:user];
        NSString *nsGroup = [NSString stringWithUTF8String:group];
        int rc = run(kDSEditGroup, @[@"-o", @"edit",
                                     add ? @"-a" : @"-d", nsUser,
                                     @"-t", @"user", nsGroup]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_add_user_to_group(const char *user, const char *group) {
    return edit_membership(user, group, YES);
}

doorman_result_t doorman_remove_user_from_group(const char *user, const char *group) {
    return edit_membership(user, group, NO);
}
