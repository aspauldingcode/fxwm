/*
 * provision.m - account and group provisioning.
 *
 * The macOS analogue of Linux useradd/userdel/groupadd/passwd. Rather than
 * editing flat files it writes through the native account substrate:
 *
 *   - users:   the Open Directory local node via `dscl .` (the store getpwnam,
 *              passwd and Login Window all read);
 *   - passwords: the OpenDirectory API (never a command line), so the plaintext
 *              is never exposed in the process table;
 *   - groups:  `dseditgroup` (correct nested/computed OD membership);
 *   - homes:   `createhomedir`, which materialises the macOS user template.
 *
 * All of these mutate the local directory and require root.
 *
 * Safety: every externally supplied short name is validated (_dm_name_ok)
 * before it is interpolated into a record path or handed to a tool, and the
 * tools are spawned via NSTask with an explicit argument vector (never a
 * shell), so neither path traversal nor argument/shell injection is possible.
 */

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <pwd.h>
#include "doorman_internal.h"

static NSString *const kDsclPath        = @"/usr/bin/dscl";
static NSString *const kDsEditGroupPath = @"/usr/sbin/dseditgroup";
static NSString *const kCreateHomePath  = @"/usr/sbin/createhomedir";

/* Run a tool with an explicit argv, optionally capturing stdout. stderr is
 * discarded to the null device so a chatty tool can never dead-lock us by
 * filling an unread pipe. Returns the exit status, or -1 if it never launched. */
static int capture_tool(NSString *path, NSArray<NSString *> *args, NSString **out) {
    @try {
        NSTask *task = [[NSTask alloc] init];
        task.launchPath = path;
        task.arguments = args;
        NSPipe *stdoutPipe = [NSPipe pipe];
        task.standardOutput = stdoutPipe;
        task.standardError = [NSFileHandle fileHandleWithNullDevice];
        [task launch];
        NSData *data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        [task waitUntilExit];
        if (out) *out = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return task.terminationStatus;
    } @catch (NSException *e) {
        NSLog(@"[doorman] provision: could not run %@: %@", path, e.reason);
        return -1;
    }
}

static int invoke_tool(NSString *path, NSArray<NSString *> *args) {
    return capture_tool(path, args, NULL);
}

static bool running_as_root(void) {
    return geteuid() == 0;
}

/* Lowest free UniqueID at or above 501, by scanning the existing records. */
static uid_t allocate_uid(void) {
    NSString *out = nil;
    if (capture_tool(kDsclPath, @[@".", @"-list", @"/Users", @"UniqueID"], &out) != 0 || !out)
        return 501;

    long highest = 500;
    for (NSString *line in [out componentsSeparatedByString:@"\n"]) {
        NSString *last = [[line componentsSeparatedByCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]] lastObject];
        if (last.length == 0) continue;
        long value = [last longLongValue];
        /* Skip the huge sentinel/system ids so we hand out a tidy human uid. */
        if (value > highest && value < 100000) highest = value;
    }
    return (uid_t)(highest + 1);
}

static NSString *user_dscl_path(const char *name) {
    return [@"/Users" stringByAppendingPathComponent:[NSString stringWithUTF8String:name]];
}

doorman_result_t doorman_create_user(const doorman_user_spec_t *spec) {
    if (!spec || !spec->name) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(spec->name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        NSString *shortName = [NSString stringWithUTF8String:spec->name];

        /* Never clobber an existing account. */
        if (getpwnam(spec->name) != NULL) return DOORMAN_ERR_SYSTEM;

        NSString *recPath = user_dscl_path(spec->name);
        NSString *realName = spec->full_name ? [NSString stringWithUTF8String:spec->full_name] : shortName;
        NSString *home = spec->home ? [NSString stringWithUTF8String:spec->home]
                                    : [@"/Users" stringByAppendingPathComponent:shortName];
        NSString *shell = spec->shell ? [NSString stringWithUTF8String:spec->shell] : @"/bin/zsh";
        uid_t uid = spec->uid ? spec->uid : allocate_uid();
        gid_t gid = spec->gid ? spec->gid : 20; /* staff */

        /* A caller-supplied field that is not valid UTF-8 decodes to nil, which
         * would throw when placed in an argument array. Reject it up front. */
        if (!realName || !home || !shell) return DOORMAN_ERR_INVALID_ARG;

        NSArray<NSArray<NSString *> *> *steps = @[
            @[@".", @"-create", recPath],
            @[@".", @"-create", recPath, @"RealName", realName],
            @[@".", @"-create", recPath, @"UniqueID", [@(uid) stringValue]],
            @[@".", @"-create", recPath, @"PrimaryGroupID", [@(gid) stringValue]],
            @[@".", @"-create", recPath, @"NFSHomeDirectory", home],
            @[@".", @"-create", recPath, @"UserShell", shell],
        ];
        for (NSArray<NSString *> *step in steps) {
            if (invoke_tool(kDsclPath, step) != 0) {
                invoke_tool(kDsclPath, @[@".", @"-delete", recPath]); /* roll back */
                return DOORMAN_ERR_SYSTEM;
            }
        }

        if (spec->hidden)
            invoke_tool(kDsclPath, @[@".", @"-create", recPath, @"IsHidden", @"1"]);

        if (spec->password) {
            /* Set through OpenDirectory, not `dscl -passwd`, to keep the
             * plaintext off every process listing. */
            if (_dm_od_set_password(spec->name, spec->password) != DOORMAN_SUCCESS) {
                invoke_tool(kDsclPath, @[@".", @"-delete", recPath]);
                return DOORMAN_ERR_SYSTEM;
            }
        }

        if (spec->admin)
            invoke_tool(kDsEditGroupPath, @[@"-o", @"edit", @"-a", shortName, @"-t", @"user", @"admin"]);

        if (spec->create_home) {
            doorman_result_t hr = doorman_create_home(spec->name);
            if (hr != DOORMAN_SUCCESS) return hr;
        }

        return DOORMAN_SUCCESS;
    }
}

doorman_result_t doorman_delete_user(const char *name, bool remove_home) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        struct passwd *pw = getpwnam(name);
        if (!pw) return DOORMAN_ERR_USER_UNKNOWN;
        NSString *home = pw->pw_dir ? [NSString stringWithUTF8String:pw->pw_dir] : nil;

        if (invoke_tool(kDsclPath, @[@".", @"-delete", user_dscl_path(name)]) != 0)
            return DOORMAN_ERR_SYSTEM;

        /* Only remove a home that is safely under /Users and free of parent
         * references, so a hand-tampered record can never trick us into
         * deleting an unrelated tree. */
        if (remove_home && home &&
            [home hasPrefix:@"/Users/"] &&
            [home rangeOfString:@".."].location == NSNotFound) {
            [[NSFileManager defaultManager] removeItemAtPath:home error:nil];
        }
        return DOORMAN_SUCCESS;
    }
}

doorman_result_t doorman_set_password(const char *name, const char *new_password) {
    if (!name || !new_password) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        if (getpwnam(name) == NULL) return DOORMAN_ERR_USER_UNKNOWN;
        return _dm_od_set_password(name, new_password);
    }
}

doorman_result_t doorman_create_home(const char *name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        /* No getpwnam() guard on purpose: createhomedir consults Open Directory
         * directly, and right after doorman_create_user() the libc passwd cache
         * may not yet reflect the new record. */
        int rc = invoke_tool(kCreateHomePath, @[@"-c", @"-u", [NSString stringWithUTF8String:name]]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_create_group(const char *name, gid_t gid,
                                      const char *full_name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        NSMutableArray *args = [@[@"-o", @"create"] mutableCopy];
        if (gid != 0) { [args addObject:@"-i"]; [args addObject:[@(gid) stringValue]]; }
        if (full_name) {
            NSString *rn = [NSString stringWithUTF8String:full_name];
            if (!rn) return DOORMAN_ERR_INVALID_ARG;
            [args addObject:@"-r"]; [args addObject:rn];
        }
        [args addObject:[NSString stringWithUTF8String:name]];
        int rc = invoke_tool(kDsEditGroupPath, args);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_delete_group(const char *name) {
    if (!name) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(name)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        int rc = invoke_tool(kDsEditGroupPath, @[@"-o", @"delete", [NSString stringWithUTF8String:name]]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

static doorman_result_t edit_membership(const char *user, const char *group, BOOL add) {
    if (!user || !group) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(user) || !_dm_name_ok(group)) return DOORMAN_ERR_INVALID_ARG;
    if (!running_as_root()) return DOORMAN_ERR_PERM;

    @autoreleasepool {
        if (getpwnam(user) == NULL) return DOORMAN_ERR_USER_UNKNOWN;
        int rc = invoke_tool(kDsEditGroupPath, @[@"-o", @"edit",
                                                 add ? @"-a" : @"-d",
                                                 [NSString stringWithUTF8String:user],
                                                 @"-t", @"user",
                                                 [NSString stringWithUTF8String:group]]);
        return rc == 0 ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t doorman_add_user_to_group(const char *user, const char *group) {
    return edit_membership(user, group, YES);
}

doorman_result_t doorman_remove_user_from_group(const char *user, const char *group) {
    return edit_membership(user, group, NO);
}
