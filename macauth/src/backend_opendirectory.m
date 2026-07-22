/*
 * backend_opendirectory.m - authentication via the OpenDirectory framework.
 *
 * This is the recommended production backend. It uses the same path the macOS
 * login window uses: open the authentication search node, find the user
 * record, and call -verifyPassword:error:. Because it goes through
 * opendirectoryd it transparently handles local, mobile, and network
 * (LDAP/AD) accounts and honors the machine's search policy.
 */

#import <Foundation/Foundation.h>
#import <OpenDirectory/OpenDirectory.h>
#include "macauth_internal.h"

static macauth_result_t map_od_error(NSError *error, BOOL verified) {
    if (verified) return MACAUTH_SUCCESS;
    if (!error) return MACAUTH_ERR_AUTH;

    /* ODFrameworkErrors: credentials that simply don't match come back as
     * eODErrorCredentialsInvalid (5000). Anything else is a system/lookup
     * problem worth surfacing distinctly. */
    switch (error.code) {
        case 5000: /* kODErrorCredentialsInvalid */
            return MACAUTH_ERR_AUTH;
        case 5001: /* kODErrorCredentialsAccountDisabled */
        case 5002: /* kODErrorCredentialsAccountInactive */
        case 5003: /* kODErrorCredentialsAccountExpired */
        case 5004: /* kODErrorCredentialsPasswordExpired */
            return MACAUTH_ERR_ACCT_DISABLED;
        default:
            return MACAUTH_ERR_SYSTEM;
    }
}

static ODRecord *copy_user_record(const char *user, NSError **outError) {
    NSString *nsUsername = [NSString stringWithUTF8String:user];

    ODSession *session = [ODSession defaultSession];
    if (!session) return nil;

    ODNode *node = [ODNode nodeWithSession:session
                                      type:kODNodeTypeAuthentication
                                     error:outError];
    if (!node) return nil;

    ODRecord *record = [node recordWithRecordType:kODRecordTypeUsers
                                             name:nsUsername
                                       attributes:nil
                                            error:outError];
    return record;
}

macauth_result_t _macauth_verify_opendirectory(const char *user, const char *password) {
    if (!user || !password) return MACAUTH_ERR_INVALID_ARG;

    @autoreleasepool {
        NSError *error = nil;
        ODRecord *record = copy_user_record(user, &error);
        if (!record) {
            /* No record => unknown user; other failures are system errors. */
            if (!error) return MACAUTH_ERR_USER_UNKNOWN;
            if (error.code == 5301 /* kODErrorRecordNoLongerExists */ ||
                error.code == 5300 /* record not found variants */) {
                return MACAUTH_ERR_USER_UNKNOWN;
            }
            return MACAUTH_ERR_USER_UNKNOWN;
        }

        NSString *nsPassword = [NSString stringWithUTF8String:password];
        error = nil;
        BOOL ok = [record verifyPassword:nsPassword error:&error];
        return map_od_error(error, ok);
    }
}

macauth_result_t _macauth_acct_mgmt_directory(const char *user) {
    if (!user) return MACAUTH_ERR_INVALID_ARG;

    @autoreleasepool {
        NSError *error = nil;
        ODRecord *record = copy_user_record(user, &error);
        if (!record) return MACAUTH_ERR_USER_UNKNOWN;

        /* A disabled local account carries a ";DisabledUser;" token in its
         * AuthenticationAuthority attribute. Treat its presence as disabled. */
        NSArray *authority =
            [record valuesForAttribute:kODAttributeTypeAuthenticationAuthority error:&error];
        for (id value in authority) {
            if ([value isKindOfClass:[NSString class]] &&
                [(NSString *)value rangeOfString:@"DisabledUser"].location != NSNotFound) {
                return MACAUTH_ERR_ACCT_DISABLED;
            }
        }
        return MACAUTH_SUCCESS;
    }
}
