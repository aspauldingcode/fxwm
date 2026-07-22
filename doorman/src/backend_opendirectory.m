/*
 * backend_opendirectory.m - authentication and password writes via the
 * OpenDirectory framework.
 *
 * This is the production path: it goes through opendirectoryd exactly as the
 * macOS login window does, so it transparently covers local, mobile, and
 * network (LDAP/AD) accounts and honours the machine's search policy. The same
 * framework is used to write a new password into the local node, which avoids
 * ever placing a plaintext password on a command line.
 */

#import <Foundation/Foundation.h>
#import <OpenDirectory/OpenDirectory.h>
#include "doorman_internal.h"

/* OpenDirectory (ODFrameworkErrors) credential result codes we care about. */
enum {
    kDMErrCredentialsInvalid  = 5000,
    kDMErrAccountDisabled     = 5001,
    kDMErrAccountInactive     = 5002,
    kDMErrAccountExpired      = 5003,
    kDMErrPasswordExpired     = 5004,
    kDMErrRecordNotFound      = 5300,
    kDMErrRecordNoLongerValid = 5301,
};

/* Fetch a user record from a node of the requested type. Returns nil and sets
 * *outErr on failure; a nil return with *outErr still nil means "not found". */
static ODRecord *fetch_record(ODNodeType nodeType, NSString *name, NSError **outErr) {
    ODSession *session = [ODSession defaultSession];
    if (!session) return nil;

    ODNode *node = [ODNode nodeWithSession:session type:nodeType error:outErr];
    if (!node) return nil;

    return [node recordWithRecordType:kODRecordTypeUsers
                                 name:name
                           attributes:nil
                                error:outErr];
}

static doorman_result_t classify_verify(BOOL verified, NSError *err) {
    if (verified) return DOORMAN_SUCCESS;
    switch (err ? err.code : kDMErrCredentialsInvalid) {
        case kDMErrCredentialsInvalid:
            return DOORMAN_ERR_AUTH;
        case kDMErrAccountDisabled:
        case kDMErrAccountInactive:
        case kDMErrAccountExpired:
        case kDMErrPasswordExpired:
            return DOORMAN_ERR_ACCT_DISABLED;
        default:
            return DOORMAN_ERR_SYSTEM;
    }
}

doorman_result_t _dm_verify_opendirectory(const char *user, const char *password) {
    if (!user || !password) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(user)) return DOORMAN_ERR_USER_UNKNOWN;

    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:user];
        NSString *secret = [NSString stringWithUTF8String:password];
        if (!name || !secret) return DOORMAN_ERR_INVALID_ARG;

        NSError *err = nil;
        ODRecord *record = fetch_record(kODNodeTypeAuthentication, name, &err);
        if (!record) return DOORMAN_ERR_USER_UNKNOWN;

        err = nil;
        BOOL ok = [record verifyPassword:secret error:&err];
        return classify_verify(ok, err);
    }
}

doorman_result_t _dm_account_is_enabled(const char *user) {
    if (!user) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(user)) return DOORMAN_ERR_USER_UNKNOWN;

    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:user];
        if (!name) return DOORMAN_ERR_INVALID_ARG;

        NSError *err = nil;
        ODRecord *record = fetch_record(kODNodeTypeAuthentication, name, &err);
        if (!record) return DOORMAN_ERR_USER_UNKNOWN;

        /* A disabled local account carries a ";DisabledUser;" token in its
         * AuthenticationAuthority values. */
        NSArray *authority =
            [record valuesForAttribute:kODAttributeTypeAuthenticationAuthority error:&err];
        for (id value in authority) {
            if ([value isKindOfClass:[NSString class]] &&
                [(NSString *)value rangeOfString:@"DisabledUser"].location != NSNotFound) {
                return DOORMAN_ERR_ACCT_DISABLED;
            }
        }
        return DOORMAN_SUCCESS;
    }
}

doorman_result_t _dm_od_set_password(const char *user, const char *new_password) {
    if (!user || !new_password) return DOORMAN_ERR_INVALID_ARG;
    if (!_dm_name_ok(user)) return DOORMAN_ERR_USER_UNKNOWN;

    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:user];
        NSString *secret = [NSString stringWithUTF8String:new_password];
        if (!name || !secret) return DOORMAN_ERR_INVALID_ARG;

        /* Write into the local node; as root an administrative reset does not
         * require the old password (pass nil). This establishes the same
         * ShadowHashData the stock `passwd` writes, with no plaintext on argv. */
        NSError *err = nil;
        ODRecord *record = fetch_record(kODNodeTypeLocalNodes, name, &err);
        if (!record) return DOORMAN_ERR_USER_UNKNOWN;

        err = nil;
        BOOL ok = [record changePassword:nil toPassword:secret error:&err];
        return ok ? DOORMAN_SUCCESS : DOORMAN_ERR_SYSTEM;
    }
}
