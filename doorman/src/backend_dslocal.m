/*
 * backend_dslocal.m - direct dsLocal ShadowHashData verification.
 *
 * This reads the on-disk local directory records under
 * /var/db/dslocal/nodes/Default/users/<name>.plist, extracts the
 * SALTED-SHA512-PBKDF2 entry from ShadowHashData, and verifies a candidate
 * password with PBKDF2-HMAC-SHA512. It needs read access to the shadow store
 * (root) but does not require opendirectoryd, which makes it usable in
 * restricted contexts.
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#include "doorman_internal.h"

static BOOL VerifyPBKDF2(NSString *password,
                         NSData *entropy,
                         NSData *salt,
                         uint32_t iterations) {
    if (!entropy || !salt || iterations == 0) return NO;

    NSMutableData *derivedKey = [NSMutableData dataWithLength:entropy.length];
    int result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      password.UTF8String,
                                      strlen(password.UTF8String),
                                      salt.bytes,
                                      salt.length,
                                      kCCPRFHmacAlgSHA512,
                                      iterations,
                                      derivedKey.mutableBytes,
                                      derivedKey.length);
    if (result != kCCSuccess) return NO;

    /* Constant-time comparison to avoid leaking match progress via timing. */
    const unsigned char *a = derivedKey.bytes;
    const unsigned char *b = entropy.bytes;
    if (derivedKey.length != entropy.length) return NO;
    unsigned char diff = 0;
    for (NSUInteger i = 0; i < entropy.length; i++) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

doorman_result_t _doorman_verify_dslocal(const char *user, const char *password) {
    if (!user || !password) return DOORMAN_ERR_INVALID_ARG;

    @autoreleasepool {
        NSString *nsUsername = [NSString stringWithUTF8String:user];
        NSString *nsPassword = [NSString stringWithUTF8String:password];

        NSString *userPlistPath = [NSString stringWithFormat:
            @"/var/db/dslocal/nodes/Default/users/%@.plist", nsUsername];
        NSDictionary *userPlist = [NSDictionary dictionaryWithContentsOfFile:userPlistPath];

        if (!userPlist) {
            /* Distinguish "no such user" from "cannot read" (needs root). */
            if (![[NSFileManager defaultManager] fileExistsAtPath:userPlistPath]) {
                return DOORMAN_ERR_USER_UNKNOWN;
            }
            NSLog(@"[doorman] dslocal: failed to read user plist at %@", userPlistPath);
            return DOORMAN_ERR_PERM;
        }

        NSArray *shadowHashArray = userPlist[@"ShadowHashData"];
        if (!shadowHashArray || shadowHashArray.count == 0) {
            NSLog(@"[doorman] dslocal: no ShadowHashData for %@", nsUsername);
            return DOORMAN_ERR_ACCT_DISABLED;
        }

        NSData *shadowHashData = shadowHashArray[0];
        NSError *error = nil;
        NSDictionary *shadowDict =
            [NSPropertyListSerialization propertyListWithData:shadowHashData
                                                      options:NSPropertyListImmutable
                                                       format:NULL
                                                        error:&error];
        if (![shadowDict isKindOfClass:[NSDictionary class]]) {
            NSLog(@"[doorman] dslocal: failed to parse ShadowHashData: %@", error);
            return DOORMAN_ERR_SYSTEM;
        }

        NSDictionary *pbkdf2Dict = shadowDict[@"SALTED-SHA512-PBKDF2"];
        if (![pbkdf2Dict isKindOfClass:[NSDictionary class]]) {
            NSLog(@"[doorman] dslocal: SALTED-SHA512-PBKDF2 not present for %@", nsUsername);
            return DOORMAN_ERR_ACCT_DISABLED;
        }

        NSData *entropy = pbkdf2Dict[@"entropy"];
        NSData *salt = pbkdf2Dict[@"salt"];
        uint32_t iterations = [pbkdf2Dict[@"iterations"] unsignedIntValue];

        if (VerifyPBKDF2(nsPassword, entropy, salt, iterations)) {
            return DOORMAN_SUCCESS;
        }
        return DOORMAN_ERR_AUTH;
    }
}
