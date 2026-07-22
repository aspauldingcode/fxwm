/*
 * backend_dslocal.m - offline verification against the local shadow store.
 *
 * When opendirectoryd is unavailable (recovery, early boot, a locked-down
 * service context) we can still authenticate a local user by reading their
 * record straight off disk at
 *     /var/db/dslocal/nodes/Default/users/<name>.plist
 * pulling the SALTED-SHA512-PBKDF2 material out of the embedded ShadowHashData
 * blob, and re-deriving the key from the candidate password. Reading the store
 * requires root; it deliberately does not talk to any daemon.
 *
 * Security notes:
 *   - the account name is validated before it touches the path, so a crafted
 *     name cannot escape the users directory (path-traversal guard);
 *   - the comparison is constant-time;
 *   - the re-derived key is scrubbed from memory before returning.
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#include "doorman_internal.h"

static NSString *const kLocalUsersDir = @"/var/db/dslocal/nodes/Default/users";

/* The three PBKDF2 parameters we need out of a ShadowHashData entry. */
typedef struct {
    NSData *stored;   /* the stored derived key ("entropy")                   */
    NSData *salt;     /* per-record salt                                      */
    uint32_t rounds;  /* iteration count                                      */
} dm_pbkdf2_params;

/*
 * Re-derive the key for `secret` under the given parameters and compare it,
 * in constant time, against the stored value. The scratch key is wiped before
 * returning regardless of outcome.
 */
static BOOL secret_matches(NSString *secret, dm_pbkdf2_params p) {
    if (!p.stored || !p.salt || p.rounds == 0 || p.stored.length == 0) return NO;

    const char *secretUTF8 = secret.UTF8String;
    if (!secretUTF8) return NO;

    NSMutableData *scratch = [NSMutableData dataWithLength:p.stored.length];
    if (!scratch) return NO;

    int kdf = CCKeyDerivationPBKDF(kCCPBKDF2,
                                   secretUTF8, strlen(secretUTF8),
                                   p.salt.bytes, p.salt.length,
                                   kCCPRFHmacAlgSHA512,
                                   p.rounds,
                                   scratch.mutableBytes, scratch.length);

    BOOL matched = NO;
    if (kdf == kCCSuccess) {
        matched = _dm_consttime_equal(scratch.mutableBytes, p.stored.bytes,
                                      p.stored.length) ? YES : NO;
    }
    _dm_scrub(scratch.mutableBytes, scratch.length);
    return matched;
}

/* Decode the first ShadowHashData element (itself a binary plist) into a dict,
 * or nil if the record has no usable shadow data. */
static NSDictionary *decode_shadow_blob(NSDictionary *record) {
    NSArray *blobs = record[@"ShadowHashData"];
    if (![blobs isKindOfClass:[NSArray class]] || blobs.count == 0) return nil;

    id first = blobs.firstObject;
    if (![first isKindOfClass:[NSData class]]) return nil;

    NSError *err = nil;
    id decoded = [NSPropertyListSerialization propertyListWithData:first
                                                           options:NSPropertyListImmutable
                                                            format:NULL
                                                             error:&err];
    return [decoded isKindOfClass:[NSDictionary class]] ? decoded : nil;
}

doorman_result_t _dm_verify_dslocal(const char *user, const char *password) {
    if (!user || !password) return DOORMAN_ERR_INVALID_ARG;
    /* Reject anything that could climb out of the users directory. */
    if (!_dm_name_ok(user)) return DOORMAN_ERR_USER_UNKNOWN;

    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:user];
        NSString *secret = [NSString stringWithUTF8String:password];
        if (!name || !secret) return DOORMAN_ERR_INVALID_ARG;

        NSString *recordPath =
            [[kLocalUsersDir stringByAppendingPathComponent:name]
                stringByAppendingPathExtension:@"plist"];

        NSDictionary *record = [NSDictionary dictionaryWithContentsOfFile:recordPath];
        if (!record) {
            /* Missing file => unknown user; present-but-unreadable => no root. */
            if (![[NSFileManager defaultManager] fileExistsAtPath:recordPath])
                return DOORMAN_ERR_USER_UNKNOWN;
            return DOORMAN_ERR_PERM;
        }

        NSDictionary *shadow = decode_shadow_blob(record);
        if (!shadow) return DOORMAN_ERR_ACCT_DISABLED;

        NSDictionary *pbkdf2 = shadow[@"SALTED-SHA512-PBKDF2"];
        if (![pbkdf2 isKindOfClass:[NSDictionary class]])
            return DOORMAN_ERR_ACCT_DISABLED;

        dm_pbkdf2_params params = {
            .stored = pbkdf2[@"entropy"],
            .salt   = pbkdf2[@"salt"],
            .rounds = (uint32_t)[pbkdf2[@"iterations"] unsignedIntValue],
        };
        if (![params.stored isKindOfClass:[NSData class]] ||
            ![params.salt isKindOfClass:[NSData class]])
            return DOORMAN_ERR_ACCT_DISABLED;

        return secret_matches(secret, params) ? DOORMAN_SUCCESS : DOORMAN_ERR_AUTH;
    }
}
