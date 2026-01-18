#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <unistd.h>

#import "metal_renderer.h"
#import "protein_events.h"
#import "mouse_events.h"
#import "ui.h"

// Helper to verify PBKDF2-SHA512 hash
static BOOL VerifyPBKDF2(NSString *password, NSData *entropy, NSData *salt, uint32_t iterations) {
    if (!entropy || !salt || iterations == 0) return NO;

    NSMutableData *derivedKey = [NSMutableData dataWithLength:entropy.length];
    int result = CCKeyDerivationPBKDF(
        kCCPBKDF2,                  // algorithm
        password.UTF8String,        // password
        password.length,            // passwordLen
        salt.bytes,                 // salt
        salt.length,                // saltLen
        kCCPRFHmacAlgSHA512,              // PRF
        iterations,                 // rounds
        derivedKey.mutableBytes,     // derivedKey
        derivedKey.length           // derivedKeyLen
    );

    if (result != kCCSuccess) return NO;
    return [derivedKey isEqualToData:entropy];
}

Boolean DoLogon(const char* username, const char* password) {
    if (!username || !password) return false;

    @autoreleasepool {
        NSString *nsUsername = [NSString stringWithUTF8String:username];
        NSString *nsPassword = [NSString stringWithUTF8String:password];

        // Path to user plist in local nodes
        NSString *userPlistPath = [NSString stringWithFormat:@"/var/db/dslocal/nodes/Default/users/%@.plist", nsUsername];
        NSDictionary *userPlist = [NSDictionary dictionaryWithContentsOfFile:userPlistPath];

        if (!userPlist) {
            NSLog(@"[Protein] DoLogon: Failed to read user plist at %@", userPlistPath);
            return false;
        }

        // ShadowHashData is an array of data, first element is a binary plist
        NSArray *shadowHashArray = userPlist[@"ShadowHashData"];
        if (!shadowHashArray || shadowHashArray.count == 0) {
            NSLog(@"[Protein] DoLogon: No ShadowHashData found for %@", nsUsername);
            return false;
        }

        NSData *shadowHashData = shadowHashArray[0];
        NSError *error = nil;
        NSDictionary *shadowDict = [NSPropertyListSerialization propertyListWithData:shadowHashData
                                                                           options:NSPropertyListImmutable
                                                                            format:NULL
                                                                             error:&error];
        if (!shadowDict) {
            NSLog(@"[Protein] DoLogon: Failed to parse ShadowHashData: %@", error);
            return false;
        }

        // Modern macOS uses SALTED-SHA512-PBKDF2
        NSDictionary *pbkdf2Dict = shadowDict[@"SALTED-SHA512-PBKDF2"];
        if (pbkdf2Dict) {
            NSData *entropy = pbkdf2Dict[@"entropy"];
            NSData *salt = pbkdf2Dict[@"salt"];
            uint32_t iterations = [pbkdf2Dict[@"iterations"] unsignedIntValue];

            if (VerifyPBKDF2(nsPassword, entropy, salt, iterations)) {
                NSLog(@"[Protein] DoLogon: PBKDF2 Authentication successful for %@", nsUsername);
                return true;
            }
        } else {
            NSLog(@"[Protein] DoLogon: SALTED-SHA512-PBKDF2 not found in shadow dict");
        }

        NSLog(@"[Protein] DoLogon: Authentication failed for %@", nsUsername);
        return false;
    }
}

void CreateLogonView(PVView *gRootView) {
    // Add a label
    PVLabel *lbl = [[PVLabel alloc] init];
    lbl.frame = CGRectMake(100, 220, 200, 30);
    lbl.text = @"enter 501 passwd";
    lbl.backgroundColor = 0x000000FF; // Black
    lbl.textColor = 0xFFFFFFFF; // White
    [gRootView addSubview:lbl];

    // Add a text field
    PVTextField *tf = [[PVTextField alloc] init];
    tf.frame = CGRectMake(800, 600, 200, 40);
    tf.placeholder = @"Type password...";
    tf.backgroundColor = 0x000000FF; // Black
    tf.textColor = 0xFFFFFFFF; // White
    tf.secureTextEntry = YES;
    tf.onEnter = ^(NSString *text) {
        // Trim whitespace/newlines
        NSString *trimmedText = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        NSLog(@"[Protein] Password Attempt Received (length: %lu)", (unsigned long)trimmedText.length);

        Boolean loginSucceded = DoLogon("bedtime", trimmedText.UTF8String);
        if (loginSucceded) {
            [lbl removeFromSuperview];
            [tf removeFromSuperview];
        } else {
            lbl.text = @"Login failed. Try again.";
            lbl.textColor = 0xFF0000FF; // Red
            tf.text = @""; // Clear password on failure
        }
    };
    [gRootView addSubview:tf];
}
