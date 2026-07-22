#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <unistd.h>

#import "metal_renderer.h"
#import "protein_events.h"
#import "mouse_events.h"
#import "ui.h"

// Authentication is delegated to the standalone macauth framework. fxwm is now
// just one consumer of the library; the credential verification, user
// enumeration and (eventually) session launch all live in libmacauth.
#import <macauth.h>

Boolean DoLogon(const char* username, const char* password) {
    if (!username || !password) return false;

    // AUTO tries OpenDirectory first (covers local + network accounts) and
    // falls back to the on-disk dsLocal ShadowHashData reader fxwm used to
    // implement inline.
    macauth_result_t r = macauth_authenticate_password(username, password,
                                                       MACAUTH_BACKEND_AUTO);
    if (r == MACAUTH_SUCCESS) {
        NSLog(@"[Protein] DoLogon: authentication successful for %s", username);
        return true;
    }
    NSLog(@"[Protein] DoLogon: authentication failed for %s (%s)",
          username, macauth_strerror(r));
    return false;
}

static NSString *gSelectedUsername = nil;

NSArray* GetUserList() {
    // Ask the library for interactive (login-eligible) accounts. This mirrors
    // what a Linux display manager gets from getpwent() with the usual
    // system-account filtering.
    macauth_user_t *users = NULL;
    size_t count = 0;
    macauth_result_t r = macauth_enumerate_users(true, &users, &count);
    if (r != MACAUTH_SUCCESS || count == 0) {
        NSLog(@"[Protein] Failed to enumerate users: %s", macauth_strerror(r));
        if (users) macauth_free_users(users, count);
        return @[@"bedtime"]; // Fallback
    }

    NSMutableArray *names = [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        if (users[i].name) [names addObject:[NSString stringWithUTF8String:users[i].name]];
    }
    macauth_free_users(users, count);
    return names;
}

void CreateLogonView(PVView *gRootView) {
    NSArray *users = GetUserList();
    gSelectedUsername = [users firstObject];

    // Add a label for instructions/status
    PVLabel *statusLbl = [[PVLabel alloc] init];
    statusLbl.frame = CGRectMake(800, 500, 400, 30);
    statusLbl.text = [NSString stringWithFormat:@"Login as: %@", gSelectedUsername ?: @"none"];
    statusLbl.backgroundColor = 0x00000000;
    statusLbl.textColor = 0xFFFFFFFF;
    [gRootView addSubview:statusLbl];

    // Create ScrollView for User List
    PVScrollView *sv = [[PVScrollView alloc] init];
    sv.frame = CGRectMake(800, 100, 200, 350);
    sv.backgroundColor = 0x222222FF;
    sv.contentSize = CGSizeMake(200, users.count * 50);
    [gRootView addSubview:sv];

    for (int i = 0; i < users.count; i++) {
        NSString *user = users[i];
        PVButton *btn = [[PVButton alloc] init];
        btn.frame = CGRectMake(5, i * 50 + 5, 190, 40);
        btn.title = user;
        btn.backgroundColor = 0x444444FF;
        btn.onClick = ^{
            gSelectedUsername = user;
            statusLbl.text = [NSString stringWithFormat:@"Login as: %@", user];
            statusLbl.textColor = 0xFFFFFFFF;
        };
        [sv addSubview:btn];
    }

    // Add a text field for password
    PVTextField *tf = [[PVTextField alloc] init];
    tf.frame = CGRectMake(800, 550, 200, 40);
    tf.placeholder = @"Type password...";
    tf.backgroundColor = 0x000000FF; // Black
    tf.textColor = 0xFFFFFFFF; // White
    tf.secureTextEntry = YES;
    tf.onEnter = ^(NSString *text) {
        if (!gSelectedUsername) return;

        // Trim whitespace/newlines
        NSString *trimmedText = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        NSLog(@"[Protein] Password Attempt for %@ (length: %lu)", gSelectedUsername, (unsigned long)trimmedText.length);

        Boolean loginSucceded = DoLogon(gSelectedUsername.UTF8String, trimmedText.UTF8String);
        if (loginSucceded) {
            [statusLbl removeFromSuperview];
            [tf removeFromSuperview];
            [sv removeFromSuperview];
        } else {
            statusLbl.text = @"Login failed. Try again.";
            statusLbl.textColor = 0xFF0000FF; // Red
            tf.text = @""; // Clear password on failure
        }
    };
    [gRootView addSubview:tf];
}
