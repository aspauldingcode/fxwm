//
//  dyld_tmp.m
//  protein_bootstrap
//
//  Created by bedtime on 10/21/25.
//

#include <Foundation/Foundation.h>
#include <_stdio.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <libgen.h>
#include <mach/machine.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>


extern int create_or_remount_overlay_symlinks(const char *path, char *out_store_path, size_t out_size);
extern int commit_overlay_changes(const char *overlay_path);
extern int reapply_all_overlays(void);
extern int unmount_if_mounted(const char *path);

// inject windowserver with dylib via tmpfs
#define __LaunchDaemons "/System/Library/LaunchDaemons"
#define __WindowServerPropertyList "/System/Library/LaunchDaemons/com.apple.WindowServer.plist"

#define __DylibProtein "../libprotein_render.dylib"

int patchy() {
    char overlay_path[PATH_MAX] = {0};

    // Create or remount overlay symlinks
    kern_return_t ret = create_or_remount_overlay_symlinks(__LaunchDaemons,
                                                           overlay_path,
                                                           sizeof(overlay_path));
    if (ret != 0) {
        fprintf(stderr, "Failed to create overlay symlinks\n");
        return -1;
    }

    fprintf(stdout, "WindowServer overlay created at %s\n", overlay_path);

    // Build destination path for dylib
    NSString *overlayStr = [NSString stringWithUTF8String:__LaunchDaemons];
    NSString *destPath = [[overlayStr stringByStandardizingPath]
                          stringByAppendingPathComponent:@"libprotein_render.dylib"];


    // Copy dylib to overlay
    NSError *error = nil;
    if ([NSFileManager.defaultManager fileExistsAtPath:destPath]) {
        remove(destPath.UTF8String);
    }

    BOOL success = [NSFileManager.defaultManager copyItemAtPath:@__DylibProtein
                                                          toPath:destPath
                                                           error:&error];
    if (!success) {
        fprintf(stderr, "Failed to copy dylib: %s\n", error.localizedDescription.UTF8String);
        return -1;
    }

    const char *destCStr = destPath.fileSystemRepresentation;
    fprintf(stdout, "Dylib copied to overlay at %s\n", destCStr);

    NSMutableDictionary * _plist = [NSMutableDictionary dictionaryWithContentsOfFile:@__WindowServerPropertyList];


    _plist[@"EnvironmentVariables"] = @{
        @"DYLD_INSERT_LIBRARIES" : @"/private/var/protein/overlays/System/Library/LaunchDaemons/libprotein_render.dylib",
        @"CA_NO_ACCEL" : @1,
        @"CA_ACCEL_BACKING" : @0,
        @"CA_DISABLE_SWAP_ICC" : @1,
        @"CA_DISABLE_FRAMEBUFFER_COMPRESSION" : @1
    };
//
//    id existingProgArgs = [_plist[@"ProgramArguments"] mutableCopy];
//    if (![existingProgArgs containsObject:@"-virtualonly"]) {
//        [existingProgArgs addObject:@"-virtualonly"];
//    }
//    _plist[@"ProgramArguments"] = existingProgArgs;

    [_plist writeToFile:@__WindowServerPropertyList atomically:NO];

    // CA_VSYNC_OFF=1

    // Commit overlay changes
    const char *overlayPathCStr = [overlayStr stringByStandardizingPath].UTF8String;
    commit_overlay_changes(overlayPathCStr);

    fprintf(stdout, "Overlay changes committed to booted store\n");

    return 0;
}
