#include <Foundation/Foundation.h>
#include <QuartzCore/QuartzCore.h>
#include <stdint.h>
#include <IOSurface/IOSurface.h>
#include <CoreGraphics/CoreGraphics.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread.h>
#include <objc/runtime.h>


#define HOOK_INSTANCE_METHOD(CLASS, SELECTOR, REPLACEMENT, ORIGINAL) \
({ \
    Class _class = (CLASS); \
    SEL _selector = (SELECTOR); \
    Method _method = class_getInstanceMethod(_class, _selector); \
    if (_method) { \
        IMP _replacement = (IMP)(REPLACEMENT); \
        *(ORIGINAL) = method_setImplementation(_method, _replacement); \
    } else { \
        NSLog(@"Warning: Failed to hook method %@ in class %@", \
              NSStringFromSelector(_selector), NSStringFromClass(_class)); \
    } \
})

#define __int64 int64_t

#include "dobby.h"
#import "sym.h"

@interface CATransaction (Priv)

+(void)setCommittingContexts:(id)arg1 ;
+(BOOL)setDisableSignPosts:(Boolean)arg1 ;
@end

@interface CAContext : NSObject

@property (class) BOOL allowsCGSConnections;

+ (instancetype)remoteContextWithOptions:(NSDictionary *)options;
+ (instancetype)remoteContext;
+ (instancetype)localContextWithOptions:(NSDictionary *)options;
+ (instancetype)localContext;
+ (instancetype)currentContext;

+ (NSArray<__kindof CAContext *> *)allContexts;
+ (void)setClientPort:(mach_port_t)port;

@property BOOL colorMatchUntaggedContent;
@property CGColorSpaceRef colorSpace;
@property uint32_t commitPriority;
@property (copy) NSString *contentsFormat;
@property (readonly) uint32_t contextId;
@property uint32_t displayMask;
@property uint32_t displayNumber;
@property uint32_t eventMask;
@property (strong) CALayer *layer;
@property (readonly) NSDictionary *options;
@property int restrictedHostProcessId;
@property (readonly) BOOL valid;

- (void)invalidate;

- (uint32_t)createSlot;
- (void)setObject:(id)object forSlot:(uint32_t)slot;
- (void)deleteSlot:(uint32_t)slot;

- (mach_port_t)createFencePort;
- (void)setFence:(uint32_t)fence count:(uint32_t)count;
- (void)setFencePort:(mach_port_t)port commitHandler:(void(^)(void))handler;
- (void)setFencePort:(mach_port_t)port;
- (void)invalidateFences;

@end

/* Can be used as the value of `CALayer.contents`. */
@interface CASlotProxy: NSObject

- (instancetype)initWithName:(uint32_t)slotName;

@end

@interface CARemoteLayerClient ()

- (CAContext *)context;

@end

@interface CALayer (CAContext)

@property (readonly) CAContext *context;

@end

CG_EXTERN CFTypeRef CGRegionCreateWithRect(CGRect rect);

void *(*_StartSubsidiaryServices)(__int64 a1);

void *(*_WindowCreate)(__int64 a1, unsigned int a2, const void *a3, int a4);
Boolean (*_WindowIsValid)(void *a1);
pid_t (*_WindowGetOwningProcessId)(void *a1);
void (*_ShapeWindowWithRect)(void *a1, CGRect a2);
void (*_OrderWindowListSpaceSwitchOptions)(__int64 a1,
                                           __int64 a2,
                                           __int64 a3,
                                           __int64 a4,
                                           unsigned int a5,
                                           unsigned int a6); // im lazyyyy

void (*_BindLocalClientContext)(void *a1, CAContext *a2, __int64 a3); // a3 usually one
void (*_WindowLayerBackingTakeOwnershipOfContext)(void *a1, CAContext *a2); // a3 usually one


void (*_InvalidateDisplayShape)(__int64 a1, __int64 a2, __int64 a3); // a3 usually one
void (*_ScheduleUpdateAllDisplays)(__int64 a1, __int64 a2); // a3 usually one


void (*__SERVER_COMMIT_START)(__int64 * int_ptr, CAContext *ptr);
void (*__SERVER_COMMIT_END)(__int64 * int_ptr);

// Linked list node structure
typedef struct WindowNode {
    void * window;
    pid_t owner;
    struct WindowNode *next;
} WindowNode;

// Head of linked list
WindowNode *gWindowList = NULL;
pthread_mutex_t gWindowListLock = PTHREAD_MUTEX_INITIALIZER;

// Helper to add a window ID
void AddWindow(void * w) {
    pid_t owner = _WindowGetOwningProcessId(w);

    NSLog(@"added window %p owned by owner %i", w, owner);

    pthread_mutex_lock(&gWindowListLock);
    WindowNode *node = malloc(sizeof(WindowNode));
    if (node) {
        node->window = w;
        node->owner = owner;
        node->next = gWindowList;
        gWindowList = node;
    }
    pthread_mutex_unlock(&gWindowListLock);
}

void GarbageCollectWindows(void) {
    pthread_mutex_lock(&gWindowListLock);

    WindowNode *prev = NULL;
    WindowNode *curr = gWindowList;

    while (curr) {
        Boolean invalid = _WindowIsValid(curr->window);

        if (invalid) {
            // Log for debugging
            NSLog(@"[gc] removing invalid window: %p", curr->window);

            // Remove node from list
            WindowNode *toFree = curr;
            if (prev) {
                prev->next = curr->next;
            } else {
                gWindowList = curr->next;
            }
            curr = curr->next;
            free(toFree);
        } else {
            prev = curr;
            curr = curr->next;
        }
    }

    pthread_mutex_unlock(&gWindowListLock);
}

void OrderWindow(void *window_ptr, int orderOp) {
    int windowID = *(int *)(window_ptr);
    int relativeWindowID = 0;

    _OrderWindowListSpaceSwitchOptions(
        0LL,                         // connection
        (__int64)&windowID,          // window list
        (__int64)&orderOp,           // order operations
        (__int64)&relativeWindowID,  // relative window ID
        1LL,                         // count
        0LL                          // options
    );
}


void *MarkWindows(__int64 a1, unsigned int a2, const void *a3, int a4) {
    void * w = _WindowCreate(a1, a2, a3, a4);
    GarbageCollectWindows();

    AddWindow(w);

    return w;
}

void *gWindowRoot = NULL;
CAContext *gRootContextPtr = NULL;

void HideAllWindowsTest(void) {
    pthread_mutex_lock(&gWindowListLock);
    WindowNode *curr = gWindowList;
    while (curr) {
        curr = curr->next;
    }
    pthread_mutex_unlock(&gWindowListLock);
}

static void RenderProteinLogToLayer(CALayer *layer) {
    const char *path = "/tmp/protein.log";
    CFStringRef logText = NULL;

    // --- Read file ---
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
                       (const UInt8 *)path, strlen(path), false);
    CFDataRef data = NULL;
    if (url &&
        CFURLCreateDataAndPropertiesFromResource(NULL, url, &data,
                                                 NULL, NULL, NULL) &&
        data)
    {
        logText = CFStringCreateFromExternalRepresentation(
            NULL, data, kCFStringEncodingUTF8);
    }
    if (url) CFRelease(url);
    if (data) CFRelease(data);
    if (!logText) return;

    // --- Create drawing surface same size as layer ---
    CGSize size = layer.bounds.size;
    size_t width  = (size_t)size.width;
    size_t height = (size_t)size.height;

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, width, height, 8, 0,
                                             cs, kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);

    // --- Clear background (white) ---
    CGContextSetRGBFillColor(ctx, 0, 0, 1, 1);
    CGContextFillRect(ctx, CGRectMake(0, 0, width, height));

    // --- Configure text drawing ---
    CGContextSetTextMatrix(ctx, CGAffineTransformMakeScale(1, 1));
    CGContextSelectFont(ctx, "Menlo", 12, kCGEncodingMacRoman);
    //CGContextSetRGBFillColor(ctx, 1, 1, 1, 1);

    // --- Convert CFString to UTF8 buffer ---
    CFIndex len = CFStringGetLength(logText);
    CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    char *buf = malloc(max);
    CFStringGetCString(logText, buf, max, kCFStringEncodingUTF8);
    CFRelease(logText);

    // --- Split into lines from the end so we show newest first ---
    const char *end = buf + strlen(buf);
    const char *p = end;
    CGFloat lineH = 14.0;
    CGFloat y = height - lineH;

    while (p > buf && y >= 0) {
        const char *lineEnd = p;
        while (p > buf && *(p-1) != '\n' && *(p-1) != '\r') p--;
        size_t lineLen = lineEnd - p;

        if (lineLen > 0) {
            // --- Draw black highlight behind text line ---
            CGContextSetRGBFillColor(ctx, 0, 0, 0, 1);  // black background
            CGContextFillRect(ctx, CGRectMake(0, y, width, lineH - 1));

            // --- Draw white text on top ---
            CGContextSetRGBFillColor(ctx, 1, 1, 1, 1);  // white text
            CGContextShowTextAtPoint(ctx, 6, y, p, lineLen);
        }

        y -= lineH;
        while (p > buf && (*(p-1) == '\n' || *(p-1) == '\r')) p--;
    }
    free(buf);

    // --- Commit to layer ---
    CGImageRef img = CGBitmapContextCreateImage(ctx);
    CGContextRelease(ctx);
    layer.contents = (__bridge id)img;
    CGImageRelease(img);
}

void UpdateProteinRoot(void) {
    CGRect _updateRect = CGRectMake(0, 0, 1800, 1169);
    CFTypeRef Region = CGRegionCreateWithRect(_updateRect);
    if (gWindowRoot == NULL) {
        gWindowRoot = _WindowCreate(0LL, 5LL, Region, 6145LL);

        gRootContextPtr = [CAContext localContextWithOptions:@{}];
        _BindLocalClientContext(gWindowRoot, gRootContextPtr, 0);
        _WindowLayerBackingTakeOwnershipOfContext(gWindowRoot, gRootContextPtr);

        __int64 intptr = 0;
        [CATransaction begin];
        [CATransaction setDisableActions:YES];
        __SERVER_COMMIT_START(&intptr, gRootContextPtr);

        CALayer * rootlayer = [CALayer new];
        _updateRect.origin = CGPointZero;
        rootlayer.frame = _updateRect;
        rootlayer.backgroundColor = CGColorCreateSRGB(1, 0, 0, 1);

        gRootContextPtr.layer = rootlayer;
        __SERVER_COMMIT_END(&intptr);
        [CATransaction commit];

        OrderWindow(gWindowRoot, 1);
    } else {
        for (;;) {
            __int64 intptr = 0;
            [CATransaction begin];
            [CATransaction setDisableActions:YES];
            [CATransaction setDisableSignPosts:YES];
            [CATransaction setCommittingContexts:gRootContextPtr];
            __SERVER_COMMIT_START(&intptr, gRootContextPtr);

            gRootContextPtr.layer.backgroundColor = CFAutorelease(CGColorCreateSRGB(0.5, 0, 0, 1.0));
            RenderProteinLogToLayer(gRootContextPtr.layer);

            __SERVER_COMMIT_END(&intptr);
            [CATransaction commit];

            _InvalidateDisplayShape(0LL, (__int64)gWindowRoot, (__int64)Region);
            _ScheduleUpdateAllDisplays(0LL, 0LL);
            OrderWindow(gWindowRoot, 1);
        }
    }
}

__int64 (*_UpdateOld)(__int64 a1, __int64 a2, __int64 a3, __int64 a4);
__int64 UpdateHook(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    HideAllWindowsTest();
    UpdateProteinRoot();
    return _UpdateOld(a1, a2, a3, a4);
}

Boolean (*_NeedsUpdateOrig)(void);
Boolean NeedsUpdateTrue(id self, SEL _cmd) {
    return true;
}

char * LibName;
void _RenderSetup(void) {
    // madman hooks
    void *Target;
    Target = symrez_resolve_once(LibName, "_CGXUpdateDisplay");
    DobbyHook(Target, (void *)UpdateHook, (void **)&_UpdateOld);

    HOOK_INSTANCE_METHOD(NSClassFromString(@"CAWindowServerDisplay"), NSSelectorFromString(@"needsUpdate"), NeedsUpdateTrue, (IMP *)&_NeedsUpdateOrig);
}

Boolean setupAlready = false;
void __BootStrapFuncHook(__int64 a1) {
    if (a1 == 9LL && !setupAlready) { // nine is called when logon.
        freopen("/tmp/protein.log", "a+", stderr);
        setbuf(stderr, NULL);

        _RenderSetup();
        setupAlready = true;
    }
    _StartSubsidiaryServices(a1);
}

__attribute__((constructor))
void _TweakConstructor(void) {
    LibName = "SkyLight";

    // madman symbol res
    _ShapeWindowWithRect = symrez_resolve_once(LibName, "_WSShapeWindowWithRect");

    _WindowIsValid = symrez_resolve_once(LibName, "_WSWindowIsInvalid");

    _WindowGetOwningProcessId = symrez_resolve_once(LibName, "_WSWindowGetOwningPID");

    _OrderWindowListSpaceSwitchOptions = symrez_resolve_once(LibName, "__ZL36CGXOrderWindowListSpaceSwitchOptionsP13CGXConnectionPKjPK10CGSOrderOpS2_jb");

    _BindLocalClientContext = symrez_resolve_once(LibName, "__ZN9CGXWindow28bind_local_ca_client_contextEP9CAContextb");

    _WindowLayerBackingTakeOwnershipOfContext = symrez_resolve_once(LibName, "_WSCALayerBackingTakeOwnershipOfContext");

    _ScheduleUpdateAllDisplays = symrez_resolve_once(LibName, "_CGXScheduleUpdateAllDisplays");

    _InvalidateDisplayShape = symrez_resolve_once(LibName, "_CGXInvalidateDisplayShape");

    _StartSubsidiaryServices = symrez_resolve_once(LibName, "_CGXStartSubsidiaryServices");

    __SERVER_COMMIT_START = symrez_resolve_once(LibName, "__ZN27WSCAContextScopeTransaction18addContextToCommitEP9CAContext");

    __SERVER_COMMIT_END = symrez_resolve_once(LibName, "__ZN27WSCAContextScopeTransactionD1Ev");


    // init hooks
    void *Target = symrez_resolve_once(LibName, "_CGXStartSubsidiaryServices");
    DobbyHook(Target, (void *)__BootStrapFuncHook, (void **)&_StartSubsidiaryServices);

    Target = symrez_resolve_once(LibName, "_WSWindowCreate");
    DobbyHook(Target, (void *)MarkWindows, (void **)&_WindowCreate);
}
