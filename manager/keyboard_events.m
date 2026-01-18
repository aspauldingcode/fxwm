#include <Foundation/Foundation.h>
#include <QuartzCore/QuartzCore.h>
#include <Carbon/Carbon.h>
#include <objc/runtime.h>
#include "keyboard_events.h"
#include "ui.h"

// External globals from libprotein_render.m
extern void *gWindowRoot;
extern PVView *gRootView; // Need to expose this if not already

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

// Function to find focused view recursively
static PVTextField *FindFocusedTextField(PVView *view) {
    if ([view isKindOfClass:[PVTextField class]] && ((PVTextField *)view).isFocused) {
        return (PVTextField *)view;
    }
    
    for (PVView *subview in view.subviews) {
        PVTextField *found = FindFocusedTextField(subview);
        if (found) return found;
    }
    return nil;
}

// Convert keycode to char (very basic)
static char KeyCodeToChar(uint16_t keyCode, int flags) {
    // This is a very simplified mapping for US layout
    // In a real WM, use TIS or UCKeyTranslate
    
    bool shift = (flags & 0x20000) != 0; // Shift key mask (approx) 
    
    if (keyCode >= 0 && keyCode <= 50) {
        // Basic letters and numbers
        // This is incomplete but works for demo
        // A=0, S=1, D=2, F=3, H=4, G=5, Z=6, X=7, C=8, V=9
        // Q=12, W=13, E=14, R=15, Y=16, T=17
        // 1=18 ...
        
        // Let's use a small lookup or just UCKeyTranslate if possible?
        // UCKeyTranslate is complex.
        // Let's rely on event data if available, but we are hooking dispatch.
        // SLSEventRecord usually has the char.
        return 0; // Placeholder, we will use event data
    }
    return 0;
}

// ============================================================================ 
// MARK: - SLSEventRecord Structure (Repeated because headers are separate)
// ============================================================================ 
// We need the full struct to access key data

#pragma pack(push, 1)
typedef struct __attribute__((packed)) SLSEventRecord_KB {
    uint16_t flags;              // +0
    uint16_t reserved1;          // +2
    uint32_t recordSize;         // +4 (always 248)
    uint32_t eventType;          // +8 (CGSEventType)
    uint32_t reserved2;          // +12
    double locationX;            // +16
    double locationY;            // +24
    double windowLocationX;      // +32
    double windowLocationY;      // +40
    uint64_t timestamp;          // +48
    uint32_t eventFlags;         // +56 (Modifiers)
    
    uint8_t padding1[136 - 60];  // +60 to +136
    
    uint16_t translatedLength;   // +136
    uint16_t reserved3;          // +138
    uint32_t reserved4;          // +140
    uint16_t keyCode;            // +144
    uint16_t reserved5;          // +146
    
    uint8_t padding2[168 - 148]; // +148 to +168
    
    uint16_t translatedString[20]; // +168 (UniChars)
    
    uint8_t tail[40];            // +208 to +248 (approx)
} SLSEventRecord_KB;
#pragma pack(pop)


// ============================================================================
// MARK: - Keyboard Event Hook
// ============================================================================

static void (*_KeyboardEventDispatch_Orig)(id self, SEL sel, SLSEventRecord_KB *event, id annotationParams, id dispatcher);

static void KeyboardEventDispatch_Hook(id self, SEL sel, SLSEventRecord_KB *event, id annotationParams, id dispatcher) {
    
    if (event->eventType == 10) { // KeyDown
        uint16_t keyCode = event->keyCode;
        char charCode = 0;
        
        if (event->translatedLength > 0) {
            // Use the first character of the translated string
            uint16_t uni = event->translatedString[0];
            if (uni >= 32 && uni <= 126) {
                charCode = (char)uni;
            }
        }
        
        // Fallback for some control keys if translation didn't catch them or we need them
        if (charCode == 0) {
            if (keyCode == 49) charCode = ' ';
            else if (keyCode == 36) charCode = '\n';
        }

        NSLog(@"[Protein] KeyDown: %d char: %c (len: %d)", keyCode, charCode, event->translatedLength);
        
        if (gRootView) {
            PVTextField *focused = FindFocusedTextField(gRootView);
            if (focused) {
                [focused handleKeyDown:keyCode character:charCode];
                
                // If we handled it, maybe we should stop propagation?
                // But this is just dispatch, original will still route it.
                // To swallow, we'd need to returning early, but return type is void.
            }
        }
    }
    
    _KeyboardEventDispatch_Orig(self, sel, event, annotationParams, dispatcher);
}

void SetupKeyboardEvents(void) {
    HOOK_INSTANCE_METHOD(
        NSClassFromString(@"WSKeyEventProcessor"),
        NSSelectorFromString(@"event_dispatch:annotationParams:dispatcher:"),
        KeyboardEventDispatch_Hook,
        (IMP *)&_KeyboardEventDispatch_Orig
    );
    
    NSLog(@"[Protein] Keyboard event hook installed on WSKeyEventProcessor");
}
