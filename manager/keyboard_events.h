//
//  keyboard_events.h
//  Protein Window Manager
//

#ifndef keyboard_events_h
#define keyboard_events_h

#ifdef __cplusplus
extern "C" {
#endif

// Initialize keyboard event hooking
void SetupKeyboardEvents(void);

// Helper to handle keyboard events
void HandleKeyboardEvent(uint16_t keyCode, bool isDown, bool isRepeat, int flags);

#ifdef __cplusplus
}
#endif

#endif /* keyboard_events_h */
