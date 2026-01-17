//
//  metal_renderer.h
//

#ifndef metal_renderer_h
#define metal_renderer_h

#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>

void MetalRendererInit(void);
void MetalRendererDrawToLayer(CALayer *layer);

// Mouse interaction - updates cube rotation based on mouse
void MetalRendererSetMousePosition(CGPoint position);
void MetalRendererSetMouseDown(bool isDown);

#endif /* metal_renderer_h */
