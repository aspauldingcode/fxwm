//
//  metal_renderer.m
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <Metal/Metal.h>
#import <CoreGraphics/CoreGraphics.h>
#include <math.h>

#import "metal_renderer.h"

// Uniforms for rendering
typedef struct {
    float scale[2];     // Scale factor for NDC mapping
    float offset[2];    // Position offset in NDC
    float color[4];     // RGBA color
} Uniforms;

// Metal rendering objects
static id<MTLDevice> gMetalDevice = nil;
static id<MTLCommandQueue> gMetalCommandQueue = nil;
static id<MTLRenderPipelineState> gMetalPipeline = nil;
static id<MTLBuffer> gMetalVertexBuffer = nil;
static CAMetalLayer *gMetalSublayer = nil;

void MetalRendererInit(void) {
    if (gMetalDevice) return;

    gMetalDevice = MTLCopyAllDevices()[0];
    if (!gMetalDevice) {
        NSLog(@"Failed to create Metal device");
        return;
    }

    gMetalCommandQueue = [gMetalDevice newCommandQueue];
    if (!gMetalCommandQueue) {
        NSLog(@"Failed to create Metal command queue");
        return;
    }

    // 2D Shader
    NSString *shaderSource = @"using namespace metal;\n"
        "struct VertexIn {\n"
        "    float2 position [[attribute(0)]];\n"
        "};\n"
        "struct VertexOut {\n"
        "    float4 position [[position]];\n"
        "    float4 color;\n"
        "};\n"
        "struct Uniforms {\n"
        "    float2 scale;\n"
        "    float2 offset;\n"
        "    float4 color;\n"
        "};\n"
        "vertex VertexOut vertex_main(VertexIn in [[stage_in]],\n"
        "                             constant Uniforms &uniforms [[buffer(1)]]) {\n"
        "    VertexOut out;\n"
        "    out.position = float4(in.position * uniforms.scale + uniforms.offset, 0.0, 1.0);\n"
        "    out.color = uniforms.color;\n"
        "    return out;\n"
        "}\n"
        "fragment float4 fragment_main(VertexOut in [[stage_in]]) {\n"
        "    return in.color;\n"
        "}";

    NSError *error = nil;
    id<MTLLibrary> library = [gMetalDevice newLibraryWithSource:shaderSource options:nil error:&error];
    if (error) {
        NSLog(@"Failed to create Metal library: %@", error);
        return;
    }

    id<MTLFunction> vertexFunction = [library newFunctionWithName:@"vertex_main"];
    id<MTLFunction> fragmentFunction = [library newFunctionWithName:@"fragment_main"];

    // Quad vertices (-1 to 1)
    float vertices[] = {
        -1.0f, -1.0f, // BL
         1.0f, -1.0f, // BR
        -1.0f,  1.0f, // TL
         1.0f, -1.0f, // BR
         1.0f,  1.0f, // TR
        -1.0f,  1.0f, // TL
    };

    gMetalVertexBuffer = [gMetalDevice newBufferWithBytes:vertices
                                                   length:sizeof(vertices)
                                                  options:MTLResourceStorageModeShared];

    MTLVertexDescriptor *vertexDescriptor = [[MTLVertexDescriptor alloc] init];
    vertexDescriptor.attributes[0].format = MTLVertexFormatFloat2;
    vertexDescriptor.attributes[0].offset = 0;
    vertexDescriptor.attributes[0].bufferIndex = 0;
    vertexDescriptor.layouts[0].stride = 2 * sizeof(float);
    vertexDescriptor.layouts[0].stepFunction = MTLVertexStepFunctionPerVertex;

    MTLRenderPipelineDescriptor *pipelineDescriptor = [[MTLRenderPipelineDescriptor alloc] init];
    pipelineDescriptor.vertexFunction = vertexFunction;
    pipelineDescriptor.fragmentFunction = fragmentFunction;
    pipelineDescriptor.vertexDescriptor = vertexDescriptor;
    pipelineDescriptor.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    pipelineDescriptor.colorAttachments[0].blendingEnabled = YES;
    pipelineDescriptor.colorAttachments[0].rgbBlendOperation = MTLBlendOperationAdd;
    pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = MTLBlendFactorSourceAlpha;
    pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = MTLBlendFactorOneMinusSourceAlpha;

    gMetalPipeline = [gMetalDevice newRenderPipelineStateWithDescriptor:pipelineDescriptor error:&error];
    if (error) {
        NSLog(@"Failed to create Metal pipeline: %@", error);
        return;
    }

    NSLog(@"Metal Renderer initialized");
}

void DrawViewRecursively(PVView *view, id<MTLRenderCommandEncoder> renderEncoder, CGSize screenSize, CGPoint parentOrigin) {
    if (screenSize.width <= 0 || screenSize.height <= 0) return;

    // Calculate Absolute Frame
    CGRect frame = view.frame;
    frame.origin.x += parentOrigin.x;
    frame.origin.y += parentOrigin.y;
    
    // Scale for NDC
    float scaleX = frame.size.width / screenSize.width;
    float scaleY = frame.size.height / screenSize.height;
    
    // Offset for NDC (Top-Left origin assumption for UI)
    float centerX = frame.origin.x + frame.size.width / 2.0;
    float centerY = frame.origin.y + frame.size.height / 2.0;
    
    float ndcX = (centerX / screenSize.width) * 2.0 - 1.0;
    float ndcY = 1.0 - (centerY / screenSize.height) * 2.0;
    
    Uniforms uniforms;
    uniforms.scale[0] = scaleX;
    uniforms.scale[1] = scaleY;
    uniforms.offset[0] = ndcX;
    uniforms.offset[1] = ndcY;
    
    // Color
    const CGFloat *components = CGColorGetComponents(view.backgroundColor);
    size_t numComponents = CGColorGetNumberOfComponents(view.backgroundColor);
    
    float r = 1, g = 1, b = 1, a = 1;
    if (numComponents >= 3) {
        r = components[0]; g = components[1]; b = components[2];
        if (numComponents >= 4) a = components[3];
    } else if (numComponents >= 1) {
        r = g = b = components[0];
        if (numComponents >= 2) a = components[1];
    }
    
    if ([view isKindOfClass:[PVButton class]]) {
        PVButton *btn = (PVButton *)view;
        if (btn.isDown) {
            r *= 0.6; g *= 0.6; b *= 0.6;
        } else if (btn.isHovering) {
            r *= 1.2; g *= 1.2; b *= 1.2;
        }
        r = fminf(r, 1.0); g = fminf(g, 1.0); b = fminf(b, 1.0);
    }
    
    uniforms.color[0] = r;
    uniforms.color[1] = g;
    uniforms.color[2] = b;
    uniforms.color[3] = a;
    
    [renderEncoder setVertexBytes:&uniforms length:sizeof(Uniforms) atIndex:1];
    [renderEncoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:6];
    
    // Recurse
    for (PVView *subview in view.subviews) {
        DrawViewRecursively(subview, renderEncoder, screenSize, frame.origin); 
        // No, view.subviews are relative to view.
        // So passed parentOrigin should be THIS view's absolute origin.
        // Wait, 'frame.origin' is the absolute origin of this view.
        // So yes, pass frame.origin.
    }
}

void MetalRendererRender(PVView *rootView, CALayer *layer) {
    if (!rootView) return;
    MetalRendererInit();
    
    CGSize size = layer.bounds.size;
    if (size.width <= 0 || size.height <= 0) return;
    
    if (!gMetalSublayer) {
        gMetalSublayer = [[CAMetalLayer alloc] init];
        gMetalSublayer.device = gMetalDevice;
        gMetalSublayer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        gMetalSublayer.frame = layer.bounds;
        gMetalSublayer.drawableSize = CGSizeMake(size.width, size.height);
        gMetalSublayer.opaque = NO;
        gMetalSublayer.backgroundColor = CGColorGetConstantColor(kCGColorClear);
        [layer addSublayer:gMetalSublayer];
    }
    
    if (!CGRectEqualToRect(gMetalSublayer.frame, layer.bounds)) {
        gMetalSublayer.frame = layer.bounds;
        gMetalSublayer.drawableSize = CGSizeMake(size.width, size.height);
    }
    
    @autoreleasepool {
        id<CAMetalDrawable> drawable = [gMetalSublayer nextDrawable];
        if (!drawable) return;
        
        id<MTLCommandBuffer> commandBuffer = [gMetalCommandQueue commandBuffer];
        MTLRenderPassDescriptor *passDescriptor = [[MTLRenderPassDescriptor alloc] init];
        passDescriptor.colorAttachments[0].texture = drawable.texture;
        passDescriptor.colorAttachments[0].loadAction = MTLLoadActionClear;
        passDescriptor.colorAttachments[0].storeAction = MTLStoreActionStore;
        passDescriptor.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 0);
        
        id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:passDescriptor];
        [encoder setViewport:(MTLViewport){0, 0, size.width, size.height, 0, 1}];
        [encoder setRenderPipelineState:gMetalPipeline];
        [encoder setVertexBuffer:gMetalVertexBuffer offset:0 atIndex:0];
        
        DrawViewRecursively(rootView, encoder, size, CGPointZero);
        
        [encoder endEncoding];
        [commandBuffer presentDrawable:drawable];
        [commandBuffer commit];
    }
}

void HandleMouseRecursively(PVView *view, CGPoint mousePos, CGPoint parentOrigin, bool isDown) {
    CGRect absFrame = view.frame;
    absFrame.origin.x += parentOrigin.x;
    absFrame.origin.y += parentOrigin.y;
    
    bool isInside = CGRectContainsPoint(absFrame, mousePos);
    
    if ([view isKindOfClass:[PVButton class]]) {
        PVButton *btn = (PVButton *)view;
        btn.isHovering = isInside;
        btn.isDown = isDown && isInside;
    }
    
    for (PVView *subview in view.subviews) {
        HandleMouseRecursively(subview, mousePos, absFrame.origin, isDown);
    }
}

void MetalRendererHandleMouse(PVView *rootView, CGPoint position, bool isDown) {
    if (!rootView) return;
    HandleMouseRecursively(rootView, position, CGPointZero, isDown);
}