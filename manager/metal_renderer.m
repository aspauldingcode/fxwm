//
//  metal_renderer.m
//

#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <Metal/Metal.h>
#import <CoreGraphics/CoreGraphics.h>
#include <math.h>

#import "metal_renderer.h"

// Simple vertex structure
typedef struct {
    float position[2]; // 2D position
    float color[4];    // RGBA color
} Vertex;

// Uniforms for rendering
typedef struct {
    float scale[2];     // Scale factor for aspect ratio correction
    float offset[2];    // Position offset
    float colorMod[4];  // Color modifier (for hover/click)
} Uniforms;

// Metal rendering objects
static id<MTLDevice> gMetalDevice = nil;
static id<MTLCommandQueue> gMetalCommandQueue = nil;
static id<MTLRenderPipelineState> gMetalPipeline = nil;
static id<MTLBuffer> gMetalVertexBuffer = nil;
static id<MTLBuffer> gMetalUniformBuffer = nil;
static CAMetalLayer *gMetalSublayer = nil;

// Mouse interaction state
static CGPoint gMousePosition = {0, 0};
static bool gMouseIsDown = false;
static bool gIsHovering = false;

// Button properties
static const CGSize kButtonSize = {200.0f, 60.0f};

void MetalRendererSetMousePosition(CGPoint position) {
    gMousePosition = position;
}

void MetalRendererSetMouseDown(bool isDown) {
    gMouseIsDown = isDown;
}

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
        "    float4 color [[attribute(1)]];\n"
        "};\n"
        "struct VertexOut {\n"
        "    float4 position [[position]];\n"
        "    float4 color;\n"
        "};\n"
        "struct Uniforms {\n"
        "    float2 scale;\n"
        "    float2 offset;\n"
        "    float4 colorMod;\n"
        "};\n"
        "vertex VertexOut vertex_main(VertexIn in [[stage_in]],\n"
        "                             constant Uniforms &uniforms [[buffer(1)]]) {\n"
        "    VertexOut out;\n"
        "    out.position = float4(in.position * uniforms.scale + uniforms.offset, 0.0, 1.0);\n"
        "    out.color = in.color * uniforms.colorMod;\n"
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

    // Define a simple quad (2 triangles) centered at 0,0 with size 2x2 (-1 to 1)
    // We will scale it down in the vertex shader
    Vertex vertices[] = {
        // Triangle 1
        {{-1.0f, -1.0f}, {0.2f, 0.6f, 1.0f, 1.0f}}, // Bottom-Left
        {{ 1.0f, -1.0f}, {0.2f, 0.6f, 1.0f, 1.0f}}, // Bottom-Right
        {{-1.0f,  1.0f}, {0.4f, 0.8f, 1.0f, 1.0f}}, // Top-Left
        // Triangle 2
        {{ 1.0f, -1.0f}, {0.2f, 0.6f, 1.0f, 1.0f}}, // Bottom-Right
        {{ 1.0f,  1.0f}, {0.4f, 0.8f, 1.0f, 1.0f}}, // Top-Right
        {{-1.0f,  1.0f}, {0.4f, 0.8f, 1.0f, 1.0f}}, // Top-Left
    };

    gMetalVertexBuffer = [gMetalDevice newBufferWithBytes:vertices
                                                   length:sizeof(vertices)
                                                  options:MTLResourceStorageModeShared];

    gMetalUniformBuffer = [gMetalDevice newBufferWithLength:sizeof(Uniforms)
                                                    options:MTLResourceStorageModeShared];

    // Vertex descriptor
    MTLVertexDescriptor *vertexDescriptor = [[MTLVertexDescriptor alloc] init];
    vertexDescriptor.attributes[0].format = MTLVertexFormatFloat2;
    vertexDescriptor.attributes[0].offset = offsetof(Vertex, position);
    vertexDescriptor.attributes[0].bufferIndex = 0;
    vertexDescriptor.attributes[1].format = MTLVertexFormatFloat4;
    vertexDescriptor.attributes[1].offset = offsetof(Vertex, color);
    vertexDescriptor.attributes[1].bufferIndex = 0;
    vertexDescriptor.layouts[0].stride = sizeof(Vertex);
    vertexDescriptor.layouts[0].stepFunction = MTLVertexStepFunctionPerVertex;

    // Create render pipeline
    MTLRenderPipelineDescriptor *pipelineDescriptor = [[MTLRenderPipelineDescriptor alloc] init];
    pipelineDescriptor.vertexFunction = vertexFunction;
    pipelineDescriptor.fragmentFunction = fragmentFunction;
    pipelineDescriptor.vertexDescriptor = vertexDescriptor;
    pipelineDescriptor.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    // Blending for rounded corners/transparency if we wanted (keeping it simple for now)
    pipelineDescriptor.colorAttachments[0].blendingEnabled = YES;
    pipelineDescriptor.colorAttachments[0].rgbBlendOperation = MTLBlendOperationAdd;
    pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = MTLBlendFactorSourceAlpha;
    pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = MTLBlendFactorOneMinusSourceAlpha;

    gMetalPipeline = [gMetalDevice newRenderPipelineStateWithDescriptor:pipelineDescriptor error:&error];
    if (error) {
        NSLog(@"Failed to create Metal pipeline: %@", error);
        return;
    }

    NSLog(@"Metal 2D Button Renderer initialized");
}

void MetalRendererDrawToLayer(CALayer *layer) {
    MetalRendererInit();

    CGSize size = layer.bounds.size;
    if (size.width <= 0 || size.height <= 0) return;

    // Create Metal sublayer if it doesn't exist
    if (!gMetalSublayer) {
        gMetalSublayer = [[CAMetalLayer alloc] init];
        gMetalSublayer.device = gMetalDevice;
        gMetalSublayer.pixelFormat = MTLPixelFormatBGRA8Unorm;
        gMetalSublayer.frame = layer.bounds;
        gMetalSublayer.drawableSize = CGSizeMake(size.width, size.height);
        gMetalSublayer.opaque = NO; // Allow transparency behind button
        gMetalSublayer.backgroundColor = CGColorGetConstantColor(kCGColorClear);

        [layer addSublayer:gMetalSublayer];
    }

    // Update frame if needed
    if (!CGRectEqualToRect(gMetalSublayer.frame, layer.bounds)) {
        gMetalSublayer.frame = layer.bounds;
        gMetalSublayer.drawableSize = CGSizeMake(size.width, size.height);
    }

    @autoreleasepool {
        // Create drawable
        id<CAMetalDrawable> drawable = [gMetalSublayer nextDrawable];
        if (!drawable) {
            NSLog(@"Failed to create Metal drawable");
            return;
        }

        // Logic to check if mouse is over the button
        // Button is centered.
        CGRect buttonRect = CGRectMake((size.width - kButtonSize.width) / 2.0,
                                     (size.height - kButtonSize.height) / 2.0,
                                     kButtonSize.width,
                                     kButtonSize.height);

        // Check hit test (simple AABB)
        gIsHovering = CGRectContainsPoint(buttonRect, gMousePosition);

        // Update Uniforms
        Uniforms *uniforms = (Uniforms *)[gMetalUniformBuffer contents];
        
        // Scale: Convert pixels to NDC size
        // Button size in pixels -> NDC (-1 to 1)
        // NDC width = buttonWidth / screenWidth * 2
        uniforms->scale[0] = (kButtonSize.width / size.width);
        uniforms->scale[1] = (kButtonSize.height / size.height);
        
        // Offset: 0,0 is center
        uniforms->offset[0] = 0.0f;
        uniforms->offset[1] = 0.0f;

        // Color interaction
        if (gIsHovering) {
            if (gMouseIsDown) {
                // Clicked: Darker
                uniforms->colorMod[0] = 0.6f;
                uniforms->colorMod[1] = 0.6f;
                uniforms->colorMod[2] = 0.6f;
                uniforms->colorMod[3] = 1.0f;
            } else {
                // Hover: Brighter
                uniforms->colorMod[0] = 1.2f;
                uniforms->colorMod[1] = 1.2f;
                uniforms->colorMod[2] = 1.2f;
                uniforms->colorMod[3] = 1.0f;
            }
        } else {
            // Normal
            uniforms->colorMod[0] = 1.0f;
            uniforms->colorMod[1] = 1.0f;
            uniforms->colorMod[2] = 1.0f;
            uniforms->colorMod[3] = 1.0f;
        }

        // Create command buffer
        id<MTLCommandBuffer> commandBuffer = [gMetalCommandQueue commandBuffer];

        // Create render pass descriptor
        MTLRenderPassDescriptor *renderPassDescriptor = [[MTLRenderPassDescriptor alloc] init];
        renderPassDescriptor.colorAttachments[0].texture = drawable.texture;
        renderPassDescriptor.colorAttachments[0].loadAction = MTLLoadActionClear;
        renderPassDescriptor.colorAttachments[0].storeAction = MTLStoreActionStore;
        // Transparent background clear color
        renderPassDescriptor.colorAttachments[0].clearColor = MTLClearColorMake(0.0, 0.0, 0.0, 0.0);

        // Begin encoding
        id<MTLRenderCommandEncoder> renderEncoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPassDescriptor];
        [renderEncoder setViewport:(MTLViewport){0.0, 0.0, size.width, size.height, 0.0, 1.0}];
        [renderEncoder setRenderPipelineState:gMetalPipeline];

        [renderEncoder setVertexBuffer:gMetalVertexBuffer offset:0 atIndex:0];
        [renderEncoder setVertexBuffer:gMetalUniformBuffer offset:0 atIndex:1];

        [renderEncoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:6];
        [renderEncoder endEncoding];

        // Present and commit
        [commandBuffer presentDrawable:drawable];
        [commandBuffer commit];
    }
}
