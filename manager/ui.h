//
//  ui.h
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

@interface PVView : NSObject {
    NSMutableArray *_internalSubviews;
    CGColorRef _backgroundColor;
    PVView *_superview;
}

@property (nonatomic, assign) CGRect frame;
@property (nonatomic, assign) CGColorRef backgroundColor;
@property (nonatomic, readonly) NSArray *subviews;
@property (nonatomic, assign) PVView *superview;

- (void)addSubview:(PVView *)view;
- (void)removeFromSuperview;
@end

@interface PVButton : PVView {
    NSString *_title;
    void (^_onClick)(void);
}

@property (nonatomic, copy) NSString *title;
@property (nonatomic, assign) BOOL isHovering;
@property (nonatomic, assign) BOOL isDown;
@property (nonatomic, copy) void (^onClick)(void);
@end