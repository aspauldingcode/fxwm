//
//  ui.m
//

#import "ui.h"

@implementation PVView

@synthesize frame = _frame;
@synthesize superview = _superview;

- (instancetype)init {
    self = [super init];
    if (self) {
        _internalSubviews = [[NSMutableArray alloc] init];
        _backgroundColor = CGColorGetConstantColor(kCGColorWhite);
        if (_backgroundColor) CGColorRetain(_backgroundColor);
    }
    return self;
}

- (void)dealloc {
    [_internalSubviews release];
    if (_backgroundColor) CGColorRelease(_backgroundColor);
    [super dealloc];
}

- (NSArray *)subviews {
    return _internalSubviews;
}

- (void)setBackgroundColor:(CGColorRef)backgroundColor {
    if (_backgroundColor != backgroundColor) {
        if (_backgroundColor) CGColorRelease(_backgroundColor);
        _backgroundColor = backgroundColor;
        if (_backgroundColor) CGColorRetain(_backgroundColor);
    }
}

- (CGColorRef)backgroundColor {
    return _backgroundColor;
}

- (void)addSubview:(PVView *)view {
    if (!view) return;
    if (view.superview) {
        [view removeFromSuperview];
    }
    [_internalSubviews addObject:view];
    view.superview = self;
}

- (void)removeFromSuperview {
    if (_superview) {
        [[_superview internalSubviews] removeObject:self];
        _superview = nil;
    }
}

- (NSMutableArray *)internalSubviews {
    return _internalSubviews;
}

@end

@implementation PVButton

@synthesize isHovering = _isHovering;
@synthesize isDown = _isDown;

- (instancetype)init {
    self = [super init];
    if (self) {
        CGColorRef color = CGColorCreateSRGB(0.0, 0.47, 0.84, 1.0);
        self.backgroundColor = color;
        if (color) CGColorRelease(color);
    }
    return self;
}

- (void)dealloc {
    [_title release];
    if (_onClick) [ (id)_onClick release];
    [super dealloc];
}

- (void)setTitle:(NSString *)title {
    if (_title != title) {
        [_title release];
        _title = [title copy];
    }
}

- (NSString *)title {
    return _title;
}

- (void)setOnClick:(void (^)(void))onClick {
    if (_onClick != onClick) {
        if (_onClick) [ (id)_onClick release];
        _onClick = [onClick copy];
    }
}

- (void (^)(void))onClick {
    return _onClick;
}

@end