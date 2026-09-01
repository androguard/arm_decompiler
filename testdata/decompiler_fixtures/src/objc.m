#import <Foundation/Foundation.h>

@interface CDSmoke : NSObject
- (int)hello:(int)x;
- (int)sum:(int)a with:(int)b;
@end

@implementation CDSmoke
- (int)hello:(int)x {
    return x + 1;
}
- (int)sum:(int)a with:(int)b {
    return a + b;
}
@end

int cd_smoke_call(CDSmoke *s, int x) {
    return [s hello:x];
}

int cd_smoke_sum(CDSmoke *s, int a, int b) {
    return [s sum:a with:b];
}

typedef int (^CDIntBlock)(int);

int cd_run_block(CDIntBlock b, int x) {
    return b(x);
}

int cd_make_and_run(int x) {
    CDIntBlock b = ^(int n) {
        return n + 1;
    };
    return cd_run_block(b, x);
}
