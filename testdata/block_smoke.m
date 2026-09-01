#import <Foundation/Foundation.h>
typedef int (^IntBlock)(int);
int run_block(IntBlock b, int x) { return b(x); }
int make_and_run(int x) {
  IntBlock b = ^(int n){ return n + 1; };
  return run_block(b, x);
}
