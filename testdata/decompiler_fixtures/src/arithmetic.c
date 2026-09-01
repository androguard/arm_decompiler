/* Arithmetic + M1 baselines. Compiled -O0 arm64 into decompiler_fixtures. */

int add1(int x) { return x + 1; }

int absdiff(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}

int mul_add(int a, int b, int c) { return a * b + c; }

int main(void) { return absdiff(3, 1) + add1(0) + mul_add(2, 3, 1); }
