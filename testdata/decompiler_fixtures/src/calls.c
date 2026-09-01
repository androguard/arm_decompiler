/* Inter-procedural call sites (bl / symbol names). */

int add1(int x);
int absdiff(int a, int b);

int call_add1(int x) { return add1(x); }

int call_absdiff(int a, int b) { return absdiff(a, b) + add1(0); }
