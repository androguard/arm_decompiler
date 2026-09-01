int add1(int x) { return x + 1; }
int absdiff(int a, int b) {
  if (a > b) return a - b;
  return b - a;
}
int main(void) { return absdiff(3, 1) + add1(0); }
