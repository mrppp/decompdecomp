extern int helper(int);
int table[4];
int add_scaled(int a, int b) { return helper(a) * 3 + table[b & 3]; }
static int square(int x) { return x * x; }
int sum_squares(int n) { int i, s = 0; for (i = 0; i < n; i++) s += square(i); return s; }
