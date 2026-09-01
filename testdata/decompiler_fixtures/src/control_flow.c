/* Control-flow shapes for region recovery (M3). */

int if_else(int x) {
    if (x > 0) {
        return 1;
    } else {
        return -1;
    }
}

int if_else_chain(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else {
        return 1;
    }
}

int nested_if(int a, int b, int c) {
    if (a) {
        if (b && c) {
            return 1;
        }
    }
    return 0;
}

int while_sum(int n) {
    int i = 0;
    int sum = 0;
    while (i < n) {
        sum += i;
        i++;
    }
    return sum;
}

int do_while_count(int n) {
    int i = 0;
    do {
        i++;
    } while (i < n);
    return i;
}

int for_sum(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

int break_in_loop(int limit) {
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        if (i >= limit) {
            break;
        }
        sum += i;
    }
    return sum;
}

int continue_in_loop(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if ((i & 1) == 0) {
            continue;
        }
        sum += i;
    }
    return sum;
}
