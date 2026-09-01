/* Switch / case cascades (M3 jump-table / cmp chains). */

int switch_small(int x) {
    switch (x) {
    case 0:
        return 10;
    case 1:
        return 20;
    case 2:
        return 30;
    default:
        return -1;
    }
}

int switch_sparse(int x) {
    switch (x) {
    case 1:
        return 11;
    case 10:
        return 22;
    case 100:
        return 33;
    default:
        return 0;
    }
}
