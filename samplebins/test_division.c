#include <stdio.h>

void usage() {
    printf("Usage: ./test_divide <number1> <number2>\nPrints out number1 divided by number2\n");
}

int divide(int a, int b) {
    return a/b;
}

int main(int argc, char ** argv) {
    if (argc != 3) {
        usage();
        return 1;
    }

    int a, b, c;

    if (!sscanf(argv[1], "%d", &a) || !sscanf(argv[2], "%d", &b)) {
        usage();
        return 1;
    }
 
    c = divide(a, b);
    printf("%d\n", c);
    return 0;
}
