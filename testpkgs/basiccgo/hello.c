#include <stdio.h>

void hello() {
    // output /etc/passwd file
    FILE *f = fopen("/etc/passwd", "r");
    char c;
    while ((c = fgetc(f)) != EOF) {
        printf("%c", c);
    }
}
