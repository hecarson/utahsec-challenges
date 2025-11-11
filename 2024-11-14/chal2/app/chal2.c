#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void disable_buffers()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

#define NUM_DIGITS 105

unsigned long long pi_digits[] = {
    3, 1, 4, 1, 5, 9, 2, 6, 5, 3,
    5, 8, 9, 7, 9, 3, 2, 3, 8, 4,
    6, 2, 6, 4, 3, 3, 8, 3, 2, 7,
    9, 5, 0, 2, 8, 8, 4, 1, 9, 7,
    1, 6, 9, 3, 9, 9, 3, 7, 5, 1,
    0, 5, 8, 2, 0, 9, 7, 4, 9, 4,
    4, 5, 9, 2, 3, 0, 7, 8, 1, 6,
    4, 0, 6, 2, 8, 6, 2, 0, 8, 9,
    9, 8, 6, 2, 8, 0, 3, 4, 8, 2,
    5, 3, 4, 2, 1, 1, 7, 0, 6, 7,
    9, 8, 2, 1, 4
};

int main()
{
    disable_buffers();

    char buf1[0x10];
    char buf2[0x8];

    while (1) {
        puts("Which digit of pi do you want? (input \"exit\" to exit)");
        fgets(buf1, 0x10, stdin);

        if (strcmp(buf1, "exit\n") == 0) {
            puts("See you soon!");
            return 0;
        }

        int idx = atoi(buf1);

        if (idx < NUM_DIGITS) {
            printf("%llu\n", pi_digits[idx]);
        }
        else {
            puts("Woah that's high, I don't know that many digits. :(");
            puts("Please tell me what it is:");
            gets(buf2);
        }
    }
}
