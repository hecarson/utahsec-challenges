#include <stdio.h>
#include <string.h>

char name[0x40];

void disable_buffers()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    disable_buffers();

    puts("What is your name?");
    fgets(name, 0x40, stdin);

    puts("What starting index for a name substring do you want?");
    int idx;
    scanf("%d", &idx);
    getchar();
    puts("What substring length do you want?");
    unsigned int length;
    scanf("%u", &length);
    getchar();

    char buf1[0x40];
    strncpy(buf1, name + idx, length);
    buf1[length] = 0;
    puts("Here is your substring:");
    puts(buf1);

    puts("What's a fun fact about yourself?");
    char buf2[0x40];
    gets(buf2);

    puts("See you soon!");

    return 0;
}
