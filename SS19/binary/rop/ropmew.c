#include <stdio.h>
#include <stdlib.h>

int guard = 0xdeadbeef;

void
readstuff(void) {
	char data[20];
    gets(data);
}

int
main(void) {
    readstuff();

    if(guard == 0xb000000f) {
	    printf("Win \\o/\n");
    } else {
        printf("N00b :(\n");
    }

    return 0;
}
