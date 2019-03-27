#include <stdio.h>
#include <stdlib.h>

char binsh[] = "/bin/sh";

void
echo(void) {
	char data[20];

    gets(data);
	printf("%s\n", data);
}

int
main(void) {
    echo();

	return 0;
}
