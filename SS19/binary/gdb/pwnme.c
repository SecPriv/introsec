#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAGIC_VALUE 1337

int
main(int argc, char *argv[]) {
	unsigned char correct_hash[20] = {
		0x4a, 0xc9, 0xb0, 0x57, 0xf8, 0x02, 0x12, 0x60, 0x6c, 0xea,
		0xab, 0xf3, 0xc6, 0x50, 0x5d, 0xaf, 0xed, 0x40, 0xa4, 0x50
	};
	char password[20];
	int authenticated = 0;

	strcpy(password, argv[1]);
	SHA1(password, strlen((char *)password), password);
	if(memcmp(password, correct_hash, 20) == 0) {
		authenticated = MAGIC_VALUE;
	}
	printf("Authenticated: %d\n", authenticated);
	if(authenticated == MAGIC_VALUE) {
		printf("CORRECT PASSWORD!\n");
	} else {
		printf("WRONG PASSWORD!\n");
	}
	fflush(stdout);

	return 0;
}
