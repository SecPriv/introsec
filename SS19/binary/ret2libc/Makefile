CFLAGS=-ansi -m32 -fno-stack-protector -no-pie -O0 -Wno-deprecated-declarations
LIBS=-lcrypto

ropme: ropme.c
	gcc $(CFLAGS) ropme.c -o ropme $(LIBS)
