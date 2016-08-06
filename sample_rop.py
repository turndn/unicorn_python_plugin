#!/usr/bin/env python
#-*- coding:utf-8 -*-
# unicorn/bindings/python/sample_x86.pyを抜粋・改変

from __future__ import print_function # Python 2.7を利用
from unicorn import *
from unicorn.x86_const import *
from capstone import *  # for disassemble
import sys              # for exit


# エミュレーション対象の機械語
X86_CODE64 = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x68\x19\x01\x40\x00\x6a\x01\x68\x06\x01\x40\x00\x68\x19\x01\x40\x00\x68\x29\x01\x40\x00\x6a\x3c\x68\x02\x01\x40\x00\x68\x10\x01\x40\x00\x48\xb8\x36\x15\x1b\x25\x67\x1a\x39\x63\x50\x68\x02\x01\x40\x00\x6a\x00\x68\x06\x01\x40\x00\x68\x14\x01\x40\x00\x68\x0c\x01\x40\x00\x68\x02\x01\x40\x00\x68\x26\x01\x40\x00\x68\x14\x01\x40\x00\x6a\x07\x68\x0a\x01\x40\x00\x6a\xe0\x68\x08\x01\x40\x00\x68\x19\x01\x40\x00\x6a\x08\x68\x04\x01\x40\x00\x6a\x00\x68\x1c\x01\x40\x00\x6a\x00\x68\x06\x01\x40\x00\x6a\x00\x68\x02\x01\x40\x00\xc3\x58\xc3\x5a\xc3\x5f\xc3\x5d\xc3\x59\xc3\x48\x01\xec\xc3\x48\x39\x06\xc3\x80\x34\x0e\x55\xc3\x0f\x05\xc3\x48\x89\xe6\x41\x5a\xc3\x48\x89\xf1\xc3\x48\xff\xc9\x75\x01\xc3\x41\x5a\xc3"

ADDRESS = 0x400000  # memory address where emulation starts
# c@Np2Ol6
INPUT_STR = [0x63, 0x40, 0x4e, 0x70, 0x32, 0x4f, 0x6c, 0x36]
EXIT_STATUS = 1


# for disassemble
class SimpleEngine:
    def __init__(self):
        self.capmd = Cs(CS_ARCH_X86, CS_MODE_64) # アーキテクチャ指定
    def disas_single(self, data):
        for i in self.capmd.disasm(data, 16): # 逆アセンブル
            print("\t%s\t%s" % (i.mnemonic, i.op_str))
            break

disasm = SimpleEngine()


# 各命令に対するコールバック
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u, " %(address, size), end="")
    # メモリから実行される命令を読む
    ins = uc.mem_read(address, size)
    disasm.disas_single(str(ins))

    if ins[0] == 0x90:
        return

    # print stack top value
    rsp_addr = uc.reg_read(UC_X86_REG_RSP)
    try:
        ret_addr = uc.mem_read(rsp_addr, 4)
        print ("[+]rsp value: 0x%02x%02x%02x%02x" % (ret_addr[2], ret_addr[3], ret_addr[1], ret_addr[0]))
        print ("[+]rsp: 0x%x" % rsp_addr)
    except:
        pass

    print ("[+]rbp: 0x%x" % uc.reg_read(UC_X86_REG_RBP))

    if ins[0] == 0x80 and ins[1] == 0x34 and ins[2] == 0xe and ins[3] ==0x55:
        read_addr = uc.reg_read(UC_X86_REG_ESI) + uc.reg_read(UC_X86_REG_ECX)
        char = uc.mem_read(read_addr, 1)
        print ("[+]esi + ecx: 0x%x" % (read_addr))
        print (char)


def hook_syscall(uc, user_data):
    syscall_rax = uc.reg_read(UC_X86_REG_RAX)
    syscall_rdi = uc.reg_read(UC_X86_REG_RDI)
    syscall_rsi = uc.reg_read(UC_X86_REG_RSI)
    syscall_rdx = uc.reg_read(UC_X86_REG_RDX)
    print ("[+]rax: 0x%x" % syscall_rax)
    print ("[+]rdi: 0x%x" % syscall_rdi)
    print ("[+]rsi: 0x%x" % syscall_rsi)
    print ("[+]rdx: 0x%x" % syscall_rdx)
    if syscall_rax == 0x0:
        read_addr = syscall_rsi
        answer_text = INPUT_STR
        for c in answer_text:
            char = chr(c)
            print ("[+]Write address: 0x%x, value: %c" % (read_addr, char))
            uc.mem_write(read_addr, char)
            read_addr += 1
    elif syscall_rax == 0x3c:
        EXIT_STATUS = syscall_rdi
        uc.emu_stop()


# x86 64bitのコードをエミュレーション
def test_x86_64():
    print("Emulate x86_64 code")
    try:
        # x86-64bitモードでエミュレータを初期化
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # エミュレーション用に2MBのメモリを割り当て
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # 割り当てられたメモリに機械語を書き込み
        mu.mem_write(ADDRESS, X86_CODE64)

        # Stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

        # 各命令に対するコールバックを設定
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # 各 System call に対するコールバックを設定
        mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

        # エミュレーション開始
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64))

        # メモリから命令列を読む
        tmp = mu.mem_read(ADDRESS, 2)
        print(">>> Read 2 bytes from [0x%x] =" %(ADDRESS), end="")
        for i in tmp:
            print(" 0x%x" %i, end="")
        print("")

    except UcError as e:
        print("ERROR: %s" % e)


def set_input(string=[0,0,0,0,0,0,0,0]):
    for i, x in enumerate(string):
        if i > 7:
            break

        INPUT_STR[i] = x

if __name__ == '__main__':
    test_x86_64()
