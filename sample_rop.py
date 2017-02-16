#!/usr/bin/env python
#-*- coding:utf-8 -*-
# unicorn/bindings/python/sample_x86.pyを抜粋・改変
# Reference: http://ntddk.github.io/2016/07/09/unicorn-internals-python/

from __future__ import print_function # Python 2.7を利用
from unicorn import *
from unicorn.x86_const import *
from capstone import *  # for disassemble
from z3 import *

# エミュレーション対象の機械語
X86_CODE64 = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x68\x19\x01\x40\x00\x6a\x01\x68\x06\x01\x40\x00\x68\x19\x01\x40\x00\x68\x29\x01\x40\x00\x6a\x3c\x68\x02\x01\x40\x00\x68\x10\x01\x40\x00\x48\xb8\x36\x15\x1b\x25\x67\x1a\x39\x63\x50\x68\x02\x01\x40\x00\x6a\x00\x68\x06\x01\x40\x00\x68\x14\x01\x40\x00\x68\x0c\x01\x40\x00\x68\x02\x01\x40\x00\x68\x26\x01\x40\x00\x68\x14\x01\x40\x00\x6a\x07\x68\x0a\x01\x40\x00\x6a\xe0\x68\x08\x01\x40\x00\x68\x19\x01\x40\x00\x6a\x08\x68\x04\x01\x40\x00\x6a\x00\x68\x1c\x01\x40\x00\x6a\x00\x68\x06\x01\x40\x00\x6a\x00\x68\x02\x01\x40\x00\xc3\x58\xc3\x5a\xc3\x5f\xc3\x5d\xc3\x59\xc3\x48\x01\xec\xc3\x48\x39\x06\xc3\x80\x34\x0e\x55\xc3\x0f\x05\xc3\x48\x89\xe6\x41\x5a\xc3\x48\x89\xf1\xc3\x48\xff\xc9\x75\x01\xc3\x41\x5a\xc3"

ADDRESS = 0x400000  # memory address where emulation starts
# c@Np2Ol6
INPUT_STR = [0x63, 0x40, 0x4e, 0x70, 0x32, 0x4f, 0x6c, 0x36]


# for disassemble
class SimpleEngine:
    def __init__(self):
        self.capmd = Cs(CS_ARCH_X86, CS_MODE_64)    # アーキテクチャ指定

    def disas_single(self, data):
        for i in self.capmd.disasm(data, 16):       # 逆アセンブル
            print("\t%s\t%s" % (i.mnemonic, i.op_str))
            break

disasm = SimpleEngine()


# 各命令に対するコールバック
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = %u," % (address, size), end="")
    # メモリから実行される命令を読む
    ins = uc.mem_read(address, size)
    disasm.disas_single(str(ins))


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
        for i in range(syscall_rdx):
            char = chr(INPUT_STR[i])
            print ("[+]Write address: 0x%x, value: %c" % (read_addr, char))
            uc.mem_write(read_addr, char)
            read_addr += 1
    elif syscall_rax == 0x3c:
        print("Exit status: %d" % syscall_rdi)
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

    except UcError as e:
        print("ERROR: %s" % e)


def set_input(string=[0, 0, 0, 0, 0, 0, 0, 0]):
    for i, x in enumerate(string):
        if i > 7:
            break

        INPUT_STR[i] = x

if __name__ == '__main__':
    xs = [BitVec("x%d" % i, 8) for i in range(8)]
    ans = [0x63, 0x39, 0x1a, 0x67, 0x25, 0x1b, 0x15, 0x36]
    s = Solver()

    for i, x in enumerate(xs):
        s.add(0x20 <= x, x <= 0x7e)
        val = 0x55 ^ x
        s.add(val == ans[len(ans) - 1 - i])

    if s.check() == sat:
        m = s.model()
        input_list = [int(str(m[x])) for x in xs]
        for x in input_list:
            print (x)
        set_input(input_list)
        test_x86_64()
