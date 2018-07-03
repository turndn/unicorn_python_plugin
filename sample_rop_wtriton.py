#! /usr/env/bin python
# -*- coding: utf-8 -*-

from triton import TritonContext, ARCH, MODE, Instruction, MemoryAccess
from triton import CPUSIZE


function = {
    0x400080: '\x68\x19\x01\x40\x00',   # pushq $0x400119
    0x400085: '\x6a\x01',   # pushq $0x1
    0x400087: '\x68\x06\x01\x40\x00',   # pushq $0x400106
    0x40008c: '\x68\x19\x01\x40\x00',   # pushq $0x400119
    0x400091: '\x68\x29\x01\x40\x00',   # pushq $0x400129
    0x400096: '\x6a\x3c',   # pushq $0x3c
    0x400098: '\x68\x02\x01\x40\x00',   # pushq $0x400102
    0x40009d: '\x68\x10\x01\x40\x00',   # pushq $0x400110
    # movabs $0x63391a67251b1536,%rax
    0x4000a2: '\x48\xb8\x36\x15\x1b\x25\x67\x1a\x39\x63',
    0x4000ac: '\x50',   # push %rax
    0x4000ad: '\x68\x02\x01\x40\x00',   # pushq $0x400102
    0x4000b2: '\x6a\x00',   # pushq $0x0
    0x4000b4: '\x68\x06\x01\x40\x00',   # pushq $0x400106
    0x4000b9: '\x68\x14\x01\x40\x00',   # pushq $0x400114
    0x4000be: '\x68\x0c\x01\x40\x00',   # pushq $0x40010c
    0x4000c3: '\x68\x02\x01\x40\x00',   # pushq $0x400102
    0x4000c8: '\x68\x26\x01\x40\x00',   # pushq $0x400126
    0x4000cd: '\x68\x14\x01\x40\x00',   # pushq $0x400114
    0x4000d2: '\x6a\x07',   # pushq $0x7
    0x4000d4: '\x68\x0a\x01\x40\x00',   # pushq $0x40010a
    0x4000d9: '\x6a\xe0',   # pushq $0xffffffffffffffe0
    # 0x4000d9: '\x90',
    # 0x4000da: '\x90',   # pushq $0xffffffffffffffe0
    0x4000db: '\x68\x08\x01\x40\x00',   # pushq $0x400108
    0x4000e0: '\x68\x19\x01\x40\x00',   # pushq $0x400119
    0x4000e5: '\x6a\x08',   # pushq $0x8
    0x4000e7: '\x68\x04\x01\x40\x00',   # pushq $0x400104
    0x4000ec: '\x6a\x00',   # pushq $0x0
    0x4000ee: '\x68\x1c\x01\x40\x00',   # pushq $0x40011c
    0x4000f3: '\x6a\x00',   # pushq $0x0
    0x4000f5: '\x68\x06\x01\x40\x00',   # pushq $0x400106
    0x4000fa: '\x6a\x00',   # pushq $0x0
    0x4000fc: '\x68\x02\x01\x40\x00',   # pushq $0x400102
    0x400101: '\xc3',   # retq
    0x400102: '\x58',   # pop %rax
    0x400103: '\xc3',   # retq
    0x400104: '\x5a',   # pop %rdx
    0x400105: '\xc3',   # retq
    0x400106: '\x5f',   # pop %rdi
    0x400107: '\xc3',   # retq
    0x400108: '\x5d',   # pop %rbp
    # 0x400108: '\x90',   # pop %rbp
    0x400109: '\xc3',   # retq
    0x40010a: '\x59',   # pop %rcx
    0x40010b: '\xc3',   # retq
    0x40010c: '\x48\x01\xec',   # add %rbp,%rsp
    0x40010f: '\xc3',   # retq
    0x400110: '\x48\x39\x06',   # cmp %rax,(%rsi)
    0x400113: '\xc3',   # retq
    0x400114: '\x80\x34\x0e\x55',   # xorb $0x55,(%rsi,%rcx,1)
    0x400118: '\xc3',   # retq
    0x400119: '\x0f\x05',   # syscall
    0x40011b: '\xc3',   # retq
    0x40011c: '\x48\x89\xe6',   # mov %rsp,%rsi
    0x40011f: '\x41\x5a',   # pop %r10
    0x400121: '\xc3',   # retq
    0x400122: '\x48\x89\xf1',   # mov %rsi,%rcx
    0x400125: '\xc3',   # retq
    0x400126: '\x48\xff\xc9',   # dec %rcx
    0x400129: '\x75\x01',   # jne 0x40012c
    0x40012b: '\xc3',   # retq
    0x40012c: '\x41\x5a',   # pop %r10
    0x40012e: '\xc3',   # retq
}


def before_processing(inst, triton):
    if inst.getAddress() == 0x400110:
        rsp = triton.getRegisterAst(triton.registers.rsp).evaluate()

        astCtxt = triton.getAstContext()
        rax = triton.getRegisterAst(triton.registers.rax).evaluate()
        rsi = triton.getRegisterAst(triton.registers.rsi).evaluate()
        print("rax: %16x rsi: %16x" % (rax, rsi))

        rax_sym = triton.getSymbolicRegister(triton.registers.rax)
        raxs = [astCtxt.extract((i + 1) * 8 - 1, i * 8,
                                rax_sym.getAst()) for i in range(8)]
        local_val = triton.getSymbolicMemory()
        values = [local_val[rsi + i] for i in range(8)]
        ast_local_val = [value.getAst() for value in values]
        conditions = [ast_local_val[i] == raxs[i] for i in range(8)]
        c = astCtxt.land(conditions)
        model = triton.getModel(c)
        for k, v in model.items():
            value = v.getValue()
            triton.setConcreteSymbolicVariableValue(
                triton.getSymbolicVariableFromId(k), value)
            print('[+] Symbolic variable %02d = %02x' % (k, value))

        var = triton.convertRegisterToSymbolicVariable(triton.registers.rsp)
        triton.setConcreteSymbolicVariableValue(var, rsp)


def after_processing(inst, triton):
    if inst.getAddress() == 0x400119:
        rax = triton.getRegisterAst(triton.registers.rax).evaluate()
        rdi = triton.getRegisterAst(triton.registers.rdi).evaluate()
        rsi = triton.getRegisterAst(triton.registers.rsi).evaluate()
        rdx = triton.getRegisterAst(triton.registers.rdx).evaluate()
        print("rax: %16x rdi: %16x" % (rax, rdi))
        print("rsi: %16x rdx: %16x" % (rsi, rdx))
        triton.setConcreteRegisterValue(triton.registers.rax, 0x0)
        triton.convertMemoryToSymbolicVariable(MemoryAccess(rsi, rdx * 8))
    elif inst.getAddress() == 0x4000d9:
        rsp = triton.getRegisterAst(triton.registers.rsp).evaluate()
        print('rsp: %16x' % rsp)
        val = triton.getConcreteMemoryValue(MemoryAccess(rsp, CPUSIZE.QWORD))
        print('value: %16x' % (val))

        triton.concretizeMemory(MemoryAccess(rsp, CPUSIZE.QWORD))
        for i in range(8):
            triton.setConcreteMemoryValue(rsp + i, 0xff)
        triton.setConcreteMemoryValue(rsp, 0xe0)

        rsp = triton.getRegisterAst(triton.registers.rsp).evaluate()
        print('rsp: %16x' % rsp)
        val = triton.getConcreteMemoryValue(MemoryAccess(rsp, CPUSIZE.QWORD))
        print('value: %16x' % (val))
    elif inst.getAddress() == 0x400114:
        rsi = triton.getRegisterAst(triton.registers.rsi).evaluate()
        rcx = triton.getRegisterAst(triton.registers.rcx).evaluate()
        print("rcx: %16x rsi: %16x" % (rcx, rsi))
    elif inst.getAddress() == 0x400108:
        rbp = triton.getRegisterAst(triton.registers.rbp).evaluate()
        print("rbp: %16x" % (rbp))
    elif inst.getAddress() == 0x400102:
        rsp = triton.getRegisterAst(triton.registers.rsp).evaluate()
        print('rsp: %16x' % rsp)
        for i in range(8):
            val = triton.getConcreteMemoryValue(
                MemoryAccess(rsp + i * CPUSIZE.QWORD, CPUSIZE.QWORD))
            print('value: %16x' % (val))


if __name__ == '__main__':
    triton = TritonContext()
    triton.setArchitecture(ARCH.X86_64)
    triton.enableMode(MODE.ALIGNED_MEMORY, True)

    pc = 0x400080

    triton.setConcreteRegisterValue(triton.registers.rsp, 0x7fffffff)

    while pc in function:
        inst = Instruction()
        inst.setOpcode(function[pc])
        inst.setAddress(pc)

        before_processing(inst, triton)

        triton.processing(inst)
        print(inst)

        after_processing(inst, triton)

        pc = triton.getRegisterAst(triton.registers.rip).evaluate()

    print("pc: %16x" % (pc))
