.global _start
_start:
	pushq $0x400119
	pushq $0x1
	pushq $0x400106
	pushq $0x400119
	pushq $0x400129
	pushq $0x3c
	pushq $0x400102
	pushq $0x400110
	movabs $0x63391a67251b1536, %rax
	pushq %rax
	pushq $0x400102
	pushq $0x0
	pushq $0x400106
	pushq $0x400114
	pushq $0x40010c
	pushq $0x400102
	pushq $0x400126
	pushq $0x400114
	pushq $0x7
	pushq $0x40010a
	pushq $0xffffffffffffffe0
	pushq $0x400108
	pushq $0x400119
	pushq $0x8
	pushq $0x400104
	pushq $0x0
	pushq $0x40011c
	pushq $0x0
	pushq $0x400106
	pushq $0x0
	pushq $0x400102
	retq
	pop %rax
	retq
	pop %rdx
	retq
	pop %rdi
	retq
	pop %rbp
	retq
	pop %rcx
	retq
	add %rsp, %rbp
	retq
	cmp %rax, (%rsi)
	retq
	xorb $0x55, (%rsi,%rcx,1)
	retq
	syscall
	retq
	mov %rsi, %rsp
	pop %r10
	retq
	mov %rcx, %rsi
	retq
	dec %rcx
	jne label
	retq

label:
	pop %r10
	retq
