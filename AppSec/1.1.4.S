.global your_asm_fn
.section .text

your_asm_fn:

push	%ebp
mov	%esp,%ebp
push	$0x00
push	$0x646f6f66
push    $0x6c6f6f63
movl	%esp, %eax
push	$0xc105ed
movl	%esp, %ebx
push	%eax
push	%ebx
push	$0xacce55ed

call	practice

pop	%ebx
pop	%eax
pop	%eax
pop	%eax

leave
ret
