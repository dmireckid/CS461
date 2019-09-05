.global _main
.section .text

_main:

push	%ebp
mov	%esp,%ebp

mov	$0x0b, %eax

push	$0x0068732f
push    $0x6e69622f
movl	%esp, %ebx

mov	$0x00, %ecx
mov	$0x00, %edx

int $0x80

pop %eax
pop %eax

leave
ret
