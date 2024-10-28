#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// $ perl -e 'print("A"x24 . "\x40\x07\x01\x00\x00\x00\x00\x00" . "B"x8 . "\x80\x07\x01\x00\x00\x00\x00\x00" . "C"x8 . "\xa8\x07\x01\x00\x00\x00\x00\x00")' | ./rop

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)		\
({															\
	register long _num  __asm__ ("a7") = (num);				\
	register long _arg1 __asm__ ("a0") = (long)(arg1);		\
	register long _arg2 __asm__ ("a1") = (long)(arg2);		\
	register long _arg3 __asm__ ("a2") = (long)(arg3);		\
	register long _arg4 __asm__ ("a3") = (long)(arg4);		\
	register long _arg5 __asm__ ("a4") = (long)(arg5);		\
															\
	__asm__ volatile (										\
		"ecall\n"											\
		: "+r"(_arg1)										\
		: "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5),	\
		  "r"(_num)											\
		: "memory", "cc"									\
	);														\
	_arg1;													\
})
#define PR_SET_SHADOW_STACK_STATUS      75
#define __NR_prctl 167

void gadget1(void) {
    printf("gadget1\n");
    // 0x10740
    asm("li t0, 0x68732f6e69622f"); // hs/nib/
    asm("sd t0, -16(sp)");
    asm("addi a0, sp, -16");
}

void gadget2(void) {
    printf("gadget2\n");
    // 0x10780
    asm("li a1, 0");
    asm("li a2, 0");
}

void gadget3(void) {
    printf("gadget3\n");
    // 0x107a8
    asm("li a7, 221");
    asm("ecall");
}

void vuln_read() {
    char buffer[10];
    read(0, buffer, 100);
}

int main(int argc, char** argv) {
    // prepare shadow stack
	int ret = my_syscall5(__NR_prctl, PR_SET_SHADOW_STACK_STATUS, 1, 0, 0, 0);
	if (ret) {
		printf("Set shadow stack failed with %d\n", ret);
        exit(1);
    }

    printf("gadget1 addr: %p\n", gadget1);
    printf("gadget2 addr: %p\n", gadget2);
    printf("gadget3 addr: %p\n", gadget3);
    vuln_read();
    printf("exit normally\n");
    return 0;
}
