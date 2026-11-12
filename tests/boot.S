/* Synthetic x86-64 execution fixture. Not a Windows guest. */
.code16
.global _start, ready, probe
_start:
    cli
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x7000, %sp
    lgdt gdt_pointer
    mov %cr4, %eax
    or $0x20, %eax
    mov %eax, %cr4
    mov $0x1000, %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx
    rdmsr
    or $0x100, %eax
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax
    mov %eax, %cr0
    ljmpl $0x08, $long_mode

.code64
long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $0x90000, %rsp
ready:
    nop
again:
    mov $0x1000, %rax
    mov %rax, %cr3
    call probe
    mov $0x5000, %rax
    mov %rax, %cr3
    call probe
    jmp again
probe:
    nop
    incq 0x400100
    ret

.balign 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:
gdt_pointer:
    .word gdt_end-gdt-1
    .long gdt

.org 510
.word 0xaa55
