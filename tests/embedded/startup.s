.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector,"a",%progbits
.global _vector_table
.type _start, %function
_vector_table:
    .word _stack_top
    .word _start
