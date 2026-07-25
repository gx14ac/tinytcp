/* Linker script for MPS2-AN385 QEMU smoke test (Cortex-M3, 4MB Flash, 4MB SRAM).
   Uses large RAM to fit full stack with reassembly buffers in BSS. */
ENTRY(_start)

MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 4096K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 4096K
}

_stack_top = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
    } > FLASH

    .data :
    {
        *(.data*)
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        *(.bss*)
        *(COMMON)
    } > RAM
}
