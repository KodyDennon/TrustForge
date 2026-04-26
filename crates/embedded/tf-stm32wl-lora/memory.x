/* STM32WLE5JC memory layout.
 *
 * Sizes match an STM32WLE5JC (256 KiB flash, 64 KiB SRAM split between
 * SRAM1 and SRAM2). For the WL55 dual-core part, this targets the CM4
 * application core; the CM0+ subsystem is reserved for the radio
 * firmware and is not touched here.
 */

MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}

/* The cortex-m-rt linker script (link.x) consumes these region names. */
