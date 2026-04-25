/* STM32WL55JCIx — dual-core Cortex-M4F + Cortex-M0+, 256 KiB flash,
   64 KiB SRAM1 + 32 KiB SRAM2. This example targets the M4 core; the
   M0+ subsystem stays in reset for the LoRa radio bridging path. */
MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
