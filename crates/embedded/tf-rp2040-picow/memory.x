/* RP2040 memory map.
 *
 * The RP2040 has no internal flash; the BOOT2 stage in the first 256 B
 * of XIP-flash trampolines into our reset vector. embassy-rp wires up
 * the BOOT2 section automatically.
 */

MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH : ORIGIN = 0x10000100, LENGTH = 2048K - 0x100
    RAM   : ORIGIN = 0x20000000, LENGTH = 264K
}

EXTERN(BOOT2_FIRMWARE)

SECTIONS {
    .boot2 ORIGIN(BOOT2) :
    {
        KEEP(*(.boot2));
    } > BOOT2
} INSERT BEFORE .text;
