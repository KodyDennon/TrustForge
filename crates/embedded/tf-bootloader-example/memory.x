/* TrustForge bootloader memory layout (illustrative, STM32F411).
 *
 *   FLASH 0x08000000 - 0x0801FFFF : Bootloader (this binary, 128 KiB)
 *   FLASH 0x08020000 - 0x0807FFFF : Application slot A (384 KiB)
 *
 * The application image starts with a 16-byte TrustForge bundle
 * header, followed by the cortex-m vector table and code. The
 * bootloader verifies the bundle (header + vector table + code) using
 * a pinned ed25519 public key before jumping to the application's
 * reset handler.
 *
 * Slot B (a second copy at the top of flash, used for failsafe A/B
 * upgrades) is omitted from this minimal example; production bootloaders
 * provision two slots and a small "boot status" word in the last page
 * to track which slot is active.
 */

MEMORY
{
    FLASH : ORIGIN = 0x08000000, LENGTH = 128K
    RAM   : ORIGIN = 0x20000000, LENGTH = 128K

    /* Application slot A — declared so the bootloader can take its
     * address as a constant, not used by the linker for this binary. */
    APP_A : ORIGIN = 0x08020000, LENGTH = 384K
}

_app_a_start = ORIGIN(APP_A);
_app_a_len   = LENGTH(APP_A);
