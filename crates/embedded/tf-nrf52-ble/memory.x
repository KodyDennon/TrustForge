/* nRF52840 memory layout, with space reserved for the Nordic
 * SoftDevice S140 v7.3.0 at the bottom of flash and RAM.
 *
 *   Flash 0x00000  - 0x26FFF : SoftDevice S140 v7.3.0 (~156 KiB)
 *   Flash 0x27000  - 0xFFFFF : Application (~868 KiB)
 *   RAM   0x20000000 - 0x20007FFF : SoftDevice (~32 KiB)
 *   RAM   0x20008000 - 0x2003FFFF : Application (~224 KiB)
 *
 * Without the SoftDevice (default features) the application owns the
 * full flash and RAM regions, so a separate `memory-no-sd.x` could be
 * provided; this file is the production ble-enabled layout.
 */

MEMORY
{
    FLASH : ORIGIN = 0x00027000, LENGTH = 868K
    RAM   : ORIGIN = 0x20008000, LENGTH = 224K
}
