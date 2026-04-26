//! TrustForge K9 — verify-then-boot bootloader binary.
//!
//! This is a minimal first-stage bootloader that:
//!
//! 1. Wakes from reset.
//! 2. Reads the application slot at `_app_a_start` (linker symbol from
//!    `memory.x`).
//! 3. Calls `tf_bootloader_example::verify_bundle` against a pinned
//!    boot key.
//! 4. On success: rewrites SCB->VTOR, sets MSP from the application's
//!    initial-SP word, and branches to the application's reset
//!    handler. On failure: enters a recovery state (here, an infinite
//!    `wfi` loop — production firmware blinks an LED and exposes USB
//!    DFU).
//!
//! See `src/lib.rs` for the verifier itself and its host-side tests.

#![no_std]
#![no_main]

use core::ptr;

use cortex_m_rt::entry;
use panic_halt as _;

use tf_bootloader_example::{verify_bundle, HEADER_LEN};

extern "C" {
    /// Application slot A start, defined by the bootloader linker
    /// script (`memory.x`). `cortex-m-rt` exposes external symbols as
    /// addresses by re-declaring them as zero-sized externs.
    static _app_a_start: u32;
    static _app_a_len: u32;
}

/// Pinned boot key. Replace with the per-product key at build time —
/// e.g. via `option_env!("TF_BOOT_PUBKEY_HEX")` and a build-script
/// hex-decode. For the reference firmware we ship a deterministic
/// known-bad key so a freshly built bootloader rejects every bundle
/// (refusing-to-boot is the safe default before provisioning).
const PINNED_BOOT_KEY: [u8; 32] = [0u8; 32];

#[entry]
fn main() -> ! {
    // SAFETY: `_app_a_start` and `_app_a_len` are linker symbols whose
    // addresses are constants. We construct a slice of `len` bytes
    // starting at that address; the slice is read-only and lives in
    // flash, not RAM.
    let slot = unsafe {
        let base = &_app_a_start as *const u32 as *const u8;
        let len = &_app_a_len as *const u32 as usize;
        core::slice::from_raw_parts(base, len)
    };

    match verify_bundle(slot, &PINNED_BOOT_KEY) {
        Ok((image_off, _image_len)) => {
            // SAFETY: the application image starts at `image_off`. The
            // first 4 bytes are the initial MSP, the next 4 are the
            // reset handler address. After verification, it is sound
            // to load these into the CPU and branch.
            unsafe { jump_to_application(slot, image_off) }
        }
        Err(_) => {
            // Recovery state: spin with interrupts off. Real firmware
            // flashes a fault LED and exposes USB DFU here.
            recovery_loop()
        }
    }
}

/// Jump to the application's reset handler. Resets MSP and SCB->VTOR.
///
/// # Safety
///
/// The caller must have validated that `slot[image_off..]` contains a
/// well-formed Cortex-M vector table (initial SP word + reset handler
/// pointer). `verify_bundle` only proves the bundle is signed; the
/// signer is responsible for ensuring the bytes are a valid image.
unsafe fn jump_to_application(slot: &[u8], image_off: usize) -> ! {
    let app_base = slot.as_ptr().add(image_off) as u32;
    // Vector table layout: [initial SP, reset handler, ...]
    let initial_sp = ptr::read_volatile(app_base as *const u32);
    let reset      = ptr::read_volatile((app_base + 4) as *const u32);

    // Point the vector table at the application.
    let scb = &*cortex_m::peripheral::SCB::PTR;
    scb.vtor.write(app_base);

    // Make sure all writes complete before we change MSP.
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    // `asm::bootstrap` writes MSP and branches to reset in one go,
    // avoiding the UB window between MSP write and the branch.
    cortex_m::asm::bootstrap(initial_sp as *const u32, reset as *const u32);
}

fn recovery_loop() -> ! {
    let _ = HEADER_LEN; // keep lib symbol live so the linker doesn't drop it.
    loop {
        cortex_m::asm::wfi();
    }
}
