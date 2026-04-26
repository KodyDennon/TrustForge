//! In-memory adapters for unit tests and host-side simulators. None
//! of these touch real hardware; they exist so the trait surface is
//! exercisable end-to-end without bring-up of a board.

use core::convert::TryInto;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use heapless::spsc::Queue;

use crate::{BleAdvertiser, Entropy, LoraRadio, NfcReader, SecureElement};

/// Errors from the mock adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockError {
    /// Radio inbox / outbox / NFC buffer was empty.
    Empty,
    /// Provided buffer too small for the next frame.
    BufferTooSmall,
    /// Outbox at capacity.
    OutboxFull,
    /// SecureElement seed could not be parsed.
    BadSeed,
    /// Internal RNG state failure (never returned by the mock — kept
    /// for symmetry with real Entropy implementations).
    Rng,
}

/// Maximum frame length carried by `MockLoraRadio`.
pub const MOCK_FRAME_CAP: usize = 1024;
/// Maximum number of frames queued in the radio outbox / inbox.
pub const MOCK_QUEUE_CAP: usize = 16;

/// In-memory LoRa radio. Implements both send and recv against a pair
/// of FIFO buffers. Tests typically pre-load `inbox` and inspect
/// `outbox` after the unit under test runs.
#[derive(Debug)]
pub struct MockLoraRadio {
    pub inbox: heapless::Vec<heapless::Vec<u8, MOCK_FRAME_CAP>, MOCK_QUEUE_CAP>,
    pub outbox: heapless::Vec<heapless::Vec<u8, MOCK_FRAME_CAP>, MOCK_QUEUE_CAP>,
}

impl Default for MockLoraRadio {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLoraRadio {
    pub fn new() -> Self {
        MockLoraRadio {
            inbox: heapless::Vec::new(),
            outbox: heapless::Vec::new(),
        }
    }

    /// Push a frame into the inbox so a subsequent `recv` returns it.
    pub fn enqueue_inbox(&mut self, frame: &[u8]) -> Result<(), MockError> {
        let mut v: heapless::Vec<u8, MOCK_FRAME_CAP> = heapless::Vec::new();
        v.extend_from_slice(frame)
            .map_err(|_| MockError::BufferTooSmall)?;
        self.inbox.push(v).map_err(|_| MockError::OutboxFull)?;
        Ok(())
    }
}

impl LoraRadio for MockLoraRadio {
    type Error = MockError;

    fn send(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        let mut v: heapless::Vec<u8, MOCK_FRAME_CAP> = heapless::Vec::new();
        v.extend_from_slice(payload)
            .map_err(|_| MockError::BufferTooSmall)?;
        self.outbox.push(v).map_err(|_| MockError::OutboxFull)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.inbox.is_empty() {
            return Err(MockError::Empty);
        }
        // Pop front — heapless::Vec doesn't have pop_front so we
        // shift. Frame counts are bounded by MOCK_QUEUE_CAP (≤16).
        let frame = self.inbox.remove(0);
        if frame.len() > buf.len() {
            return Err(MockError::BufferTooSmall);
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
}

/// In-memory BLE advertiser; captures advertised payloads in `last`.
#[derive(Debug)]
pub struct MockBleAdvertiser {
    pub last: Option<heapless::Vec<u8, MOCK_FRAME_CAP>>,
    pub advertise_count: u32,
}

impl Default for MockBleAdvertiser {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBleAdvertiser {
    pub fn new() -> Self {
        MockBleAdvertiser {
            last: None,
            advertise_count: 0,
        }
    }
}

impl BleAdvertiser for MockBleAdvertiser {
    type Error = MockError;
    fn advertise(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        let mut v: heapless::Vec<u8, MOCK_FRAME_CAP> = heapless::Vec::new();
        v.extend_from_slice(payload)
            .map_err(|_| MockError::BufferTooSmall)?;
        self.last = Some(v);
        self.advertise_count += 1;
        Ok(())
    }
}

/// In-memory NFC reader — `read` returns frames previously pushed via
/// [`MockNfcReader::enqueue`].
#[derive(Debug)]
pub struct MockNfcReader {
    pub queue: heapless::Vec<heapless::Vec<u8, MOCK_FRAME_CAP>, MOCK_QUEUE_CAP>,
}

impl Default for MockNfcReader {
    fn default() -> Self {
        Self::new()
    }
}

impl MockNfcReader {
    pub fn new() -> Self {
        MockNfcReader {
            queue: heapless::Vec::new(),
        }
    }
    pub fn enqueue(&mut self, frame: &[u8]) -> Result<(), MockError> {
        let mut v: heapless::Vec<u8, MOCK_FRAME_CAP> = heapless::Vec::new();
        v.extend_from_slice(frame)
            .map_err(|_| MockError::BufferTooSmall)?;
        self.queue.push(v).map_err(|_| MockError::OutboxFull)?;
        Ok(())
    }
}

impl NfcReader for MockNfcReader {
    type Error = MockError;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.queue.is_empty() {
            return Err(MockError::Empty);
        }
        let frame = self.queue.remove(0);
        if frame.len() > buf.len() {
            return Err(MockError::BufferTooSmall);
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
}

/// SecureElement backed by a fixed seed. Useful for tests and host
/// simulators; should never be used in a production build because it
/// keeps the seed in plain RAM.
#[derive(Debug)]
pub struct MockSecureElement {
    keypair: KeyPair,
    pub_bytes: [u8; 32],
}

impl MockSecureElement {
    /// Create from a 32-byte ed25519 seed.
    pub fn from_seed(seed_bytes: [u8; 32]) -> Result<Self, MockError> {
        let seed = Seed::from_slice(&seed_bytes).map_err(|_| MockError::BadSeed)?;
        let keypair = KeyPair::from_seed(seed);
        let pub_bytes: [u8; 32] = keypair
            .pk
            .as_ref()
            .try_into()
            .map_err(|_| MockError::BadSeed)?;
        Ok(MockSecureElement { keypair, pub_bytes })
    }

    /// Verify a signature against this element's public key. Useful in
    /// round-trip tests.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let sig = match Signature::from_slice(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pk = match PublicKey::from_slice(&self.pub_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        pk.verify(msg, &sig).is_ok()
    }
}

impl SecureElement for MockSecureElement {
    type Error = MockError;

    fn sign(&mut self, msg: &[u8]) -> Result<[u8; 64], Self::Error> {
        let sig = self.keypair.sk.sign(msg, None);
        let bytes: [u8; 64] = sig.as_ref().try_into().expect("ed25519 sig is 64 bytes");
        Ok(bytes)
    }

    fn pubkey(&self) -> [u8; 32] {
        self.pub_bytes
    }
}

/// Simple deterministic RNG for tests. Uses xorshift64* seeded from a
/// constructor argument. Not cryptographically secure — production
/// drivers must implement `Entropy` against a real HW-RNG.
#[derive(Debug)]
pub struct MockEntropy {
    state: u64,
}

impl MockEntropy {
    pub fn new(seed: u64) -> Self {
        // xorshift64* requires non-zero state.
        let s = if seed == 0 {
            0xdead_beef_dead_beef
        } else {
            seed
        };
        MockEntropy { state: s }
    }
}

impl Entropy for MockEntropy {
    type Error = MockError;
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in buf.chunks_mut(8) {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            let v = self.state.wrapping_mul(0x2545_F491_4F6C_DD1Du64);
            let bytes = v.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

// `Queue` is not used by the mocks today but the import keeps the
// crate's heapless feature surface visible to downstream callers.
#[doc(hidden)]
pub type _UnusedQueueImport<T, const N: usize> = Queue<T, N>;
