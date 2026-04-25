//! Replay-protected packet receiver — no_std edition.
//!
//! Mirrors `tf-types::constrained::PacketReceiver`. The receiver keeps
//! a sliding window of recently-seen `(packet_id, expires_at)` pairs:
//!
//! * On `observe`, if `expires_at < now`, return `Reject(Expired)`.
//! * Otherwise, if `packet_id` is already in the window, return
//!   `Reject(Replay)`.
//! * Otherwise, accept and record. The window evicts FIFO once it
//!   reaches its bounded capacity.
//!
//! With the `alloc` feature, the cache is backed by a `VecDeque` /
//! `BTreeSet` pair sized at runtime (capacity is still bounded). With
//! `--no-default-features`, the cache uses `heapless::Deque` and a
//! membership probe over the deque, both with a const-generic `N`.

#[cfg(not(feature = "alloc"))]
use heapless::String as HString;

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;
#[cfg(feature = "alloc")]
use alloc::string::String;

/// Maximum length of a packet ID (per TF-0001 actor-id sizing — packet
/// IDs are short ULIDs / UUIDs but we leave headroom).
pub const PACKET_ID_CAP: usize = 64;
/// Maximum length of an `expires_at` ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub const TIMESTAMP_CAP: usize = 32;

/// Why a `PacketReceiver` rejected a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    Replay,
    Expired,
    FutureDated,
    /// Packet ID exceeded the local cap.
    IdTooLarge,
    /// Cache full and no entry could be evicted.
    CacheFull,
}

/// Result of `PacketReceiver::observe`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverDecision {
    Accept,
    Reject(RejectReason),
}

/* -------------------- alloc backing -------------------- */

/// `PacketReceiver` with a `VecDeque`-backed window. Available with the
/// `alloc` feature.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct PacketReceiver {
    seen: VecDeque<(String, String)>,
    capacity: usize,
}

#[cfg(feature = "alloc")]
impl PacketReceiver {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        PacketReceiver {
            seen: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    pub fn observe(
        &mut self,
        packet_id: &str,
        expires_at: Option<&str>,
        now: &str,
    ) -> ReceiverDecision {
        if let Some(exp) = expires_at {
            if exp < now {
                return ReceiverDecision::Reject(RejectReason::Expired);
            }
        }
        if self.seen.iter().any(|(id, _)| id == packet_id) {
            return ReceiverDecision::Reject(RejectReason::Replay);
        }
        if self.seen.len() >= self.capacity {
            self.seen.pop_front();
        }
        self.seen
            .push_back((packet_id.into(), expires_at.unwrap_or("").into()));
        ReceiverDecision::Accept
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/* ------------------- heapless backing ------------------- */

/// `PacketReceiver` with a fixed-capacity heapless backing. The cache
/// holds up to `N` packet IDs.
#[cfg(not(feature = "alloc"))]
#[derive(Debug)]
pub struct PacketReceiver<const N: usize> {
    seen: heapless::Deque<HString<PACKET_ID_CAP>, N>,
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> PacketReceiver<N> {
    pub fn new() -> Self {
        PacketReceiver {
            seen: heapless::Deque::new(),
        }
    }

    pub fn observe(
        &mut self,
        packet_id: &str,
        expires_at: Option<&str>,
        now: &str,
    ) -> ReceiverDecision {
        if let Some(exp) = expires_at {
            if exp < now {
                return ReceiverDecision::Reject(RejectReason::Expired);
            }
        }
        let mut hid: HString<PACKET_ID_CAP> = HString::new();
        if hid.push_str(packet_id).is_err() {
            return ReceiverDecision::Reject(RejectReason::IdTooLarge);
        }
        if self.seen.iter().any(|s| s == &hid) {
            return ReceiverDecision::Reject(RejectReason::Replay);
        }
        if self.seen.is_full() {
            self.seen.pop_front();
        }
        if self.seen.push_back(hid).is_err() {
            return ReceiverDecision::Reject(RejectReason::CacheFull);
        }
        ReceiverDecision::Accept
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(not(feature = "alloc"))]
impl<const N: usize> Default for PacketReceiver<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn replay_rejected_alloc() {
        let mut rx = PacketReceiver::new(8);
        let now = "2026-04-25T00:00:00Z";
        assert_eq!(
            rx.observe("pkt-001", Some("2099-01-01T00:00:00Z"), now),
            ReceiverDecision::Accept
        );
        assert_eq!(
            rx.observe("pkt-001", Some("2099-01-01T00:00:00Z"), now),
            ReceiverDecision::Reject(RejectReason::Replay)
        );
        assert_eq!(rx.len(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn expired_rejected_alloc() {
        let mut rx = PacketReceiver::new(8);
        assert_eq!(
            rx.observe("pkt-1", Some("2026-04-01T00:00:00Z"), "2026-04-25T00:00:00Z"),
            ReceiverDecision::Reject(RejectReason::Expired)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn evicts_oldest_when_full_alloc() {
        let mut rx = PacketReceiver::new(2);
        rx.observe("a", None, "2026-04-25T00:00:00Z");
        rx.observe("b", None, "2026-04-25T00:00:00Z");
        rx.observe("c", None, "2026-04-25T00:00:00Z");
        // 'a' was evicted, so re-submitting it must accept.
        assert_eq!(
            rx.observe("a", None, "2026-04-25T00:00:00Z"),
            ReceiverDecision::Accept
        );
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn replay_rejected_no_alloc() {
        let mut rx: PacketReceiver<8> = PacketReceiver::new();
        let now = "2026-04-25T00:00:00Z";
        assert_eq!(
            rx.observe("pkt-001", Some("2099-01-01T00:00:00Z"), now),
            ReceiverDecision::Accept
        );
        assert_eq!(
            rx.observe("pkt-001", Some("2099-01-01T00:00:00Z"), now),
            ReceiverDecision::Reject(RejectReason::Replay)
        );
    }
}
