//! Session protocol — Phase 3 prototype. Mirrors
//! `tools/tf-types-ts/src/core/session.ts` byte-for-byte where deterministic.
//!
//! 3-message handshake (HelloI, HelloR, Auth) followed by sequence-numbered
//! AEAD frames. Rekey is in-band via rekey-req / rekey-ack.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::actor_id::derive_peer_actor;
use crate::canonical::canonicalize;
use crate::crypto::{
    b64decode, b64encode, chacha20poly1305_decrypt, chacha20poly1305_encrypt, ed25519_verify,
    hkdf_sha256, x25519_diffie_hellman, x25519_from_bytes, x25519_generate, AeadError, CryptoError,
    Ed25519Signer, X25519KeyPair,
};
use crate::crypto_pq::{ml_dsa_65_sign, ml_dsa_65_verify};

fn is_hybrid_suite(suite: &str) -> bool {
    suite.ends_with("+ml-dsa-65")
}

pub const SESSION_VERSION: u32 = 0;
pub const SESSION_SUITE: &str = "x25519-hkdf-sha256-chacha20poly1305-ed25519";
pub const SESSION_SUITE_HYBRID_ED25519_MLDSA65: &str =
    "x25519-hkdf-sha256-chacha20poly1305-ed25519+ml-dsa-65";

/// Suites this build of TrustForge knows how to honour. Order is preference.
pub const KNOWN_SESSION_SUITES: &[&str] = &[SESSION_SUITE, SESSION_SUITE_HYBRID_ED25519_MLDSA65];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session error: {0}")]
    Generic(String),
    #[error("aead failure at seq {0}")]
    Aead(u64),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<CryptoError> for SessionError {
    fn from(e: CryptoError) -> Self {
        SessionError::Crypto(e.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename = "hello-i")]
pub struct HelloI {
    pub version: u32,
    pub suite: String,
    /// Suite preference list. Earlier entries are preferred. The default
    /// classical suite is always implicit so existing peers still
    /// interoperate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supported_suites: Option<Vec<String>>,
    pub session_id: String,
    pub peer_hint: String,
    /// Initiator's self-claimed actor URI (advisory; not bound to the key).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub self_hint: Option<String>,
    pub eph_pub: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename = "hello-r")]
pub struct HelloR {
    pub eph_pub: String,
    pub ident_pub: String,
    /// Suite the responder selected from the initiator's supported_suites.
    /// When omitted, the responder agrees to the suite the initiator named
    /// in HelloI.suite.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub selected_suite: Option<String>,
    /// Responder's self-claimed actor URI (advisory).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub self_hint: Option<String>,
    /// Hybrid-PQ companion signature over the same transcript_hash. When
    /// present, both the ed25519 `signature` and `signature_mldsa` MUST
    /// verify for the handshake to be accepted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature_mldsa: Option<String>,
    /// Public ml-dsa key used to verify `signature_mldsa`. Required when
    /// `signature_mldsa` is present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ident_pub_mldsa: Option<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename = "auth")]
pub struct Auth {
    pub ident_pub: String,
    /// Hybrid-PQ companion signature; required when the negotiated suite
    /// is the hybrid `*+ml-dsa-65` variant.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature_mldsa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ident_pub_mldsa: Option<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SessionFrame {
    Data {
        payload: serde_json::Value,
    },
    RekeyReq {
        eph_pub: String,
    },
    RekeyAck {
        eph_pub: String,
    },
    Close {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Ping {
        nonce: String,
    },
    Pong {
        nonce: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct SessionConfig {
    pub self_actor: String,
    pub peer_hint: Option<String>,
    /// Optional self-claimed actor URI advertised in HelloI / HelloR.
    pub self_hint: Option<String>,
    pub identity_priv: [u8; 32],
    pub identity_pub: [u8; 32],
    /// Preferred suite. Default: SESSION_SUITE.
    pub preferred_suite: Option<String>,
    /// Suites this peer is willing to accept; defaults to KNOWN_SESSION_SUITES.
    pub supported_suites: Option<Vec<String>>,
    /// ml-dsa-65 secret key. Required when the negotiated suite is hybrid.
    pub identity_mldsa_priv: Option<Vec<u8>>,
    /// ml-dsa-65 public key. Required when the negotiated suite is hybrid.
    pub identity_mldsa_pub: Option<Vec<u8>>,
    pub eph_seed: Option<[u8; 32]>,
    pub session_id_seed: Option<[u8; 16]>,
}

pub struct Initiator {
    cfg: SessionConfig,
    state: InitiatorState,
}

enum InitiatorState {
    Fresh,
    AwaitingHelloR { hello_i: HelloI, eph_priv: [u8; 32] },
    Established(SessionState),
}

impl Initiator {
    pub fn new(cfg: SessionConfig) -> Self {
        Initiator {
            cfg,
            state: InitiatorState::Fresh,
        }
    }

    /// Returns the established session state when the handshake has completed,
    /// otherwise None. Callers use this to inspect the session without having
    /// to retain a separate copy.
    pub fn established_session(&self) -> Option<&SessionState> {
        match &self.state {
            InitiatorState::Established(s) => Some(s),
            _ => None,
        }
    }

    pub fn start(&mut self) -> Result<HelloI, SessionError> {
        let InitiatorState::Fresh = self.state else {
            return Err(SessionError::Generic("initiator already started".into()));
        };
        let eph = make_ephemeral(&self.cfg.eph_seed);
        let session_id_bytes = match &self.cfg.session_id_seed {
            Some(seed) => *seed,
            None => {
                let mut buf = [0u8; 16];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut buf);
                buf
            }
        };
        let preferred = self
            .cfg
            .preferred_suite
            .clone()
            .unwrap_or_else(|| SESSION_SUITE.to_owned());
        let mut supported = self
            .cfg
            .supported_suites
            .clone()
            .unwrap_or_else(|| KNOWN_SESSION_SUITES.iter().map(|s| s.to_string()).collect());
        // Move preferred to the front so the responder's first-match
        // negotiation honours preference.
        supported.retain(|s| s != &preferred);
        supported.insert(0, preferred.clone());
        let hello_i = HelloI {
            version: SESSION_VERSION,
            suite: preferred,
            supported_suites: Some(supported),
            session_id: b64encode(&session_id_bytes),
            peer_hint: self.cfg.peer_hint.clone().unwrap_or_default(),
            self_hint: self.cfg.self_hint.clone(),
            eph_pub: b64encode(&eph.public),
        };
        self.state = InitiatorState::AwaitingHelloR {
            hello_i: hello_i.clone(),
            eph_priv: eph.private,
        };
        Ok(hello_i)
    }

    pub fn process_hello_r(&mut self, msg: HelloR) -> Result<(Auth, SessionState), SessionError> {
        let (hello_i, eph_priv) = match std::mem::replace(&mut self.state, InitiatorState::Fresh) {
            InitiatorState::AwaitingHelloR { hello_i, eph_priv } => (hello_i, eph_priv),
            _ => return Err(SessionError::Generic("not awaiting hello-r".into())),
        };

        // For canonical transcript bytes both parties drop ed25519+mldsa
        // signature fields together so neither side embeds the wrong pair
        // of signatures.
        let hello_r_unsigned = HelloR {
            signature: String::new(),
            signature_mldsa: None,
            ..msg.clone()
        };
        let transcript = canonical_concat(&[
            &serde_json::to_value(&hello_i).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&hello_r_unsigned)
                .map_err(|e| SessionError::Generic(e.to_string()))?,
        ])?;
        let transcript_hash = Sha256::digest(transcript.as_bytes());

        let ident_pub = b64decode(&msg.ident_pub)?;
        let sig = b64decode(&msg.signature)?;
        ed25519_verify(&ident_pub, &transcript_hash, &sig)
            .map_err(|_| SessionError::Generic("responder identity signature invalid".into()))?;

        let negotiated_suite = msg
            .selected_suite
            .clone()
            .unwrap_or_else(|| hello_i.suite.clone());
        if is_hybrid_suite(&negotiated_suite) {
            let pq_sig_b64 = msg.signature_mldsa.as_deref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but HelloR missing signature_mldsa",
                    negotiated_suite
                ))
            })?;
            let pq_pub_b64 = msg.ident_pub_mldsa.as_deref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but HelloR missing ident_pub_mldsa",
                    negotiated_suite
                ))
            })?;
            let pq_sig = b64decode(pq_sig_b64)?;
            let pq_pub = b64decode(pq_pub_b64)?;
            if !ml_dsa_65_verify(&pq_pub, transcript_hash.as_slice(), &pq_sig) {
                return Err(SessionError::Generic(
                    "responder ml-dsa-65 signature invalid".into(),
                ));
            }
        }

        let peer_eph: [u8; 32] = b64decode(&msg.eph_pub)?
            .try_into()
            .map_err(|_| SessionError::Generic("eph_pub not 32 bytes".into()))?;
        let shared = x25519_diffie_hellman(&eph_priv, &peer_eph);

        let auth_unsigned = Auth {
            ident_pub: b64encode(&self.cfg.identity_pub),
            signature_mldsa: None,
            ident_pub_mldsa: if is_hybrid_suite(&negotiated_suite) {
                self.cfg.identity_mldsa_pub.as_deref().map(b64encode)
            } else {
                None
            },
            signature: String::new(),
        };
        let full_transcript = canonical_concat(&[
            &serde_json::to_value(&hello_i).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&msg).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&auth_unsigned)
                .map_err(|e| SessionError::Generic(e.to_string()))?,
        ])?;
        let full_hash = Sha256::digest(full_transcript.as_bytes());

        let signer = Ed25519Signer::from_bytes(&self.cfg.identity_priv);
        let auth_sig = signer.sign(&full_hash);
        let auth_pq_sig = if is_hybrid_suite(&negotiated_suite) {
            let priv_bytes = self.cfg.identity_mldsa_priv.as_ref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but initiator is missing identity_mldsa_priv",
                    negotiated_suite
                ))
            })?;
            Some(b64encode(
                &ml_dsa_65_sign(priv_bytes, full_hash.as_slice())
                    .map_err(|e| SessionError::Generic(e.to_string()))?,
            ))
        } else {
            None
        };
        let auth = Auth {
            ident_pub: b64encode(&self.cfg.identity_pub),
            signature_mldsa: auth_pq_sig,
            ident_pub_mldsa: auth_unsigned.ident_pub_mldsa.clone(),
            signature: b64encode(&auth_sig),
        };

        let session_id_bytes = b64decode(&hello_i.session_id)?;
        let peer_actor = derive_peer_actor(&ident_pub)
            .map_err(|e| SessionError::Generic(format!("derive_peer_actor: {e}")))?;
        // Responder's self-claimed actor URI travels in HelloR.self_hint.
        let peer_claim = msg.self_hint.clone().filter(|s| !s.is_empty());
        let session = SessionState::derive_with_claim(
            Role::Initiator,
            &shared,
            &session_id_bytes,
            &full_hash,
            &self.cfg.self_actor,
            &peer_actor,
            peer_claim,
        );
        self.state = InitiatorState::Established(session.clone());
        Ok((auth, session))
    }
}

pub struct Responder {
    cfg: SessionConfig,
    state: ResponderState,
}

enum ResponderState {
    Fresh,
    AwaitingAuth {
        hello_i: HelloI,
        hello_r: HelloR,
        shared: [u8; 32],
    },
    Established(SessionState),
}

impl Responder {
    /// Returns the established session state when the handshake has completed,
    /// otherwise None.
    pub fn established_session(&self) -> Option<&SessionState> {
        match &self.state {
            ResponderState::Established(s) => Some(s),
            _ => None,
        }
    }

    pub fn new(cfg: SessionConfig) -> Self {
        Responder {
            cfg,
            state: ResponderState::Fresh,
        }
    }

    pub fn process_hello_i(&mut self, msg: HelloI) -> Result<HelloR, SessionError> {
        let ResponderState::Fresh = self.state else {
            return Err(SessionError::Generic("responder already engaged".into()));
        };
        if msg.version != SESSION_VERSION {
            return Err(SessionError::Generic(format!(
                "unsupported version {}",
                msg.version
            )));
        }
        // Suite negotiation: pick the first entry of the initiator's
        // supported_suites that we know AND that we accept; fall back to
        // msg.suite for legacy peers without supported_suites.
        let our_supported: Vec<String> = self
            .cfg
            .supported_suites
            .clone()
            .unwrap_or_else(|| KNOWN_SESSION_SUITES.iter().map(|s| s.to_string()).collect());
        let chosen = match &msg.supported_suites {
            Some(client_supports) => client_supports
                .iter()
                .find(|s| our_supported.iter().any(|o| o == *s))
                .cloned()
                .ok_or_else(|| {
                    SessionError::Generic(format!(
                        "no mutually-supported suite (peer offered {:?}, we support {:?})",
                        client_supports, our_supported
                    ))
                })?,
            None => {
                if !our_supported.iter().any(|s| s == &msg.suite) {
                    return Err(SessionError::Generic(format!(
                        "unsupported suite {}",
                        msg.suite
                    )));
                }
                msg.suite.clone()
            }
        };

        let eph = make_ephemeral(&self.cfg.eph_seed);
        let peer_eph: [u8; 32] = b64decode(&msg.eph_pub)?
            .try_into()
            .map_err(|_| SessionError::Generic("eph_pub not 32 bytes".into()))?;
        let shared = x25519_diffie_hellman(&eph.private, &peer_eph);

        let hello_r_unsigned = HelloR {
            eph_pub: b64encode(&eph.public),
            ident_pub: b64encode(&self.cfg.identity_pub),
            selected_suite: Some(chosen.clone()),
            self_hint: self.cfg.self_hint.clone(),
            signature_mldsa: None,
            ident_pub_mldsa: if is_hybrid_suite(&chosen) {
                self.cfg.identity_mldsa_pub.as_deref().map(b64encode)
            } else {
                None
            },
            signature: String::new(),
        };
        let transcript = canonical_concat(&[
            &serde_json::to_value(&msg).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&hello_r_unsigned)
                .map_err(|e| SessionError::Generic(e.to_string()))?,
        ])?;
        let transcript_hash = Sha256::digest(transcript.as_bytes());

        let signer = Ed25519Signer::from_bytes(&self.cfg.identity_priv);
        let sig = signer.sign(&transcript_hash);
        let pq_sig = if is_hybrid_suite(&chosen) {
            let priv_bytes = self.cfg.identity_mldsa_priv.as_ref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but responder is missing identity_mldsa_priv",
                    chosen
                ))
            })?;
            Some(b64encode(
                &ml_dsa_65_sign(priv_bytes, transcript_hash.as_slice())
                    .map_err(|e| SessionError::Generic(e.to_string()))?,
            ))
        } else {
            None
        };
        let hello_r = HelloR {
            signature: b64encode(&sig),
            signature_mldsa: pq_sig,
            ..hello_r_unsigned
        };

        self.state = ResponderState::AwaitingAuth {
            hello_i: msg,
            hello_r: hello_r.clone(),
            shared,
        };
        Ok(hello_r)
    }

    pub fn process_auth(&mut self, msg: Auth) -> Result<SessionState, SessionError> {
        let (hello_i, hello_r, shared) =
            match std::mem::replace(&mut self.state, ResponderState::Fresh) {
                ResponderState::AwaitingAuth {
                    hello_i,
                    hello_r,
                    shared,
                } => (hello_i, hello_r, shared),
                _ => return Err(SessionError::Generic("not awaiting auth".into())),
            };

        let auth_unsigned = Auth {
            signature: String::new(),
            signature_mldsa: None,
            ..msg.clone()
        };
        let full_transcript = canonical_concat(&[
            &serde_json::to_value(&hello_i).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&hello_r).map_err(|e| SessionError::Generic(e.to_string()))?,
            &serde_json::to_value(&auth_unsigned)
                .map_err(|e| SessionError::Generic(e.to_string()))?,
        ])?;
        let full_hash = Sha256::digest(full_transcript.as_bytes());

        let ident_pub = b64decode(&msg.ident_pub)?;
        let sig = b64decode(&msg.signature)?;
        ed25519_verify(&ident_pub, &full_hash, &sig)
            .map_err(|_| SessionError::Generic("initiator identity signature invalid".into()))?;

        let negotiated_suite = hello_r
            .selected_suite
            .clone()
            .unwrap_or_else(|| hello_i.suite.clone());
        if is_hybrid_suite(&negotiated_suite) {
            let pq_sig_b64 = msg.signature_mldsa.as_deref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but Auth missing signature_mldsa",
                    negotiated_suite
                ))
            })?;
            let pq_pub_b64 = msg.ident_pub_mldsa.as_deref().ok_or_else(|| {
                SessionError::Generic(format!(
                    "negotiated hybrid suite {} but Auth missing ident_pub_mldsa",
                    negotiated_suite
                ))
            })?;
            let pq_sig = b64decode(pq_sig_b64)?;
            let pq_pub = b64decode(pq_pub_b64)?;
            if !ml_dsa_65_verify(&pq_pub, full_hash.as_slice(), &pq_sig) {
                return Err(SessionError::Generic(
                    "initiator ml-dsa-65 signature invalid".into(),
                ));
            }
        }

        let session_id_bytes = b64decode(&hello_i.session_id)?;
        let peer_actor = derive_peer_actor(&ident_pub)
            .map_err(|e| SessionError::Generic(format!("derive_peer_actor: {e}")))?;
        // Initiator's self-claimed actor URI travels in HelloI.self_hint.
        let peer_claim = hello_i.self_hint.clone().filter(|s| !s.is_empty());
        let session = SessionState::derive_with_claim(
            Role::Responder,
            &shared,
            &session_id_bytes,
            &full_hash,
            &self.cfg.self_actor,
            &peer_actor,
            peer_claim,
        );
        self.state = ResponderState::Established(session.clone());
        Ok(session)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Debug)]
pub struct SessionState {
    pub self_actor: String,
    /// Key-derived canonical peer actor URI. Authoritative.
    pub peer_actor: String,
    /// Self-claimed peer actor URI from `peer_hint`. Advisory only.
    pub peer_actor_claim: Option<String>,
    pub session_id: Vec<u8>,
    pub generation: u32,
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_seq: u64,
    pub recv_seq: u64,
    pub closed: bool,
    pending_rekey_priv: Option<[u8; 32]>,
}

impl SessionState {
    pub fn derive(
        role: Role,
        shared_secret: &[u8; 32],
        session_id: &[u8],
        transcript_hash: &[u8],
        self_actor: &str,
        peer_actor: &str,
    ) -> Self {
        Self::derive_with_claim(
            role,
            shared_secret,
            session_id,
            transcript_hash,
            self_actor,
            peer_actor,
            None,
        )
    }

    pub fn derive_with_claim(
        role: Role,
        shared_secret: &[u8; 32],
        session_id: &[u8],
        transcript_hash: &[u8],
        self_actor: &str,
        peer_actor: &str,
        peer_actor_claim: Option<String>,
    ) -> Self {
        let mut info = b"tf-session/v0/keys".to_vec();
        info.extend_from_slice(transcript_hash);
        let ikm = hkdf_sha256(shared_secret, session_id, &info, 64);
        let i_to_r: [u8; 32] = ikm[0..32].try_into().unwrap();
        let r_to_i: [u8; 32] = ikm[32..64].try_into().unwrap();
        let (send_key, recv_key) = match role {
            Role::Initiator => (i_to_r, r_to_i),
            Role::Responder => (r_to_i, i_to_r),
        };
        SessionState {
            self_actor: self_actor.to_owned(),
            peer_actor: peer_actor.to_owned(),
            peer_actor_claim,
            session_id: session_id.to_vec(),
            generation: 0,
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
            closed: false,
            pending_rekey_priv: None,
        }
    }

    pub fn encrypt(&mut self, frame: &SessionFrame) -> Result<Vec<u8>, SessionError> {
        if self.closed {
            return Err(SessionError::Generic("session is closed".into()));
        }
        let body_value =
            serde_json::to_value(frame).map_err(|e| SessionError::Generic(e.to_string()))?;
        let body = canonicalize(&body_value).map_err(|e| SessionError::Generic(e.to_string()))?;
        let plaintext = body.into_bytes();
        let seq = self.send_seq;
        let nonce = nonce_for(seq);
        let length = 8 + plaintext.len() + 16;
        if length > u32::MAX as usize {
            return Err(SessionError::Generic("frame too long".into()));
        }
        let aad = make_aad(length as u32, seq);
        let ct = chacha20poly1305_encrypt(&self.send_key, &nonce, &aad, &plaintext);
        let mut out = Vec::with_capacity(4 + length);
        out.extend_from_slice(&(length as u32).to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&ct);
        self.send_seq = seq.wrapping_add(1);
        Ok(out)
    }

    pub fn decrypt(&mut self, bytes: &[u8]) -> Result<SessionFrame, SessionError> {
        if self.closed {
            return Err(SessionError::Generic("session is closed".into()));
        }
        if bytes.len() < 12 + 16 {
            return Err(SessionError::Generic("frame too short".into()));
        }
        let length = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if 4 + length != bytes.len() {
            return Err(SessionError::Generic("length mismatch".into()));
        }
        let seq = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        if seq != self.recv_seq {
            return Err(SessionError::Generic(format!(
                "out-of-order frame: got {}, expected {}",
                seq, self.recv_seq
            )));
        }
        let aad = make_aad(length as u32, seq);
        let nonce = nonce_for(seq);
        let pt = chacha20poly1305_decrypt(&self.recv_key, &nonce, &aad, &bytes[12..])
            .map_err(|_: AeadError| SessionError::Aead(seq))?;
        let value: serde_json::Value =
            serde_json::from_slice(&pt).map_err(|e| SessionError::Generic(e.to_string()))?;
        let frame: SessionFrame =
            serde_json::from_value(value).map_err(|e| SessionError::Generic(e.to_string()))?;
        self.recv_seq = seq.wrapping_add(1);
        Ok(frame)
    }

    pub fn request_rekey(&mut self, seed: Option<[u8; 32]>) -> Result<Vec<u8>, SessionError> {
        let eph = make_ephemeral(&seed);
        self.pending_rekey_priv = Some(eph.private);
        self.encrypt(&SessionFrame::RekeyReq {
            eph_pub: b64encode(&eph.public),
        })
    }

    pub fn process_rekey_req(
        &mut self,
        peer_eph_pub_b64: &str,
        seed: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, SessionError> {
        let eph = make_ephemeral(&seed);
        let peer_eph: [u8; 32] = b64decode(peer_eph_pub_b64)?
            .try_into()
            .map_err(|_| SessionError::Generic("eph_pub not 32 bytes".into()))?;
        let shared = x25519_diffie_hellman(&eph.private, &peer_eph);
        let ack = self.encrypt(&SessionFrame::RekeyAck {
            eph_pub: b64encode(&eph.public),
        })?;
        self.rotate_keys(&shared);
        Ok(ack)
    }

    pub fn process_rekey_ack(&mut self, peer_eph_pub_b64: &str) -> Result<(), SessionError> {
        let pending = self
            .pending_rekey_priv
            .take()
            .ok_or_else(|| SessionError::Generic("no pending rekey".into()))?;
        let peer_eph: [u8; 32] = b64decode(peer_eph_pub_b64)?
            .try_into()
            .map_err(|_| SessionError::Generic("eph_pub not 32 bytes".into()))?;
        let shared = x25519_diffie_hellman(&pending, &peer_eph);
        self.rotate_keys(&shared);
        Ok(())
    }

    fn rotate_keys(&mut self, shared: &[u8; 32]) {
        // Canonical concat: lower-hex first.
        let send_hex = hex_lower_32(&self.send_key);
        let recv_hex = hex_lower_32(&self.recv_key);
        let send_is_lower = send_hex < recv_hex;
        let lo = if send_is_lower {
            &self.send_key
        } else {
            &self.recv_key
        };
        let hi = if send_is_lower {
            &self.recv_key
        } else {
            &self.send_key
        };
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(lo);
        concat.extend_from_slice(hi);
        let prev_hash = Sha256::digest(&concat);

        let info_label = format!("tf-session/v0/keys/g{}", self.generation + 1);
        let mut info = info_label.into_bytes();
        info.extend_from_slice(&prev_hash);
        let ikm = hkdf_sha256(shared, &self.session_id, &info, 64);
        let k1: [u8; 32] = ikm[0..32].try_into().unwrap();
        let k2: [u8; 32] = ikm[32..64].try_into().unwrap();
        if send_is_lower {
            self.send_key = k1;
            self.recv_key = k2;
        } else {
            self.send_key = k2;
            self.recv_key = k1;
        }
        self.send_seq = 0;
        self.recv_seq = 0;
        self.generation += 1;
    }
}

fn nonce_for(seq: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

fn make_aad(length: u32, seq: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&length.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

fn make_ephemeral(seed: &Option<[u8; 32]>) -> X25519KeyPair {
    match seed {
        Some(s) => x25519_from_bytes(s),
        None => {
            let mut rng = rand::thread_rng();
            x25519_generate(&mut rng)
        }
    }
}

fn canonical_concat(values: &[&serde_json::Value]) -> Result<String, SessionError> {
    let mut out = String::new();
    for v in values {
        let s = canonicalize(v).map_err(|e| SessionError::Generic(e.to_string()))?;
        out.push_str(&s);
    }
    Ok(out)
}

fn hex_lower_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
