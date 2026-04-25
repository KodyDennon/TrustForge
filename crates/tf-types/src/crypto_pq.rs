//! Post-quantum signature primitives (FIPS 204 ML-DSA), mirror of
//! `tools/tf-types-ts/src/core/crypto.ts` hybridSign/hybridVerify.
//!
//! TrustForge uses parallel composition for hybrid PQ signatures: the
//! same transcript bytes are signed independently with ed25519 AND
//! ml-dsa-65; both signatures must verify. This survives a future break
//! of either algorithm with the other intact (NIST CNSA 2.0 / IETF
//! hybrid-signature drafts).

use crate::crypto::CryptoError;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _, Verifier as _};

/// Generate an ml-dsa-65 key pair. Returns (private_key_bytes, public_key_bytes).
pub fn ml_dsa_65_generate() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (pk, sk) = ml_dsa_65::try_keygen()
        .map_err(|e| CryptoError::Generic(format!("ml-dsa-65 keygen: {e}")))?;
    Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec()))
}

/// Sign a message with ml-dsa-65.
pub fn ml_dsa_65_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let bytes: [u8; ml_dsa_65::SK_LEN] = private_key
        .try_into()
        .map_err(|_| CryptoError::Generic(format!("ml-dsa-65 priv must be {} bytes", ml_dsa_65::SK_LEN)))?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(bytes)
        .map_err(|e| CryptoError::Generic(format!("ml-dsa-65 priv parse: {e}")))?;
    let sig = sk
        .try_sign(message, &[])
        .map_err(|e| CryptoError::Generic(format!("ml-dsa-65 sign: {e}")))?;
    Ok(sig.to_vec())
}

/// Verify an ml-dsa-65 signature. Returns false on any failure mode.
pub fn ml_dsa_65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: [u8; ml_dsa_65::PK_LEN] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk = match ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig: [u8; ml_dsa_65::SIG_LEN] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(message, &sig, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sign_and_verify() {
        let (sk, pk) = ml_dsa_65_generate().expect("keygen");
        let msg = b"hello hybrid pq";
        let sig = ml_dsa_65_sign(&sk, msg).expect("sign");
        assert!(ml_dsa_65_verify(&pk, msg, &sig));
        // tampered message rejects
        assert!(!ml_dsa_65_verify(&pk, b"goodbye", &sig));
        // tampered signature rejects (flip first byte)
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(!ml_dsa_65_verify(&pk, msg, &bad));
    }

    #[test]
    fn wrong_public_key_rejects() {
        let (sk, _) = ml_dsa_65_generate().expect("keygen-1");
        let (_, pk2) = ml_dsa_65_generate().expect("keygen-2");
        let msg = b"x";
        let sig = ml_dsa_65_sign(&sk, msg).expect("sign");
        assert!(!ml_dsa_65_verify(&pk2, msg, &sig));
    }
}
