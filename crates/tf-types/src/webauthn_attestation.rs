#![allow(clippy::unnecessary_unwrap)]
//! Full WebAuthn attestation parser + verifier.
//!
//! Mirrors `tools/tf-types-ts/src/core/webauthn-attestation.ts`. Supports
//! the three attestation formats real authenticators emit for the common
//! flows: `none`, `packed` (self-attestation; full x5c verification when
//! a chain is present), and `fido-u2f`. CBOR decoding uses `ciborium`
//! and signature verification uses `p256` / `ed25519-dalek` so we don't
//! depend on Node-style runtime crypto.
//!
//! Path validation against trust anchors is intentionally out of scope
//! here — the TLS bridge handles X.509 chain validation when an
//! attestation includes x5c. Use `verify_attestation_chain` from the
//! caller side if the deployment requires it.

use std::convert::TryInto;

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::Signature as P256Signature;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use sha2::{Digest, Sha256};

use crate::bridges::BridgeError;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    Es256,
    EdDsa,
    Rs256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationFormat {
    None_,
    Packed,
    FidoU2f,
}

#[derive(Debug, Clone)]
pub struct CosePublicKey {
    pub kty: i64,
    pub alg: Option<CoseAlgorithm>,
    pub crv: Option<i64>,
    pub x: Option<Vec<u8>>,
    pub y: Option<Vec<u8>>,
    pub n: Option<Vec<u8>>,
    pub e: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ParsedAuthData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub sign_count: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key_cose: Option<Vec<u8>>,
    pub credential_public_key: Option<CosePublicKey>,
}

#[derive(Debug, Clone)]
pub struct AttestationObject {
    pub fmt: AttestationFormat,
    pub att_stmt: CborValue,
    pub auth_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ClientData {
    pub r#type: String,
    pub challenge: String,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct VerifyAttestationOptions {
    pub rp_id: String,
    pub expected_origin: String,
    pub expected_challenge: String,
    pub allowed_algorithms: Option<Vec<CoseAlgorithm>>,
    pub require_attestation_signature: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub format: AttestationFormat,
    pub auth_data: ParsedAuthData,
    pub client_data: ClientData,
    pub credential_public_key: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub algorithm: CoseAlgorithm,
    pub x5c: Option<Vec<Vec<u8>>>,
    pub sign_count: u32,
    pub flags: u8,
    pub aaguid: Option<Vec<u8>>,
}

pub fn parse_authenticator_data(buf: &[u8]) -> Result<ParsedAuthData, BridgeError> {
    if buf.len() < 37 {
        return Err(BridgeError::InvalidInput(format!(
            "authData too short ({} bytes)",
            buf.len()
        )));
    }
    let rp_id_hash = buf[0..32].to_vec();
    let flags = buf[32];
    let sign_count = u32::from_be_bytes([buf[33], buf[34], buf[35], buf[36]]);
    if flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
        return Ok(ParsedAuthData {
            rp_id_hash,
            flags,
            sign_count,
            aaguid: None,
            credential_id: None,
            credential_public_key_cose: None,
            credential_public_key: None,
        });
    }
    if buf.len() < 55 {
        return Err(BridgeError::InvalidInput(
            "authData has AT flag but is too short for attested credential data".into(),
        ));
    }
    let aaguid = buf[37..53].to_vec();
    let cred_id_len = u16::from_be_bytes([buf[53], buf[54]]) as usize;
    if buf.len() < 55 + cred_id_len {
        return Err(BridgeError::InvalidInput(format!(
            "authData truncated reading credentialId (declared {} bytes)",
            cred_id_len
        )));
    }
    let credential_id = buf[55..55 + cred_id_len].to_vec();
    let cose_bytes = &buf[55 + cred_id_len..];
    let credential_public_key = parse_cose_public_key(cose_bytes)?;

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        aaguid: Some(aaguid),
        credential_id: Some(credential_id),
        credential_public_key_cose: Some(cose_bytes.to_vec()),
        credential_public_key: Some(credential_public_key),
    })
}

pub fn parse_cose_public_key(cose: &[u8]) -> Result<CosePublicKey, BridgeError> {
    let val: CborValue = ciborium::de::from_reader(cose)
        .map_err(|e| BridgeError::InvalidInput(format!("COSE key not valid CBOR: {}", e)))?;
    let map = match &val {
        CborValue::Map(m) => m,
        _ => return Err(BridgeError::InvalidInput("COSE key not a map".into())),
    };
    let mut kty = None;
    let mut alg: Option<CoseAlgorithm> = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    let mut n = None;
    let mut e_field = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Integer(i) => Some(i64::try_from(*i).unwrap_or(0)),
            _ => None,
        };
        match key {
            Some(1) => {
                if let CborValue::Integer(i) = v {
                    kty = Some(i64::try_from(*i).unwrap_or(0));
                }
            }
            Some(3) => {
                if let CborValue::Integer(i) = v {
                    alg = match i64::try_from(*i).unwrap_or(0) {
                        -7 => Some(CoseAlgorithm::Es256),
                        -8 => Some(CoseAlgorithm::EdDsa),
                        -257 => Some(CoseAlgorithm::Rs256),
                        _ => None,
                    };
                }
            }
            Some(-1) => {
                if let CborValue::Integer(i) = v {
                    crv = Some(i64::try_from(*i).unwrap_or(0));
                } else if let CborValue::Bytes(b) = v {
                    // RSA modulus (kty=3 puts it at -1)
                    n = Some(b.clone());
                }
            }
            Some(-2) => {
                if let CborValue::Bytes(b) = v {
                    x = Some(b.clone());
                }
            }
            Some(-3) => {
                if let CborValue::Bytes(b) = v {
                    y = Some(b.clone());
                }
            }
            Some(-4) => {
                if let CborValue::Bytes(b) = v {
                    e_field = Some(b.clone());
                }
            }
            _ => {}
        }
    }
    let kty = kty.ok_or_else(|| BridgeError::InvalidInput("COSE key missing kty".into()))?;
    // For RSA the modulus is `-1` and exponent is `-2` per RFC 8230 — fix mapping above:
    // since our extractor put `-1` integer into crv and `-1` bytes into n, both branches are
    // mutually exclusive depending on kty. Same applies for `-2` (x for EC2/OKP, e for RSA).
    let (n_final, e_final) = if kty == 3 {
        // For kty=3 our switch above stored modulus in n (when -1 was bytes) and x (when -2
        // was bytes); we need to swap x→e here because RSA's exponent is -2.
        (n.clone().or(None), x.clone().or(None))
    } else {
        (None, None)
    };
    Ok(CosePublicKey {
        kty,
        alg,
        crv,
        x: if kty == 3 { None } else { x },
        y: if kty == 3 { None } else { y },
        n: n_final,
        e: e_final.or(e_field),
    })
}

pub fn decode_attestation_object(buf: &[u8]) -> Result<AttestationObject, BridgeError> {
    let val: CborValue = ciborium::de::from_reader(buf).map_err(|e| {
        BridgeError::InvalidInput(format!("attestationObject not valid CBOR: {}", e))
    })?;
    let map = match val {
        CborValue::Map(m) => m,
        _ => {
            return Err(BridgeError::InvalidInput(
                "attestationObject not a map".into(),
            ))
        }
    };
    let mut fmt = None;
    let mut att_stmt = None;
    let mut auth_data = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t,
            _ => continue,
        };
        match key.as_str() {
            "fmt" => fmt = v.as_text().map(|s| s.to_string()),
            "attStmt" => att_stmt = Some(v),
            "authData" => auth_data = v.as_bytes().map(|b| b.to_vec()),
            _ => {}
        }
    }
    let fmt = fmt.ok_or_else(|| BridgeError::InvalidInput("missing fmt".into()))?;
    let auth_data =
        auth_data.ok_or_else(|| BridgeError::InvalidInput("missing authData bytes".into()))?;
    let att_stmt = att_stmt.ok_or_else(|| BridgeError::InvalidInput("missing attStmt".into()))?;
    let format = match fmt.as_str() {
        "none" => AttestationFormat::None_,
        "packed" => AttestationFormat::Packed,
        "fido-u2f" => AttestationFormat::FidoU2f,
        other => {
            return Err(BridgeError::Unsupported(format!(
                "attestation format {} not supported",
                other
            )))
        }
    };
    Ok(AttestationObject {
        fmt: format,
        att_stmt,
        auth_data,
    })
}

pub fn parse_client_data(buf: &[u8]) -> Result<ClientData, BridgeError> {
    let json: serde_json::Value = serde_json::from_slice(buf)
        .map_err(|e| BridgeError::InvalidInput(format!("clientDataJSON not valid JSON: {}", e)))?;
    let obj = json
        .as_object()
        .ok_or_else(|| BridgeError::InvalidInput("clientDataJSON not an object".into()))?;
    let r#type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BridgeError::InvalidInput("missing clientData.type".into()))?
        .to_string();
    let challenge = obj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BridgeError::InvalidInput("missing clientData.challenge".into()))?
        .to_string();
    let origin = obj
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BridgeError::InvalidInput("missing clientData.origin".into()))?
        .to_string();
    Ok(ClientData {
        r#type,
        challenge,
        origin,
    })
}

pub fn verify_attestation(
    attestation_object: &[u8],
    client_data_json: &[u8],
    opts: &VerifyAttestationOptions,
) -> Result<VerifiedAttestation, BridgeError> {
    let att = decode_attestation_object(attestation_object)?;
    let auth = parse_authenticator_data(&att.auth_data)?;
    let client = parse_client_data(client_data_json)?;
    if client.r#type != "webauthn.create" {
        return Err(BridgeError::Rejected(format!(
            "clientData.type {} is not webauthn.create",
            client.r#type
        )));
    }
    if client.origin != opts.expected_origin {
        return Err(BridgeError::Rejected(format!(
            "clientData.origin {} does not match expected {}",
            client.origin, opts.expected_origin
        )));
    }
    if client.challenge != opts.expected_challenge {
        return Err(BridgeError::Rejected(
            "clientData.challenge does not match expected".into(),
        ));
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(opts.rp_id.as_bytes()).into();
    if auth.rp_id_hash != expected_rp_hash {
        return Err(BridgeError::Rejected(
            "authData rpIdHash does not match sha256(rpId)".into(),
        ));
    }
    if auth.flags & FLAG_USER_PRESENT == 0 {
        return Err(BridgeError::Rejected(
            "authData missing User Present flag".into(),
        ));
    }
    if auth.flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
        return Err(BridgeError::Rejected(
            "authData missing AT flag (no attested credential data)".into(),
        ));
    }
    let cose = auth
        .credential_public_key
        .as_ref()
        .ok_or_else(|| BridgeError::InvalidInput("credential public key missing".into()))?;
    let credential_id = auth
        .credential_id
        .as_ref()
        .ok_or_else(|| BridgeError::InvalidInput("credential id missing".into()))?
        .clone();
    let alg = cose.alg.ok_or_else(|| {
        BridgeError::InvalidInput("credential public key has no algorithm".into())
    })?;
    if let Some(allowed) = &opts.allowed_algorithms {
        if !allowed.contains(&alg) {
            return Err(BridgeError::Rejected(format!(
                "algorithm {:?} not in allow-list",
                alg
            )));
        }
    }
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();

    match att.fmt {
        AttestationFormat::Packed => verify_packed(&att, &auth, &client_data_hash)?,
        AttestationFormat::FidoU2f => verify_fido_u2f(&att, &auth, &client_data_hash)?,
        AttestationFormat::None_ => {
            if opts.require_attestation_signature {
                return Err(BridgeError::Rejected(
                    "format=none rejected when require_attestation_signature=true".into(),
                ));
            }
        }
    }

    let credential_public_key = encode_raw_public_key(cose)?;
    let x5c = pick_x5c(&att.att_stmt);

    Ok(VerifiedAttestation {
        format: att.fmt,
        auth_data: auth.clone(),
        client_data: client,
        credential_public_key,
        credential_id,
        algorithm: alg,
        x5c,
        sign_count: auth.sign_count,
        flags: auth.flags,
        aaguid: auth.aaguid,
    })
}

fn verify_packed(
    att: &AttestationObject,
    auth: &ParsedAuthData,
    client_data_hash: &[u8; 32],
) -> Result<(), BridgeError> {
    let map = match &att.att_stmt {
        CborValue::Map(m) => m,
        _ => return Err(BridgeError::InvalidInput("packed attStmt not a map".into())),
    };
    let mut sig: Option<Vec<u8>> = None;
    let mut alg: Option<i64> = None;
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "sig" => sig = v.as_bytes().map(|b| b.to_vec()),
            "alg" => {
                if let CborValue::Integer(i) = v {
                    alg = Some(i64::try_from(*i).unwrap_or(0));
                }
            }
            "x5c" => {
                if let CborValue::Array(arr) = v {
                    x5c = Some(
                        arr.iter()
                            .filter_map(|c| c.as_bytes().map(|b| b.to_vec()))
                            .collect(),
                    );
                }
            }
            _ => {}
        }
    }
    let sig = sig.ok_or_else(|| BridgeError::InvalidInput("packed attStmt missing sig".into()))?;
    let alg = alg.ok_or_else(|| BridgeError::InvalidInput("packed attStmt missing alg".into()))?;
    let mut data = att.auth_data.clone();
    data.extend_from_slice(client_data_hash);
    if let Some(chain) = x5c.as_ref() {
        if let Some(cert_der) = chain.first() {
            verify_with_cert(cert_der, &data, &sig, alg)?;
            return Ok(());
        }
    }
    let cose = auth.credential_public_key.as_ref().ok_or_else(|| {
        BridgeError::InvalidInput("self-attestation needs credential public key".into())
    })?;
    verify_cose_signature(cose, &data, &sig, alg)
}

fn verify_fido_u2f(
    att: &AttestationObject,
    auth: &ParsedAuthData,
    client_data_hash: &[u8; 32],
) -> Result<(), BridgeError> {
    let map = match &att.att_stmt {
        CborValue::Map(m) => m,
        _ => {
            return Err(BridgeError::InvalidInput(
                "fido-u2f attStmt not a map".into(),
            ))
        }
    };
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "sig" => sig = v.as_bytes().map(|b| b.to_vec()),
            "x5c" => {
                if let CborValue::Array(arr) = v {
                    x5c = Some(
                        arr.iter()
                            .filter_map(|c| c.as_bytes().map(|b| b.to_vec()))
                            .collect(),
                    );
                }
            }
            _ => {}
        }
    }
    let sig =
        sig.ok_or_else(|| BridgeError::InvalidInput("fido-u2f attStmt missing sig".into()))?;
    let x5c =
        x5c.ok_or_else(|| BridgeError::InvalidInput("fido-u2f attStmt missing x5c".into()))?;
    let cose = auth
        .credential_public_key
        .as_ref()
        .ok_or_else(|| BridgeError::InvalidInput("fido-u2f needs credential pubkey".into()))?;
    if cose.kty != 2 || cose.x.is_none() || cose.y.is_none() {
        return Err(BridgeError::InvalidInput(
            "fido-u2f requires EC2 P-256 credential public key".into(),
        ));
    }
    let mut data = Vec::new();
    data.push(0x00);
    data.extend_from_slice(&auth.rp_id_hash);
    data.extend_from_slice(client_data_hash);
    data.extend_from_slice(auth.credential_id.as_ref().unwrap());
    data.push(0x04);
    data.extend_from_slice(cose.x.as_ref().unwrap());
    data.extend_from_slice(cose.y.as_ref().unwrap());
    let cert = x5c
        .first()
        .ok_or_else(|| BridgeError::InvalidInput("fido-u2f x5c empty".into()))?;
    verify_with_cert(cert, &data, &sig, -7)
}

fn verify_with_cert(
    cert_der: &[u8],
    data: &[u8],
    signature: &[u8],
    cose_alg: i64,
) -> Result<(), BridgeError> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| BridgeError::InvalidInput(format!("cert DER parse: {}", e)))?;
    let alg_oid = cert.public_key().algorithm.algorithm.to_id_string();
    let key_bytes = cert.public_key().subject_public_key.data.as_ref();
    match alg_oid.as_str() {
        "1.2.840.10045.2.1" if cose_alg == -7 => verify_p256_der(key_bytes, data, signature),
        "1.3.101.112" if cose_alg == -8 => verify_ed25519(key_bytes, data, signature),
        _ => Err(BridgeError::Unsupported(format!(
            "x5c algorithm {} not supported for cose alg {}",
            alg_oid, cose_alg
        ))),
    }
}

fn verify_cose_signature(
    cose: &CosePublicKey,
    data: &[u8],
    sig: &[u8],
    alg: i64,
) -> Result<(), BridgeError> {
    if alg == -7 && cose.kty == 2 {
        let x = cose
            .x
            .as_ref()
            .ok_or_else(|| BridgeError::InvalidInput("EC2 missing x".into()))?;
        let y = cose
            .y
            .as_ref()
            .ok_or_else(|| BridgeError::InvalidInput("EC2 missing y".into()))?;
        let mut pub_bytes = vec![0x04];
        pub_bytes.extend_from_slice(x);
        pub_bytes.extend_from_slice(y);
        return verify_p256_der(&pub_bytes, data, sig);
    }
    if alg == -8 && cose.kty == 1 {
        let x = cose
            .x
            .as_ref()
            .ok_or_else(|| BridgeError::InvalidInput("OKP missing x".into()))?;
        return verify_ed25519(x, data, sig);
    }
    Err(BridgeError::Unsupported(format!(
        "self-attestation alg {} on kty {} not supported",
        alg, cose.kty
    )))
}

fn verify_p256_der(
    public_uncompressed: &[u8],
    data: &[u8],
    der_sig: &[u8],
) -> Result<(), BridgeError> {
    let vk = P256VerifyingKey::from_sec1_bytes(public_uncompressed)
        .map_err(|e| BridgeError::InvalidInput(format!("bad P-256 SEC1 key: {}", e)))?;
    let sig = P256Signature::from_der(der_sig)
        .map_err(|e| BridgeError::InvalidInput(format!("bad ECDSA DER sig: {}", e)))?;
    vk.verify(data, &sig)
        .map_err(|e| BridgeError::Rejected(format!("ES256 verify failed: {}", e)))
}

fn verify_ed25519(public: &[u8], data: &[u8], sig: &[u8]) -> Result<(), BridgeError> {
    let public_arr: [u8; 32] = public
        .try_into()
        .map_err(|_| BridgeError::InvalidInput("Ed25519 key not 32 bytes".into()))?;
    let vk = Ed25519VerifyingKey::from_bytes(&public_arr)
        .map_err(|e| BridgeError::InvalidInput(format!("bad Ed25519 key: {}", e)))?;
    let sig_arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| BridgeError::InvalidInput("Ed25519 signature not 64 bytes".into()))?;
    let sig = Ed25519Signature::from_bytes(&sig_arr);
    vk.verify(data, &sig)
        .map_err(|e| BridgeError::Rejected(format!("EdDSA verify failed: {}", e)))
}

fn pick_x5c(att_stmt: &CborValue) -> Option<Vec<Vec<u8>>> {
    if let CborValue::Map(m) = att_stmt {
        for (k, v) in m {
            if let CborValue::Text(t) = k {
                if t == "x5c" {
                    if let CborValue::Array(arr) = v {
                        let collected: Vec<Vec<u8>> = arr
                            .iter()
                            .filter_map(|c| c.as_bytes().map(|b| b.to_vec()))
                            .collect();
                        if !collected.is_empty() {
                            return Some(collected);
                        }
                    }
                }
            }
        }
    }
    None
}

fn encode_raw_public_key(cose: &CosePublicKey) -> Result<Vec<u8>, BridgeError> {
    if cose.kty == 2 && cose.x.is_some() && cose.y.is_some() {
        let mut out = vec![0x04];
        out.extend_from_slice(cose.x.as_ref().unwrap());
        out.extend_from_slice(cose.y.as_ref().unwrap());
        return Ok(out);
    }
    if cose.kty == 1 && cose.x.is_some() {
        return Ok(cose.x.clone().unwrap());
    }
    if cose.kty == 3 && cose.n.is_some() {
        return Ok(cose.n.clone().unwrap());
    }
    Err(BridgeError::InvalidInput(
        "unsupported COSE key shape".into(),
    ))
}
