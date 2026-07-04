//! First-party file-backed implementations of the TrustForge persistence
//! traits.
//!
//! The store is intentionally simple and owned by TrustForge:
//! append-only proof events, a revocation snapshot, and opaque evidence
//! bundle files. It is designed for local/default deployments and as the
//! no-database baseline for the broader dependency replacement program.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tf_types::canonical::canonicalize;
use tf_types::crypto::sha256_hashref;
use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache, StoreError};

#[derive(Debug)]
struct State {
    proof_order: Vec<String>,
    proof_payloads: HashMap<String, Value>,
    revocations: BTreeMap<(String, String), String>,
}

/// Shared file-backed store. Open once, then construct any of the trait
/// adapters from it.
pub struct FileStore {
    root: PathBuf,
    state: Mutex<State>,
}

pub struct FileProofLedger {
    inner: Arc<FileStore>,
}

pub struct FileRevocationCache {
    inner: Arc<FileStore>,
}

pub struct FileEvidenceArchive {
    inner: Arc<FileStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub proof_events: usize,
    pub revocations: usize,
    pub evidence_bundles: usize,
}

impl FileStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("evidence")).map_err(map_io)?;
        cleanup_stale_temps(&root)?;
        let state = State {
            proof_order: Vec::new(),
            proof_payloads: HashMap::new(),
            revocations: BTreeMap::new(),
        };
        let store = Self {
            root,
            state: Mutex::new(state),
        };
        store.load()?;
        Ok(store)
    }

    fn load(&self) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("file store state poisoned");
        state.proof_order.clear();
        state.proof_payloads.clear();
        state.revocations.clear();

        let proof_log = self.proof_log_path();
        if proof_log.exists() {
            let file = File::open(&proof_log).map_err(map_io)?;
            for (line_no, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(map_io)?;
                if line.trim().is_empty() {
                    continue;
                }
                let mut parts = line.splitn(3, '\t');
                let hash = parts.next().unwrap_or_default();
                let checksum = parts.next().ok_or_else(|| {
                    StoreError::Other(format!("malformed proof.log line {}", line_no + 1))
                })?;
                let payload = parts.next().ok_or_else(|| {
                    StoreError::Other(format!("malformed proof.log line {}", line_no + 1))
                })?;
                let expected_checksum = record_checksum(hash, payload);
                if checksum != expected_checksum {
                    return Err(StoreError::Other(format!(
                        "proof.log line {} checksum mismatch",
                        line_no + 1
                    )));
                }
                let expected_hash = sha256_hashref(payload.as_bytes());
                if hash != expected_hash {
                    return Err(StoreError::Other(format!(
                        "proof.log line {} event hash mismatch",
                        line_no + 1
                    )));
                }
                let value: Value = serde_json::from_str(payload).map_err(|e| {
                    StoreError::Other(format!("parse proof.log line {}: {e}", line_no + 1))
                })?;
                if !state.proof_payloads.contains_key(hash) {
                    state.proof_order.push(hash.to_string());
                }
                state.proof_payloads.insert(hash.to_string(), value);
            }
        }

        let revocations = self.revocations_path();
        if revocations.exists() {
            let file = File::open(&revocations).map_err(map_io)?;
            for (line_no, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(map_io)?;
                if line.trim().is_empty() {
                    continue;
                }
                let mut parts = line.splitn(3, '\t');
                let kind = parts.next().unwrap_or_default();
                let id = parts.next().unwrap_or_default();
                let effective_at = parts.next().ok_or_else(|| {
                    StoreError::Other(format!("malformed revocations.tsv line {}", line_no + 1))
                })?;
                state.revocations.insert(
                    (unescape_field(kind)?, unescape_field(id)?),
                    unescape_field(effective_at)?,
                );
            }
        }

        Ok(())
    }

    /// Rewrite file-backed indexes from the in-memory state.
    ///
    /// This removes duplicate proof-log records left by manual edits or
    /// older writers and rewrites checksums using the current format.
    pub fn compact(&self) -> Result<(), StoreError> {
        let state = self.state.lock().expect("file store state poisoned");
        persist_proof_log(self, &state.proof_order, &state.proof_payloads)?;
        persist_revocations(self, &state.revocations)
    }

    /// Verify all on-disk records and evidence checksum sidecars.
    ///
    /// This is intended for startup probes and backup/export jobs. It
    /// re-reads the durable files instead of trusting the in-memory indexes.
    pub fn health_check(&self) -> Result<HealthReport, StoreError> {
        let (proof_events, revocations) = verify_indexes_on_disk(self)?;
        let evidence_bundles = verify_all_evidence(self)?;
        Ok(HealthReport {
            proof_events,
            revocations,
            evidence_bundles,
        })
    }

    fn proof_log_path(&self) -> PathBuf {
        self.root.join("proof.log")
    }

    fn revocations_path(&self) -> PathBuf {
        self.root.join("revocations.tsv")
    }

    fn evidence_dir(&self) -> PathBuf {
        self.root.join("evidence")
    }
}

impl FileProofLedger {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(FileStore::open(root)?),
        })
    }

    pub fn from_store(store: Arc<FileStore>) -> Self {
        Self { inner: store }
    }
}

impl FileRevocationCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(FileStore::open(root)?),
        })
    }

    pub fn from_store(store: Arc<FileStore>) -> Self {
        Self { inner: store }
    }
}

impl FileEvidenceArchive {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(FileStore::open(root)?),
        })
    }

    pub fn from_store(store: Arc<FileStore>) -> Self {
        Self { inner: store }
    }
}

impl ProofLedger for FileProofLedger {
    fn append(&self, event: &Value) -> Result<String, StoreError> {
        let canonical =
            canonicalize(event).map_err(|e| StoreError::Other(format!("canonicalize: {e}")))?;
        let hash = sha256_hashref(canonical.as_bytes());
        let mut state = self.inner.state.lock().expect("file store state poisoned");
        if state.proof_payloads.contains_key(&hash) {
            return Ok(hash);
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.inner.proof_log_path())
            .map_err(map_io)?;
        let checksum = record_checksum(&hash, &canonical);
        file.write_all(hash.as_bytes()).map_err(map_io)?;
        file.write_all(b"\t").map_err(map_io)?;
        file.write_all(checksum.as_bytes()).map_err(map_io)?;
        file.write_all(b"\t").map_err(map_io)?;
        file.write_all(canonical.as_bytes()).map_err(map_io)?;
        file.write_all(b"\n").map_err(map_io)?;
        file.sync_data().map_err(map_io)?;

        state.proof_order.push(hash.clone());
        state.proof_payloads.insert(hash.clone(), event.clone());
        Ok(hash)
    }

    fn lookup(&self, event_hash: &str) -> Result<Option<Value>, StoreError> {
        let state = self.inner.state.lock().expect("file store state poisoned");
        Ok(state.proof_payloads.get(event_hash).cloned())
    }

    fn tail(&self, limit: usize) -> Result<Vec<Value>, StoreError> {
        let state = self.inner.state.lock().expect("file store state poisoned");
        let start = state.proof_order.len().saturating_sub(limit);
        let mut out = Vec::new();
        for hash in &state.proof_order[start..] {
            if let Some(value) = state.proof_payloads.get(hash) {
                out.push(value.clone());
            }
        }
        Ok(out)
    }
}

impl RevocationCache for FileRevocationCache {
    fn insert(
        &self,
        target_kind: &str,
        target_id: &str,
        effective_at: &str,
    ) -> Result<(), StoreError> {
        let mut state = self.inner.state.lock().expect("file store state poisoned");
        state.revocations.insert(
            (target_kind.to_string(), target_id.to_string()),
            effective_at.to_string(),
        );
        persist_revocations(&self.inner, &state.revocations)
    }

    fn is_revoked(&self, target_kind: &str, target_id: &str, at: &str) -> Result<bool, StoreError> {
        let state = self.inner.state.lock().expect("file store state poisoned");
        Ok(state
            .revocations
            .get(&(target_kind.to_string(), target_id.to_string()))
            .is_some_and(|effective_at| effective_at.as_str() <= at))
    }

    fn list(&self) -> Result<Vec<(String, String, String)>, StoreError> {
        let state = self.inner.state.lock().expect("file store state poisoned");
        Ok(state
            .revocations
            .iter()
            .map(|((kind, id), effective_at)| (kind.clone(), id.clone(), effective_at.clone()))
            .collect())
    }
}

impl EvidenceArchive for FileEvidenceArchive {
    fn put(&self, bundle_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if bundle_id.is_empty() {
            return Err(StoreError::Other("empty bundle id".into()));
        }
        let _guard = self.inner.state.lock().expect("file store state poisoned");
        fs::create_dir_all(self.inner.evidence_dir()).map_err(map_io)?;
        let path = self
            .inner
            .evidence_dir()
            .join(hex_encode(bundle_id.as_bytes()));
        let checksum_path = evidence_checksum_path(&path);
        let tmp = path.with_extension("tmp");
        let checksum_tmp = evidence_checksum_tmp_path(&path);
        {
            let mut file = File::create(&tmp).map_err(map_io)?;
            file.write_all(bytes).map_err(map_io)?;
            file.sync_data().map_err(map_io)?;
        }
        {
            let mut file = File::create(&checksum_tmp).map_err(map_io)?;
            file.write_all(sha256_hashref(bytes).as_bytes())
                .map_err(map_io)?;
            file.write_all(b"\n").map_err(map_io)?;
            file.sync_data().map_err(map_io)?;
        }
        fs::rename(tmp, &path).map_err(map_io)?;
        fs::rename(checksum_tmp, checksum_path).map_err(map_io)?;
        sync_dir(&self.inner.evidence_dir())
    }

    fn get(&self, bundle_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self
            .inner
            .evidence_dir()
            .join(hex_encode(bundle_id.as_bytes()));
        match fs::read(&path) {
            Ok(bytes) => {
                verify_evidence_checksum(&path, &bytes)?;
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(map_io(e)),
        }
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let _guard = self.inner.state.lock().expect("file store state poisoned");
        let dir = self.inner.evidence_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            if !entry.file_type().map_err(map_io)?.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.ends_with(".tmp") || name.ends_with(".sha256") {
                continue;
            }
            out.push(String::from_utf8(hex_decode(&name)?).map_err(|e| {
                StoreError::Other(format!("invalid evidence bundle id filename {name}: {e}"))
            })?);
        }
        out.sort();
        Ok(out)
    }
}

fn persist_proof_log(
    store: &FileStore,
    proof_order: &[String],
    proof_payloads: &HashMap<String, Value>,
) -> Result<(), StoreError> {
    let path = store.proof_log_path();
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(map_io)?;
        for hash in proof_order {
            let Some(value) = proof_payloads.get(hash) else {
                continue;
            };
            let canonical =
                canonicalize(value).map_err(|e| StoreError::Other(format!("canonicalize: {e}")))?;
            let checksum = record_checksum(hash, &canonical);
            file.write_all(hash.as_bytes()).map_err(map_io)?;
            file.write_all(b"\t").map_err(map_io)?;
            file.write_all(checksum.as_bytes()).map_err(map_io)?;
            file.write_all(b"\t").map_err(map_io)?;
            file.write_all(canonical.as_bytes()).map_err(map_io)?;
            file.write_all(b"\n").map_err(map_io)?;
        }
        file.sync_data().map_err(map_io)?;
    }
    fs::rename(tmp, path)
        .map_err(map_io)
        .and_then(|_| sync_dir(&store.root))
}

fn persist_revocations(
    store: &FileStore,
    revocations: &BTreeMap<(String, String), String>,
) -> Result<(), StoreError> {
    let path = store.revocations_path();
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(map_io)?;
        for ((kind, id), effective_at) in revocations {
            file.write_all(escape_field(kind).as_bytes())
                .map_err(map_io)?;
            file.write_all(b"\t").map_err(map_io)?;
            file.write_all(escape_field(id).as_bytes())
                .map_err(map_io)?;
            file.write_all(b"\t").map_err(map_io)?;
            file.write_all(escape_field(effective_at).as_bytes())
                .map_err(map_io)?;
            file.write_all(b"\n").map_err(map_io)?;
        }
        file.sync_data().map_err(map_io)?;
    }
    fs::rename(tmp, path)
        .map_err(map_io)
        .and_then(|_| sync_dir(&store.root))
}

fn cleanup_stale_temps(root: &Path) -> Result<(), StoreError> {
    remove_if_exists(root.join("proof.tmp"))?;
    remove_if_exists(root.join("revocations.tmp"))?;
    let evidence_dir = root.join("evidence");
    if evidence_dir.exists() {
        for entry in fs::read_dir(&evidence_dir).map_err(map_io)? {
            let entry = entry.map_err(map_io)?;
            if !entry.file_type().map_err(map_io)?.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.ends_with(".tmp") {
                fs::remove_file(entry.path()).map_err(map_io)?;
            }
        }
        sync_dir(&evidence_dir)?;
    }
    sync_dir(root)
}

fn remove_if_exists(path: PathBuf) -> Result<(), StoreError> {
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(map_io(e)),
    }
}

fn verify_indexes_on_disk(store: &FileStore) -> Result<(usize, usize), StoreError> {
    let mut proof_events = 0usize;
    let proof_log = store.proof_log_path();
    if proof_log.exists() {
        let file = File::open(&proof_log).map_err(map_io)?;
        for (line_no, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(map_io)?;
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, '\t');
            let hash = parts.next().unwrap_or_default();
            let checksum = parts.next().ok_or_else(|| {
                StoreError::Other(format!("malformed proof.log line {}", line_no + 1))
            })?;
            let payload = parts.next().ok_or_else(|| {
                StoreError::Other(format!("malformed proof.log line {}", line_no + 1))
            })?;
            if checksum != record_checksum(hash, payload) {
                return Err(StoreError::Other(format!(
                    "proof.log line {} checksum mismatch",
                    line_no + 1
                )));
            }
            if hash != sha256_hashref(payload.as_bytes()) {
                return Err(StoreError::Other(format!(
                    "proof.log line {} event hash mismatch",
                    line_no + 1
                )));
            }
            let _: Value = serde_json::from_str(payload).map_err(|e| {
                StoreError::Other(format!("parse proof.log line {}: {e}", line_no + 1))
            })?;
            proof_events += 1;
        }
    }

    let mut revocations = 0usize;
    let revocations_path = store.revocations_path();
    if revocations_path.exists() {
        let file = File::open(&revocations_path).map_err(map_io)?;
        for (line_no, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(map_io)?;
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, '\t');
            let kind = parts.next().unwrap_or_default();
            let id = parts.next().unwrap_or_default();
            let effective_at = parts.next().ok_or_else(|| {
                StoreError::Other(format!("malformed revocations.tsv line {}", line_no + 1))
            })?;
            let _ = unescape_field(kind)?;
            let _ = unescape_field(id)?;
            let _ = unescape_field(effective_at)?;
            revocations += 1;
        }
    }

    Ok((proof_events, revocations))
}

fn verify_all_evidence(store: &FileStore) -> Result<usize, StoreError> {
    let dir = store.evidence_dir();
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(&dir).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        if !entry.file_type().map_err(map_io)?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.ends_with(".tmp") || name.ends_with(".sha256") {
            continue;
        }
        let path = entry.path();
        let bytes = fs::read(&path).map_err(map_io)?;
        verify_evidence_checksum(&path, &bytes)?;
        count += 1;
    }
    Ok(count)
}

fn escape_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'%' => out.push_str("%25"),
            b'\t' => out.push_str("%09"),
            b'\n' => out.push_str("%0a"),
            b'\r' => out.push_str("%0d"),
            b => out.push(b as char),
        }
    }
    out
}

fn unescape_field(s: &str) -> Result<String, StoreError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(StoreError::Other(format!("bad escape in field: {s}")));
            }
            let hi = hex_value(bytes[i + 1])?;
            let lo = hex_value(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| StoreError::Other(format!("field is not utf-8: {e}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, StoreError> {
    if !s.len().is_multiple_of(2) {
        return Err(StoreError::Other(format!("odd-length hex string: {s}")));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((hex_value(bytes[i])? << 4) | hex_value(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

fn record_checksum(hash: &str, canonical_payload: &str) -> String {
    let mut bytes = Vec::with_capacity(hash.len() + 1 + canonical_payload.len());
    bytes.extend_from_slice(hash.as_bytes());
    bytes.push(b'\t');
    bytes.extend_from_slice(canonical_payload.as_bytes());
    sha256_hashref(&bytes)
}

fn evidence_checksum_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    name.push_str(".sha256");
    path.with_file_name(name)
}

fn evidence_checksum_tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    name.push_str(".sha256.tmp");
    path.with_file_name(name)
}

fn verify_evidence_checksum(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let checksum_path = evidence_checksum_path(path);
    let expected = match fs::read_to_string(&checksum_path) {
        Ok(text) => text.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::Other(format!(
                "missing evidence checksum: {}",
                checksum_path.display()
            )));
        }
        Err(e) => return Err(map_io(e)),
    };
    let actual = sha256_hashref(bytes);
    if expected != actual {
        return Err(StoreError::Other(format!(
            "evidence checksum mismatch: {}",
            path.display()
        )));
    }
    Ok(())
}

fn hex_value(b: u8) -> Result<u8, StoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StoreError::Other(format!("invalid hex byte: {b}"))),
    }
}

fn map_io(e: std::io::Error) -> StoreError {
    StoreError::Other(e.to_string())
}

fn sync_dir(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(map_io)
}
