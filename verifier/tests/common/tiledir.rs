//! Hand-rolled tlog-tiles directory builder for tests — bytes only, no Go.
//!
//! Reproduces exactly what the Tessera v1.0.4 POSIX driver + the Go log
//! service put on disk: a signed note `checkpoint`, a note-format vkey at
//! `keys/checkpoint.vkey`, entry bundles at `tile/entries/<NNN>[.p/<w>]`
//! (2-byte big-endian length framing), and level-0 hash tiles at
//! `tile/0/<NNN>[.p/<w>]`. Envelopes are byte-for-byte what
//! `internal/tlog/envelope.go BuildEnvelope` writes.

#![allow(dead_code)] // not every integration test uses every helper

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use behalf_verify::merkle::{leaf_hash, HashStore};
use behalf_verify::pae::{pae, RECEIPT_PAYLOAD_TYPE};
use behalf_verify::tiles::TILE_WIDTH;
use behalf_verify::util::hex_encode;

use super::TestSigner;

pub const LOG_ORIGIN: &str = "behalf.sh/log/test";

/// The note algorithm byte for Ed25519.
const ALG_ED25519: u8 = 1;

/// Deterministic note (checkpoint) signing key from a fixed seed byte.
pub fn note_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn note_key_data(sk: &SigningKey) -> Vec<u8> {
    let mut kd = vec![ALG_ED25519];
    kd.extend_from_slice(sk.verifying_key().as_bytes());
    kd
}

fn note_key_hash(origin: &str, key_data: &[u8]) -> [u8; 4] {
    let mut input = Vec::new();
    input.extend_from_slice(origin.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(key_data);
    let h = behalf_verify::util::sha256(&input);
    [h[0], h[1], h[2], h[3]]
}

/// The note-format verifier key string for a checkpoint signing key.
pub fn vkey_string(origin: &str, sk: &SigningKey) -> String {
    let kd = note_key_data(sk);
    format!(
        "{origin}+{}+{}",
        hex_encode(&note_key_hash(origin, &kd)),
        BASE64_STD.encode(&kd)
    )
}

/// A signed checkpoint note: origin line, decimal size, base64 root, blank
/// line, `— <origin> <base64(hash4 || sig)>`.
pub fn checkpoint_note(origin: &str, sk: &SigningKey, size: u64, root: &[u8; 32]) -> Vec<u8> {
    let text = format!("{origin}\n{size}\n{}\n", BASE64_STD.encode(root));
    let sig = sk.sign(text.as_bytes());
    let mut sig_blob = note_key_hash(origin, &note_key_data(sk)).to_vec();
    sig_blob.extend_from_slice(&sig.to_bytes());
    let mut note = text.into_bytes();
    note.extend_from_slice(b"\n");
    note.extend_from_slice("\u{2014} ".as_bytes());
    note.extend_from_slice(origin.as_bytes());
    note.push(b' ');
    note.extend_from_slice(BASE64_STD.encode(&sig_blob).as_bytes());
    note.push(b'\n');
    note
}

/// Byte-for-byte what internal/tlog/envelope.go BuildEnvelope writes.
pub fn build_envelope(payload_type: &str, payload: &[u8], keyid: &str, sig: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"{\"v\":\"behalf.sh/envelope/v1\",\"payloadType\":");
    b.extend_from_slice(serde_json::to_string(payload_type).unwrap().as_bytes());
    b.extend_from_slice(b",\"payload\":");
    b.extend_from_slice(payload);
    b.extend_from_slice(b",\"sig\":{\"keyid\":");
    b.extend_from_slice(serde_json::to_string(keyid).unwrap().as_bytes());
    b.extend_from_slice(b",\"sig\":\"");
    b.extend_from_slice(BASE64_STD.encode(sig).as_bytes());
    b.extend_from_slice(b"\"}}");
    b
}

/// A DSSE-signed receipt envelope over exact payload bytes.
pub fn signed_envelope(emitter: &TestSigner, payload: &str) -> Vec<u8> {
    let sig = emitter.sk.sign(&pae(RECEIPT_PAYLOAD_TYPE, payload.as_bytes()));
    build_envelope(
        RECEIPT_PAYLOAD_TYPE,
        payload.as_bytes(),
        &emitter.jkt,
        &sig.to_bytes(),
    )
}

/// `n` signed envelopes over simple distinct receipt payloads.
pub fn make_envelopes(emitter: &TestSigner, n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            signed_envelope(
                emitter,
                &format!("{{\"receipt_id\":\"r{i}\",\"step\":{i},\"amount\":\"{i}.00\"}}"),
            )
        })
        .collect()
}

/// RFC 6962 root over the first `m` envelopes.
pub fn root_over(envelopes: &[Vec<u8>], m: usize) -> [u8; 32] {
    let mut store = HashStore::new();
    for env in &envelopes[..m] {
        store.push_leaf(leaf_hash(env)).expect("push");
    }
    store.root_at(m as u64).expect("root")
}

fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, data).expect("write");
}

/// Frame envelopes into one bundle file's bytes.
pub fn frame_bundle(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&u16::try_from(e.len()).expect("entry fits u16").to_be_bytes());
        out.extend_from_slice(e);
    }
    out
}

/// Write entry bundles and level-0 hash tiles covering `envelopes`, exactly
/// as Tessera lays them out: full tiles for complete rows of 256, a partial
/// `.p/<w>` for the trailing row.
pub fn write_tiles(dir: &Path, envelopes: &[Vec<u8>]) {
    let width = usize::try_from(TILE_WIDTH).expect("width");
    for (b, chunk) in envelopes.chunks(width).enumerate() {
        let index_path = behalf_verify::tiles::tile_index_path(b as u64);
        let (entry_rel, hash_rel) = if chunk.len() == width {
            (index_path.clone(), index_path.clone())
        } else {
            (
                format!("{index_path}.p/{}", chunk.len()),
                format!("{index_path}.p/{}", chunk.len()),
            )
        };
        write(
            &dir.join("tile").join("entries").join(&entry_rel),
            &frame_bundle(chunk),
        );
        let mut hashes = Vec::new();
        for e in chunk {
            hashes.extend_from_slice(&leaf_hash(e));
        }
        write(&dir.join("tile").join("0").join(&hash_rel), &hashes);
    }
}

/// Additionally write the stale partials a growing Tessera log leaves
/// behind (GC off): bundle + hash-tile partials for an earlier size `m`.
pub fn write_stale_partials(dir: &Path, envelopes: &[Vec<u8>], m: usize) {
    let width = usize::try_from(TILE_WIDTH).expect("width");
    assert!(m < width, "stale-partial helper covers the first tile only");
    let rel = format!("000.p/{m}");
    write(
        &dir.join("tile").join("entries").join(&rel),
        &frame_bundle(&envelopes[..m]),
    );
    let mut hashes = Vec::new();
    for e in &envelopes[..m] {
        hashes.extend_from_slice(&leaf_hash(e));
    }
    write(&dir.join("tile").join("0").join(&rel), &hashes);
}

/// Write a complete, intact log directory: vkey, tiles over all envelopes,
/// and a checkpoint covering `cp_size` of them.
pub fn write_log_dir(
    dir: &Path,
    note_sk: &SigningKey,
    envelopes: &[Vec<u8>],
    cp_size: usize,
) {
    write(
        &dir.join("keys").join("checkpoint.vkey"),
        format!("{}\n", vkey_string(LOG_ORIGIN, note_sk)).as_bytes(),
    );
    write_tiles(dir, envelopes);
    let root = root_over(envelopes, cp_size);
    write(
        &dir.join("checkpoint"),
        &checkpoint_note(LOG_ORIGIN, note_sk, cp_size as u64, &root),
    );
}

/// The emitter key set JSON (export-header shape) for `--emitter-keys`.
pub fn emitter_keys_json(emitter: &TestSigner) -> String {
    format!(
        "{{\"keys\":[{{\"jkt\":\"{}\",\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}}}]}}",
        emitter.jkt, emitter.x_b64
    )
}
