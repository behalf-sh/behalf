//! Hand-rolled export builder for tests, independent of the Go writer.
//!
//! Everything here works in raw strings so tests control the exact bytes
//! that land in the file — the same byte-exactness the verifier promises.

#![allow(dead_code)] // not every integration test uses every helper

pub mod tiledir;

use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use behalf_verify::chain::compute_chain;
use behalf_verify::keys::okp_thumbprint;
use behalf_verify::pae::{pae, CHAIN_HEAD_PAYLOAD_TYPE, RECEIPT_PAYLOAD_TYPE};
use behalf_verify::util::{hex_encode, sha256};

pub const ORIGIN: &str = "behalf.sh/test-origin";

pub struct TestSigner {
    pub sk: SigningKey,
    pub x_b64: String,
    pub jkt: String,
}

/// Deterministic test key from a fixed seed byte. Never used outside tests.
pub fn test_signer(seed: u8) -> TestSigner {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let x_b64 = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
    let jkt = okp_thumbprint("Ed25519", "OKP", &x_b64).expect("thumbprint");
    TestSigner { sk, x_b64, jkt }
}

pub fn header_line(signer: &TestSigner) -> String {
    header_line_multi(&[signer])
}

pub fn header_line_multi(signers: &[&TestSigner]) -> String {
    let keys: Vec<String> = signers
        .iter()
        .map(|s| {
            format!(
                "{{\"jkt\":\"{}\",\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}}}",
                s.jkt, s.x_b64
            )
        })
        .collect();
    format!(
        "{{\"kind\":\"header\",\"format\":\"behalf.sh/export/v1\",\"log_origin\":\"{ORIGIN}\",\
         \"keys\":[{}]}}",
        keys.join(",")
    )
}

/// Sign a payload (exact bytes) and build the leaf line around it. The
/// payload string is spliced in verbatim, per the contract.
pub fn leaf_line(signer: &TestSigner, index: u64, payload_json: &str) -> String {
    let pae_bytes = pae(RECEIPT_PAYLOAD_TYPE, payload_json.as_bytes());
    let sig_b64 = BASE64_STD.encode(signer.sk.sign(&pae_bytes).to_bytes());
    let leaf_hash = hex_encode(&sha256(&pae_bytes));
    format!(
        "{{\"kind\":\"leaf\",\"index\":{index},\"payloadType\":\"{RECEIPT_PAYLOAD_TYPE}\",\
         \"payload\":{payload_json},\"sig\":{{\"keyid\":\"{}\",\"sig\":\"{sig_b64}\"}},\
         \"leaf_hash\":\"{leaf_hash}\"}}",
        signer.jkt
    )
}

/// Leaf hash of a payload exactly as `leaf_line` computes it.
pub fn leaf_hash_of(payload_json: &str) -> [u8; 32] {
    sha256(&pae(RECEIPT_PAYLOAD_TYPE, payload_json.as_bytes()))
}

/// Build and sign a head line for the given chain value.
pub fn head_line(signer: &TestSigner, count: u64, chain_hex: &str) -> String {
    let head_value = format!(
        "{{\"format\":\"behalf.sh/export/v1\",\"log_origin\":\"{ORIGIN}\",\
         \"count\":{count},\"chain\":\"{chain_hex}\"}}"
    );
    let pae_bytes = pae(CHAIN_HEAD_PAYLOAD_TYPE, head_value.as_bytes());
    let sig_b64 = BASE64_STD.encode(signer.sk.sign(&pae_bytes).to_bytes());
    format!(
        "{{\"kind\":\"head\",\"head\":{head_value},\"sig\":{{\"keyid\":\"{}\",\"sig\":\"{sig_b64}\"}}}}",
        signer.jkt
    )
}

/// A complete intact export over the given payload strings.
pub fn build_export(signer: &TestSigner, payloads: &[&str]) -> String {
    build_export_two_keys(signer, signer, payloads)
}

/// An intact export where the head is signed by a (possibly) different key
/// than the leaves, mirroring the two-key intact_tiny vector.
pub fn build_export_two_keys(
    emitter: &TestSigner,
    head_signer: &TestSigner,
    payloads: &[&str],
) -> String {
    let hashes: Vec<[u8; 32]> = payloads.iter().map(|p| leaf_hash_of(p)).collect();
    let chain_hex = hex_encode(&compute_chain(ORIGIN, &hashes));
    let mut out = String::new();
    if emitter.jkt == head_signer.jkt {
        out.push_str(&header_line(emitter));
    } else {
        out.push_str(&header_line_multi(&[emitter, head_signer]));
    }
    out.push('\n');
    for (i, p) in payloads.iter().enumerate() {
        out.push_str(&leaf_line(emitter, i as u64, p));
        out.push('\n');
    }
    out.push_str(&head_line(head_signer, payloads.len() as u64, &chain_hex));
    out.push('\n');
    out
}

/// `n` simple distinct receipt payloads (`receipt_id` r0, r1, …).
pub fn simple_payloads(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("{{\"receipt_id\":\"r{i}\",\"step\":{i},\"amount\":\"{i}.00\"}}"))
        .collect()
}

pub fn as_strs(payloads: &[String]) -> Vec<&str> {
    payloads.iter().map(String::as_str).collect()
}

// ---- delegation chains (ENG-38) -------------------------------------------

/// One minted delegation hop: the compact JWS and the claim set inside it.
pub struct TestHop {
    pub jws: String,
    /// The confirmed key's holder — whoever signs the next hop down the chain.
    pub holder: SigningKey,
    pub x_b64: String,
    pub claims: String,
}

impl TestHop {
    /// `sha256:<hex>` over the compact JWS — the address the receipt names.
    pub fn evidence_ref(&self) -> String {
        format!("sha256:{}", hex_encode(&sha256(self.jws.as_bytes())))
    }

    /// The value a child must carry as its `par_hash`.
    pub fn par_hash(&self) -> String {
        hex_encode(&sha256(self.jws.as_bytes()))
    }
}

pub const ROOT_PAR_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Mint one hop. `signer` is the key that signs it — the parent's holder key,
/// or the hop's own key at depth 0. `seed` derives the key this hop confirms.
pub fn mint_hop(
    signer: &SigningKey,
    seed: u8,
    del_depth: i64,
    del_max_depth: i64,
    par_hash: &str,
    exp: i64,
    jti: &str,
) -> TestHop {
    let holder = SigningKey::from_bytes(&[seed; 32]);
    let x_b64 = URL_SAFE_NO_PAD.encode(holder.verifying_key().to_bytes());
    let claims = format!(
        "{{\"del_depth\":{del_depth},\"del_max_depth\":{del_max_depth},\
         \"par_hash\":\"{par_hash}\",\
         \"cnf\":{{\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{x_b64}\"}}}},\
         \"exp\":{exp},\"jti\":\"{jti}\"}}"
    );
    let protected = "{\"alg\":\"EdDSA\",\"typ\":\"aat+jwt\",\"kid\":\"test\"}";
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(protected.as_bytes()),
        URL_SAFE_NO_PAD.encode(claims.as_bytes())
    );
    let sig = URL_SAFE_NO_PAD.encode(signer.sign(signing_input.as_bytes()).to_bytes());
    TestHop {
        jws: format!("{signing_input}.{sig}"),
        holder,
        x_b64,
        claims,
    }
}

/// A sound two-hop chain: a self-signed depth-0 root and one delegation above
/// it, narrowing the depth budget and expiring no later than its parent.
pub fn sound_chain() -> Vec<TestHop> {
    let root_key = SigningKey::from_bytes(&[70u8; 32]);
    let root = mint_hop(&root_key, 70, 0, 4, ROOT_PAR_HASH, 2_000_000_000, "jti-root");
    let child = mint_hop(
        &root.holder,
        71,
        1,
        4,
        &root.par_hash(),
        1_900_000_000,
        "jti-child",
    );
    vec![root, child]
}

/// A receipt payload embedding `hops` as its authority chain, with each hop's
/// claim set mirrored the way a real receipt mirrors it.
pub fn payload_with_chain(receipt_id: &str, hops: &[TestHop]) -> String {
    let chain: Vec<String> = hops
        .iter()
        .map(|h| {
            let claims = h.claims.trim_end_matches('}');
            format!(
                "{claims},\"verification\":{{\"status\":\"verified\",\"method\":\"aat-jws-ed25519\",\
                 \"evidence_ref\":\"{}\"}}}}",
                h.evidence_ref()
            )
        })
        .collect();
    format!(
        "{{\"receipt_id\":\"{receipt_id}\",\"authority\":{{\"chain\":[{}]}}}}",
        chain.join(",")
    )
}

/// The header's `tokens` section for `hops`.
pub fn tokens_json(hops: &[TestHop]) -> String {
    let entries: Vec<String> = hops
        .iter()
        .map(|h| format!("\"{}\":\"{}\"", h.evidence_ref(), h.jws))
        .collect();
    format!("{{{}}}", entries.join(","))
}

/// An intact export whose header carries `hops` as tokens.
pub fn build_export_with_tokens(
    signer: &TestSigner,
    payloads: &[&str],
    tokens_obj: &str,
) -> String {
    let hashes: Vec<[u8; 32]> = payloads.iter().map(|p| leaf_hash_of(p)).collect();
    let chain_hex = hex_encode(&compute_chain(ORIGIN, &hashes));
    let mut out = String::new();
    out.push_str(&format!(
        "{{\"kind\":\"header\",\"format\":\"behalf.sh/export/v1\",\"log_origin\":\"{ORIGIN}\",\
         \"keys\":[{{\"jkt\":\"{}\",\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}}}],\
         \"tokens\":{tokens_obj}}}",
        signer.jkt, signer.x_b64
    ));
    out.push('\n');
    for (i, p) in payloads.iter().enumerate() {
        out.push_str(&leaf_line(signer, i as u64, p));
        out.push('\n');
    }
    out.push_str(&head_line(signer, payloads.len() as u64, &chain_hex));
    out.push('\n');
    out
}
