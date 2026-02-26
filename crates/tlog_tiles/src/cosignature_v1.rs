// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use signed_note::{compute_key_id, KeyName, NoteError, NoteSignature, NoteVerifier, SignatureType};

use crate::{CheckpointSigner, CheckpointText, UnixTimestamp};

/// The first line present in a signed note using the cosignature-v1 signature scheme
const COSIGNATURE_V1_DOMAIN_SEPARATING_PREFIX: &[u8] = b"cosignature/v1";

/// Implementation of [`CheckpointSigner`] that produces a timestamped Ed25519 cosignature/v1 (alg
/// 0x04 from <https://c2sp.org/signed-note>).
pub struct CosignatureV1CheckpointSigner(CustomPrefixTimestampedCheckpointSigner);

impl CosignatureV1CheckpointSigner {
    pub fn new(name: KeyName, k: Ed25519SigningKey) -> Self {
        Self(CustomPrefixTimestampedCheckpointSigner::new(
            name,
            k,
            COSIGNATURE_V1_DOMAIN_SEPARATING_PREFIX.to_vec(),
            SignatureType::CosignatureV1 as u8,
        ))
    }
}

impl CheckpointSigner for CosignatureV1CheckpointSigner {
    fn name(&self) -> &KeyName {
        self.0.name()
    }

    fn key_id(&self) -> u32 {
        self.0.key_id()
    }

    fn sign(
        &self,
        timestamp_unix_millis: UnixTimestamp,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        self.0.sign(timestamp_unix_millis, checkpoint)
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        self.0.verifier()
    }
}

/// Implementation of [`CheckpointSigner`] that produces a timestamped Ed25519 signature (alg 0x04
/// from <https://c2sp.org/signed-note>). Uses a custom domain separating prefix and a custom
/// signature type. When the domain separating prefix is `cosignature/v1` and the signature type is
/// `0x04`, this is equivalent to [`CosignatureV1CheckpointSigner`].
pub struct CustomPrefixTimestampedCheckpointSigner {
    v: CustomPrefixTimestampedNoteVerifier,
    k: Ed25519SigningKey,
    domain_separating_prefix: Vec<u8>,
}

impl CustomPrefixTimestampedCheckpointSigner {
    /// Returns a new `CosignatureV1CheckpointSigner`.
    pub fn new(
        name: KeyName,
        k: Ed25519SigningKey,
        domain_separating_prefix: Vec<u8>,
        signature_type: u8,
    ) -> Self {
        Self {
            v: CustomPrefixTimestampedNoteVerifier::new(
                name,
                k.verifying_key(),
                domain_separating_prefix.clone(),
                signature_type,
            ),
            k,
            domain_separating_prefix,
        }
    }
}

impl CheckpointSigner for CustomPrefixTimestampedCheckpointSigner {
    fn name(&self) -> &KeyName {
        self.v.name()
    }

    fn key_id(&self) -> u32 {
        self.v.key_id()
    }

    fn sign(
        &self,
        timestamp_unix_millis: UnixTimestamp,
        checkpoint: &CheckpointText,
    ) -> Result<NoteSignature, NoteError> {
        // Timestamp is in seconds
        let timestamp_unix_secs = timestamp_unix_millis / 1000;

        let msg = construct_timestamped_message(
            &self.domain_separating_prefix,
            &checkpoint,
            timestamp_unix_secs,
        );

        // Ed25519 signing cannot fail
        let sig = self.k.try_sign(&msg).unwrap();

        // Now format the final signature according to <https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md#format>.
        // struct timestamped_signature {
        //     u64 timestamp;
        //     u8 signature[64];
        // }
        let mut note_sig = Vec::new();
        note_sig
            .write_u64::<BigEndian>(timestamp_unix_secs)
            .unwrap();
        note_sig.extend(&sig.to_bytes());

        // Return the note signature.
        Ok(NoteSignature::new(
            self.name().clone(),
            self.key_id(),
            note_sig,
        ))
    }

    fn verifier(&self) -> Box<dyn NoteVerifier> {
        Box::new(self.v.clone())
    }
}

/// Verifier for the timestamped Ed25519 cosignature type defined in <https://c2sp.org/tlog-cosignature>.
#[derive(Clone)]
pub struct CosignatureV1NoteVerifier(CustomPrefixTimestampedNoteVerifier);

impl CosignatureV1NoteVerifier {
    pub fn new(name: KeyName, verifying_key: Ed25519VerifyingKey) -> Self {
        Self(CustomPrefixTimestampedNoteVerifier::new(
            name,
            verifying_key,
            COSIGNATURE_V1_DOMAIN_SEPARATING_PREFIX.to_vec(),
            SignatureType::CosignatureV1 as u8,
        ))
    }
}

impl NoteVerifier for CosignatureV1NoteVerifier {
    fn name(&self) -> &KeyName {
        self.0.name()
    }

    fn key_id(&self) -> u32 {
        self.0.key_id()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.0.verify(msg, sig)
    }

    fn extract_timestamp_millis(&self, sig: &[u8]) -> Result<Option<u64>, NoteError> {
        self.0.extract_timestamp_millis(sig)
    }
}

/// Verifier for the timestamped Ed25519 cosignature type defined in
/// <https://c2sp.org/tlog-cosignature>. Uses a custom domain separating prefix and custom signature
/// type. When the domain separating prefix is `cosignature/v1` and the signature type is `0x04`,
/// this is equivalent to [`CosignatureV1NoteVerifier`].
#[derive(Clone)]
pub struct CustomPrefixTimestampedNoteVerifier {
    name: KeyName,
    id: u32,
    verifying_key: Ed25519VerifyingKey,
    domain_separating_prefix: Vec<u8>,
}

impl CustomPrefixTimestampedNoteVerifier {
    pub fn new(
        name: KeyName,
        verifying_key: Ed25519VerifyingKey,
        domain_separating_prefix: Vec<u8>,
        signature_type: u8,
    ) -> Self {
        let id = {
            let pubkey = [&[signature_type], verifying_key.to_bytes().as_slice()].concat();
            compute_key_id(&name, &pubkey)
        };

        Self {
            name,
            id,
            verifying_key,
            domain_separating_prefix,
        }
    }
}

impl NoteVerifier for CustomPrefixTimestampedNoteVerifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], mut sig: &[u8]) -> bool {
        // The message itself should be a valid checkpoint.
        let Ok(checkpoint) = CheckpointText::from_bytes(msg) else {
            return false;
        };
        // timestamped_signature.timestamp
        let Ok(sig_timestamp) = sig.read_u64::<BigEndian>() else {
            return false;
        };
        // timestamped_signature.signature
        let sig_bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH] = match sig.try_into() {
            Ok(ok) => ok,
            Err(_) => return false,
        };

        // Construct message to be signed from <https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md#signed-message>.
        let msg = construct_timestamped_message(
            &self.domain_separating_prefix,
            &checkpoint,
            sig_timestamp,
        );
        self.verifying_key
            .verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_ok()
    }

    fn extract_timestamp_millis(&self, mut sig: &[u8]) -> Result<Option<u64>, NoteError> {
        // The timestamp is the first 8 bytes of the signature, and is in seconds.
        let ts = sig
            .read_u64::<BigEndian>()
            .map_err(|_| NoteError::Timestamp)?;
        Ok(Some(ts * 1000))
    }
}

/// Produces the text of a note to be signed by the timestamped signing algorithm. This is of the form:
/// ```
/// <domain_separating_prefix>
/// time <sig_timestamp>
/// <checkpoint>
/// ```
fn construct_timestamped_message(
    domain_separating_prefix: &[u8],
    checkpoint: &CheckpointText,
    sig_timestamp: u64,
) -> Vec<u8> {
    [
        domain_separating_prefix,
        b"\ntime ",
        sig_timestamp.to_string().as_bytes(),
        b"\n",
        checkpoint.to_bytes().as_ref(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {

    use crate::{open_checkpoint, record_hash, TreeWithTimestamp};

    use super::*;
    use rand::rngs::OsRng;
    use signed_note::VerifierList;

    #[test]
    fn test_cosignature_v1_sign_verify() {
        let mut rng = OsRng;

        let origin = "example.com/origin";
        let timestamp = 100;
        let tree_size = 4;

        // Make a tree head and sign it
        let tree = TreeWithTimestamp::new(tree_size, record_hash(b"hello world"), timestamp);
        let signer = {
            let sk = Ed25519SigningKey::generate(&mut rng);
            let name = KeyName::new("my-signer".into()).unwrap();
            CosignatureV1CheckpointSigner::new(name, sk)
        };
        let checkpoint = tree.sign(origin, &[], &[&signer], &mut rng).unwrap();

        // Now verify the signed checkpoint
        let verifier = signer.verifier();
        open_checkpoint(
            origin,
            &VerifierList::new(vec![verifier]),
            timestamp,
            &checkpoint,
        )
        .unwrap();
    }
}
