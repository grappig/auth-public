use crate::{
    error::{KeySystemError, Result},
    models::{ClientSecurityState, ProtectedState, RevocationChecker, RevocationFreshness},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_RESPONSE_LENGTH: usize = 32_768;
const MAX_PAYLOAD_LENGTH: usize = 16_384;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;
const MAX_REVOKED_KEYS: usize = 4_096;
const MAX_LICENSE_KEY_ID_LENGTH: usize = 128;
pub const KSR1_SIGNING_PREFIX: &[u8] = b"key-system/revocation/ksr1/v1\0";

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveSignature([u8; SIGNATURE_LENGTH]);

#[derive(Clone, Copy, Debug)]
pub struct RevocationPolicy {
    pub max_age: Duration,
    pub max_future_issue_time: Duration,
}

impl RevocationPolicy {
    pub fn default_policy() -> Result<Self> {
        let policy = Self {
            max_age: Duration::days(7),
            max_future_issue_time: Duration::minutes(5),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_age <= Duration::zero() || self.max_future_issue_time < Duration::zero() {
            return Err(KeySystemError::InvalidPolicy(
                "revocation durations must be positive/non-negative",
            ));
        }
        Ok(())
    }
}

pub struct RevocationVerifier {
    authority_key: VerifyingKey,
    policy: RevocationPolicy,
}

impl RevocationVerifier {
    pub fn new_embedded(
        embedded_revocation_authority_key: &str,
        policy: RevocationPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        if embedded_revocation_authority_key.len() > 128 {
            return Err(KeySystemError::InvalidPublicKey);
        }
        let mut decoded = URL_SAFE_NO_PAD.decode(embedded_revocation_authority_key)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] = match decoded.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                decoded.zeroize();
                return Err(KeySystemError::InvalidPublicKey);
            }
        };
        decoded.zeroize();
        let authority_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| KeySystemError::InvalidPublicKey)?;
        Ok(Self {
            authority_key,
            policy,
        })
    }

    pub fn verify(
        &self,
        response: &str,
        now: DateTime<Utc>,
        state: &mut ClientSecurityState,
    ) -> Result<RevocationList> {
        let mut candidate = state.clone();
        let list = self.verify_inner(response, now, &mut candidate)?;
        *state = candidate;
        Ok(list)
    }

    pub fn verify_with_protected_state(
        &self,
        response: &str,
        now: DateTime<Utc>,
        state_store: &mut dyn ProtectedState,
    ) -> Result<RevocationList> {
        let mut state = state_store.load()?;
        let list = self.verify(response, now, &mut state)?;
        state_store.store(&state)?;
        Ok(list)
    }

    fn verify_inner(
        &self,
        response: &str,
        now: DateTime<Utc>,
        state: &mut ClientSecurityState,
    ) -> Result<RevocationList> {
        if response.len() > MAX_RESPONSE_LENGTH {
            return Err(KeySystemError::TokenTooLarge);
        }
        let mut parts = response.split('.');
        let version = parts
            .next()
            .ok_or(KeySystemError::MalformedRevocationResponse)?;
        let payload_segment = parts
            .next()
            .ok_or(KeySystemError::MalformedRevocationResponse)?;
        let signature_segment = parts
            .next()
            .ok_or(KeySystemError::MalformedRevocationResponse)?;
        if parts.next().is_some()
            || !bool::from(version.as_bytes().ct_eq(b"ksr1"))
            || payload_segment.is_empty()
            || signature_segment.is_empty()
        {
            return Err(KeySystemError::MalformedRevocationResponse);
        }
        let mut payload = URL_SAFE_NO_PAD.decode(payload_segment)?;
        if payload.len() > MAX_PAYLOAD_LENGTH {
            payload.zeroize();
            return Err(KeySystemError::TokenTooLarge);
        }
        let mut signature_bytes = URL_SAFE_NO_PAD.decode(signature_segment)?;
        let signature_array: [u8; SIGNATURE_LENGTH] = match signature_bytes.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                signature_bytes.zeroize();
                return Err(KeySystemError::InvalidRevocationSignature);
            }
        };
        signature_bytes.zeroize();
        let signature = Signature::from_bytes(&SensitiveSignature(signature_array).0);
        let signing_input = revocation_signing_preimage(payload_segment);
        self.authority_key
            .verify_strict(&signing_input, &signature)
            .map_err(|_| KeySystemError::InvalidRevocationSignature)?;
        let parsed: SignedRevocationPayload = serde_json::from_slice(&payload)
            .map_err(|_| KeySystemError::MalformedRevocationResponse)?;
        let response_hash: [u8; 32] = Sha256::digest(&payload).into();
        payload.zeroize();
        parsed.validate()?;
        let latest_issue_time = now
            .checked_add_signed(self.policy.max_future_issue_time)
            .ok_or(KeySystemError::StaleRevocationResponse)?;
        let oldest_issue_time = now
            .checked_sub_signed(self.policy.max_age)
            .ok_or(KeySystemError::StaleRevocationResponse)?;
        let latest_expiry = parsed
            .issued_at
            .checked_add_signed(self.policy.max_age)
            .ok_or(KeySystemError::StaleRevocationResponse)?;
        if parsed.issued_at > latest_issue_time
            || parsed.issued_at < oldest_issue_time
            || now >= parsed.expires_at
            || parsed.expires_at > latest_expiry
        {
            return Err(KeySystemError::StaleRevocationResponse);
        }
        if let Some(previous) = state.revocation() {
            if parsed.sequence < previous.sequence
                || parsed.issued_at < previous.issued_at
                || (parsed.sequence == previous.sequence
                    && !bool::from(response_hash.ct_eq(&previous.response_hash)))
            {
                return Err(KeySystemError::RevocationRollback);
            }
        }
        state.set_revocation(RevocationFreshness {
            sequence: parsed.sequence,
            issued_at: parsed.issued_at,
            response_hash,
        });
        Ok(RevocationList {
            revoked_key_ids: parsed.revoked_key_ids,
            expires_at: parsed.expires_at,
        })
    }
}

fn revocation_signing_preimage(payload_segment: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(KSR1_SIGNING_PREFIX.len() + payload_segment.len());
    message.extend_from_slice(KSR1_SIGNING_PREFIX);
    message.extend_from_slice(payload_segment.as_bytes());
    message
}

#[derive(Clone, Debug)]
pub struct RevocationList {
    revoked_key_ids: Vec<String>,
    expires_at: DateTime<Utc>,
}

impl RevocationList {
    pub fn expires_at(&self) -> Result<DateTime<Utc>> {
        Ok(self.expires_at)
    }

    pub fn is_fresh_at(&self, now: DateTime<Utc>) -> Result<bool> {
        Ok(now < self.expires_at)
    }
}

impl RevocationChecker for RevocationList {
    fn is_revoked(&self, key_id: &str) -> Result<bool> {
        if key_id.is_empty() || key_id.len() > MAX_LICENSE_KEY_ID_LENGTH {
            return Err(KeySystemError::InvalidPolicy("invalid license key ID"));
        }
        let mut found = 0_u8;
        for revoked_key_id in &self.revoked_key_ids {
            found |= u8::from(bool::from(
                revoked_key_id.as_bytes().ct_eq(key_id.as_bytes()),
            ));
        }
        Ok(found == 1)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRevocationPayload {
    sequence: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_key_ids: Vec<String>,
}

impl SignedRevocationPayload {
    fn validate(&self) -> Result<()> {
        if self.expires_at <= self.issued_at
            || self.revoked_key_ids.len() > MAX_REVOKED_KEYS
            || self
                .revoked_key_ids
                .iter()
                .any(|key_id| key_id.is_empty() || key_id.len() > MAX_LICENSE_KEY_ID_LENGTH)
        {
            return Err(KeySystemError::MalformedRevocationResponse);
        }
        Ok(())
    }
}
