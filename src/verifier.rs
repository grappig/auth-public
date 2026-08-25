use crate::{
    error::{KeySystemError, Result},
    models::{
        ClientSecurityState, ClockFloor, LicenseClaims, ProtectedState, RevocationChecker,
        VerificationPolicy,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_TOKEN_LENGTH: usize = 16_384;
const MAX_PAYLOAD_LENGTH: usize = 8_192;
const PUBLIC_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;
const MAX_KEY_RING_SIZE: usize = 16;
const MAX_SIGNING_KEY_ID_LENGTH: usize = 64;
/// Exact Ed25519 domain separator for `ksl2` signatures.
pub const KSL2_SIGNING_PREFIX: &[u8] = b"key-system/license/ksl2/v1\0";

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveSignature([u8; SIGNATURE_LENGTH]);

/// A public signing key used by a `ksl2` token. The identifier is signed as part of the token.
#[derive(Clone, Debug)]
pub struct EmbeddedVerificationKey {
    pub key_id: String,
    pub public_key: String,
}

/// A bounded, application-embedded public key ring used to verify rotation-ready `ksl2` tokens.
#[derive(Clone, Debug)]
pub struct VerificationKeyRing {
    keys: Vec<(String, VerifyingKey)>,
}

impl VerificationKeyRing {
    pub fn new(keys: Vec<EmbeddedVerificationKey>) -> Result<Self> {
        if keys.is_empty() || keys.len() > MAX_KEY_RING_SIZE {
            return Err(KeySystemError::InvalidPolicy("invalid key ring size"));
        }
        let mut parsed_keys = Vec::with_capacity(keys.len());
        for key in keys {
            validate_signing_key_id(&key.key_id)?;
            if parsed_keys.iter().any(|(id, _)| id == &key.key_id) {
                return Err(KeySystemError::InvalidPolicy("duplicate signing key ID"));
            }
            parsed_keys.push((key.key_id, decode_public_key(&key.public_key)?));
        }
        Ok(Self { keys: parsed_keys })
    }

    fn lookup(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys
            .iter()
            .find(|(candidate, _)| bool::from(candidate.as_bytes().ct_eq(key_id.as_bytes())))
            .map(|(_, key)| key)
    }
}

pub struct LicenseVerifier {
    legacy_public_key: Option<VerifyingKey>,
    key_ring: VerificationKeyRing,
    expected_target: String,
    policy: VerificationPolicy,
}

impl LicenseVerifier {
    /// Construct a legacy-only verifier that accepts existing `ksl1` tokens.
    pub fn new_embedded(
        embedded_public_key: &str,
        software_target: impl Into<String>,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        Self::new_with_legacy_key(
            Some(embedded_public_key),
            VerificationKeyRing { keys: Vec::new() },
            software_target,
            policy,
        )
    }

    /// Construct a verifier that accepts only key-rotatable `ksl2` tokens.
    pub fn new_key_ring(
        key_ring: VerificationKeyRing,
        software_target: impl Into<String>,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        Self::new_with_legacy_key(None, key_ring, software_target, policy)
    }

    /// Construct a transition verifier that accepts legacy `ksl1` and rotation-ready `ksl2`.
    pub fn new_with_legacy_key(
        legacy_public_key: Option<&str>,
        key_ring: VerificationKeyRing,
        software_target: impl Into<String>,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let expected_target = software_target.into();
        if expected_target.is_empty() || expected_target.len() > 128 {
            return Err(KeySystemError::InvalidPolicy("invalid software target"));
        }
        let legacy_public_key = legacy_public_key.map(decode_public_key).transpose()?;
        Ok(Self {
            legacy_public_key,
            key_ring,
            expected_target,
            policy,
        })
    }

    /// Legacy API using an in-memory clock floor. Use protected state for restart-safe rollback
    /// protection in production.
    pub fn verify(
        &self,
        token: &str,
        now: DateTime<Utc>,
        clock_floor: &mut ClockFloor,
        revocation: Option<&dyn RevocationChecker>,
    ) -> Result<License> {
        let mut state = ClientSecurityState::new(clock_floor.last_verified_at()?)?;
        let license = self.verify_with_state(token, now, &mut state, revocation)?;
        *clock_floor = ClockFloor::new(state.last_verified_at()?)?;
        Ok(license)
    }

    /// Verify using caller-owned state. Persist this state between launches for rollback defense.
    pub fn verify_with_state(
        &self,
        token: &str,
        now: DateTime<Utc>,
        state: &mut ClientSecurityState,
        revocation: Option<&dyn RevocationChecker>,
    ) -> Result<License> {
        let mut candidate = state.clone();
        let license = self.verify_inner(token, now, &mut candidate, revocation)?;
        *state = candidate;
        Ok(license)
    }

    /// Verify and persist anti-rollback state before returning a license.
    pub fn verify_with_protected_state(
        &self,
        token: &str,
        now: DateTime<Utc>,
        state_store: &mut dyn ProtectedState,
        revocation: Option<&dyn RevocationChecker>,
    ) -> Result<License> {
        let mut state = state_store.load()?;
        let license = self.verify_with_state(token, now, &mut state, revocation)?;
        state_store.store(&state)?;
        Ok(license)
    }

    fn verify_inner(
        &self,
        token: &str,
        now: DateTime<Utc>,
        state: &mut ClientSecurityState,
        revocation: Option<&dyn RevocationChecker>,
    ) -> Result<License> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(KeySystemError::TokenTooLarge);
        }
        let mut parts = token.split('.');
        let version = parts.next().ok_or(KeySystemError::MalformedToken)?;
        let first_segment = parts.next().ok_or(KeySystemError::MalformedToken)?;
        let second_segment = parts.next().ok_or(KeySystemError::MalformedToken)?;
        let final_segment = parts.next();
        let (payload_segment, signature_segment, signing_input, public_key) =
            if bool::from(version.as_bytes().ct_eq(b"ksl1")) {
                if final_segment.is_some() || first_segment.is_empty() || second_segment.is_empty()
                {
                    return Err(KeySystemError::MalformedToken);
                }
                (
                    first_segment,
                    second_segment,
                    SigningInput::Borrowed(first_segment.as_bytes()),
                    self.legacy_public_key
                        .as_ref()
                        .ok_or(KeySystemError::UnknownSigningKey)?,
                )
            } else if bool::from(version.as_bytes().ct_eq(b"ksl2")) {
                let signature_segment = final_segment.ok_or(KeySystemError::MalformedToken)?;
                if parts.next().is_some()
                    || first_segment.is_empty()
                    || second_segment.is_empty()
                    || signature_segment.is_empty()
                {
                    return Err(KeySystemError::MalformedToken);
                }
                validate_signing_key_id(first_segment)
                    .map_err(|_| KeySystemError::MalformedToken)?;
                let public_key = self
                    .key_ring
                    .lookup(first_segment)
                    .ok_or(KeySystemError::UnknownSigningKey)?;
                let signing_input = license_signing_preimage(first_segment, second_segment);
                (second_segment, signature_segment, signing_input, public_key)
            } else {
                return Err(KeySystemError::MalformedToken);
            };

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
                return Err(KeySystemError::InvalidSignature);
            }
        };
        signature_bytes.zeroize();
        let sensitive_signature = SensitiveSignature(signature_array);
        let signature = Signature::from_bytes(&sensitive_signature.0);
        public_key
            .verify_strict(signing_input.as_ref(), &signature)
            .map_err(|_| KeySystemError::InvalidSignature)?;
        let claims = LicenseClaims::from_json(&payload);
        payload.zeroize();
        let claims = claims?;
        if !bool::from(
            claims
                .software_target()?
                .as_bytes()
                .ct_eq(self.expected_target.as_bytes()),
        ) {
            return Err(KeySystemError::SoftwareTargetMismatch);
        }
        let latest_issue_time = now
            .checked_add_signed(self.policy.max_future_issue_time)
            .ok_or(KeySystemError::IssuedInFuture)?;
        if claims.issued_at()? > latest_issue_time {
            return Err(KeySystemError::IssuedInFuture);
        }
        state.advance_clock(now, self.policy.max_clock_drift)?;
        if claims.is_expired_at(now)? {
            return Err(KeySystemError::Expired);
        }
        if let Some(revocation) = revocation {
            if revocation.is_revoked(claims.key_id()?)? {
                return Err(KeySystemError::Revoked);
            }
        }
        Ok(License {
            claims,
            verified_at: now,
        })
    }
}

enum SigningInput<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for SigningInput<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

fn license_signing_preimage(signing_key_id: &str, payload_segment: &str) -> SigningInput<'static> {
    let mut message = Vec::with_capacity(
        KSL2_SIGNING_PREFIX.len() + signing_key_id.len() + 1 + payload_segment.len(),
    );
    message.extend_from_slice(KSL2_SIGNING_PREFIX);
    message.extend_from_slice(signing_key_id.as_bytes());
    message.push(b'.');
    message.extend_from_slice(payload_segment.as_bytes());
    SigningInput::Owned(message)
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey> {
    if encoded.len() > 128 {
        return Err(KeySystemError::InvalidPublicKey);
    }
    let mut decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    let bytes: [u8; PUBLIC_KEY_LENGTH] = match decoded.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            decoded.zeroize();
            return Err(KeySystemError::InvalidPublicKey);
        }
    };
    decoded.zeroize();
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeySystemError::InvalidPublicKey)
}

fn validate_signing_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > MAX_SIGNING_KEY_ID_LENGTH
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(KeySystemError::InvalidPolicy("invalid signing key ID"));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct License {
    claims: LicenseClaims,
    verified_at: DateTime<Utc>,
}

impl License {
    pub fn claims(&self) -> Result<&LicenseClaims> {
        Ok(&self.claims)
    }

    pub fn verified_at(&self) -> Result<DateTime<Utc>> {
        Ok(self.verified_at)
    }

    pub fn is_valid(&self) -> Result<bool> {
        self.is_valid_at(Utc::now())
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> Result<bool> {
        Ok(!self.claims.is_expired_at(now)?)
    }

    pub fn is_expired(&self) -> Result<bool> {
        self.is_expired_at(Utc::now())
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> Result<bool> {
        self.claims.is_expired_at(now)
    }

    pub fn has_feature(&self, feature: &str) -> Result<bool> {
        self.claims.has_feature(feature)
    }

    pub fn matches_hardware(&self, hardware_id: &str) -> Result<bool> {
        self.claims.matches_hardware(hardware_id)
    }

    pub fn is_revoked(&self, checker: &dyn RevocationChecker) -> Result<bool> {
        checker.is_revoked(self.claims.key_id()?)
    }
}
