use crate::{
    error::{KeySystemError, Result},
    models::{ClockFloor, LicenseClaims, RevocationChecker, VerificationPolicy},
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

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveSignature([u8; SIGNATURE_LENGTH]);

pub struct LicenseVerifier {
    public_key: VerifyingKey,
    expected_target: String,
    policy: VerificationPolicy,
}

impl LicenseVerifier {
    pub fn new_embedded(
        embedded_public_key: &str,
        software_target: impl Into<String>,
        policy: VerificationPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let expected_target = software_target.into();
        if expected_target.is_empty() || expected_target.len() > 128 {
            return Err(KeySystemError::InvalidPolicy("invalid software target"));
        }
        let decoded = URL_SAFE_NO_PAD.decode(embedded_public_key)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeySystemError::InvalidPublicKey)?;
        let public_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| KeySystemError::InvalidPublicKey)?;
        Ok(Self {
            public_key,
            expected_target,
            policy,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        now: DateTime<Utc>,
        clock_floor: &mut ClockFloor,
        revocation: Option<&dyn RevocationChecker>,
    ) -> Result<License> {
        if token.len() > MAX_TOKEN_LENGTH {
            return Err(KeySystemError::TokenTooLarge);
        }
        let mut parts = token.split('.');
        let version = parts.next().ok_or(KeySystemError::MalformedToken)?;
        let payload_segment = parts.next().ok_or(KeySystemError::MalformedToken)?;
        let signature_segment = parts.next().ok_or(KeySystemError::MalformedToken)?;
        if parts.next().is_some()
            || version.as_bytes().ct_eq(b"ksl1").unwrap_u8() != 1
            || payload_segment.is_empty()
            || signature_segment.is_empty()
        {
            return Err(KeySystemError::MalformedToken);
        }

        let mut payload = URL_SAFE_NO_PAD.decode(payload_segment)?;
        if payload.len() > MAX_PAYLOAD_LENGTH {
            payload.zeroize();
            return Err(KeySystemError::TokenTooLarge);
        }
        let mut signature_bytes = URL_SAFE_NO_PAD.decode(signature_segment)?;
        let signature_array: [u8; SIGNATURE_LENGTH] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeySystemError::InvalidSignature)?;
        signature_bytes.zeroize();
        let sensitive_signature = SensitiveSignature(signature_array);
        let signature = Signature::from_bytes(&sensitive_signature.0);
        self.public_key
            .verify_strict(payload_segment.as_bytes(), &signature)
            .map_err(|_| KeySystemError::InvalidSignature)?;
        let claims = LicenseClaims::from_json(&payload);
        payload.zeroize();
        let claims = claims?;
        if claims
            .software_target()?
            .as_bytes()
            .ct_eq(self.expected_target.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(KeySystemError::SoftwareTargetMismatch);
        }
        if claims.issued_at()? > now + self.policy.max_future_issue_time {
            return Err(KeySystemError::IssuedInFuture);
        }
        clock_floor.advance(now, self.policy.max_clock_drift)?;
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
