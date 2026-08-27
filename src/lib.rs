#![forbid(unsafe_code)]
//! Public, verification-only SDK for `ksl1` and key-rotatable `ksl2` Ed25519 licenses.
//!
//! Embed one application-specific public key in each product binary. This crate deliberately
//! contains no signing API, private-key parser, key generator, or server credential support.

mod error;
mod models;
mod revocation;
mod verifier;

pub use error::{KeySystemError, Result};
pub use models::{
    ClientSecurityState, ClockFloor, LicenseClaims, ProtectedState, RevocationChecker,
    VerificationPolicy,
};
pub use revocation::{KSR1_SIGNING_PREFIX, RevocationList, RevocationPolicy, RevocationVerifier};
pub use verifier::{
    EmbeddedVerificationKey, KSL2_SIGNING_PREFIX, License, LicenseVerifier, VerificationKeyRing,
};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{Duration, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use serde_json::json;

    fn now() -> chrono::DateTime<Utc> {
        Utc::now()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key(key: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
    }

    fn claims(now: chrono::DateTime<Utc>, key_id: &str) -> String {
        json!({
            "key_id": key_id,
            "client_id": "client-1",
            "software_target": "desktop-app",
            "tier": "pro",
            "issued_at": now - Duration::hours(1),
            "expires_at": now + Duration::days(30),
            "features": ["reports"],
            "hardware_id": null
        })
        .to_string()
    }

    fn license_token(
        version: &str,
        signing_key_id: Option<&str>,
        key: &SigningKey,
        body: &str,
    ) -> String {
        let payload = URL_SAFE_NO_PAD.encode(body);
        let signed = match signing_key_id {
            Some(key_id) => {
                let mut value = Vec::new();
                value.extend_from_slice(KSL2_SIGNING_PREFIX);
                value.extend_from_slice(key_id.as_bytes());
                value.push(b'.');
                value.extend_from_slice(payload.as_bytes());
                value
            }
            None => payload.as_bytes().to_vec(),
        };
        let signature = URL_SAFE_NO_PAD.encode(key.sign(&signed).to_bytes());
        match signing_key_id {
            Some(key_id) => format!("{version}.{key_id}.{payload}.{signature}"),
            None => format!("{version}.{payload}.{signature}"),
        }
    }

    fn revocation_response(
        key: &SigningKey,
        sequence: u64,
        issued_at: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
        revoked_key_ids: &[&str],
    ) -> String {
        let payload = URL_SAFE_NO_PAD.encode(
            json!({
                "sequence": sequence,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "revoked_key_ids": revoked_key_ids,
            })
            .to_string(),
        );
        let mut signing_input = KSR1_SIGNING_PREFIX.to_vec();
        signing_input.extend_from_slice(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(key.sign(&signing_input).to_bytes());
        format!("ksr1.{payload}.{signature}")
    }

    #[test]
    fn verifies_legacy_and_rotated_tokens() -> Result<()> {
        let time = now();
        let old = signing_key(1);
        let new = signing_key(2);
        let ring = VerificationKeyRing::new(vec![EmbeddedVerificationKey {
            key_id: "2026-q3".to_owned(),
            public_key: public_key(&new),
        }])?;
        let verifier = LicenseVerifier::new_with_legacy_key(
            Some(&public_key(&old)),
            ring,
            "desktop-app",
            VerificationPolicy::default_policy()?,
        )?;
        let legacy = license_token("ksl1", None, &old, &claims(time, "license-old"));
        let rotated = license_token("ksl2", Some("2026-q3"), &new, &claims(time, "license-new"));
        let mut state = ClientSecurityState::new(None)?;
        assert_eq!(
            verifier
                .verify_with_state(&legacy, time, &mut state, None)?
                .claims()?
                .key_id()?,
            "license-old"
        );
        assert_eq!(
            verifier
                .verify_with_state(&rotated, time, &mut state, None)?
                .claims()?
                .key_id()?,
            "license-new"
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_or_unknown_rotation_tokens() -> Result<()> {
        let key = signing_key(3);
        let verifier = LicenseVerifier::new_key_ring(
            VerificationKeyRing::new(vec![EmbeddedVerificationKey {
                key_id: "active".to_owned(),
                public_key: public_key(&key),
            }])?,
            "desktop-app",
            VerificationPolicy::default_policy()?,
        )?;
        let mut state = ClientSecurityState::new(None)?;
        assert!(matches!(
            verifier.verify_with_state("ksl2.active.payload", now(), &mut state, None),
            Err(KeySystemError::MalformedToken)
        ));
        let token = license_token("ksl2", Some("unknown"), &key, &claims(now(), "license-1"));
        assert!(matches!(
            verifier.verify_with_state(&token, now(), &mut state, None),
            Err(KeySystemError::UnknownSigningKey)
        ));
        assert!(matches!(
            verifier.verify_with_state("ksl2.bad!.x.y", now(), &mut state, None),
            Err(KeySystemError::MalformedToken)
        ));
        Ok(())
    }

    #[test]
    fn verifies_fresh_signed_revocations_and_rejects_rollback() -> Result<()> {
        let time = now();
        let authority = signing_key(4);
        let verifier = RevocationVerifier::new_embedded(
            &public_key(&authority),
            RevocationPolicy::default_policy()?,
        )?;
        let mut state = ClientSecurityState::new(None)?;
        let current = revocation_response(
            &authority,
            9,
            time - Duration::minutes(1),
            time + Duration::days(1),
            &["license-revoked"],
        );
        let list = verifier.verify(&current, time, &mut state)?;
        assert!(list.is_revoked("license-revoked")?);
        let rollback = revocation_response(
            &authority,
            8,
            time - Duration::minutes(2),
            time + Duration::days(1),
            &[],
        );
        assert!(matches!(
            verifier.verify(&rollback, time, &mut state),
            Err(KeySystemError::RevocationRollback)
        ));
        let altered_same_sequence = revocation_response(
            &authority,
            9,
            time - Duration::minutes(1),
            time + Duration::days(1),
            &[],
        );
        assert!(matches!(
            verifier.verify(&altered_same_sequence, time, &mut state),
            Err(KeySystemError::RevocationRollback)
        ));
        Ok(())
    }

    #[test]
    fn rejects_expired_and_wrong_authority_revocations() -> Result<()> {
        let time = now();
        let authority = signing_key(5);
        let other = signing_key(6);
        let verifier = RevocationVerifier::new_embedded(
            &public_key(&authority),
            RevocationPolicy::default_policy()?,
        )?;
        let expired = revocation_response(
            &authority,
            1,
            time - Duration::days(2),
            time - Duration::seconds(1),
            &[],
        );
        let mut state = ClientSecurityState::new(None)?;
        assert!(matches!(
            verifier.verify(&expired, time, &mut state),
            Err(KeySystemError::StaleRevocationResponse)
        ));
        let wrong_authority = revocation_response(&other, 2, time, time + Duration::days(1), &[]);
        assert!(matches!(
            verifier.verify(&wrong_authority, time, &mut state),
            Err(KeySystemError::InvalidRevocationSignature)
        ));
        let overlong = revocation_response(&authority, 3, time, time + Duration::days(8), &[]);
        assert!(matches!(
            verifier.verify(&overlong, time, &mut state),
            Err(KeySystemError::StaleRevocationResponse)
        ));
        Ok(())
    }

    #[derive(Debug)]
    struct MemoryProtectedState {
        state: ClientSecurityState,
        writes: usize,
    }

    impl ProtectedState for MemoryProtectedState {
        fn load(&self) -> Result<ClientSecurityState> {
            Ok(self.state.clone())
        }

        fn store(&mut self, state: &ClientSecurityState) -> Result<()> {
            self.state = state.clone();
            self.writes += 1;
            Ok(())
        }
    }

    #[test]
    fn protected_state_is_written_only_after_a_successful_verification() -> Result<()> {
        let time = now();
        let authority = signing_key(8);
        let verifier = RevocationVerifier::new_embedded(
            &public_key(&authority),
            RevocationPolicy::default_policy()?,
        )?;
        let mut state = MemoryProtectedState {
            state: ClientSecurityState::new(None)?,
            writes: 0,
        };
        let valid = revocation_response(&authority, 1, time, time + Duration::days(1), &[]);
        verifier.verify_with_protected_state(&valid, time, &mut state)?;
        assert_eq!(state.writes, 1);
        let stale = revocation_response(
            &authority,
            2,
            time - Duration::days(8),
            time - Duration::seconds(1),
            &[],
        );
        assert!(matches!(
            verifier.verify_with_protected_state(&stale, time, &mut state),
            Err(KeySystemError::StaleRevocationResponse)
        ));
        assert_eq!(state.writes, 1);
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_token_text_never_panics(token in ".{0,17000}") {
            let key = signing_key(7);
            let verifier = LicenseVerifier::new_embedded(
                &public_key(&key),
                "desktop-app",
                VerificationPolicy {
                    max_clock_drift: chrono::Duration::minutes(5),
                    max_future_issue_time: chrono::Duration::minutes(5),
                },
            );
            let state = ClientSecurityState::new(None);
            if let (Ok(verifier), Ok(ref mut state)) = (verifier, state) {
                let _ = verifier.verify_with_state(&token, now(), state, None);
            }
        }
    }
}
