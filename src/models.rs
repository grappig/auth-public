use crate::error::{KeySystemError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use subtle::ConstantTimeEq;

const MAX_IDENTIFIER_LENGTH: usize = 128;
const MAX_FEATURES: usize = 64;
const MAX_FEATURE_LENGTH: usize = 128;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LicenseClaims {
    key_id: String,
    client_id: String,
    software_target: String,
    tier: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    features: Vec<String>,
    hardware_id: Option<String>,
}

impl LicenseClaims {
    pub fn from_json(payload: &[u8]) -> Result<Self> {
        let claims: Self = serde_json::from_slice(payload)?;
        claims.validate()?;
        Ok(claims)
    }

    pub fn key_id(&self) -> Result<&str> {
        Ok(&self.key_id)
    }

    pub fn client_id(&self) -> Result<&str> {
        Ok(&self.client_id)
    }

    pub fn software_target(&self) -> Result<&str> {
        Ok(&self.software_target)
    }

    pub fn tier(&self) -> Result<&str> {
        Ok(&self.tier)
    }

    pub fn issued_at(&self) -> Result<DateTime<Utc>> {
        Ok(self.issued_at)
    }

    pub fn expires_at(&self) -> Result<DateTime<Utc>> {
        Ok(self.expires_at)
    }

    pub fn features(&self) -> Result<&[String]> {
        Ok(&self.features)
    }

    pub fn is_expired(&self) -> Result<bool> {
        self.is_expired_at(Utc::now())
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> Result<bool> {
        Ok(now >= self.expires_at)
    }

    pub fn has_feature(&self, feature: &str) -> Result<bool> {
        if feature.is_empty() || feature.len() > MAX_FEATURE_LENGTH {
            return Err(KeySystemError::InvalidPolicy("invalid feature query"));
        }
        let mut found = 0_u8;
        for entitlement in &self.features {
            found |= entitlement.as_bytes().ct_eq(feature.as_bytes()).unwrap_u8();
        }
        Ok(found == 1)
    }

    pub fn matches_hardware(&self, hardware_id: &str) -> Result<bool> {
        if hardware_id.is_empty() || hardware_id.len() > MAX_IDENTIFIER_LENGTH {
            return Err(KeySystemError::InvalidPolicy("invalid hardware identifier"));
        }
        Ok(self
            .hardware_id
            .as_ref()
            .map(|bound| bound.as_bytes().ct_eq(hardware_id.as_bytes()).unwrap_u8() == 1)
            .unwrap_or(false))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_identifier(&self.key_id)?;
        validate_identifier(&self.client_id)?;
        validate_identifier(&self.software_target)?;
        validate_identifier(&self.tier)?;
        if self.expires_at <= self.issued_at || self.features.len() > MAX_FEATURES {
            return Err(KeySystemError::InvalidPayload);
        }
        for feature in &self.features {
            if feature.is_empty() || feature.len() > MAX_FEATURE_LENGTH {
                return Err(KeySystemError::InvalidPayload);
            }
        }
        if let Some(hardware_id) = &self.hardware_id {
            validate_identifier(hardware_id)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerificationPolicy {
    pub max_clock_drift: Duration,
    pub max_future_issue_time: Duration,
}

impl VerificationPolicy {
    pub fn default_policy() -> Result<Self> {
        let policy = Self {
            max_clock_drift: Duration::minutes(5),
            max_future_issue_time: Duration::minutes(5),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_clock_drift < Duration::zero() || self.max_future_issue_time < Duration::zero()
        {
            return Err(KeySystemError::InvalidPolicy(
                "durations cannot be negative",
            ));
        }
        Ok(())
    }
}

/// Persist this high-water mark in application-owned protected storage between launches.
#[derive(Clone, Copy, Debug)]
pub struct ClockFloor(Option<DateTime<Utc>>);

impl ClockFloor {
    pub fn new(last_verified_at: Option<DateTime<Utc>>) -> Result<Self> {
        Ok(Self(last_verified_at))
    }

    pub fn last_verified_at(&self) -> Result<Option<DateTime<Utc>>> {
        Ok(self.0)
    }

    pub(crate) fn advance(&mut self, now: DateTime<Utc>, max_clock_drift: Duration) -> Result<()> {
        if let Some(previous) = self.0 {
            if now < previous - max_clock_drift {
                return Err(KeySystemError::ClockRollback);
            }
        }
        if self.0.map(|previous| now > previous).unwrap_or(true) {
            self.0 = Some(now);
        }
        Ok(())
    }
}

pub trait RevocationChecker: Send + Sync {
    fn is_revoked(&self, key_id: &str) -> Result<bool>;
}

fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(KeySystemError::InvalidPayload);
    }
    Ok(())
}
