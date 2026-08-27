Verify legacy `ksl1` and key-rotatable `ksl2` licenses with embedded Ed25519 public keys. This crate only verifies licenses; it cannot create them.

```rust
use chrono::Utc;
use key_system_verify::{ClockFloor, LicenseVerifier, VerificationPolicy};

let verifier = LicenseVerifier::new_embedded(
    "your-app-public-key",
    "App-Beta",
    VerificationPolicy::default_policy()?,
)?;
let mut clock_floor = ClockFloor::new(None)?;
let license = verifier.verify(token, Utc::now(), &mut clock_floor, None)?;

assert!(license.is_valid()?);
assert!(license.has_feature("reports")?);
assert!(license.matches_hardware("hashed-device-id")?);
# Ok::<(), key_system_verify::KeySystemError>(())
```

For new integrations, use `VerificationKeyRing` and `LicenseVerifier::new_key_ring`. `ksl2`
tokens use `ksl2.<signing-key-id>.<base64url-payload>.<base64url-signature>` and sign the first
three segments under a fixed domain separator. During migration, `new_with_legacy_key` accepts
both formats.

Signed revocation responses use a separately embedded revocation-authority public key and the
format `ksr1.<base64url-payload>.<base64url-signature>`. Verify them with `RevocationVerifier`
and persist `ClientSecurityState` with a platform-protected, durable `ProtectedState`
implementation. This persistence is required for clock and revocation rollback protection across
restarts; plain files without integrity protection are not sufficient.
