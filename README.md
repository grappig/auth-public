Verify `ksl1` licenses with an embedded Ed25519 public key. This crate only verifies licenses; it cannot create them.

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
