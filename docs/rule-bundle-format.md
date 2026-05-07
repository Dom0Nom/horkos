# Rule Bundle Wire Format

The ban-engine consumes server-pushed signed rule bundles. Phase 2 ships the
data structures and a fail-closed loader; the real Ed25519 verifier and the
durable rotation pipeline land in a follow-up /tdd phase.

## On-the-wire JSON shape

```json
{
  "metadata": {
    "version":     1,
    "sha256":      "<lowercase hex digest of the canonical rules array>",
    "signed_by":   "<key id>",
    "expires_at":  "<RFC 3339 timestamp>"
  },
  "signature": "<lowercase hex Ed25519 signature over canonical (metadata || rules)>",
  "rules": [ ... ]
}
```

## Fail-closed invariants (already enforced in Phase 2)

1. **Signature presence is mandatory.** `RuleBundle::parse` rejects bundles
   whose `signature` field is missing or empty (`BundleUnsigned`).
2. **Default verifier rejects.** `BundleLoader::default()` sets `must_verify =
   true`. Without the dev-only feature flag `unverified_bundles_dev_only`, any
   call to `verify` returns `BanEngineError::VerifierNotImplemented`. The
   route surface is reachable but no untrusted bundle can be granted
   acceptance.
3. **Release builds refuse the dev feature.** `cargo build --release
   --features unverified_bundles_dev_only` triggers a `compile_error!` so a
   release artifact cannot ship the placeholder verifier.

## Rotation strategy (follow-up phase)

- Server pushes a new bundle weekly.
- Local cache is short-lived; clients refuse a bundle past `expires_at`.
- The signing key rotates on a separate, longer cadence and is distributed
  with the AC binary; the loader carries multiple trusted keys for graceful
  rotation.

## Reviewer checklist

- [ ] No new bundle path bypasses `BundleLoader::verify`.
- [ ] No code references the placeholder verifier outside
      `cfg(feature = "unverified_bundles_dev_only")`.
- [ ] CI rejects `unverified_bundles_dev_only` on release branches.
