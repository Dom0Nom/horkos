# Windows Driver Signing (Phase 3)

This repo **never bypasses signing**. There is no `--no-verify`, no disabling of
integrity checks in production. Two distinct flows:

## Test-signing (Phase 3 acceptance, VM only)

1. In the VM: `bcdedit /set testsigning on`, reboot.
2. Create a test certificate (one-time):
   ```
   makecert -r -pe -ss PrivateCertStore -n CN=HorkosTestCert horkos_test.cer
   ```
   (or `New-SelfSignedCertificate` + export).
3. Sign the driver and catalog with `signtool`:
   ```
   signtool sign /v /s PrivateCertStore /n HorkosTestCert /fd sha256 horkos.sys
   inf2cat /driver:. /os:10_X64
   signtool sign /v /s PrivateCertStore /n HorkosTestCert /fd sha256 horkos.cat
   ```
4. Import the test cert into the VM's Trusted Root + Trusted Publishers stores.

Test-signing is sufficient for Phase 3 acceptance (driver loads, `verifier.exe`
clean, smoke test passes). It is **not** valid on a machine without test-signing
mode, and never on an end-user box.

## Production signing (ship prerequisite, not a Phase 3 gate)

1. **EV code-signing certificate** on a hardware token (DigiCert / Sectigo).
   Lead time 1–4 weeks. Procurement was kicked off at Phase 0 (risk register R11).
2. **Attestation signing / WHQL** via the Microsoft Hardware Dev Center: submit
   the driver + INF + `.cat` for attestation signing. Required for a boot-start
   kernel driver on Secure-Boot machines (risk register R12).
3. **Allocated Altitude** for `ObRegisterCallbacks` requested from Microsoft
   (the `385201` value used in `Callbacks.c` is a development placeholder in the
   FSFilter Activity Monitor range).

Production boot-start on Secure Boot requires the WHQL/attestation-signed catalog
— a self-signed test cert will not boot there. The ship checklist tracks this in
`docs/ship-readiness.md` (created in Phase 5).
