# Nintendo Switch - Platform Stub

This directory is a placeholder. No NintendoSDK headers or implementation are present.

## Public-doc surface shape

The Nintendo Switch SDK (NintendoSDK) exposes the following anti-cheat-relevant surfaces per
public Nintendo developer documentation:

- **nn::account** - User and account identity. Provides `nn::account::OpenPreselectedUser` and
  `nn::account::GetUserId` for binding a session to a device-resident user account.
- **nn::nifm** (Network Interface Manager) - Network reachability, used to require an online
  check before match entry.
- **nn::fs** - File-system access control; relevant for detecting unauthorized file manipulation.
- **Process isolation** - NintendoSDK does not expose a ptrace-equivalent; process observation
  is limited to the SDK's own logging and crash-reporting hooks.

## Attestation mapping

The attestation stub `attestation/backends/console/nintendo/AttestationNintendo.cpp` maps to
the `nn::account` identity surface. A full implementation would bind the TPM-equivalent
device certificate (DeviceCertificate from the NintendoSDK) to the attestation quote payload.

Implementation requires NDA / dev-account access and is intentionally absent from this repository.
