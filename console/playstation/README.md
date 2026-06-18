# PlayStation - Platform Stub

This directory is a placeholder. No PlayStation SDK headers or implementation are present.

## Public-doc surface shape

The PlayStation SDK (PS4/PS5) exposes the following anti-cheat-relevant surfaces per
public Sony Interactive Entertainment developer documentation:

- **sceNpTrophy / sceNp** - PlayStation Network identity and trophy service; provides the
  PSN account token used for session authentication.
- **sceUserService** - User management on PS4/PS5: `sceUserServiceGetLoginUserIdList` for
  binding a match session to logged-in users.
- **sceSystemService** - System-level queries including `sceSystemServiceGetAppStatus` for
  detecting abnormal execution contexts.
- **sceSaveData** - Save data integrity surface, relevant for detecting offline manipulation.
- **sceNpGameIntent** - Deeplink and session invite validation.

## Attestation mapping

`attestation/backends/console/playstation/AttestationPlayStation.cpp` maps to the PSN account
token obtained via `sceNp`. A real implementation would include the platform certificate chain
returned by the PSN backend and bind it to the Horkos attestation quote payload.

Implementation requires NDA / dev-account access and is intentionally absent from this repository.
