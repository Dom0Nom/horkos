# Xbox / GDK — Platform Stub

This directory is a placeholder. No GDK / XDK headers or implementation are present.

## Public-doc surface shape

The Microsoft Game Development Kit (GDK) exposes the following anti-cheat-relevant surfaces per
public documentation at learn.microsoft.com/en-us/gaming/gdk:

- **XGameRuntime** — Core runtime lifecycle: `XGameRuntimeInitialize` / `XGameRuntimeUninitialize`.
- **XUser** — User identity and authentication:
  - `XUserAddAsync` — sign in a user.
  - `XUserGetTokenAndSignatureAsync` — obtain a platform attestation token signed by Xbox Live.
    This is the primary attestation surface and maps to `AttestationGdk` in this codebase.
  - `XUserGetId` — retrieve the XUID for session binding.
- **XNetworking** — Network quality of service: `XNetworkingQueryPreferredLocalUdpMultiplayerPort`.
- **XPackage** — Package integrity: `XPackageMount` / `XPackageGetMountPath` for detecting
  unauthorized file modifications.

## Attestation mapping

`attestation/backends/console/gdk/AttestationGdk.cpp` maps to `XUserGetTokenAndSignatureAsync`.
A real implementation would submit the audience URL for the game server and verify the returned
JWT signature chain against the Xbox Live signing certificates.

Implementation requires NDA / dev-account access and is intentionally absent from this repository.
