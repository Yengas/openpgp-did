# Design Notes

This project keeps two security-sensitive concerns behind small public interfaces: access to the OpenPGP card and verification of credentials received from elsewhere.

## Smart-card access

A smart card is shared, stateful hardware that may also be used by GnuPG for operations such as Git signing. The CLI therefore keeps card selection, PIN verification, and signing in one locked `scdaemon` session. This prevents another process from changing the card state midway through an operation.

GnuPG owns PIN entry through `pinentry`; the CLI never receives the PIN. The credential signature still uses an OpenPGP signing APDU because the required raw Ed25519 operation is not available through the tested GnuPG agent interface.

This design requires GnuPG 2.4 or newer and exactly one inserted card. An operation can also fail while another GnuPG client holds the card.

## Credential verification

A valid signature is not enough by itself: the signing key must be authorized by the issuer, the credential must be within its validity period, and any supported revocation or status entry must be valid and clear.

Issuer and status URLs come from the credential, so they are untrusted input. Network access is restricted to bounded requests to public HTTPS hosts. This prevents a credential from turning verification into access to local services or an unbounded download or decompression operation.

The tradeoff is a deliberately narrow verifier: it accepts public `did:web` issuers and the supported VC 1.x status-list formats, but not private hosts, redirects, explicit ports, or proxy-only environments. It verifies credential integrity and status; applications must still decide whether they trust the issuer and claims.
