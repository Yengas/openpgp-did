# End-to-End did:web Credential Test

This guide exercises the full flow:

1. Prepare an OpenPGP smart card.
2. Generate an `openpgp-did` DID document from the card keys.
3. Publish that document as a `did:web` document.
4. Sign a sample Verifiable Credential with the card.
5. Verify credential structure, validity, status, and proof locally.
6. Optionally try an independent external verifier for interoperability.

The commands below build and install the CLI from your current checkout, then use the installed `openpgp-did` command. This is closer to normal use and also verifies that your shell `PATH`, GnuPG, scdaemon, and pinentry setup work together.

## 1. Install Runtime Dependencies

You need:

- Rust 1.88 or newer and Cargo.
- GnuPG 2.4 or newer with `gpg`, `gpg-agent`, `scdaemon`, and `gpg-connect-agent`. The multi-card `card_list` and exact-card selection commands used by the CLI require a current GnuPG release.
- A `pinentry` program configured for `gpg-agent`.
- Exactly one inserted OpenPGP card or YubiKey with an Ed25519 signing key and a Cv25519 encryption key.

Platform notes:

- macOS: Homebrew GnuPG works well. Install a pinentry program such as `pinentry-mac` and configure it for `gpg-agent`.
- Linux: install your distribution's GnuPG packages. Some systems also need `pcscd` and CCID packages so GnuPG's `scdaemon` can see USB smart cards.
- Windows: use a GnuPG distribution such as Gpg4win, and make sure `gpg-connect-agent` is in `PATH`. Windows builds and unit tests run in CI; physical-card testing is still performed separately.

If you need to create the OpenPGP card keys from scratch, follow your YubiKey/OpenPGP setup guide first. This project assumes the keys already exist on the card.

## 2. Confirm GnuPG Sees The Card

```bash
gpg --card-status
gpg-connect-agent "SCD SERIALNO" /bye
gpg-connect-agent "SCD GETINFO card_list" /bye
```

`gpg --card-status` should show an OpenPGP application, an Ed25519 signature key, and a Cv25519 encryption key. `card_list` should report exactly one `SERIALNO`.

If GnuPG cannot see the card, fix that first. `openpgp-did` sends card APDUs through `scdaemon`, so it depends on the same card visibility.

## 3. Build And Run Card Diagnostics

Build and install the CLI from this checkout:

```bash
cargo build --locked
cargo install --locked --path .
```

Make sure your shell can find the installed command:

```bash
openpgp-did help
```

Then run the card diagnostics:

```bash
openpgp-did card diagnostic
openpgp-did card info
```

The diagnostic command should report `SUCCESS` for all checks and exit successfully. It exits non-zero if card initialization, reads, keys, or curve checks fail.

## 4. Initialize Your DID

Choose the HTTPS domain that will host your DID document. For example:

- DID: `did:web:example.com`
- DID document URL: `https://example.com/.well-known/did.json`

Initialize local configuration:

```bash
openpgp-did did init
```

When prompted, enter your DID, for example:

```text
did:web:example.com
```

The command writes `~/.openpgp-did/did-configuration.yml` with the DID and the card key fingerprints.

## 5. Publish The DID Document

Generate the DID document:

```bash
openpgp-did did document > did.json
```

Publish `did.json` at:

```text
https://example.com/.well-known/did.json
```

Then verify that it is publicly reachable:

```bash
curl -fsSL https://example.com/.well-known/did.json
```

The returned JSON should contain:

- `id` equal to your `did:web:...` value.
- A `JsonWebKey2020` verification method for the Ed25519 signing key.
- A `JsonWebKey2020` key agreement method for the X25519/Cv25519 encryption key.

## 6. Sign A Sample Credential

This repository includes a minimal unsigned credential at `examples/unsigned-credential.json`.
It defines its example-specific type and claim in an inline JSON-LD context. Add equivalent context definitions whenever you add custom credential types or claims.

Sign it with the card:

```bash
openpgp-did ssi sign-credential \
  --file examples/unsigned-credential.json \
  > signed-credential.json
```

The CLI sets the credential issuer to your configured DID and adds `issuanceDate` if the input did not include one.

The output should include a `proof` object with:

- `type`: `JsonWebSignature2020`
- `proofPurpose`: usually `assertionMethod`
- `verificationMethod`: a DID URL under your `did:web:...` DID
- `jws`: the detached JWS signature created by the OpenPGP card

## 7. Verify The Credential

First, verify the credential against the published `did:web` document:

```bash
openpgp-did ssi verify-credential --file signed-credential.json
```

The command prints a verification result and exits successfully only when its `errors` array is empty. It validates:

- Required Verifiable Credential structure.
- `issuanceDate` is not in the future and `expirationDate` has not passed.
- The proof verification method is authorized by the issuer's `assertionMethod`.
- Every applicable proof until one succeeds, including credentials containing multiple proofs.
- Supported `RevocationList2020Status` and `StatusList2021Entry` status lists when present.
- Status-list issuer, identifier, purpose, index bounds, proof, and revoked bit.

Verification resolves only public `did:web` issuers and public HTTPS status-list URLs. Private hosts, redirects, explicit ports, and proxy-only environments are intentionally unsupported; see the [design notes](./design.md) for why.

### Optional interoperability check

The public [POSSIBLE-X Verifier](https://possible.fokus.fraunhofer.de/verifier/) can be used as an independent experiment, but it targets Gaia-X Compliance Credentials and may reject a generic VC 1.x credential. The local command above is the primary verification path.

Only submit test credentials or credentials you are comfortable sharing with that service. Other external tools must support `did:web`, `JsonWebKey2020`, `JsonWebSignature2020`, and Ed25519 detached JWS verification.

If verification fails:

- Confirm `curl -fsSL https://example.com/.well-known/did.json` returns the current DID document.
- Confirm the `proof.verificationMethod` in `signed-credential.json` exists in the DID document.
- Confirm your verifier supports `JsonWebSignature2020`; some newer VC tooling focuses on Data Integrity proofs instead.
- Re-run `openpgp-did did document` and compare it with the hosted document.

## PIN And Card Session Notes

Signing follows one card transaction:

1. The CLI selects and locks the single inserted card through `scdaemon`.
2. GnuPG verifies the PIN through `pinentry`; the CLI never receives it.
3. The CLI sends the credential signing operation through the same session.

Keeping those steps together prevents another GnuPG client from changing card state midway through signing. GnuPG's normal PIN-cache behavior applies, and card configuration may still require confirmation for every signature. See the [design notes](./design.md) for the rationale and limitations.
