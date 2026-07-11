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

The built-in resolver accepts only public `did:web` issuers and public HTTPS status-list URLs. It rejects private/local destinations, pins public DNS results, ignores system proxy settings, disables redirects, and uses bounded timeouts. DID documents are limited to 1 MiB, status-list credential JSON to 2 MiB, and decompressed status bitstrings to 16 MiB. Environments that require an outbound HTTP proxy are intentionally unsupported because proxy-side DNS would bypass origin pinning.

The public [POSSIBLE-X Verifier](https://possible.fokus.fraunhofer.de/verifier/) is an optional independent interoperability experiment. It uses Gaia-X AISBL's [JsonWebSignature2020 TypeScript library](https://gitlab.com/gaia-x/lab/libraries/json-web-signature-2020), but it is aimed at Gaia-X Compliance Credentials and may reject generic VC 1.x credentials. The local command above is the primary project verification path.

The verifier fetches your `did:web` document from the public internet. Only submit test credentials or credentials you are comfortable sharing with that third-party service.

The verifier needs support for:

- `did:web` resolution over HTTPS.
- `JsonWebKey2020`.
- `JsonWebSignature2020`.
- Ed25519 / `EdDSA` detached JWS verification.

This proof format is from the VC 1.x ecosystem; some newer VC tooling focuses only on Data Integrity proofs, so it will not verify this credential. A successful result confirms that the proof signature matches the Ed25519 public key in your published DID document.

If verification fails:

- Confirm `curl -fsSL https://example.com/.well-known/did.json` returns the current DID document.
- Confirm the `proof.verificationMethod` in `signed-credential.json` exists in the DID document.
- Confirm your verifier supports `JsonWebSignature2020`; some newer VC tooling focuses on Data Integrity proofs instead.
- Re-run `openpgp-did did document` and compare it with the hosted document.

## PIN And Card Session Notes

The current implementation uses GnuPG's `scdaemon` as the card transport, but the signature itself is still produced through OpenPGP-card APDUs:

1. The CLI asks GnuPG to verify the PIN with `SCD CHECKPIN`; GnuPG owns the `pinentry` interaction and its cache policy.
2. `scdaemon` verifies the card PIN without returning it to the CLI.
3. It sends `PSO: COMPUTE DIGITAL SIGNATURE` through `scdaemon`.

Card selection, PIN verification, and signing stay in one exclusive scdaemon session, so another GnuPG client cannot interleave them. Direct PIN-bearing VERIFY APDUs are rejected by the backend; the PIN is never placed in a process argument, application error, or CLI-generated APDU command. The session has bounded command and shutdown timeouts, and closing it releases the card lock even during error unwinding.

GnuPG's normal PIN-cache behavior applies to `SCD CHECKPIN`. Card configuration may still require confirmation for every signature.

The natural alternative would be to ask `scdaemon` or `gpg-agent` to perform the signing operation directly, rather than only managing PIN verification.

For this project, that is not a direct swap today. The credential proof needs an Ed25519 signature over the exact SSI/JWS signing bytes. GnuPG's agent signing protocol signs hashes, and on the tested GnuPG/scdaemon setup `SCD PKSIGN --hash=none OPENPGP.1` is advertised in help but rejected by scdaemon for the OpenPGP signing slot. So the current APDU signing path remains necessary unless we find a GnuPG-supported raw Ed25519 signing route or change the proof format to something GnuPG can sign natively.
