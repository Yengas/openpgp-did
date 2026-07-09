# End-to-End did:web Credential Test

This guide exercises the full flow:

1. Prepare an OpenPGP smart card.
2. Generate an `openpgp-did` DID document from the card keys.
3. Publish that document as a `did:web` document.
4. Sign a sample Verifiable Credential with the card.
5. Verify the result with an independent verifier.

The commands below build and install the CLI from your current checkout, then use the installed `openpgp-did` command. This is closer to normal use and also verifies that your shell `PATH`, GnuPG, scdaemon, and pinentry setup work together.

## 1. Install Runtime Dependencies

You need:

- Rust and Cargo.
- GnuPG with `gpg`, `gpg-agent`, `scdaemon`, and `gpg-connect-agent`.
- A `pinentry` executable available in `PATH`.
- An OpenPGP card or YubiKey with an Ed25519 signing key and a Cv25519 encryption key.

Platform notes:

- macOS: Homebrew GnuPG works well. Install a pinentry program such as `pinentry-mac`, and make sure `pinentry` resolves in `PATH`.
- Linux: install your distribution's GnuPG packages. Some systems also need `pcscd` and CCID packages so GnuPG's `scdaemon` can see USB smart cards.
- Windows: use a GnuPG distribution such as Gpg4win, and make sure `gpg-connect-agent` is in `PATH`. This project talks through GnuPG rather than opening PC/SC directly, but Windows is not part of routine project verification yet.

If you need to create the OpenPGP card keys from scratch, follow your YubiKey/OpenPGP setup guide first. This project assumes the keys already exist on the card.

## 2. Confirm GnuPG Sees The Card

```bash
gpg --card-status
gpg-connect-agent "SCD SERIALNO" /bye
```

`gpg --card-status` should show an OpenPGP application, an Ed25519 signature key, and a Cv25519 encryption key.

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

The diagnostic command should report `SUCCESS` for all checks.

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

## 7. Verify With An Independent Verifier

Use the public [POSSIBLE-X Verifier](https://possible.fokus.fraunhofer.de/verifier/): paste the contents of `signed-credential.json` into the form and select **Validate**. It uses Gaia-X AISBL's independent [JsonWebSignature2020 TypeScript library](https://gitlab.com/gaia-x/lab/libraries/json-web-signature-2020), so it is a useful interoperability check outside this Rust codebase.

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

## PIN Caching Notes

The current implementation uses GnuPG's `scdaemon` as the card transport, but the signature itself is still produced through OpenPGP-card APDUs:

1. `openpgp-did` asks for the card PIN using `pinentry`.
2. It sends `VERIFY` through `scdaemon`.
3. It sends `PSO: COMPUTE DIGITAL SIGNATURE` through `scdaemon`.

That means the CLI coexists with GnuPG and git signing, but it does not yet reuse gpg-agent's signing PIN cache.

The natural alternative would be to ask `scdaemon` or `gpg-agent` to perform the signing operation directly. That would let GnuPG own the PIN prompt and use `gpg-agent.conf` settings such as `default-cache-ttl`, `max-cache-ttl`, and `ignore-cache-for-signing`.

For this project, that is not a direct swap today. The credential proof needs an Ed25519 signature over the exact SSI/JWS signing bytes. GnuPG's agent signing protocol signs hashes, and on the tested GnuPG/scdaemon setup `SCD PKSIGN --hash=none OPENPGP.1` is advertised in help but rejected by scdaemon for the OpenPGP signing slot. So the current APDU signing path remains necessary unless we find a GnuPG-supported raw Ed25519 signing route or change the proof format to something GnuPG can sign natively.
