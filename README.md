# OpenPGP-DID CLI

`openpgp-did` creates `did:web` documents and signs Verifiable Credentials with the Ed25519 signing key on an OpenPGP smart card.

Card commands use one locked GnuPG `scdaemon` session per operation so they coordinate safely with normal GnuPG uses such as Git commit signing. The [design notes](./docs/design.md) explain this and the verifier's security boundaries.

## Features

- OpenPGP smart-card communication through [openpgp-card](https://crates.io/crates/openpgp-card) and GnuPG's `scdaemon`.
- `did:web` document creation from the card's Ed25519 signing key and Cv25519 encryption key.
- Verifiable Credential signing with the [SpruceID SSI library](https://github.com/spruceid/ssi).

## Requirements

- Rust 1.88 or newer and Cargo to build the CLI. Installing Rust with
  [rustup](https://rustup.rs/) is recommended.
- GnuPG 2.4 or newer, including `gpg`, `gpg-agent`, `scdaemon`, `gpg-connect-agent`, and a configured `pinentry`. The CLI relies on GnuPG's multi-card `card_list` and exact-card selection support.
- An OpenPGP card with an Ed25519 signing key and a Cv25519 encryption key.
- Exactly one inserted OpenPGP card. The CLI enumerates cards and pins every transaction to that card's serial number.

Confirm that GnuPG can see the card before using the CLI:

```bash
gpg --card-status
gpg-connect-agent "SCD SERIALNO" /bye
gpg-connect-agent "SCD GETINFO card_list" /bye
```

## Install

```bash
git clone https://github.com/Yengas/openpgp-did.git
cd openpgp-did
cargo build --locked
cargo install --locked --path .
```

## Quick Check

```bash
openpgp-did card diagnostic
openpgp-did card info
```

All diagnostic checks should report `SUCCESS`. The diagnostic command exits non-zero if any check fails.

## Usage

```bash
openpgp-did help
openpgp-did card help
openpgp-did did help
openpgp-did ssi help
```

For platform setup, card-key preparation, `did:web` publishing, credential signing, local verification, and an optional independent interoperability check, follow the [end-to-end test guide](./docs/e2e-did-web-credential.md).

## Credential Verification

`openpgp-did ssi verify-credential` fails closed. It checks credential structure, issuance and expiration times, issuer assertion authorization, applicable proofs until one succeeds, and supported credential status lists.

Because credentials control the URLs being fetched, resolution is restricted to bounded requests to public HTTPS hosts. Private hosts, redirects, explicit ports, and proxy-only environments are unsupported. See the [design notes](./docs/design.md) for the rationale and tradeoffs.

Dependency advisories are enforced in CI. See [Dependency Security](./docs/dependency-security.md) for the narrow, unreachable legacy SSI exceptions and their removal criteria.

## Troubleshooting

If card access becomes stuck, restart GnuPG's card services and retry:

```bash
gpgconf --kill scdaemon
gpgconf --kill gpg-agent
```

If the CLI reports that the card is busy, let the other GnuPG operation finish and retry. GnuPG owns PIN entry through `pinentry`, so its normal PIN-cache behavior applies.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT.
