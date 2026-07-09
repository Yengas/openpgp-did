# OpenPGP-DID CLI

`openpgp-did` creates `did:web` documents and signs Verifiable Credentials with the Ed25519 signing key on an OpenPGP smart card.

Card commands use GnuPG's `scdaemon` rather than opening the card directly. This lets the CLI coexist with normal GnuPG uses such as Git commit signing.

## Features

- OpenPGP smart-card communication through [openpgp-card](https://crates.io/crates/openpgp-card) and GnuPG's `scdaemon`.
- `did:web` document creation from the card's Ed25519 signing key and Cv25519 encryption key.
- Verifiable Credential signing with the [SpruceID SSI library](https://github.com/spruceid/ssi).

## Requirements

- Rust and Cargo to build the CLI.
- GnuPG, including `gpg`, `gpg-agent`, `scdaemon`, `gpg-connect-agent`, and `pinentry`.
- An OpenPGP card with an Ed25519 signing key and a Cv25519 encryption key.

Confirm that GnuPG can see the card before using the CLI:

```bash
gpg --card-status
gpg-connect-agent "SCD SERIALNO" /bye
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

All diagnostic checks should report `SUCCESS`.

## Usage

```bash
openpgp-did help
openpgp-did card help
openpgp-did did help
openpgp-did ssi help
```

For platform setup, card-key preparation, `did:web` publishing, credential signing, and independent verification, follow the [end-to-end test guide](./docs/e2e-did-web-credential.md).

## Troubleshooting

If card access becomes stuck, restart GnuPG's card services and retry:

```bash
gpgconf --kill scdaemon
gpgconf --kill gpg-agent
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT.
