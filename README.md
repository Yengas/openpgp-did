# OpenPGP-DID CLI

The OpenPGP-DID project provides a command-line interface (CLI) that uses your Smart Card Hardware OpenPGP applet to perform DID (Decentralized Identifiers) / SSI (Self-sovereign Identity) related operations using your existing signing / encryption keys for OpenPGP.

## Features

- Cross-platform communication with your smart card using [openpgp-card](https://crates.io/crates/openpgp-card) crate and [pcsc](https://crates.io/crates/openpgp-card-pcsc).
- SSI sign operation using your OpenPGP applet smart card. Made possible by [SpruceID SSI Library](https://github.com/spruceid/ssi).
- Creation of DID documents. E.g. [did:web:yigitcan.dev](https://yigitcan.dev/.well-known/did.json)

## Pre-requisites

Before using this CLI, you need to initiate signing and encryption keys for your OpenPGP Applet. This operation is not orchestrated by this CLI, you need to follow other docs and videos to do this yourself. The keys you create must be Elliptic Curve keys e.g. Ed25519 and Cv25519.

Check out [Youtube - How to set up Git commit signing with GPG and a YubiKey on macOS](https://www.youtube.com/watch?v=7LuMTyhFA-g) if you are on Mac and are using Yubikey.

You can ensure the initial setup is properly completed by running `openpgp-did card diagnostic`. You should see **SUCCESS** for all the diagnostic checks.

## Installation

Install the OpenPGP-DID CLI by cloning the repository and using cargo:

```bash
git clone https://github.com/Yengas/openpgp-did.git
cd openpgp-did
cargo build
cargo install --path .
```

## Usage

To see the list of available commands, you can run:

```bash
openpgp-did help
```

For detailed usage instructions of specific commands, refer to their respective help menus:

```bash
openpgp-did card help
openpgp-did did help
openpgp-did ssi help
```

## Known Issues

Sometimes gpg agent keeps lock on the Smart Card. Run `gpgconf --kill gpg-agent` to kill the GPG agent.

## Contributing

Contributions to the OpenPGP-DID project are welcome! Please review the [CONTRIBUTING.md](./CONTRIBUTING.md) for details on how to get started.

## License

This project is licensed under the MIT License.