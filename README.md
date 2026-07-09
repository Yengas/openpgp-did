# OpenPGP-DID CLI

The OpenPGP-DID project provides a command-line interface (CLI) that uses your Smart Card Hardware OpenPGP applet to perform DID (Decentralized Identifiers) / SSI (Self-sovereign Identity) related operations using your existing signing / encryption keys for OpenPGP.

## Features

- Communication with your smart card using [openpgp-card](https://crates.io/crates/openpgp-card) and GnuPG's `scdaemon`.
- SSI sign operation using your OpenPGP applet smart card. Made possible by [SpruceID SSI Library](https://github.com/spruceid/ssi).
- Creation of DID documents. E.g. [did:web:yigitcan.dev](https://yigitcan.dev/.well-known/did.json)

## Pre-requisites

You need Rust/Cargo to build the CLI, and GnuPG with `gpg`, `gpg-agent`, `scdaemon`, `gpg-connect-agent`, and `pinentry` available on your machine. The CLI sends OpenPGP card APDUs through `scdaemon`, so it can coexist with GnuPG workflows such as git commit signing. This is not macOS-specific; the important requirement is that GnuPG can see and use your OpenPGP card.

The current signing flow looks for an executable named `pinentry` when it prompts for the card PIN. If your platform installs a differently named pinentry program, configure or symlink it so `pinentry` resolves in `PATH`.

Before using this CLI, you need to initialize signing and encryption keys for your OpenPGP applet. This operation is not orchestrated by this CLI. The keys you create must be elliptic curve keys: Ed25519 for signing and Cv25519 for encryption.

First make sure GnuPG can see your card:

```bash
gpg --card-status
gpg-connect-agent "SCD SERIALNO" /bye
```

If those commands fail, fix your GnuPG/card setup before debugging `openpgp-did`.

Platform notes:

- macOS: Homebrew GnuPG works well. You may also want `pinentry-mac` if you use graphical PIN prompts, but make sure a `pinentry` command is available in `PATH`.
- Linux: install your distribution's GnuPG package. Some distributions also require the PC/SC daemon and CCID driver packages for `scdaemon` to see USB smart cards.
- Windows: use a GnuPG distribution such as Gpg4win, and make sure `gpg-connect-agent` is in `PATH`. Windows support should work through GnuPG, but is not currently part of this project's routine verification.

Check out [Youtube - How to set up Git commit signing with GPG and a YubiKey on macOS](https://www.youtube.com/watch?v=7LuMTyhFA-g) if you are on Mac and are using Yubikey.

You can ensure the initial setup is properly completed by running `openpgp-did card diagnostic`. You should see **SUCCESS** for all the diagnostic checks.

```
$ openpgp-did card diagnostic 

+---------+--------------------------------------+---------+
| Code    | Description                          | Result  |
+---------+--------------------------------------+---------+
| DIAG-01 | card connection must be successful   | SUCCESS |
+---------+--------------------------------------+---------+
| DIAG-02 | card information must be read        | SUCCESS |
+---------+--------------------------------------+---------+
| DIAG-03 | signing key must exist               | SUCCESS |
+---------+--------------------------------------+---------+
| DIAG-04 | encryption key must exist            | SUCCESS |
+---------+--------------------------------------+---------+
| DIAG-05 | signing key curve must be Ed25519    | SUCCESS |
+---------+--------------------------------------+---------+
| DIAG-06 | encryption key curve must be Cv25519 | SUCCESS |
+---------+--------------------------------------+---------+
```

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

For a complete setup and verification walkthrough, see [docs/e2e-did-web-credential.md](./docs/e2e-did-web-credential.md).

## Known Issues

If card access gets stuck, restart GnuPG's card services and retry:

```bash
gpgconf --kill scdaemon
gpgconf --kill gpg-agent
```

You should not need to do this during normal use; `openpgp-did` talks through `scdaemon` instead of competing with it.

## Contributing

Contributions to the OpenPGP-DID project are welcome! Please review the [CONTRIBUTING.md](./CONTRIBUTING.md) for details on how to get started.

## License

This project is licensed under the MIT License.
