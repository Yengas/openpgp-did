use std::error::Error;

use base64::{engine, Engine};
use prettytable::{Cell, Row, Table};

use crate::{
    crypto::{
        key::{EncryptionKey, EncryptionKeyCurve, Key, SigningKey, SigningKeyCurve},
        smart_card::SmartCard,
    },
    smart_card::openpgp::OpenPgpSmartCard,
};

pub async fn cmd_card_info() -> Result<(), Box<dyn Error>> {
    let mut smart_card = OpenPgpSmartCard::try_new().expect("could not initialize OpenPGP Card");

    let smart_card_info = smart_card
        .get_card_info()
        .expect("could not get smart card info");

    let mut general_info_table = Table::new();

    general_info_table.add_row(Row::new(vec![
        Cell::new("Application Identifier="),
        Cell::new(smart_card_info.application_identifier.as_str()),
    ]));

    general_info_table.add_row(Row::new(vec![
        Cell::new("Firmware Version="),
        Cell::new(smart_card_info.firmware_version.as_str()),
    ]));

    general_info_table.add_row(Row::new(vec![
        Cell::new("Digital Signature Counter="),
        Cell::new(smart_card_info.signing_counter.to_string().as_str()),
    ]));

    println!("=== GENERAL INFO ===");
    general_info_table.printstd();

    let mut keys_table = Table::new();

    keys_table.add_row(Row::new(vec![
        Cell::new("Fingerprint"),
        Cell::new("Type"),
        Cell::new("Curve"),
        Cell::new("Public Key Base64(URL Safe, No Pad)"),
    ]));

    for key in smart_card_info.keys {
        let public_key_as_base64 = engine::general_purpose::URL_SAFE_NO_PAD.encode(key.pub_data());

        keys_table.add_row(Row::new(vec![
            Cell::new(key.fingerprint().as_str()),
            Cell::new(match key {
                Key::Signing(_) => "Signing",
                Key::Encryption(_) => "Encryption",
            }),
            Cell::new(key.curve_as_string().as_str()),
            Cell::new(public_key_as_base64.as_str()),
        ]));
    }

    println!("=== KEYS ===");
    keys_table.printstd();

    Ok(())
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum DiagnosticCheckResult {
    Success(),
    Failed(),
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct DiagnosticCheck {
    pub code: String,
    pub description: String,
    pub check_result: DiagnosticCheckResult,
}

fn check_encryption_key_existence(
    opt_encryption_key: Option<&EncryptionKey>,
) -> DiagnosticCheckResult {
    match opt_encryption_key {
        Some(_) => DiagnosticCheckResult::Success(),
        _ => DiagnosticCheckResult::Failed(),
    }
}

fn check_encryption_key_curve(opt_encryption_key: Option<&EncryptionKey>) -> DiagnosticCheckResult {
    match opt_encryption_key {
        Some(encryption_key) => match encryption_key.curve() {
            EncryptionKeyCurve::Cv25519 => DiagnosticCheckResult::Success(),
            _ => DiagnosticCheckResult::Failed(),
        },
        _ => DiagnosticCheckResult::Failed(),
    }
}

fn check_signing_key_existence(opt_signing_key: Option<&SigningKey>) -> DiagnosticCheckResult {
    match opt_signing_key {
        Some(_) => DiagnosticCheckResult::Success(),
        _ => DiagnosticCheckResult::Failed(),
    }
}

fn check_signing_key_curve(opt_signing_key: Option<&SigningKey>) -> DiagnosticCheckResult {
    match opt_signing_key {
        Some(signing_key) => match signing_key.curve() {
            SigningKeyCurve::Ed25519 => DiagnosticCheckResult::Success(),
            _ => DiagnosticCheckResult::Failed(),
        },
        _ => DiagnosticCheckResult::Failed(),
    }
}

fn do_card_diagnostics_checks() -> Vec<DiagnosticCheck> {
    let mut diagnostic_checks: Vec<DiagnosticCheck> = Vec::new();

    let smart_card = OpenPgpSmartCard::try_new().ok();

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-01".into(),
        description: "card connection must be successful".into(),
        check_result: smart_card
            .as_ref()
            .map_or(DiagnosticCheckResult::Failed(), |_| {
                DiagnosticCheckResult::Success()
            }),
    });

    let smart_card_info = smart_card.and_then(|mut sc| sc.get_card_info().ok());

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-02".into(),
        description: "card information must be read".into(),
        check_result: smart_card_info
            .as_ref()
            .map_or(DiagnosticCheckResult::Failed(), |_| {
                DiagnosticCheckResult::Success()
            }),
    });

    let signing_key = smart_card_info.as_ref().and_then(|info| {
        info.keys.iter().find_map(|key| match key {
            Key::Signing(signing_key) => Some(signing_key.clone()),
            _ => None,
        })
    });

    let encryption_key = smart_card_info.as_ref().and_then(|info| {
        info.keys.iter().find_map(|key| match key {
            Key::Encryption(encryption_key) => Some(encryption_key.clone()),
            _ => None,
        })
    });

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-03".into(),
        description: "signing key must exist".into(),
        check_result: check_signing_key_existence(signing_key.as_ref()),
    });

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-04".into(),
        description: "encryption key must exist".into(),
        check_result: check_encryption_key_existence(encryption_key.as_ref()),
    });

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-05".into(),
        description: "signing key curve must be Ed25519".into(),
        check_result: check_signing_key_curve(signing_key.as_ref()),
    });

    diagnostic_checks.push(DiagnosticCheck {
        code: "DIAG-06".into(),
        description: "encryption key curve must be Cv25519".into(),
        check_result: check_encryption_key_curve(encryption_key.as_ref()),
    });

    diagnostic_checks
}

pub async fn cmd_card_diagnostic() -> Result<(), Box<dyn Error>> {
    let card_diagnostic_checks = do_card_diagnostics_checks();
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("Code"),
        Cell::new("Description"),
        Cell::new("Result"),
    ]));

    for diagnostic_check in card_diagnostic_checks {
        table.add_row(Row::new(vec![
            Cell::new(diagnostic_check.code.as_str()),
            Cell::new(diagnostic_check.description.as_str()),
            Cell::new(match diagnostic_check.check_result {
                DiagnosticCheckResult::Success() => "SUCCESS",
                DiagnosticCheckResult::Failed() => "FAILED",
            }),
        ]));
    }

    table.printstd();

    Ok(())
}
