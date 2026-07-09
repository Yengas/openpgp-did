use std::{error::Error, process::Command};

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};

pub struct ScdaemonBackend;

pub struct ScdaemonTransaction;

impl ScdaemonBackend {
    pub fn try_new() -> Result<Self, Box<dyn Error>> {
        let output = run_gpg_connect_agent(["SCD SERIALNO --all", "/bye"])?;
        let serial_numbers = output
            .lines()
            .filter_map(|line| line.strip_prefix("S SERIALNO "))
            .map(str::to_string)
            .collect::<Vec<_>>();

        match serial_numbers.as_slice() {
            [_serial_number] => Ok(Self),
            [] => Err("expected exactly one card in scdaemon but got 0".into()),
            _ => Err(format!(
                "expected exactly one card in scdaemon but got {} ({})",
                serial_numbers.len(),
                serial_numbers.join(", ")
            )
            .into()),
        }
    }
}

impl CardBackend for ScdaemonBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        card_caps
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        if let Some(application) = reselect_application {
            let mut response = select_application(application)?;

            if response.len() > 2 {
                response.drain(0..response.len() - 2);
            }

            if response != [0x90, 0x00] {
                return Err(SmartcardError::Error(format!(
                    "failed to reselect application through scdaemon: {:x?}",
                    response
                )));
            }
        }

        Ok(Box::new(ScdaemonTransaction))
    }
}

impl CardTransaction for ScdaemonTransaction {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        transmit_apdu(cmd)
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "reader-side PIN verification is not supported through scdaemon".into(),
        ))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error(
            "reader-side PIN modification is not supported through scdaemon".into(),
        ))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

impl From<ScdaemonBackend> for Box<dyn CardBackend + Sync + Send> {
    fn from(backend: ScdaemonBackend) -> Self {
        Box::new(backend)
    }
}

fn transmit_apdu(cmd: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    let apdu_command = format!("SCD APDU --exlen {}", encode_hex(cmd));
    let output =
        run_gpg_connect_agent(["--hex", apdu_command.as_str(), "/bye"]).map_err(|err| {
            SmartcardError::Error(format!(
                "failed to run gpg-connect-agent for APDU {}: {err}",
                encode_hex(cmd)
            ))
        })?;

    parse_hex_dump_data_lines(&output)
        .and_then(|bytes| percent_decode(&bytes))
        .map_err(|err| {
            SmartcardError::Error(format!("failed to parse scdaemon APDU response: {err}"))
        })
}

fn select_application(application: &[u8]) -> Result<Vec<u8>, SmartcardError> {
    let mut cmd = vec![0x00, 0xa4, 0x04, 0x00];
    cmd.push(application.len() as u8);
    cmd.extend_from_slice(application);
    cmd.push(0x00);

    transmit_apdu(&cmd)
}

fn run_gpg_connect_agent<'a>(
    args: impl IntoIterator<Item = &'a str>,
) -> Result<String, Box<dyn Error>> {
    let output = Command::new("gpg-connect-agent").args(args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        return Err(format!(
            "gpg-connect-agent exited with status {}: {}{}",
            output.status, stdout, stderr
        )
        .into());
    }

    let stdout = String::from_utf8(output.stdout)?;

    if stdout.lines().any(|line| line.starts_with("ERR ")) {
        return Err(format!("gpg-connect-agent returned an error: {stdout}").into());
    }

    Ok(stdout)
}

fn parse_hex_dump_data_lines(output: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();

    for line in output.lines().filter(|line| line.starts_with("D[")) {
        let Some((_, after_offset)) = line.split_once(']') else {
            return Err(format!("malformed data line: {line}").into());
        };

        for token in after_offset.split_whitespace() {
            if token.len() != 2 || !token.chars().all(|char| char.is_ascii_hexdigit()) {
                break;
            }

            bytes.push(u8::from_str_radix(token, 16)?);
        }
    }

    if bytes.is_empty() {
        return Err(format!("no APDU response data in output: {output}").into());
    }

    Ok(bytes)
}

fn percent_decode(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut decoded = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("unterminated percent escape".into());
            }

            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])?;
            decoded.push(u8::from_str_radix(hex, 16)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    Ok(decoded)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_dump_data_lines, percent_decode};

    #[test]
    fn parses_gpg_connect_agent_hex_dump_data_lines() {
        let output = "\
D[0000]  90 00                                              ..\n\
OK\n";

        assert_eq!(parse_hex_dump_data_lines(output).unwrap(), [0x90, 0x00]);
    }

    #[test]
    fn decodes_assuan_percent_escapes() {
        assert_eq!(percent_decode(b"\xC0%0A%25").unwrap(), [0xC0, 0x0A, b'%']);
    }
}
