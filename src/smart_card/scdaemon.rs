use std::{
    error::Error,
    fmt::Write as FmtWrite,
    io::{BufRead, BufReader, Write as IoWrite},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use secrecy::{ExposeSecret, SecretString};

const HEX_DUMP_BYTES_PER_LINE: usize = 16;
const HEX_DUMP_FIELD_WIDTH: usize = 2 + (HEX_DUMP_BYTES_PER_LINE * 3);
const ASSUAN_MAX_SERIALIZED_APDU_BYTES: u16 = 480;
// openpgp-card uses this value as a chained payload size even though CardCaps
// defines it as a serialized APDU size. Reserve the worst-case extended APDU
// header so the serialized command still fits the Assuan command line.
const OPENPGP_CARD_MAX_COMMAND_BYTES: u16 = ASSUAN_MAX_SERIALIZED_APDU_BYTES - 9;
const SCDAEMON_MAX_RESPONSE_BYTES: u16 = 4096;
const MAX_AGENT_RESPONSE_BYTES: usize = 64 * 1024;
const AGENT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const AGENT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

/// Card backend that routes OpenPGP-card APDUs through one locked scdaemon
/// session for the lifetime of each card transaction.
pub struct ScdaemonBackend {
    serial_number: String,
}

pub struct ScdaemonTransaction {
    session: GpgConnectAgent,
    serial_number: String,
    locked: bool,
}

#[derive(Default)]
struct AgentResponse {
    data: Vec<u8>,
    status_lines: Vec<String>,
}

struct GpgConnectAgent {
    child: Child,
    stdin: Option<ChildStdin>,
    output: Mutex<Receiver<AgentOutput>>,
    closed: bool,
}

enum AgentOutput {
    Line(String),
    Eof,
    Error(String),
}

impl ScdaemonBackend {
    pub fn try_new() -> Result<Self, Box<dyn Error>> {
        let mut session = GpgConnectAgent::spawn()?;
        // Refresh scdaemon's view of inserted cards before asking for the
        // complete list. A missing card is represented by an empty list below.
        let _ = session.command("SCD SERIALNO");
        let response = session.command("SCD GETINFO card_list")?;
        let serial_numbers = parse_card_list(&response.status_lines)?;

        let serial_number = match serial_numbers.as_slice() {
            [serial_number] => serial_number.clone(),
            [] => return Err("expected exactly one card in scdaemon but got 0".into()),
            _ => {
                return Err(format!(
                    "expected exactly one card in scdaemon but got {} ({})",
                    serial_numbers.len(),
                    serial_numbers.join(", ")
                )
                .into());
            }
        };

        select_card(&mut session, &serial_number)?;

        Ok(Self { serial_number })
    }
}

impl CardBackend for ScdaemonBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        CardCaps::new(
            card_caps.ext_support(),
            card_caps.chaining_support(),
            card_caps
                .max_cmd_bytes()
                .min(OPENPGP_CARD_MAX_COMMAND_BYTES),
            card_caps.max_rsp_bytes().min(SCDAEMON_MAX_RESPONSE_BYTES),
            card_caps.pw1_max_len(),
            card_caps.pw3_max_len(),
        )
    }

    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        let mut session = GpgConnectAgent::spawn().map_err(smartcard_error)?;
        select_card(&mut session, &self.serial_number).map_err(smartcard_error)?;
        session.command("SCD LOCK").map_err(|error| {
            SmartcardError::Error(format!(
                "could not lock the selected card; another GnuPG operation may be using it: {error}"
            ))
        })?;

        let mut transaction = ScdaemonTransaction {
            session,
            serial_number: self.serial_number.clone(),
            locked: true,
        };

        if let Some(application) = reselect_application {
            let response = transaction.transmit(&select_application_command(application), 2)?;

            if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
                return Err(SmartcardError::Error(format!(
                    "failed to reselect OpenPGP application through scdaemon: {:x?}",
                    response
                )));
            }
        }

        Ok(Box::new(transaction))
    }
}

impl CardTransaction for ScdaemonTransaction {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        if is_pin_bearing_verify(cmd) {
            return Err(SmartcardError::Error(
                "direct PIN-bearing VERIFY APDUs are disabled; use GnuPG-managed PIN verification"
                    .into(),
            ));
        }

        if cmd.len() > usize::from(ASSUAN_MAX_SERIALIZED_APDU_BYTES) {
            return Err(SmartcardError::Error(format!(
                "APDU is too large for scdaemon's Assuan transport: {} bytes (maximum {})",
                cmd.len(),
                ASSUAN_MAX_SERIALIZED_APDU_BYTES
            )));
        }

        let response_limit = buf_size.clamp(2, usize::from(SCDAEMON_MAX_RESPONSE_BYTES));
        let command = apdu_command(cmd, response_limit);
        let response = self.session.secret_command(&command).map_err(|err| {
            SmartcardError::Error(format!(
                "scdaemon APDU transport failed for {}: {err}",
                describe_apdu(cmd)
            ))
        })?;

        if response.data.len() > response_limit + 2 {
            return Err(SmartcardError::Error(format!(
                "scdaemon APDU response exceeded the requested limit: {} bytes (maximum {})",
                response.data.len(),
                response_limit + 2
            )));
        }

        Ok(response.data)
    }

    fn feature_pinpad_verify(&self) -> bool {
        true
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        let identifier = checkpin_identifier(&self.serial_number, pin);
        self.session
            .command(&format!("SCD CHECKPIN {identifier}"))
            .map_err(|error| {
                SmartcardError::Error(format!("GnuPG-managed PIN verification failed: {error}"))
            })?;

        Ok(vec![0x90, 0x00])
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

impl Drop for ScdaemonTransaction {
    fn drop(&mut self) {
        if self.locked {
            // Closing the Assuan connection releases SCD LOCK. Avoid a final
            // blocking protocol round trip during error unwinding/shutdown.
            self.session.close();
            self.locked = false;
        }
    }
}

impl From<ScdaemonBackend> for Box<dyn CardBackend + Sync + Send> {
    fn from(backend: ScdaemonBackend) -> Self {
        Box::new(backend)
    }
}

impl GpgConnectAgent {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new("gpg-connect-agent")
            .args(["--unbuffered", "--hex", "--no-history"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or("gpg-connect-agent did not provide stdin")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("gpg-connect-agent did not provide stdout")?;
        let output = spawn_output_reader(stdout);

        Ok(Self {
            child,
            stdin: Some(stdin),
            output: Mutex::new(output),
            closed: false,
        })
    }

    fn command(&mut self, command: &str) -> Result<AgentResponse, Box<dyn Error>> {
        self.command_bytes(command.as_bytes())
    }

    fn secret_command(&mut self, command: &SecretString) -> Result<AgentResponse, Box<dyn Error>> {
        self.command_bytes(command.expose_secret().as_bytes())
    }

    fn command_bytes(&mut self, command: &[u8]) -> Result<AgentResponse, Box<dyn Error>> {
        if command.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err("gpg-connect-agent command contains a newline".into());
        }

        let stdin = self
            .stdin
            .as_mut()
            .ok_or("gpg-connect-agent session is closed")?;
        stdin.write_all(command)?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;

        let mut response = AgentResponse::default();
        let mut frame_offset = 0;
        let deadline = Instant::now() + AGENT_COMMAND_TIMEOUT;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.close();
                return Err("gpg-connect-agent command timed out".into());
            }

            let output = {
                let receiver = self
                    .output
                    .lock()
                    .map_err(|_| "gpg-connect-agent output reader lock was poisoned")?;
                receiver.recv_timeout(remaining)
            };
            let line = match output {
                Ok(AgentOutput::Line(line)) => line,
                Ok(AgentOutput::Eof) => {
                    let status = self.child.try_wait()?;
                    return Err(format!(
                        "gpg-connect-agent closed its output unexpectedly{}",
                        status
                            .map(|status| format!(" with status {status}"))
                            .unwrap_or_default()
                    )
                    .into());
                }
                Ok(AgentOutput::Error(error)) => {
                    return Err(format!("could not read gpg-connect-agent output: {error}").into());
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.close();
                    return Err("gpg-connect-agent command timed out".into());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("gpg-connect-agent output reader stopped unexpectedly".into());
                }
            };

            let line = line.trim_end_matches(['\r', '\n']);

            if line.starts_with("D[") {
                append_hex_dump_data_line(&mut response.data, &mut frame_offset, line)?;
            } else if let Some(status) = line.strip_prefix("S ") {
                response.status_lines.push(status.to_owned());
            } else if line == "OK" || line.starts_with("OK ") {
                response.data = percent_decode(&response.data)?;
                return Ok(response);
            } else if line.starts_with("ERR ") {
                return Err(format!("scdaemon returned {line}").into());
            } else if line.starts_with('#') || line.is_empty() {
                continue;
            } else if line.starts_with("INQUIRE ") {
                return Err(format!("unsupported scdaemon inquiry: {line}").into());
            } else {
                return Err(format!("unexpected gpg-connect-agent output: {line}").into());
            }
        }
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;

        // EOF is the reliable, protocol-independent way to end the client and
        // release a card lock. Bound both graceful exit and forced shutdown.
        drop(self.stdin.take());
        if !wait_for_child(&mut self.child, AGENT_SHUTDOWN_TIMEOUT) {
            let _ = self.child.kill();
            let _ = wait_for_child(&mut self.child, AGENT_SHUTDOWN_TIMEOUT);
        }
    }
}

impl Drop for GpgConnectAgent {
    fn drop(&mut self) {
        self.close();
    }
}

fn select_card(session: &mut GpgConnectAgent, serial_number: &str) -> Result<(), Box<dyn Error>> {
    validate_serial_number(serial_number)?;
    let response = session.command(&format!("SCD SERIALNO --demand={serial_number} openpgp"))?;
    let selected_serial = response
        .status_lines
        .iter()
        .find_map(|line| line.strip_prefix("SERIALNO "))
        .ok_or("scdaemon did not report the selected card serial number")?;

    if !selected_serial.eq_ignore_ascii_case(serial_number) {
        return Err(
            format!("scdaemon selected card {selected_serial}, expected {serial_number}").into(),
        );
    }

    Ok(())
}

fn parse_card_list(status_lines: &[String]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut serial_numbers = Vec::new();

    for serial_number in status_lines
        .iter()
        .filter_map(|line| line.strip_prefix("SERIALNO "))
    {
        let serial_number = serial_number.trim();
        if !serial_numbers
            .iter()
            .any(|known: &String| known.eq_ignore_ascii_case(serial_number))
        {
            validate_serial_number(serial_number)?;
            serial_numbers.push(serial_number.to_owned());
        }
    }

    Ok(serial_numbers)
}

fn validate_serial_number(serial_number: &str) -> Result<(), Box<dyn Error>> {
    if serial_number.is_empty() || !serial_number.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid scdaemon card serial number: {serial_number:?}").into());
    }

    Ok(())
}

fn spawn_output_reader(stdout: ChildStdout) -> Receiver<AgentOutput> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match stdout.read_line(&mut line) {
                Ok(0) => {
                    let _ = sender.send(AgentOutput::Eof);
                    break;
                }
                Ok(_) => {
                    if sender.send(AgentOutput::Line(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(AgentOutput::Error(error.to_string()));
                    break;
                }
            }
        }
    });

    receiver
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => return false,
        }
    }
}

fn checkpin_identifier(serial_number: &str, pin: PinType) -> String {
    match pin {
        PinType::Sign | PinType::User => serial_number.to_owned(),
        PinType::Admin => format!("{serial_number}[CHV3]"),
    }
}

fn select_application_command(application: &[u8]) -> Vec<u8> {
    let mut cmd = vec![0x00, 0xa4, 0x04, 0x00];
    cmd.push(application.len() as u8);
    cmd.extend_from_slice(application);
    cmd.push(0x00);
    cmd
}

fn apdu_command(cmd: &[u8], response_limit: usize) -> SecretString {
    let mut command = String::with_capacity(25 + (cmd.len() * 2));
    write!(&mut command, "SCD APDU --exlen={response_limit} ")
        .expect("writing to a String cannot fail");

    for byte in cmd {
        write!(&mut command, "{byte:02X}").expect("writing to a String cannot fail");
    }

    command.into()
}

fn describe_apdu(cmd: &[u8]) -> String {
    if cmd.len() < 4 {
        return "malformed APDU".into();
    }

    if cmd[1] == 0x20 {
        return format!(
            "VERIFY APDU (cla={:02X}, p1={:02X}, p2={:02X}, data redacted)",
            cmd[0], cmd[2], cmd[3]
        );
    }

    format!(
        "APDU header {:02X}{:02X}{:02X}{:02X}",
        cmd[0], cmd[1], cmd[2], cmd[3]
    )
}

fn is_pin_bearing_verify(cmd: &[u8]) -> bool {
    cmd.len() > 5 && cmd.get(1) == Some(&0x20)
}

fn parse_hex_dump_data_line(line: &str) -> Result<(usize, Vec<u8>), Box<dyn Error>> {
    let Some((offset, after_offset)) = line.split_once(']') else {
        return Err(format!("malformed data line: {line}").into());
    };
    let Some(offset) = offset.strip_prefix("D[") else {
        return Err(format!("malformed data line: {line}").into());
    };

    if offset.len() != 4 || !offset.chars().all(|char| char.is_ascii_hexdigit()) {
        return Err(format!("malformed data-line offset: {line}").into());
    }
    let offset = usize::from_str_radix(offset, 16)?;

    let hex_field = after_offset
        .get(..HEX_DUMP_FIELD_WIDTH)
        .ok_or_else(|| format!("short data line: {line}"))?;
    let mut bytes = Vec::new();

    for token in hex_field.split_whitespace() {
        if token.len() != 2 || !token.chars().all(|char| char.is_ascii_hexdigit()) {
            return Err(format!("malformed hex byte in data line: {line}").into());
        }
        bytes.push(u8::from_str_radix(token, 16)?);
    }

    if bytes.len() > HEX_DUMP_BYTES_PER_LINE {
        return Err(format!("too many bytes in data line: {line}").into());
    }

    Ok((offset, bytes))
}

fn append_hex_dump_data_line(
    data: &mut Vec<u8>,
    frame_offset: &mut usize,
    line: &str,
) -> Result<(), Box<dyn Error>> {
    let (offset, bytes) = parse_hex_dump_data_line(line)?;

    // --hex offsets are local to each Assuan D frame. Long responses can
    // therefore legitimately restart at D[0000] more than once.
    if offset == 0 {
        *frame_offset = 0;
    }
    if offset != *frame_offset {
        return Err(format!(
            "non-contiguous gpg-connect-agent data offset: expected {:04X}, got {offset:04X}",
            *frame_offset
        )
        .into());
    }
    if data.len() + bytes.len() > MAX_AGENT_RESPONSE_BYTES {
        return Err(format!(
            "gpg-connect-agent response exceeded {MAX_AGENT_RESPONSE_BYTES} bytes"
        )
        .into());
    }

    *frame_offset += bytes.len();
    data.extend(bytes);
    Ok(())
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

fn smartcard_error(error: impl std::fmt::Display) -> SmartcardError {
    SmartcardError::Error(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        apdu_command, append_hex_dump_data_line, checkpin_identifier, describe_apdu,
        is_pin_bearing_verify, parse_card_list, parse_hex_dump_data_line, percent_decode,
    };
    use card_backend::PinType;
    use secrecy::ExposeSecret;

    #[test]
    fn parses_gpg_connect_agent_hex_dump_data_line() {
        let line = "D[0000]  90 00                                              ..              ";

        assert_eq!(
            parse_hex_dump_data_line(line).unwrap(),
            (0, vec![0x90, 0x00])
        );
    }

    #[test]
    fn ignores_hex_looking_ascii_display_column() {
        let line = "D[0000]  41 42 20 90 00                                     AB ..           ";

        assert_eq!(
            parse_hex_dump_data_line(line).unwrap(),
            (0, vec![0x41, 0x42, 0x20, 0x90, 0x00])
        );
    }

    #[test]
    fn parses_full_sixteen_byte_hex_dump_line() {
        let line = "D[0000]  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  0123456789ABCDEF";

        assert_eq!(
            parse_hex_dump_data_line(line).unwrap(),
            (0, (0_u8..16).collect())
        );
    }

    #[test]
    fn accepts_offsets_restarting_for_new_assuan_data_frames() {
        let mut data = Vec::new();
        let mut frame_offset = 0;
        append_hex_dump_data_line(
            &mut data,
            &mut frame_offset,
            "D[0000]  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ................",
        )
        .unwrap();
        append_hex_dump_data_line(
            &mut data,
            &mut frame_offset,
            "D[0010]  10 11                                             ..              ",
        )
        .unwrap();
        append_hex_dump_data_line(
            &mut data,
            &mut frame_offset,
            "D[0000]  12 13                                             ..              ",
        )
        .unwrap();

        assert_eq!(data, (0_u8..20).collect::<Vec<_>>());
    }

    #[test]
    fn decodes_assuan_percent_escapes() {
        assert_eq!(percent_decode(b"\xC0%0A%25").unwrap(), [0xC0, 0x0A, b'%']);
    }

    #[test]
    fn parses_and_validates_card_list() {
        assert_eq!(
            parse_card_list(&["SERIALNO D2760001240100000000000000010000".to_owned()]).unwrap(),
            ["D2760001240100000000000000010000"]
        );
        assert!(parse_card_list(&["SERIALNO not-a-serial".to_owned()]).is_err());
    }

    #[test]
    fn redacts_verify_apdu_diagnostics() {
        let pin = b"123456";
        let mut apdu = vec![0x00, 0x20, 0x00, 0x81, pin.len() as u8];
        apdu.extend_from_slice(pin);

        let description = describe_apdu(&apdu);
        assert!(description.contains("VERIFY"));
        assert!(!description.contains("123456"));
        assert!(is_pin_bearing_verify(&apdu));

        let command = apdu_command(&apdu, 4096);
        assert!(command.expose_secret().contains("313233343536"));
    }

    #[test]
    fn gpg_manages_pin_verification_without_inline_pin_data() {
        let serial = "D2760001240100000000000000010000";

        assert_eq!(checkpin_identifier(serial, PinType::Sign), serial);
        assert_eq!(checkpin_identifier(serial, PinType::User), serial);
        assert_eq!(
            checkpin_identifier(serial, PinType::Admin),
            format!("{serial}[CHV3]")
        );
    }
}
