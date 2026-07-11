//! Bounded client for the line-oriented gpg-connect-agent protocol.
//!
//! Commands use stdin rather than process arguments. A reader thread makes
//! command deadlines possible despite blocking child output, while strict
//! parsing and response limits keep malformed output from reaching the card
//! library.

use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret, SecretString};

const HEX_DUMP_BYTES_PER_LINE: usize = 16;
const HEX_DUMP_FIELD_WIDTH: usize = 2 + (HEX_DUMP_BYTES_PER_LINE * 3);
const MAX_AGENT_RESPONSE_BYTES: usize = 64 * 1024;
const AGENT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const AGENT_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Default)]
pub(super) struct AgentResponse {
    pub(super) data: Vec<u8>,
    pub(super) status_lines: Vec<String>,
}

pub(super) struct GpgConnectAgent {
    child: Child,
    stdin: Option<ChildStdin>,
    // CardTransaction must be Sync, while Receiver is single-consumer.
    output: Mutex<Receiver<AgentOutput>>,
    closed: bool,
}

enum AgentOutput {
    Line(String),
    Eof,
    Error(String),
}

impl GpgConnectAgent {
    pub(super) fn spawn() -> Result<Self, Box<dyn Error>> {
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

    pub(super) fn command(&mut self, command: &str) -> Result<AgentResponse, Box<dyn Error>> {
        self.command_bytes(command.as_bytes())
    }

    pub(super) fn secret_command(
        &mut self,
        command: &SecretString,
    ) -> Result<AgentResponse, Box<dyn Error>> {
        self.command_bytes(command.expose_secret().as_bytes())
    }

    fn command_bytes(&mut self, command: &[u8]) -> Result<AgentResponse, Box<dyn Error>> {
        // Assuan accepts one command per line, so reject command-delimiter
        // injection at the process boundary.
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

    pub(super) fn close(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::{append_hex_dump_data_line, parse_hex_dump_data_line, percent_decode};

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
}
