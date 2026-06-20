use crate::analyzer::Analyzer;
use crate::warning;
use anyhow::Context;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

pub fn run(shell: Option<PathBuf>) -> anyhow::Result<()> {
    let shell = shell.unwrap_or_else(default_shell);
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("failed to open PTY")?;

    let mut command = CommandBuilder::new(shell.as_os_str());
    command.env("COMMANDGUARD", "1");
    let mut child = pair
        .slave
        .spawn_command(command)
        .with_context(|| format!("failed to launch shell {}", shell.display()))?;
    drop(pair.slave);

    let reader = pair
        .master
        .try_clone_reader()
        .context("failed to clone PTY reader")?;
    let mut writer = pair
        .master
        .take_writer()
        .context("failed to open PTY writer")?;
    let alternate_screen = Arc::new(AtomicBool::new(false));
    let output_thread = spawn_output_thread(reader, alternate_screen.clone());

    let _terminal = TerminalModeGuard::enter()?;
    let analyzer = Analyzer::default();
    let mut scanner = PasteScanner::default();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut byte = [0_u8; 1];

    loop {
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if alternate_screen.load(Ordering::Relaxed) {
                    writer.write_all(&byte)?;
                    writer.flush()?;
                    continue;
                }

                for action in scanner.feed_byte(byte[0]) {
                    match action {
                        InputAction::Forward(bytes) => {
                            writer.write_all(&bytes)?;
                            writer.flush()?;
                        }
                        InputAction::Paste(bytes) => {
                            handle_paste(&bytes, &analyzer, &mut stdin, &mut writer)?;
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("failed to read terminal input"),
        }
    }

    let _ = child.wait();
    let _ = output_thread.join();
    Ok(())
}

fn default_shell() -> PathBuf {
    std::env::var_os("SHELL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/bin/bash"))
}

fn spawn_output_thread(
    mut reader: Box<dyn Read + Send>,
    alternate_screen: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    update_alternate_screen(&buf[..n], &alternate_screen);
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    if stdout.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn update_alternate_screen(bytes: &[u8], alternate_screen: &AtomicBool) {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("\x1b[?1049h") || text.contains("\x1b[?1047h") || text.contains("\x1b[?47h") {
        alternate_screen.store(true, Ordering::Relaxed);
    }
    if text.contains("\x1b[?1049l") || text.contains("\x1b[?1047l") || text.contains("\x1b[?47l") {
        alternate_screen.store(false, Ordering::Relaxed);
    }
}

fn handle_paste<R: Read, W: Write>(
    paste: &[u8],
    analyzer: &Analyzer,
    stdin: &mut R,
    writer: &mut W,
) -> anyhow::Result<()> {
    let text = String::from_utf8_lossy(paste);
    let analysis = analyzer.analyze(&text);
    let trailing_newline = text.ends_with('\n') || text.ends_with('\r');

    if !analysis.severity.should_interrupt() && !trailing_newline {
        writer.write_all(paste)?;
        writer.flush()?;
        return Ok(());
    }

    let mut show_decoded = false;
    loop {
        let prompt = warning::paste_warning(&analysis, trailing_newline, show_decoded);
        let mut stderr = io::stderr();
        stderr.write_all(prompt.as_bytes())?;
        stderr.flush()?;

        match read_choice(stdin)? {
            PasteChoice::Cancel => {
                stderr.write_all(b"\r\nPaste canceled.\r\n")?;
                stderr.flush()?;
                return Ok(());
            }
            PasteChoice::ShowDecoded => {
                show_decoded = true;
            }
            PasteChoice::ExecuteAnyway => {
                stderr.write_all(b"\r\nExecuting pasted text.\r\n")?;
                stderr.flush()?;
                writer.write_all(paste)?;
                writer.flush()?;
                return Ok(());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasteChoice {
    Cancel,
    ShowDecoded,
    ExecuteAnyway,
}

fn read_choice<R: Read>(stdin: &mut R) -> anyhow::Result<PasteChoice> {
    let mut byte = [0_u8; 1];
    loop {
        stdin.read_exact(&mut byte)?;
        match byte[0].to_ascii_lowercase() {
            b'c' | 3 | 27 => return Ok(PasteChoice::Cancel),
            b's' => return Ok(PasteChoice::ShowDecoded),
            b'e' => return Ok(PasteChoice::ExecuteAnyway),
            _ => {}
        }
    }
}

struct TerminalModeGuard;

impl TerminalModeGuard {
    fn enter() -> anyhow::Result<Self> {
        enable_raw_mode().context("failed to enable terminal raw mode")?;
        let mut stdout = io::stdout();
        stdout.write_all(b"\x1b[?2004h")?;
        stdout.flush()?;
        Ok(Self)
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"\x1b[?2004l");
        let _ = stdout.flush();
        let _ = disable_raw_mode();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    Forward(Vec<u8>),
    Paste(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScannerState {
    Normal,
    Escape(Vec<u8>),
    Paste {
        bytes: Vec<u8>,
        possible_end: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteScanner {
    state: ScannerState,
}

impl Default for PasteScanner {
    fn default() -> Self {
        Self {
            state: ScannerState::Normal,
        }
    }
}

impl PasteScanner {
    pub fn feed_byte(&mut self, byte: u8) -> Vec<InputAction> {
        let mut actions = Vec::new();

        match &mut self.state {
            ScannerState::Normal => {
                if byte == b'\x1b' {
                    self.state = ScannerState::Escape(vec![byte]);
                } else {
                    actions.push(InputAction::Forward(vec![byte]));
                }
            }
            ScannerState::Escape(buffer) => {
                buffer.push(byte);
                if buffer.as_slice() == PASTE_START {
                    self.state = ScannerState::Paste {
                        bytes: Vec::new(),
                        possible_end: Vec::new(),
                    };
                } else if PASTE_START.starts_with(buffer.as_slice()) {
                    // Keep buffering until the full marker is known.
                } else {
                    actions.push(InputAction::Forward(buffer.clone()));
                    self.state = ScannerState::Normal;
                }
            }
            ScannerState::Paste {
                bytes,
                possible_end,
            } => {
                if !possible_end.is_empty() || byte == b'\x1b' {
                    possible_end.push(byte);
                    if possible_end.as_slice() == PASTE_END {
                        let paste = std::mem::take(bytes);
                        possible_end.clear();
                        self.state = ScannerState::Normal;
                        actions.push(InputAction::Paste(paste));
                    } else if PASTE_END.starts_with(possible_end.as_slice()) {
                        // Keep buffering until the full marker is known.
                    } else {
                        bytes.extend(std::mem::take(possible_end));
                    }
                } else {
                    bytes.push(byte);
                }
            }
        }

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_normal_input() {
        let mut scanner = PasteScanner::default();
        assert_eq!(
            scanner.feed_byte(b'a'),
            vec![InputAction::Forward(vec![b'a'])]
        );
    }

    #[test]
    fn captures_bracketed_paste() {
        let mut scanner = PasteScanner::default();
        let mut actions = Vec::new();
        for byte in b"\x1b[200~echo hi\x1b[201~" {
            actions.extend(scanner.feed_byte(*byte));
        }

        assert_eq!(actions, vec![InputAction::Paste(b"echo hi".to_vec())]);
    }

    #[test]
    fn forwards_non_paste_escape_sequence() {
        let mut scanner = PasteScanner::default();
        let mut actions = Vec::new();
        for byte in b"\x1b[A" {
            actions.extend(scanner.feed_byte(*byte));
        }

        assert_eq!(actions, vec![InputAction::Forward(b"\x1b[A".to_vec())]);
    }
}
