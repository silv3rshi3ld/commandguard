use crate::model::DecodedVariant;
use base64::{engine::general_purpose, Engine as _};
use flate2::read::GzDecoder;
use std::io::Read;
use thiserror::Error;

const DISPLAY_LIMIT: usize = 8192;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("encoded input is larger than the configured limit")]
    InputTooLarge,
    #[error("decoded output is larger than the configured limit")]
    OutputTooLarge,
    #[error("input is not valid encoded data")]
    Invalid,
    #[error("decoded data is not utf8 text")]
    NotText,
}

#[derive(Debug, Clone)]
pub struct DecodeOutcome {
    pub bytes: Vec<u8>,
    pub text: String,
    pub variant: DecodedVariant,
}

pub fn decode_base64_text(
    input: &str,
    max_input: usize,
    max_output: usize,
) -> Result<DecodeOutcome, DecodeError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() > max_input {
        return Err(DecodeError::InputTooLarge);
    }

    let padded = pad_base64(&cleaned);
    let bytes = general_purpose::STANDARD
        .decode(padded.as_bytes())
        .or_else(|_| general_purpose::URL_SAFE.decode(padded.as_bytes()))
        .map_err(|_| DecodeError::Invalid)?;
    decode_bytes("base64_decode", bytes, max_output)
}

pub fn decode_hex_text(
    input: &str,
    max_input: usize,
    max_output: usize,
) -> Result<DecodeOutcome, DecodeError> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() > max_input || cleaned.len() % 2 != 0 {
        return Err(DecodeError::Invalid);
    }

    let bytes = hex::decode(cleaned).map_err(|_| DecodeError::Invalid)?;
    decode_bytes("hex_decode", bytes, max_output)
}

pub fn decode_gzip_bytes(input: &[u8], max_output: usize) -> Result<DecodeOutcome, DecodeError> {
    let mut decoder = GzDecoder::new(input);
    let mut bytes = Vec::new();
    decoder
        .by_ref()
        .take((max_output + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| DecodeError::Invalid)?;
    decode_bytes("gzip_decompress", bytes, max_output)
}

fn decode_bytes(
    transform: &str,
    bytes: Vec<u8>,
    max_output: usize,
) -> Result<DecodeOutcome, DecodeError> {
    if bytes.len() > max_output {
        return Err(DecodeError::OutputTooLarge);
    }
    let text = String::from_utf8(bytes.clone()).map_err(|_| DecodeError::NotText)?;
    let variant = DecodedVariant {
        transform: transform.to_string(),
        text: truncate_display(&text).0,
        truncated: truncate_display(&text).1,
    };
    Ok(DecodeOutcome {
        bytes,
        text,
        variant,
    })
}

fn pad_base64(input: &str) -> String {
    let mut padded = input.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    padded
}

fn truncate_display(input: &str) -> (String, bool) {
    if input.len() <= DISPLAY_LIMIT {
        return (input.to_string(), false);
    }

    let mut end = DISPLAY_LIMIT;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    (input[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unpadded_base64_text() {
        let out = decode_base64_text("SGVsbG8", 1024, 1024).unwrap();
        assert_eq!(out.text, "Hello");
    }

    #[test]
    fn decodes_hex_text() {
        let out = decode_hex_text("6563686f206869", 1024, 1024).unwrap();
        assert_eq!(out.text, "echo hi");
    }
}
