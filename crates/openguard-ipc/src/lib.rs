#![forbid(unsafe_code)]

use openguard_domain::{PROTOCOL_VERSION, RequestEnvelope, ResponseEnvelope};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Read, Write};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame size {actual} is outside the allowed range 1..={maximum}")]
    InvalidSize { actual: usize, maximum: usize },
    #[error("unsupported protocol version {actual}; expected {expected}")]
    UnsupportedProtocol { actual: u16, expected: u16 },
    #[error("request identifier must be 1..=64 visible ASCII letters, digits, '-' or '_'")]
    InvalidRequestId,
}

/// Serializes one bounded value and writes its little-endian length prefix.
///
/// # Errors
///
/// Returns a frame error when serialization fails, the payload exceeds the
/// protocol limit, or the writer cannot accept the complete frame.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::InvalidSize {
            actual: payload.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }
    let size = u32::try_from(payload.len()).map_err(|_| FrameError::InvalidSize {
        actual: payload.len(),
        maximum: MAX_FRAME_BYTES,
    })?;
    writer.write_all(&size.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Reads and strictly deserializes one length-prefixed frame.
///
/// # Errors
///
/// Returns a frame error for invalid lengths, incomplete reads, malformed
/// JSON, unknown required structure, or trailing JSON content.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(FrameError::InvalidSize {
            actual: size,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&payload);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Verifies the negotiated protocol and request identifier syntax.
///
/// # Errors
///
/// Returns an unsupported-protocol or invalid-request-ID error when the
/// envelope is not valid for v1.
pub fn validate_request(request: &RequestEnvelope) -> Result<(), FrameError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedProtocol {
            actual: request.protocol,
            expected: PROTOCOL_VERSION,
        });
    }
    if !valid_request_id(&request.request_id) {
        return Err(FrameError::InvalidRequestId);
    }
    Ok(())
}

/// Verifies the negotiated protocol and response identifier syntax.
///
/// # Errors
///
/// Returns an unsupported-protocol or invalid-request-ID error when the
/// envelope is not valid for v1.
pub fn validate_response(response: &ResponseEnvelope) -> Result<(), FrameError> {
    if response.protocol != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedProtocol {
            actual: response.protocol,
            expected: PROTOCOL_VERSION,
        });
    }
    if !valid_request_id(&response.request_id) {
        return Err(FrameError::InvalidRequestId);
    }
    Ok(())
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openguard_domain::{Request, RequestEnvelope};
    use std::io::Cursor;

    #[test]
    fn request_round_trip_is_length_prefixed_and_strict() {
        let request = RequestEnvelope::new("request-1", Request::GetSnapshot);
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).expect("encode request");
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        let decoded: RequestEnvelope = read_frame(&mut Cursor::new(bytes)).expect("decode request");
        assert_eq!(decoded, request);
        validate_request(&decoded).expect("validate request");
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let header = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_le_bytes();
        let error = read_frame::<RequestEnvelope>(&mut Cursor::new(header)).unwrap_err();
        assert!(matches!(error, FrameError::InvalidSize { .. }));
    }

    #[test]
    fn unknown_json_fields_fail_closed() {
        let payload =
            br#"{"protocol":1,"request_id":"one","body":{"operation":"ping"},"extra":true}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(payload);
        assert!(read_frame::<RequestEnvelope>(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn unsupported_protocol_and_bad_identifier_are_rejected() {
        let mut request = RequestEnvelope::new("request-1", Request::Ping);
        request.protocol = PROTOCOL_VERSION + 1;
        assert!(matches!(
            validate_request(&request),
            Err(FrameError::UnsupportedProtocol { .. })
        ));
        request.protocol = PROTOCOL_VERSION;
        request.request_id = "contains a space".into();
        assert!(matches!(
            validate_request(&request),
            Err(FrameError::InvalidRequestId)
        ));
    }
}
