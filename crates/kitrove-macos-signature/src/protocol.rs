//! Fixed request framing only; a decoded request carries no trust or launch authority.
use super::{AppleSignatureCandidate, SignatureRefused, inspect_fingerprints};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Instant;

const MAGIC: &[u8; 8] = b"KRVAM001";
const HEADER_BYTES: usize = 8 + 2 + 20 + 32;
const MAX_PATH_BYTES: usize = 4096;
/// Transport readers must enforce this bound before allocating or collecting input.
pub const MAX_INSPECTION_REQUEST_BYTES: usize = HEADER_BYTES + MAX_PATH_BYTES;
/// Exact acknowledgement; only meaningful with trusted child, clean exit and cleanup.
pub const INSPECTION_SUCCESS_RESPONSE: &[u8] = b"kitrove-apple-inspection-v1:ok\n";

/// One validated request with a monotonic offset and an absolute caller deadline.
/// This records transport progress only; it neither writes nor resumes a helper.
pub struct InspectionRequest {
    bytes: Vec<u8>,
    offset: usize,
    deadline: Instant,
    refused: bool,
}

impl InspectionRequest {
    pub fn new(
        path: &Path,
        candidate: &AppleSignatureCandidate,
        deadline: Instant,
    ) -> Result<Self, SignatureRefused> {
        Self::from_frame(encode_inspection_request(path, candidate)?, deadline)
    }

    fn from_frame(bytes: Vec<u8>, deadline: Instant) -> Result<Self, SignatureRefused> {
        decode(&bytes)?;
        let mut request = Self {
            bytes,
            offset: 0,
            deadline,
            refused: false,
        };
        request.check()?;
        Ok(request)
    }

    /// An empty slice means all bytes were written, not that input was closed.
    /// Pending writes leave the offset unchanged and must revisit this deadline.
    pub fn remaining(&mut self) -> Result<&[u8], SignatureRefused> {
        self.check()?;
        Ok(&self.bytes[self.offset..])
    }

    /// Record only an observed successful write, never requested byte count.
    pub fn written(&mut self, count: usize) -> Result<(), SignatureRefused> {
        self.check()?;
        if count == 0 || count > self.bytes.len() - self.offset {
            self.refused = true;
            return Err(SignatureRefused);
        }
        self.offset += count;
        Ok(())
    }

    /// Consume only after closing transport input. This checks byte accounting,
    /// not actual descriptor closure, response contents, child exit or cleanup.
    pub fn finish_after_input_closed(mut self) -> Result<(), SignatureRefused> {
        self.check()?;
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SignatureRefused)
        }
    }

    fn check(&mut self) -> Result<(), SignatureRefused> {
        self.refused |= Instant::now() >= self.deadline;
        if self.refused {
            Err(SignatureRefused)
        } else {
            Ok(())
        }
    }
}

/// Allocation-free response framing, not helper trust or execution authority.
/// A driver must separately establish deadline, successful exit, cleanup and
/// retained authenticated payload identity. Any framing refusal is permanent.
#[derive(Default)]
pub struct InspectionResponse {
    matched: usize,
    output_eof: bool,
    error_eof: bool,
    refused: bool,
}

impl InspectionResponse {
    /// Consume nonempty stdout bytes, refusing any mismatch or excess immediately.
    pub fn output_chunk(&mut self, bytes: &[u8]) -> Result<(), SignatureRefused> {
        let remaining = &INSPECTION_SUCCESS_RESPONSE[self.matched..];
        self.require(!self.output_eof && !bytes.is_empty() && remaining.starts_with(bytes))?;
        self.matched += bytes.len();
        Ok(())
    }

    /// Any stderr bytes refuse. Empty chunks are not valid transport events.
    pub fn error_chunk(&mut self, _bytes: &[u8]) -> Result<(), SignatureRefused> {
        self.require(false)
    }

    pub fn output_eof(&mut self) -> Result<(), SignatureRefused> {
        self.require(!self.output_eof && self.matched == INSPECTION_SUCCESS_RESPONSE.len())?;
        self.output_eof = true;
        Ok(())
    }

    pub fn error_eof(&mut self) -> Result<(), SignatureRefused> {
        self.require(!self.error_eof)?;
        self.error_eof = true;
        Ok(())
    }

    /// Confirms framing only. Exact bytes without both EOFs are incomplete.
    pub fn finish(self) -> Result<(), SignatureRefused> {
        if !self.refused && self.output_eof && self.error_eof {
            Ok(())
        } else {
            Err(SignatureRefused)
        }
    }

    fn require(&mut self, valid: bool) -> Result<(), SignatureRefused> {
        self.refused |= !valid;
        if self.refused {
            Err(SignatureRefused)
        } else {
            Ok(())
        }
    }
}

/// Serve one request, emitting no success bytes until native inspection succeeds.
/// This does not impose a wall-clock deadline: invoke only in a contained child.
/// The parent must close input after one frame and require exact acknowledgement,
/// empty stderr, successful exit, retained identity and confirmed child cleanup.
pub fn serve_inspection(input: impl Read, output: impl Write) -> Result<(), SignatureRefused> {
    let request = read_request(input)?;
    inspect_request(&request)?;
    write_success(output)
}

fn read_request(input: impl Read) -> Result<Vec<u8>, SignatureRefused> {
    let mut request = Vec::new();
    input
        .take((MAX_INSPECTION_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|_| SignatureRefused)?;
    decode(&request)?;
    Ok(request)
}

fn write_success(mut output: impl Write) -> Result<(), SignatureRefused> {
    output
        .write_all(INSPECTION_SUCCESS_RESPONSE)
        .map_err(|_| SignatureRefused)?;
    output.flush().map_err(|_| SignatureRefused)
}

/// Encode one fixed Apple inspection operation, never a command or policy override.
/// Captured fingerprints are untrusted claims until checked by the native API.
pub fn encode_inspection_request(
    path: &Path,
    candidate: &AppleSignatureCandidate,
) -> Result<Vec<u8>, SignatureRefused> {
    encode(path, candidate.cdhash(), candidate.cms_sha256())
}

fn encode(path: &Path, cdhash: &[u8; 20], cms: &[u8; 32]) -> Result<Vec<u8>, SignatureRefused> {
    let path = path.as_os_str().as_bytes();
    validate_path(path)?;
    let length = u16::try_from(path.len()).map_err(|_| SignatureRefused)?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + path.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(cdhash);
    bytes.extend_from_slice(cms);
    bytes.extend_from_slice(path);
    Ok(bytes)
}

struct Request<'a> {
    path: &'a Path,
    cdhash: &'a [u8; 20],
    cms: &'a [u8; 32],
}

fn decode(bytes: &[u8]) -> Result<Request<'_>, SignatureRefused> {
    if !(HEADER_BYTES..=MAX_INSPECTION_REQUEST_BYTES).contains(&bytes.len()) || &bytes[..8] != MAGIC
    {
        return Err(SignatureRefused);
    }
    let length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    if bytes.len() != HEADER_BYTES + length {
        return Err(SignatureRefused);
    }
    let path = &bytes[HEADER_BYTES..];
    validate_path(path)?;
    Ok(Request {
        path: Path::new(OsStr::from_bytes(path)),
        cdhash: bytes[10..30].try_into().map_err(|_| SignatureRefused)?,
        cms: bytes[30..HEADER_BYTES]
            .try_into()
            .map_err(|_| SignatureRefused)?,
    })
}

fn validate_path(path: &[u8]) -> Result<(), SignatureRefused> {
    if path.len() > MAX_PATH_BYTES
        || !path.starts_with(b"/")
        || path.contains(&0)
        || path[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(SignatureRefused);
    }
    Ok(())
}

/// Inspect an exact bounded frame using the fixed native publisher policy.
/// This may block and must run only inside the future deadline-controlled helper.
/// Success is not a serialized readiness receipt: the parent must independently
/// establish helper trust, retained payload identity, deadline and cleanup evidence.
pub fn inspect_request(bytes: &[u8]) -> Result<(), SignatureRefused> {
    let request = decode(bytes)?;
    inspect_fingerprints(request.path, request.cdhash, request.cms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_accounts_for_partial_writes_without_resetting_deadline() {
        let frame = encode(Path::new("/private/payload"), &[7; 20], &[9; 32]).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut request = InspectionRequest::from_frame(frame.clone(), deadline).unwrap();
        for offset in 0..frame.len() {
            assert_eq!(request.remaining().unwrap(), &frame[offset..]);
            // A pending write makes no progress and does not refresh the deadline.
            assert_eq!(request.remaining().unwrap(), &frame[offset..]);
            assert_eq!(request.deadline, deadline);
            request.written(1).unwrap();
        }
        assert!(request.remaining().unwrap().is_empty());
        request.finish_after_input_closed().unwrap();
    }

    #[test]
    fn request_refuses_bad_progress_expiry_and_incomplete_input() {
        let frame = encode(Path::new("/private/payload"), &[7; 20], &[9; 32]).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        assert!(InspectionRequest::from_frame(frame.clone(), Instant::now()).is_err());
        assert!(InspectionRequest::from_frame(b"bad frame".to_vec(), deadline).is_err());
        for count in [0, frame.len() + 1, usize::MAX] {
            let mut request = InspectionRequest::from_frame(frame.clone(), deadline).unwrap();
            assert!(request.written(count).is_err());
            assert!(request.remaining().is_err());
            assert!(request.written(1).is_err());
            assert!(request.finish_after_input_closed().is_err());
        }
        let request = InspectionRequest::from_frame(frame.clone(), deadline).unwrap();
        assert!(request.finish_after_input_closed().is_err());
        let mut request = InspectionRequest::from_frame(frame, deadline).unwrap();
        request.deadline = Instant::now();
        assert!(request.remaining().is_err());
        assert!(request.written(1).is_err());
        assert!(request.finish_after_input_closed().is_err());
    }

    #[test]
    fn response_accepts_every_split_only_after_both_eofs() {
        for split in 0..=INSPECTION_SUCCESS_RESPONSE.len() {
            let mut response = InspectionResponse::default();
            response.error_eof().unwrap();
            for chunk in [
                &INSPECTION_SUCCESS_RESPONSE[..split],
                &INSPECTION_SUCCESS_RESPONSE[split..],
            ] {
                if !chunk.is_empty() {
                    response.output_chunk(chunk).unwrap();
                }
            }
            response.output_eof().unwrap();
            response.finish().unwrap();
        }
        let mut response = InspectionResponse::default();
        for byte in INSPECTION_SUCCESS_RESPONSE {
            response.output_chunk(&[*byte]).unwrap();
        }
        response.output_eof().unwrap();
        assert!(response.finish().is_err());
        let mut response = InspectionResponse::default();
        response.output_chunk(INSPECTION_SUCCESS_RESPONSE).unwrap();
        response.error_eof().unwrap();
        assert!(response.finish().is_err());
    }

    #[test]
    fn response_refuses_corruption_truncation_and_trailing_bytes_permanently() {
        for index in 0..INSPECTION_SUCCESS_RESPONSE.len() {
            let mut bytes = INSPECTION_SUCCESS_RESPONSE.to_vec();
            bytes[index] ^= 1;
            let mut response = InspectionResponse::default();
            assert!(response.output_chunk(&bytes).is_err());
            assert!(response.output_chunk(INSPECTION_SUCCESS_RESPONSE).is_err());
            assert!(response.finish().is_err());

            let mut response = InspectionResponse::default();
            if index != 0 {
                response
                    .output_chunk(&INSPECTION_SUCCESS_RESPONSE[..index])
                    .unwrap();
            }
            assert!(response.output_eof().is_err());
            assert!(response.finish().is_err());
        }
        let mut response = InspectionResponse::default();
        response.output_chunk(INSPECTION_SUCCESS_RESPONSE).unwrap();
        assert!(response.output_chunk(b"x").is_err());
        assert!(response.finish().is_err());
        let mut response = InspectionResponse::default();
        assert!(response.output_chunk(&[]).is_err());
        assert!(response.finish().is_err());
    }

    #[test]
    fn response_refuses_stderr_and_events_after_eof() {
        for bytes in [b"private detail".as_slice(), b""] {
            let mut response = InspectionResponse::default();
            assert!(response.error_chunk(bytes).is_err());
            assert!(response.error_eof().is_err());
            assert!(response.finish().is_err());
        }
        let mut response = InspectionResponse::default();
        response.output_chunk(INSPECTION_SUCCESS_RESPONSE).unwrap();
        response.output_eof().unwrap();
        assert!(response.output_chunk(b"x").is_err());
        assert!(response.finish().is_err());
        let mut response = InspectionResponse::default();
        response.output_chunk(INSPECTION_SUCCESS_RESPONSE).unwrap();
        response.output_eof().unwrap();
        assert!(response.output_eof().is_err());
        assert!(response.finish().is_err());
        let mut response = InspectionResponse::default();
        response.error_eof().unwrap();
        assert!(response.error_eof().is_err());
        assert!(response.finish().is_err());
    }

    #[test]
    fn transport_bounds_reads_and_never_acknowledges_refused_input() {
        let mut endless = std::io::repeat(0);
        let mut bounded = (&mut endless).take((MAX_INSPECTION_REQUEST_BYTES + 100) as u64);
        let mut output = Vec::new();
        assert!(serve_inspection(&mut bounded, &mut output).is_err());
        assert_eq!(bounded.limit(), 99);
        assert!(output.is_empty());
        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private read detail"))
            }
        }
        assert_eq!(
            serve_inspection(FailedReader, &mut output)
                .unwrap_err()
                .to_string(),
            "native Apple signature inspection refused"
        );
        assert!(output.is_empty());
        let frame = encode(Path::new("/private/payload"), &[7; 20], &[9; 32]).unwrap();
        assert_eq!(read_request(frame.as_slice()).unwrap(), frame);
    }

    #[test]
    fn acknowledgement_is_exact_and_write_or_flush_failure_refuses() {
        let mut bytes = Vec::new();
        write_success(&mut bytes).unwrap();
        assert_eq!(bytes, INSPECTION_SUCCESS_RESPONSE);
        struct FailedWriter {
            fail_write: bool,
        }
        impl Write for FailedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    Err(std::io::Error::other("private write detail"))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("private flush detail"))
            }
        }
        assert!(write_success(FailedWriter { fail_write: true }).is_err());
        assert!(write_success(FailedWriter { fail_write: false }).is_err());
    }

    #[test]
    fn exact_frame_preserves_native_path_bytes_and_both_fingerprints() {
        let path = Path::new(OsStr::from_bytes(b"/private/non-utf8-\xff/payload"));
        let encoded = encode(path, &[7; 20], &[9; 32]).unwrap();
        let parsed = decode(&encoded).unwrap();
        assert_eq!(parsed.path, path);
        assert_eq!(parsed.cdhash, &[7; 20]);
        assert_eq!(parsed.cms, &[9; 32]);
        assert_eq!(
            encode(parsed.path, parsed.cdhash, parsed.cms).unwrap(),
            encoded
        );
    }

    #[test]
    fn refuses_truncation_trailing_data_unknown_version_and_forged_length() {
        let encoded = encode(Path::new("/private/payload"), &[7; 20], &[9; 32]).unwrap();
        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length]).is_err());
        }
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        for index in 0..10 {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(decode(&changed).is_err());
        }
    }

    #[test]
    fn rejects_ambiguous_paths_and_bounds_allocation() {
        for path in [
            "", "/", "relative", "/a/../b", "/a/./b", "//a", "/a/", "/a\0b",
        ] {
            assert!(encode(Path::new(path), &[0; 20], &[0; 32]).is_err());
        }
        let maximum = format!("/{}", "x".repeat(MAX_PATH_BYTES - 1));
        let encoded = encode(Path::new(&maximum), &[0; 20], &[0; 32]).unwrap();
        assert_eq!(encoded.len(), MAX_INSPECTION_REQUEST_BYTES);
        assert!(decode(&encoded).is_ok());
        assert!(encode(Path::new(&(maximum + "x")), &[0; 20], &[0; 32]).is_err());
        assert!(decode(&vec![0; MAX_INSPECTION_REQUEST_BYTES + 1]).is_err());
        // Decoder also validates paths; it cannot rely on our encoder being the sender.
        let mut forged = encode(Path::new("/a/b"), &[0; 20], &[0; 32]).unwrap();
        forged[HEADER_BYTES + 1] = 0;
        assert!(decode(&forged).is_err());
        assert!(inspect_request(b"invalid").is_err());
    }
}
