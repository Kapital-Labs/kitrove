//! Cooperative bounded transport steps, not child execution or installer readiness.
use crate::{AppleSignatureCandidate, InspectionRequest, InspectionResponse, SignatureRefused};
use kitrove_macos_process::{InputProgress, InspectionStream, InspectionTransport, OutputProgress};
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeProgress {
    Pending,
    /// Exact framing and both EOFs only. Successful exit and cleanup remain required.
    Framed,
}

/// Drives one fixed request without spawning, resuming or taking child ownership.
/// The verified child owner must retain this state and the exact transport together,
/// enforce the same deadline while waiting for exit, and clean up on any refusal.
pub struct InspectionExchange {
    request: Option<InspectionRequest>,
    response: InspectionResponse,
    deadline: Instant,
    output_eof: bool,
    error_eof: bool,
    terminal: bool,
}

impl InspectionExchange {
    pub fn new(
        path: &Path,
        candidate: &AppleSignatureCandidate,
        deadline: Instant,
    ) -> Result<Self, SignatureRefused> {
        Ok(Self::from_request(
            InspectionRequest::new(path, candidate, deadline)?,
            deadline,
        ))
    }

    fn from_request(request: InspectionRequest, deadline: Instant) -> Self {
        Self {
            request: Some(request),
            response: InspectionResponse::default(),
            deadline,
            output_eof: false,
            error_eof: false,
            terminal: false,
        }
    }

    /// Performs at most one bounded write and one bounded read per output stream.
    /// Pending never means success. Callers must not busy-spin or refresh deadlines.
    pub fn poll(
        &mut self,
        transport: &mut InspectionTransport,
    ) -> Result<ExchangeProgress, SignatureRefused> {
        self.step(transport)
    }

    fn step(
        &mut self,
        transport: &mut impl Transport,
    ) -> Result<ExchangeProgress, SignatureRefused> {
        if self.terminal || Instant::now() >= self.deadline {
            self.terminal = true;
            return Err(SignatureRefused);
        }
        let result = self.transfer(transport);
        if result.is_err() || result == Ok(ExchangeProgress::Framed) {
            self.terminal = true;
        }
        result
    }

    fn transfer(
        &mut self,
        transport: &mut impl Transport,
    ) -> Result<ExchangeProgress, SignatureRefused> {
        if let Some(request) = &mut self.request {
            match transport.write(request.remaining()?)? {
                InputProgress::Written(count) => request.written(count)?,
                InputProgress::Pending => {}
            }
            if request.remaining()?.is_empty() {
                transport.close_input();
                self.request
                    .take()
                    .ok_or(SignatureRefused)?
                    .finish_after_input_closed()?;
            }
        }
        let mut buffer = [0; 1024];
        for stream in [InspectionStream::Output, InspectionStream::Error] {
            let eof = match stream {
                InspectionStream::Output => &mut self.output_eof,
                InspectionStream::Error => &mut self.error_eof,
            };
            if *eof {
                continue;
            }
            match transport.read(stream, &mut buffer)? {
                OutputProgress::Pending => {}
                OutputProgress::Read(count) => {
                    let bytes = buffer
                        .get(..count)
                        .filter(|_| count != 0)
                        .ok_or(SignatureRefused)?;
                    match stream {
                        InspectionStream::Output => self.response.output_chunk(bytes)?,
                        InspectionStream::Error => self.response.error_chunk(bytes)?,
                    }
                }
                OutputProgress::Eof => {
                    match stream {
                        InspectionStream::Output => self.response.output_eof()?,
                        InspectionStream::Error => self.response.error_eof()?,
                    }
                    *eof = true;
                }
            }
        }
        if Instant::now() >= self.deadline {
            return Err(SignatureRefused);
        }
        if self.request.is_none() && self.output_eof && self.error_eof {
            std::mem::take(&mut self.response).finish()?;
            Ok(ExchangeProgress::Framed)
        } else {
            Ok(ExchangeProgress::Pending)
        }
    }
}

// Private seam lets adversarial tests exercise the same driver without resuming a
// process or introducing a caller-selectable command/verification implementation.
trait Transport {
    fn write(&mut self, bytes: &[u8]) -> Result<InputProgress, SignatureRefused>;
    fn close_input(&mut self);
    fn read(
        &mut self,
        stream: InspectionStream,
        buffer: &mut [u8],
    ) -> Result<OutputProgress, SignatureRefused>;
}

impl Transport for InspectionTransport {
    fn write(&mut self, bytes: &[u8]) -> Result<InputProgress, SignatureRefused> {
        self.write_input_chunk(bytes).map_err(|_| SignatureRefused)
    }
    fn close_input(&mut self) {
        InspectionTransport::close_input(self);
    }
    fn read(
        &mut self,
        stream: InspectionStream,
        buffer: &mut [u8],
    ) -> Result<OutputProgress, SignatureRefused> {
        self.read_output_chunk(stream, buffer)
            .map_err(|_| SignatureRefused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::INSPECTION_SUCCESS_RESPONSE;
    use std::collections::VecDeque;
    use std::time::Duration;

    #[derive(Default)]
    struct Script {
        sent: Vec<u8>,
        closed: bool,
        pending: bool,
        fail: bool,
        output: VecDeque<Vec<u8>>,
        error: VecDeque<Vec<u8>>,
        calls: usize,
    }
    impl Transport for Script {
        fn write(&mut self, bytes: &[u8]) -> Result<InputProgress, SignatureRefused> {
            self.calls += 1;
            assert!(!self.closed);
            if self.fail {
                return Err(SignatureRefused);
            }
            if self.pending {
                return Ok(InputProgress::Pending);
            }
            let count = bytes.len().min(3);
            self.sent.extend_from_slice(&bytes[..count]);
            Ok(InputProgress::Written(count))
        }
        fn close_input(&mut self) {
            assert!(!self.closed);
            self.closed = true;
        }
        fn read(
            &mut self,
            stream: InspectionStream,
            buffer: &mut [u8],
        ) -> Result<OutputProgress, SignatureRefused> {
            self.calls += 1;
            if !self.closed {
                return Ok(OutputProgress::Pending);
            }
            let queue = match stream {
                InspectionStream::Output => &mut self.output,
                InspectionStream::Error => &mut self.error,
            };
            match queue.pop_front() {
                Some(bytes) => {
                    buffer[..bytes.len()].copy_from_slice(&bytes);
                    Ok(OutputProgress::Read(bytes.len()))
                }
                None => Ok(OutputProgress::Eof),
            }
        }
    }
    fn fixture() -> (InspectionExchange, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut request = InspectionRequest::fixture(deadline);
        let expected = request.remaining().unwrap().to_vec();
        (
            InspectionExchange::from_request(request, deadline),
            expected,
        )
    }

    #[test]
    fn partial_writes_close_before_response_and_frame_once() {
        let (mut exchange, expected) = fixture();
        let mut script = Script {
            output: INSPECTION_SUCCESS_RESPONSE
                .chunks(2)
                .map(<[u8]>::to_vec)
                .collect(),
            ..Script::default()
        };
        let mut result = ExchangeProgress::Pending;
        for _ in 0..200 {
            let before = script.calls;
            result = exchange.step(&mut script).unwrap();
            assert!(script.calls - before <= 3);
            if result == ExchangeProgress::Framed {
                break;
            }
        }
        assert_eq!(result, ExchangeProgress::Framed);
        assert_eq!(script.sent, expected);
        assert!(script.closed);
        let calls = script.calls;
        assert!(exchange.step(&mut script).is_err());
        assert_eq!(script.calls, calls);
    }

    #[test]
    fn pending_does_not_refresh_deadline_and_expiry_permanently_refuses() {
        let (mut exchange, _) = fixture();
        let deadline = exchange.deadline;
        let mut script = Script {
            pending: true,
            ..Script::default()
        };
        assert_eq!(
            exchange.step(&mut script).unwrap(),
            ExchangeProgress::Pending
        );
        assert_eq!(exchange.deadline, deadline);
        assert!(script.sent.is_empty());
        exchange.deadline = Instant::now();
        let calls = script.calls;
        assert!(exchange.step(&mut script).is_err());
        assert_eq!(script.calls, calls);
        assert!(!script.closed);
    }

    #[test]
    fn transport_failure_and_stderr_never_frame() {
        let (mut exchange, _) = fixture();
        let mut script = Script {
            fail: true,
            ..Script::default()
        };
        assert!(exchange.step(&mut script).is_err());
        script.fail = false;
        assert!(exchange.step(&mut script).is_err());
        let (mut exchange, _) = fixture();
        let mut script = Script {
            output: [INSPECTION_SUCCESS_RESPONSE.to_vec()].into(),
            error: [b"private error".to_vec()].into(),
            ..Script::default()
        };
        let mut refused = false;
        for _ in 0..200 {
            match exchange.step(&mut script) {
                Ok(ExchangeProgress::Pending) => {}
                Ok(ExchangeProgress::Framed) => panic!("stderr accepted"),
                Err(_) => {
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused);
    }
}
