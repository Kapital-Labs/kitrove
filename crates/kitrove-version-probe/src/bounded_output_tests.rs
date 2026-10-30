use super::bounded_output::{read_probe_output, receive_probe_output};
use super::inspection_failure::InspectionFailure;
use crate::MAX_PROBE_OUTPUT_BYTES;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn caller_limits_and_reader_deadlines_are_explicit() {
    for limit in [0, 1, 17] {
        assert_eq!(
            read_probe_output(&vec![b'x'; limit][..], limit)
                .unwrap()
                .len(),
            limit
        );
        assert_eq!(
            read_probe_output(&vec![b'x'; limit + 1][..], limit),
            Err(InspectionFailure::OutputLimit)
        );
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    assert_eq!(
        receive_probe_output(receiver, Duration::ZERO),
        Err(InspectionFailure::OutputWaitTimedOut)
    );
    drop(sender);
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(sender);
    assert_eq!(
        receive_probe_output(receiver, Duration::ZERO),
        Err(InspectionFailure::OutputChannelClosed)
    );
    let (sender, receiver) = mpsc::sync_channel(1);
    sender.send(Ok("ready".to_owned())).unwrap();
    assert_eq!(
        receive_probe_output(receiver, Duration::ZERO).unwrap(),
        "ready"
    );
}

#[test]
fn accepts_exact_bound_and_rejects_one_extra_byte() {
    let exact = vec![b'x'; MAX_PROBE_OUTPUT_BYTES];
    assert_eq!(
        read_probe_output(exact.as_slice(), MAX_PROBE_OUTPUT_BYTES)
            .unwrap()
            .len(),
        exact.len()
    );
    let oversized = vec![b'x'; MAX_PROBE_OUTPUT_BYTES + 1];
    assert_eq!(
        read_probe_output(oversized.as_slice(), MAX_PROBE_OUTPUT_BYTES).unwrap_err(),
        InspectionFailure::OutputLimit
    );
}

#[test]
fn refuses_invalid_text_and_read_failure() {
    assert!(read_probe_output([0xff].as_slice(), MAX_PROBE_OUTPUT_BYTES).is_err());
    struct FailedReader;
    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic read failure"))
        }
    }
    assert!(read_probe_output(FailedReader, MAX_PROBE_OUTPUT_BYTES).is_err());
}

#[test]
fn read_failure_retains_closed_category_without_private_io_message() {
    struct PrivateFailure;
    impl Read for PrivateFailure {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private-probe-canary/path/account/value",
            ))
        }
    }
    let error = crate::ProbeError::from(
        read_probe_output(PrivateFailure, MAX_PROBE_OUTPUT_BYTES).unwrap_err(),
    );
    assert_eq!(error.code(), "version.probe_failed");
    assert_eq!(error.message(), crate::probe_failed().message());
    let debug = format!("{error:?}");
    assert!(debug.contains("operation: OutputRead"));
    assert!(debug.contains("kind: PermissionDenied"));
    assert!(!debug.contains("private-probe-canary"));
    assert!(!format!("{error}").contains("private-probe-canary"));
}
