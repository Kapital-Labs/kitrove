//! Bounded output collection shared by reviewed local inspections.
use super::inspection_failure::InspectionFailure;
use std::io::Read;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

pub(super) fn spawn_output_reader(
    mut output: impl Read + Send + 'static,
    maximum: usize,
) -> Result<Receiver<Result<String, InspectionFailure>>, InspectionFailure> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("kitrove-version-output".to_owned())
        .spawn(move || {
            let result = read_probe_output(&mut output, maximum);
            let _ = sender.send(result);
        })
        .map_err(|_| InspectionFailure::Failed)?;
    Ok(receiver)
}

pub(super) fn receive_probe_output(
    receiver: Receiver<Result<String, InspectionFailure>>,
    timeout: Duration,
) -> Result<String, InspectionFailure> {
    receiver
        .recv_timeout(timeout)
        .map_err(|_| InspectionFailure::Failed)?
}

fn read_probe_output(mut output: impl Read, maximum: usize) -> Result<String, InspectionFailure> {
    let mut bytes = Vec::new();
    output
        .by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| InspectionFailure::Failed)?;
    if bytes.len() > maximum {
        return Err(InspectionFailure::OutputLimit);
    }
    String::from_utf8(bytes).map_err(|_| InspectionFailure::InvalidOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_PROBE_OUTPUT_BYTES;

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
            Err(InspectionFailure::Failed)
        );
        drop(sender);
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
}
