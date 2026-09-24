//! Bounded output collection shared by reviewed local inspections.
use super::{
    MAX_PROBE_OUTPUT_BYTES, OUTPUT_READER_TIMEOUT, ProbeError, invalid_output, probe_failed,
};
use std::io::Read;
use std::sync::mpsc::{self, Receiver};
use std::thread;

pub(super) fn spawn_output_reader(
    mut output: impl Read + Send + 'static,
) -> Result<Receiver<Result<String, ProbeError>>, ProbeError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("kitrove-version-output".to_owned())
        .spawn(move || {
            let result = read_probe_output(&mut output);
            let _ = sender.send(result);
        })
        .map_err(|_| probe_failed())?;
    Ok(receiver)
}

pub(super) fn receive_probe_output(
    receiver: Receiver<Result<String, ProbeError>>,
) -> Result<String, ProbeError> {
    receiver
        .recv_timeout(OUTPUT_READER_TIMEOUT)
        .map_err(|_| probe_failed())?
}

fn read_probe_output(mut output: impl Read) -> Result<String, ProbeError> {
    let mut bytes = Vec::new();
    output
        .by_ref()
        .take(
            u64::try_from(MAX_PROBE_OUTPUT_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| probe_failed())?;
    if bytes.len() > MAX_PROBE_OUTPUT_BYTES {
        return Err(ProbeError::new(
            "version.probe_output_limit",
            "the harness version probe output exceeds the supported bound",
        ));
    }
    String::from_utf8(bytes).map_err(|_| invalid_output())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_bound_and_rejects_one_extra_byte() {
        let exact = vec![b'x'; MAX_PROBE_OUTPUT_BYTES];
        assert_eq!(
            read_probe_output(exact.as_slice()).unwrap().len(),
            exact.len()
        );
        let oversized = vec![b'x'; MAX_PROBE_OUTPUT_BYTES + 1];
        assert_eq!(
            read_probe_output(oversized.as_slice()).unwrap_err().code(),
            "version.probe_output_limit"
        );
    }

    #[test]
    fn refuses_invalid_text_and_read_failure() {
        assert!(read_probe_output([0xff].as_slice()).is_err());
        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic read failure"))
            }
        }
        assert!(read_probe_output(FailedReader).is_err());
    }
}
