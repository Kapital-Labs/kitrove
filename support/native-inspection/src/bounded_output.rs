//! Bounded output collection shared by reviewed local inspections.
use super::inspection_failure::{InspectionFailure, InspectionOperation};
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
        .map_err(|error| InspectionFailure::io(InspectionOperation::OutputReaderStart, &error))?;
    Ok(receiver)
}

pub(super) fn receive_probe_output(
    receiver: Receiver<Result<String, InspectionFailure>>,
    timeout: Duration,
) -> Result<String, InspectionFailure> {
    receiver
        .recv_timeout(timeout)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => InspectionFailure::OutputWaitTimedOut,
            mpsc::RecvTimeoutError::Disconnected => InspectionFailure::OutputChannelClosed,
        })?
}

pub(super) fn read_probe_output(
    mut output: impl Read,
    maximum: usize,
) -> Result<String, InspectionFailure> {
    let mut bytes = Vec::new();
    output
        .by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| InspectionFailure::io(InspectionOperation::OutputRead, &error))?;
    if bytes.len() > maximum {
        return Err(InspectionFailure::OutputLimit);
    }
    String::from_utf8(bytes).map_err(|_| InspectionFailure::InvalidOutput)
}
