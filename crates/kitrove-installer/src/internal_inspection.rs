//! Fixed child-only wire operation. No readiness or downloaded executable launch.
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

pub(crate) fn is_internal(argument: &OsStr) -> bool {
    argument.as_bytes() == kitrove_macos_signature::INSPECTION_ARGUMENT.to_bytes()
}

/// This serving call can block in native code; only the owning parent's process
/// deadline can contain it. No ordinary CLI message may contaminate the response.
pub(crate) fn run(
    mut remaining: impl Iterator<Item = OsString>,
    input: impl Read,
    output: impl Write,
) -> ExitCode {
    if remaining.next().is_some()
        || kitrove_macos_signature::serve_inspection(input, output).is_err()
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_requires_exact_shared_argument() {
        let exact = OsStr::from_bytes(kitrove_macos_signature::INSPECTION_ARGUMENT.to_bytes());
        assert!(is_internal(exact));
        for other in [
            "",
            "--help",
            "--internal-native-inspection-v2",
            "--internal-native-inspection-v1=x",
        ] {
            assert!(!is_internal(OsStr::new(other)));
        }
        assert!(!is_internal(OsStr::from_bytes(
            b"--internal-native-inspection-v1\xff"
        )));
    }

    #[test]
    fn rejects_extra_arguments_before_reading_and_malformed_frames_without_output() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("unexpected input read")
            }
        }
        let mut output = Vec::new();
        assert_eq!(
            run(
                [OsString::from("extra")].into_iter(),
                MustNotRead,
                &mut output
            ),
            ExitCode::FAILURE
        );
        assert!(output.is_empty());
        assert_eq!(
            run(std::iter::empty(), b"malformed".as_slice(), &mut output),
            ExitCode::FAILURE
        );
        assert!(output.is_empty());
    }
}
