#![forbid(unsafe_code)]

use std::process::{Command, Stdio};

#[test]
fn closed_stdout_ends_quietly_instead_of_panicking() {
    let root = kitrove_testkit::trusted_tempdir(".kitrove-closed-stdout-");
    for args in [&["north-star"][..], &["help"], &["--version"]] {
        // The reader is dropped before launch, so the first write meets a closed pipe.
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_kitrove"))
            .env_clear()
            .env("HOME", root.path())
            .env("USERPROFILE", root.path())
            .current_dir(root.path())
            .args(args)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }
}
