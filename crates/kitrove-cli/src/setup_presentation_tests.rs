use super::*;

#[test]
fn prompt_and_command_output_have_distinct_plain_text_boundaries() {
    let mut dialog = Dialog {
        input: io::Cursor::new("yes\n"),
        output: Vec::new(),
        color: false,
    };
    dialog
        .report("initialized collection\nmachine: fixture")
        .unwrap();
    assert_eq!(
        dialog.ask("Continue?\ny/yes confirms; n skips.").unwrap(),
        "yes"
    );
    assert_eq!(
        String::from_utf8(dialog.output).unwrap(),
        "\nCommand output\n  | initialized collection\n  | machine: fixture\n\n? Continue?\n  y/yes confirms; n skips.\n> "
    );
}

#[test]
fn command_output_cannot_inject_terminal_style_or_a_real_prompt() {
    let mut dialog = Dialog {
        input: io::Cursor::new(""),
        output: Vec::new(),
        color: false,
    };
    dialog
        .report("\x1b[31mspoof\n? Confirm a different action?\rhidden")
        .unwrap();
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(!output.contains('\x1b'));
    assert!(output.contains("  | \\u{1b}[31mspoof"));
    assert!(output.contains("\n  | ? Confirm a different action?\\rhidden"));
}

#[test]
fn goal_menu_keeps_apply_distinct_from_sharing_and_copying() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-goals-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = super::tests::machine(&root, "goals");
    let output = super::tests::script(
        &a,
        &format!("1\n{}\nfixture\nyes\n5\n", a.join("collection").display()),
        false,
        "",
    );
    assert!(output.contains("2. Choose skills to add to your AI tools"));
    assert!(output.contains("3. Share this collection with another computer"));
    assert!(output.contains("4. Copy selected items from another collection"));
    assert!(!output.contains("Backend 1-3"));
    assert!(!output.contains("HTTPS Git"));
    assert!(!output.contains("bidirectional)"));
}

#[test]
fn colors_never_change_confirmation_defaults_or_eof_behavior() {
    for color in [false, true] {
        for (input, expected) in [
            ("y\n", true),
            ("yes\n", true),
            ("\n", false),
            ("n\n", false),
        ] {
            let mut dialog = Dialog {
                input: io::Cursor::new(input),
                output: Vec::new(),
                color,
            };
            assert_eq!(dialog.confirm("Proceed?").unwrap(), expected);
        }
        for input in ["", "q\n"] {
            let mut dialog = Dialog {
                input: io::Cursor::new(input),
                output: Vec::new(),
                color,
            };
            assert_eq!(
                dialog.confirm("Proceed?").unwrap_err().code,
                "setup.cancelled"
            );
        }
    }
}

#[test]
fn sharing_can_be_skipped_or_cancelled_before_any_location_is_selected() {
    for input in ["\n", "n\n", "invalid\nn\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
        };
        assert!(remote(&mut dialog).unwrap().is_none());
        let output = String::from_utf8(dialog.output).unwrap();
        assert!(output.contains("Not now"));
        assert!(!output.contains("Shared Kitrove folder path:"));
        assert!(!output.contains("HTTPS URL without"));
    }
    for input in ["", "q\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
        };
        assert_eq!(remote(&mut dialog).unwrap_err().code, "setup.cancelled");
    }
}

#[test]
fn operation_results_are_not_presented_as_uncommitted_previews_or_success() {
    let mut dialog = Dialog {
        input: io::Cursor::new(""),
        output: Vec::new(),
        color: true,
    };
    dialog.outcome(r#"{"outcome":"blocked"}"#).unwrap();
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(output.contains("Result"));
    assert!(output.contains("blocked"));
    assert!(!output.contains("Preview"));
    assert!(!output.contains("Completed"));
    assert!(!output.contains("\x1b[32m"));
}

#[test]
fn output_failure_never_consumes_or_accepts_input() {
    struct Unwritable {
        fail_flush: bool,
    }
    impl Write for Unwritable {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_flush {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("fixture"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("fixture"))
        }
    }
    for color in [false, true] {
        for fail_flush in [false, true] {
            let mut dialog = Dialog {
                input: io::Cursor::new("yes\n"),
                output: Unwritable { fail_flush },
                color,
            };
            assert_eq!(
                dialog.confirm("Proceed?").unwrap_err().code,
                "setup.input_output"
            );
            assert_eq!(dialog.input.position(), 0);
        }
    }
}

#[test]
fn not_now_returns_to_the_menu_without_changing_the_existing_collection_or_state() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-sharing-skip-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = super::tests::machine(&root, "skip");
    super::tests::script(
        &a,
        &format!("1\n{}\nfixture\nyes\n5\n", a.join("collection").display()),
        false,
        "",
    );
    let state = std::fs::read(a.join("state/state.json")).unwrap();
    let manifest = std::fs::read(a.join("collection/kitrove.toml")).unwrap();
    let output = super::tests::script(&a, "\n3\nn\n4\n\n5\n", true, "");
    assert_eq!(
        output
            .matches("Where is the shared collection stored?")
            .count(),
        2
    );
    assert!(!output.contains("Shared Kitrove folder path:"));
    assert_eq!(std::fs::read(a.join("state/state.json")).unwrap(), state);
    assert_eq!(
        std::fs::read(a.join("collection/kitrove.toml")).unwrap(),
        manifest
    );
}
