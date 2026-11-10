use super::*;

#[test]
fn prompt_and_command_output_have_distinct_plain_text_boundaries() {
    let mut dialog = Dialog {
        input: io::Cursor::new("yes\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
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
        single_key: false,
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
                single_key: false,
            };
            assert_eq!(dialog.confirm("Proceed?").unwrap(), expected);
        }
        for input in ["", "q\n"] {
            let mut dialog = Dialog {
                input: io::Cursor::new(input),
                output: Vec::new(),
                color,
                single_key: false,
            };
            assert_eq!(
                dialog.confirm("Proceed?").unwrap_err().code,
                "setup.cancelled"
            );
        }
    }
}

#[test]
fn immediate_navigation_does_not_make_confirmations_or_text_single_key() {
    for (input, expected) in [
        ("y\n", true),
        ("yes\n", true),
        ("\n", false),
        ("n\n", false),
    ] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
            single_key: true,
        };
        assert_eq!(dialog.confirm("Proceed?").unwrap(), expected);
    }
    for input in ["y", "yes", "", "q\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
            single_key: true,
        };
        assert_eq!(
            dialog.confirm("Proceed?").unwrap_err().code,
            "setup.cancelled"
        );
    }
    let mut dialog = Dialog {
        input: io::Cursor::new("from codex,-13,-20\n"),
        output: Vec::new(),
        color: false,
        single_key: true,
    };
    assert_eq!(dialog.ask("Choose skills").unwrap(), "from codex,-13,-20");
    let mut dialog = Dialog {
        input: io::Cursor::new("from pi\n\n"),
        output: Vec::new(),
        color: false,
        single_key: true,
    };
    assert_eq!(dialog.ask("Choose skills").unwrap(), "from pi");
    assert_eq!(
        dialog.input.position(),
        9,
        "queued Enter is not next-preview approval"
    );
}

#[test]
fn sharing_can_be_skipped_or_cancelled_before_any_location_is_selected() {
    for input in ["\n", "n\n", "invalid\nn\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
            single_key: false,
        };
        assert!(remote(&mut dialog, false).unwrap().is_none());
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
            single_key: false,
        };
        assert_eq!(
            remote(&mut dialog, false).unwrap_err().code,
            "setup.cancelled"
        );
    }
}

#[test]
fn one_git_choice_detects_ssh_before_requesting_host_trust() {
    let hosts = kitrove_testkit::trusted_tempdir(".setup-git-hosts-");
    let known_hosts = hosts.path().canonicalize().unwrap().join("known_hosts");
    let mut dialog = Dialog {
        input: io::Cursor::new(format!(
            "2\nssh://git@example.test/team/collection.git\n{}\n",
            known_hosts.display()
        )),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    let selected = remote(&mut dialog, false).unwrap().unwrap();
    assert!(
        matches!(selected, SyncRemoteArgs::Ssh { url, known_hosts: path }
        if url == "ssh://git@example.test/team/collection.git" && path == known_hosts)
    );
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(output.contains("2. Git repository\n"));
    assert!(output.contains("already exist"));
    assert!(!output.contains("Create a private repository"));
    assert!(!output.contains("3. Git repository"));
    assert!(!output.contains("How should Kitrove connect?"));
    assert!(
        !known_hosts.exists(),
        "selection must not create trust files"
    );
}

#[test]
fn git_url_infers_https_without_a_protocol_question() {
    let mut dialog = Dialog {
        input: io::Cursor::new("2\nhttps://example.test/team/collection.git\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(
        matches!(remote(&mut dialog, false).unwrap().unwrap(), SyncRemoteArgs::Git { url, credentials: GitCredentialSource::Terminal }
        if url == "https://example.test/team/collection.git")
    );
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(!output.contains("How should Kitrove connect?"));
    assert!(!output.contains("Known-hosts file path:"));
}

#[test]
fn git_creation_guidance_returns_to_the_existing_clone_url_flow() {
    let mut dialog = Dialog {
        input: io::Cursor::new("2\nc\nhttps://example.test/team/new.git\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(
        matches!(remote(&mut dialog, true).unwrap().unwrap(), SyncRemoteArgs::Git { url, credentials: GitCredentialSource::Terminal }
        if url == "https://example.test/team/new.git")
    );
    let output = String::from_utf8(dialog.output).unwrap();
    assert_eq!(output.matches("Git repository URL:").count(), 2);
    assert!(output.contains("https://github.com/new?visibility=private"));
    assert!(output.contains("Select Private"));
    assert!(output.contains("README, .gitignore and license unset"));
    assert!(!output.contains("Git token:"));
}

#[test]
fn terminal_dialog_does_not_hold_the_lock_needed_by_git_authentication() {
    let (acquired_while_dialog_exists, reader) = {
        let _dialog = Dialog::terminal();
        let (ready, wait) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _input = io::stdin().lock();
            ready.send(()).unwrap();
        });
        (wait.recv_timeout(std::time::Duration::from_secs(5)), reader)
    };
    reader.join().unwrap();
    acquired_while_dialog_exists.expect("credential input must be available between prompts");
}

#[test]
fn scheme_less_git_location_requires_explicit_transport_selection() {
    let mut dialog = Dialog {
        input: io::Cursor::new("2\nexample.test/team/collection.git\n1\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(
        matches!(remote(&mut dialog, false).unwrap().unwrap(), SyncRemoteArgs::Git { url, .. }
        if url == "https://example.test/team/collection.git")
    );
    assert!(
        String::from_utf8(dialog.output)
            .unwrap()
            .contains("How should Kitrove connect?")
    );
}

#[test]
fn scheme_less_git_location_can_explicitly_select_ssh_without_falling_back() {
    let hosts = kitrove_testkit::trusted_tempdir(".setup-git-hosts-");
    let known_hosts = hosts.path().canonicalize().unwrap().join("known_hosts");
    let mut dialog = Dialog {
        input: io::Cursor::new(format!(
            "2\ngit@example.test/team/collection.git\n2\n{}\n",
            known_hosts.display()
        )),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(
        matches!(remote(&mut dialog, false).unwrap().unwrap(), SyncRemoteArgs::Ssh { url, known_hosts: path }
        if url == "ssh://git@example.test/team/collection.git" && path == known_hosts)
    );
    assert!(!known_hosts.exists());
}

#[test]
fn invalid_or_credential_bearing_git_urls_do_not_echo_or_become_backend_args() {
    for url in [
        "https://user:URL-CREDENTIAL-CANARY@example.test/team/collection.git",
        "http://example.test/team/collection.git",
        "ssh://git@example.test/team/../other.git",
        "file:///some/repository",
    ] {
        let mut dialog = Dialog {
            input: io::Cursor::new(format!("2\n{url}\nn\n")),
            output: Vec::new(),
            color: false,
            single_key: false,
        };
        assert!(remote(&mut dialog, false).unwrap().is_none());
        let output = String::from_utf8(dialog.output).unwrap();
        assert!(!output.contains(url));
        assert!(!output.contains("URL-CREDENTIAL-CANARY"));
        assert!(!output.contains("Known-hosts file path:"));
    }
}

#[test]
fn git_checkout_and_scp_inputs_get_specific_guidance_without_a_protocol_guess() {
    for (location, guidance) in [
        (
            "/some/local/checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            r"\some\local\checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            r"C:\some\local\checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            r"C:some\local\checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            r"\\fixture-server\fixture-share\checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            "./some/local/checkout",
            "Paste a remote repository URL, not a local checkout path.",
        ),
        (
            "git@example.test:team/collection.git",
            "Use the ssh:// URL form, not the colon-separated Git address.",
        ),
    ] {
        let mut dialog = Dialog {
            input: io::Cursor::new(format!("2\n{location}\nn\n")),
            output: Vec::new(),
            color: false,
            single_key: false,
        };
        assert!(remote(&mut dialog, false).unwrap().is_none());
        let output = String::from_utf8(dialog.output).unwrap();
        assert!(
            output.contains(guidance),
            "missing guidance for fixture {location}"
        );
        assert!(!output.contains("How should Kitrove connect?"));
        assert!(!output.contains(location));
    }
}

#[test]
fn git_nested_choices_skip_and_cancel_before_connecting_or_selecting_credentials() {
    for input in [
        "2\n\n",
        "2\nn\n",
        "2\nc\nn\n",
        "2\nexample.test/team/collection.git\nn\n",
        "2\nssh://git@example.test/team/collection.git\nrelative-hosts\nn\n",
    ] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
            single_key: false,
        };
        assert!(remote(&mut dialog, true).unwrap().is_none());
        assert!(
            !String::from_utf8(dialog.output)
                .unwrap()
                .contains("Git token:")
        );
    }
    for input in [
        "2\n",
        "2\nq\n",
        "2\nc\nq\n",
        "2\nexample.test/team/collection.git\n",
        "2\nexample.test/team/collection.git\nq\n",
        "2\nssh://git@example.test/team/collection.git\nq\n",
    ] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
            single_key: false,
        };
        assert_eq!(
            remote(&mut dialog, true).unwrap_err().code,
            "setup.cancelled"
        );
    }
}

#[test]
fn operation_results_are_not_presented_as_uncommitted_previews_or_success() {
    let mut dialog = Dialog {
        input: io::Cursor::new(""),
        output: Vec::new(),
        color: true,
        single_key: false,
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
                single_key: false,
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
