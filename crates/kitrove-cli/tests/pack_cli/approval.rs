use super::*;

struct Fixture {
    _root: tempfile::TempDir,
    environment: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = kitrove_testkit::trusted_tempdir(".kitrove-pack-approval-");
        let environment = fs::canonicalize(root.path()).unwrap().join("collection");
        fs::create_dir(&environment).unwrap();
        let manifest = manifest();
        owned_fixture::create(
            &environment.join("kitrove.toml"),
            manifest.to_toml().unwrap().as_bytes(),
        );
        owned_fixture::create(
            &environment.join("kitrove.lock.json"),
            derive_lockfile(&manifest)
                .unwrap()
                .to_json()
                .unwrap()
                .as_bytes(),
        );
        Self {
            _root: root,
            environment,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_kitrove"))
            .arg("pack")
            .args(args)
            .arg("--environment")
            .arg(&self.environment)
            .arg("--json")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn authority(&self) -> (Vec<u8>, Vec<u8>) {
        (
            fs::read(self.environment.join("kitrove.toml")).unwrap(),
            fs::read(self.environment.join("kitrove.lock.json")).unwrap(),
        )
    }

    fn preview(&self) -> serde_json::Value {
        let before = self.authority();
        let result = self.run(&["create", "--pack", "suite", "--member", "tooling", "--plan"]);
        assert!(result.status.success(), "{result:?}");
        assert!(result.stderr.is_empty());
        assert_eq!(self.authority(), before);
        assert!(!self.environment.join(".kitrove").exists());
        serde_json::from_slice(&result.stdout).unwrap()
    }

    fn create(&self, digest: &str) -> std::process::Output {
        self.run(&[
            "create",
            "--pack",
            "suite",
            "--member",
            "tooling",
            "--confirm",
            digest,
        ])
    }
}

#[test]
fn preview_and_exact_create_update_work_without_stdin() {
    let fixture = Fixture::new();
    let plan = fixture.preview();
    let digest = plan["digest"].as_str().unwrap();
    let before = fixture.authority();
    let wrong = fixture.create(ContentHash::digest(b"wrong").as_str());
    assert_eq!(wrong.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("pack.plan_stale"));
    assert_eq!(fixture.authority(), before);
    let expanded = fixture.run(&[
        "create",
        "--pack",
        "suite",
        "--member",
        "tooling",
        "--member",
        "utilities",
        "--confirm",
        digest,
    ]);
    assert_eq!(expanded.status.code(), Some(1));
    assert_eq!(fixture.authority(), before);
    let created = fixture.create(digest);
    assert!(created.status.success(), "{created:?}");
    assert!(created.stderr.is_empty());
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let prior = created["pack"]["revision"].as_str().unwrap();
    let before_update = fixture.authority();
    let preview = fixture.run(&[
        "update",
        "--pack",
        "suite",
        "--expected-prior",
        prior,
        "--member",
        "utilities",
        "--plan",
    ]);
    assert!(preview.status.success(), "{preview:?}");
    assert_eq!(fixture.authority(), before_update);
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let updated = fixture.run(&[
        "update",
        "--pack",
        "suite",
        "--expected-prior",
        prior,
        "--member",
        "utilities",
        "--confirm",
        preview["digest"].as_str().unwrap(),
    ]);
    assert!(updated.status.success(), "{updated:?}");
    assert!(updated.stderr.is_empty());
    assert_ne!(fixture.authority(), before_update);
}

#[test]
fn explicit_authored_creation_binds_mode_and_preserves_members() {
    let fixture = Fixture::new();
    let original = manifest();
    let before = fixture.authority();
    let args = [
        "create",
        "--authored",
        "--pack",
        "suite",
        "--member",
        "alpha",
    ];
    let preview = fixture.run(&[args.as_slice(), &["--plan"]].concat());
    assert!(preview.status.success(), "{preview:?}");
    assert_eq!(fixture.authority(), before);
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let digest = plan["digest"].as_str().unwrap();
    let wrong = fixture.run(
        &[
            args.as_slice(),
            &["--confirm", ContentHash::digest(b"wrong").as_str()],
        ]
        .concat(),
    );
    assert_eq!(wrong.status.code(), Some(1));
    assert_eq!(fixture.authority(), before);
    let implicit = fixture.run(&[
        "create",
        "--pack",
        "suite",
        "--member",
        "alpha",
        "--confirm",
        digest,
    ]);
    assert_eq!(implicit.status.code(), Some(1));
    assert_eq!(fixture.authority(), before);
    let duplicate = fixture.run(&[args.as_slice(), &["--authored", "--plan"]].concat());
    assert_eq!(duplicate.status.code(), Some(2));
    let created = fixture.run(&[args.as_slice(), &["--confirm", digest]].concat());
    assert!(created.status.success(), "{created:?}");
    let created =
        EnvironmentManifest::from_toml(&String::from_utf8(fixture.authority().0).unwrap()).unwrap();
    assert_eq!(created.assets, original.assets);
    let suite = &created.packs[&AssetId::parse("suite").unwrap()];
    assert_eq!(suite.source, Source::AuthoredPack);
    let update_args = [
        "update",
        "--pack",
        "suite",
        "--expected-prior",
        suite.content_hash.as_str(),
        "--member",
        "tooling",
    ];
    let preview = fixture.run(&[update_args.as_slice(), &["--plan"]].concat());
    assert!(preview.status.success(), "{preview:?}");
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let updated = fixture.run(
        &[
            update_args.as_slice(),
            &["--confirm", plan["digest"].as_str().unwrap()],
        ]
        .concat(),
    );
    assert!(updated.status.success(), "{updated:?}");
    let updated =
        EnvironmentManifest::from_toml(&String::from_utf8(fixture.authority().0).unwrap()).unwrap();
    assert_eq!(updated.assets, original.assets);
    assert_eq!(
        updated.packs[&AssetId::parse("suite").unwrap()].source,
        Source::AuthoredPack
    );
}

#[test]
fn approval_refuses_all_portable_recovery_authorities_without_modifying_them() {
    for name in [
        "adoption-journal.json",
        "adoption-journal.pending",
        "sync-portable-journal.json",
        "sync-portable-journal.pending",
        "sync-transaction.guard",
    ] {
        let fixture = Fixture::new();
        let plan = fixture.preview();
        let control = fixture.environment.join(".kitrove");
        fs::create_dir(&control).unwrap();
        let journal = control.join(name);
        owned_fixture::create(&journal, b"RECOVERY CANARY");
        let before = fixture.authority();
        let result = fixture.create(plan["digest"].as_str().unwrap());
        assert_eq!(result.status.code(), Some(1), "{name}: {result:?}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("RECOVERY CANARY"));
        assert_eq!(fs::read(journal).unwrap(), b"RECOVERY CANARY");
        assert_eq!(fixture.authority(), before);
    }
}

#[test]
fn approval_flags_are_mutually_exclusive_and_cannot_be_repeated() {
    let fixture = Fixture::new();
    let digest = ContentHash::digest(b"approval");
    for flags in [
        vec!["--plan", "--plan"],
        vec!["--confirm", digest.as_str(), "--plan"],
        vec!["--plan", "--confirm", digest.as_str()],
        vec!["--confirm", digest.as_str(), "--confirm", digest.as_str()],
        vec!["--confirm", "invalid"],
        vec!["--confirm"],
    ] {
        let mut args = vec!["create", "--pack", "suite", "--member", "tooling"];
        args.extend(flags);
        let result = fixture.run(&args);
        assert_eq!(result.status.code(), Some(2), "{result:?}");
    }
    assert!(!fixture.environment.join(".kitrove").exists());
}
