use std::io::Read as _;

pub fn run(signal_inherited_event: impl Fn(usize) -> bool) {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--fixture-child")
    {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    if arguments.len() != 2 || arguments[1] != "--version" {
        std::process::exit(2);
    }
    let executable = std::env::current_exe().expect("fixture executable path");
    if std::path::Path::new(&arguments[0]) != executable {
        std::process::exit(7);
    }
    let name = executable
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("fixture executable name");
    let expected: &[(&str, &str)] = match name.to_ascii_lowercase().as_str() {
        "pi.exe" => &[("PI_OFFLINE", "1"), ("PI_SKIP_VERSION_CHECK", "1")],
        "opencode2.exe" => &[
            ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
            ("OPENCODE_DISABLE_PROJECT_CONFIG", "1"),
        ],
        "kitrove.exe" => &[],
        _ => std::process::exit(3),
    };
    let mut observed: Vec<_> = std::env::vars().collect();
    observed.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    let mut expected: Vec<_> = expected
        .iter()
        .map(|&(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    expected.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    if observed != expected {
        std::process::exit(4);
    }
    let cwd = std::env::current_dir().expect("fixture cwd");
    if !cwd
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("System32"))
    {
        std::process::exit(5);
    }
    let mut stdin = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin)
        .expect("fixture stdin");
    if !stdin.is_empty() {
        std::process::exit(6);
    }

    let behavior = executable
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    if behavior.starts_with("descendant") {
        spawn_descendant(&executable);
    }
    if let Some(handle) = behavior.strip_prefix("handle-") {
        let handle = handle.parse::<usize>().expect("canary handle");
        let _ = signal_inherited_event(handle);
    }
    match behavior {
        "malformed" => println!("not a version"),
        "stderr" => eprintln!("unexpected stderr"),
        "oversized" => println!("{}", "x".repeat(5_000)),
        "timeout" => std::thread::sleep(std::time::Duration::from_secs(10)),
        "descendant-timeout" => std::thread::sleep(std::time::Duration::from_secs(10)),
        "descendant-stderr" => eprintln!("unexpected stderr"),
        _ if name.eq_ignore_ascii_case("pi.exe") => println!("0.83.0"),
        _ if name.eq_ignore_ascii_case("opencode2.exe") => println!("opencode2 v2.1.0"),
        _ => println!("kitrove 1.2.3"),
    }
}

#[allow(
    clippy::zombie_processes,
    reason = "the containment fixture must leave its descendant running"
)]
fn spawn_descendant(executable: &std::path::Path) {
    let child = std::process::Command::new(executable)
        .arg("--fixture-child")
        .spawn()
        .expect("descendant fixture");
    std::fs::write(
        executable.parent().unwrap().join("descendant.pid"),
        child.id().to_string(),
    )
    .expect("descendant PID");
}
