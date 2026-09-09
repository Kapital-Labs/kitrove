//! Operator-only native signing. Never used by scan, installers, or ordinary CI.
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kitrove_release_policy::APPLICATION_ARCHIVE_LIMITS;
use serde::Deserialize;

const APPLE_IDENTITY: &str = "Developer ID Application: Kapital Labs LLC (98RZ36ES7A)";
const APPLE_REQUIREMENT: &str = concat!(
    "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists ",
    "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists ",
    "and certificate leaf[subject.OU] = \"98RZ36ES7A\""
);
const WINDOWS_VERIFY: &str = r#"
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $env:KITROVE_VERIFY_FILE
if ($signature.Status -ne 'Valid' -or
    $signature.SignatureType -ne 'Authenticode' -or
    $null -eq $signature.SignerCertificate -or
    $null -eq $signature.TimeStamperCertificate -or
    $signature.SignerCertificate.Subject -cne $env:KITROVE_WINDOWS_PUBLISHER) {
    throw 'Expected timestamped publisher signature is absent or invalid'
}
"#;

enum Signer {
    Apple {
        profile: OsString,
        keychain: Option<PathBuf>,
    },
    Windows {
        tool: PathBuf,
        dlib: PathBuf,
        metadata: PathBuf,
        publisher: OsString,
    },
    Linux,
}

#[derive(Debug, PartialEq, Eq)]
enum Platform {
    Apple,
    Windows,
    Linux,
}

fn required(name: &str) -> Result<OsString, String> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("platform signing requires {name}; unsigned fallback is forbidden"))
}

fn required_file(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(required(name)?);
    validate_file(path, name)
}

fn validate_file(path: PathBuf, name: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() || !fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
        return Err(format!(
            "{name} must select an absolute regular tool/configuration file"
        ));
    }
    Ok(path)
}

fn signing_keychain(value: Option<OsString>) -> Result<Option<PathBuf>, String> {
    value
        .map(|value| validate_file(PathBuf::from(value), "KITROVE_SIGNING_KEYCHAIN"))
        .transpose()
}

fn select_keychain<'a>(command: &'a mut Command, keychain: Option<&Path>) -> &'a mut Command {
    if let Some(keychain) = keychain {
        command.arg("--keychain").arg(keychain);
    }
    command
}

fn platform(target: &str, host: &str) -> Result<Platform, String> {
    match (target, host) {
        ("aarch64-apple-darwin" | "x86_64-apple-darwin", "macos") => Ok(Platform::Apple),
        ("x86_64-pc-windows-msvc", "windows") => Ok(Platform::Windows),
        ("x86_64-unknown-linux-gnu", "linux") => Ok(Platform::Linux),
        _ => Err(
            "platform signing requires a reviewed target on its native operating system".to_owned(),
        ),
    }
}

impl Signer {
    fn configured(target: &str) -> Result<Self, String> {
        match platform(target, env::consts::OS)? {
            Platform::Apple => Ok(Self::Apple {
                profile: required("KITROVE_NOTARY_PROFILE")?,
                keychain: signing_keychain(env::var_os("KITROVE_SIGNING_KEYCHAIN"))?,
            }),
            Platform::Windows => Ok(Self::Windows {
                tool: required_file("KITROVE_SIGNTOOL")?,
                dlib: required_file("KITROVE_AZURE_SIGNING_DLIB")?,
                metadata: required_file("KITROVE_AZURE_SIGNING_METADATA")?,
                publisher: required("KITROVE_WINDOWS_PUBLISHER")?,
            }),
            Platform::Linux => Ok(Self::Linux),
        }
    }

    fn sign_and_verify(&self, file: &Path, directory: &Path) -> Result<Vec<u8>, String> {
        match self {
            Self::Apple { profile, keychain } => {
                run(
                    select_keychain(
                        Command::new("/usr/bin/codesign").args([
                            "--force",
                            "--sign",
                            APPLE_IDENTITY,
                            "--options",
                            "runtime",
                            "--timestamp",
                        ]),
                        keychain.as_deref(),
                    )
                    .arg(file),
                    "Apple code signing",
                )?;
                let mut signed = capture_signed_file(file)?;
                run(
                    Command::new("/usr/bin/codesign")
                        .args(["--verify", "--strict", "-R", APPLE_REQUIREMENT])
                        .arg(file),
                    "Apple signature and team verification",
                )?;
                let detail = run(
                    Command::new("/usr/bin/codesign")
                        .args(["--display", "--verbose=4"])
                        .arg(file),
                    "Apple signature inspection",
                )?;
                verify_apple_detail(&detail.stderr)?;
                // Only this fixed executable is placed in the notary ZIP. The same
                // snapshot remains held through verification, upload and publication.
                let upload = directory.join("notary.zip");
                run(
                    Command::new("/usr/bin/ditto")
                        .args(["-c", "-k"])
                        .arg(file)
                        .arg(&upload),
                    "notarization ZIP creation",
                )?;
                let response = run(
                    select_keychain(
                        Command::new("/usr/bin/xcrun")
                            .args(["notarytool", "submit"])
                            .arg(&upload)
                            .arg("--keychain-profile")
                            .arg(profile)
                            .args(["--wait", "--timeout", "20m", "--output-format", "json"]),
                        keychain.as_deref(),
                    ),
                    "Apple notarization (a timeout may leave a pending Apple submission)",
                )?;
                verify_notary_response(&response.stdout)?;
                signed.revalidate()?;
                Ok(signed.bytes)
            }
            Self::Windows {
                tool,
                dlib,
                metadata,
                publisher,
            } => {
                run(
                    Command::new(tool)
                        .args([
                            "sign",
                            "/fd",
                            "SHA256",
                            "/tr",
                            "http://timestamp.acs.microsoft.com",
                            "/td",
                            "SHA256",
                            "/dlib",
                        ])
                        .arg(dlib)
                        .arg("/dmdf")
                        .arg(metadata)
                        .arg(file),
                    "Azure Authenticode signing",
                )?;
                let mut signed = capture_signed_file(file)?;
                run(
                    Command::new(tool)
                        .args(["verify", "/pa", "/all", "/tw"])
                        .arg(file),
                    "Windows signature verification",
                )?;
                run(
                    Command::new("powershell.exe")
                        // Intermediate native processes inherit PS7 module paths;
                        // Windows PowerShell must construct its own compatible path.
                        .env_remove("PSModulePath")
                        .args([
                            "-NoLogo",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            WINDOWS_VERIFY,
                        ])
                        .env("KITROVE_VERIFY_FILE", file)
                        .env("KITROVE_WINDOWS_PUBLISHER", publisher),
                    "Windows publisher verification",
                )?;
                signed.revalidate()?;
                Ok(signed.bytes)
            }
            Self::Linux => Err("Linux does not use platform signing".to_owned()),
        }
    }
}

fn capture_signed_file(file: &Path) -> Result<super::RetainedFile, String> {
    super::read_bounded_file(
        file,
        APPLICATION_ARCHIVE_LIMITS.max_entry_bytes,
        "signed executable",
        false,
    )
}

// Native tool failures intentionally omit argv, stdout and stderr: provider errors
// can include account configuration. Operators may diagnose separately locally.
fn run(command: &mut Command, label: &str) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|_| format!("cannot start {label}"))?;
    if !output.status.success() {
        return Err(format!("{label} failed; no release archive was prepared"));
    }
    Ok(output)
}

fn verify_apple_detail(detail: &[u8]) -> Result<(), String> {
    let detail = String::from_utf8_lossy(detail);
    if !detail
        .lines()
        .any(|line| line.starts_with("Timestamp=") && line.len() > 10)
        || !detail
            .lines()
            .any(|line| line.starts_with("CodeDirectory ") && line.contains("(runtime)"))
    {
        return Err("Apple signature lacks hardened runtime or secure timestamp".to_owned());
    }
    Ok(())
}

fn verify_notary_response(response: &[u8]) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Submission {
        id: String,
        status: String,
    }
    let result: Submission = serde_json::from_slice(response)
        .map_err(|_| "Apple notarization returned an invalid result".to_owned())?;
    if result.status != "Accepted" || result.id.is_empty() {
        return Err("Apple notarization was not Accepted; release preparation stopped".to_owned());
    }
    Ok(())
}

pub(super) fn sign(target: &str, name: &str, bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let signer = Signer::configured(target)?;
    if matches!(signer, Signer::Linux) {
        return Ok(None); // Linux continues to require archive checksums and provenance.
    }
    if !matches!(
        name,
        "kitrove" | "kitrove-installer" | "kitrove.exe" | "kitrove-installer.exe"
    ) {
        return Err("unreviewed signing executable name".to_owned());
    }
    let directory = tempfile::Builder::new()
        .prefix("kitrove-sign-")
        .tempdir()
        .map_err(|_| "cannot create isolated signing directory".to_owned())?;
    let path = directory.path().join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| "cannot create isolated signing executable".to_owned())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot stage signing executable".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot restrict signing executable permissions".to_owned())?;
    }
    drop(file);
    Ok(Some(signer.sign_and_verify(&path, directory.path())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_keychain_refuses_invalid_configuration_without_fallback() {
        assert_eq!(signing_keychain(None).unwrap(), None);
        let directory = tempfile::tempdir().unwrap();
        for path in [
            PathBuf::new(),
            PathBuf::from("relative.keychain-db"),
            directory.path().to_owned(),
            directory.path().join("missing"),
        ] {
            assert!(signing_keychain(Some(path.into_os_string())).is_err());
        }
        let file = directory.path().join("signing keychain.keychain-db");
        fs::write(&file, b"fixture").unwrap();
        assert_eq!(
            signing_keychain(Some(file.clone().into_os_string())).unwrap(),
            Some(file.clone())
        );
        #[cfg(unix)]
        {
            let link = directory.path().join("alias");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(signing_keychain(Some(link.into_os_string())).is_err());
        }
    }

    #[test]
    fn keychain_selection_preserves_one_argument_and_default_behavior() {
        for program in ["/usr/bin/codesign", "/usr/bin/xcrun"] {
            let mut command = Command::new(program);
            select_keychain(&mut command, None);
            assert_eq!(command.get_args().count(), 0);
            let path = Path::new("/private/signing keys/store.keychain-db");
            select_keychain(&mut command, Some(path));
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                vec![std::ffi::OsStr::new("--keychain"), path.as_os_str()]
            );
        }
    }

    #[test]
    fn apple_requirement_is_inline_and_pins_developer_id_team() {
        assert!(APPLE_REQUIREMENT.starts_with("=anchor apple generic"));
        assert!(APPLE_REQUIREMENT.contains("certificate leaf[subject.OU] = \"98RZ36ES7A\""));
        assert!(
            APPLE_REQUIREMENT.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists")
        );
    }

    #[test]
    fn target_requires_native_host_and_closed_catalog() {
        for (target, host, expected) in [
            ("aarch64-apple-darwin", "macos", Platform::Apple),
            ("x86_64-apple-darwin", "macos", Platform::Apple),
            ("x86_64-pc-windows-msvc", "windows", Platform::Windows),
            ("x86_64-unknown-linux-gnu", "linux", Platform::Linux),
        ] {
            assert_eq!(platform(target, host).unwrap(), expected);
            assert!(platform(target, "unsupported").is_err());
        }
        assert!(platform("aarch64-unknown-linux-gnu", "linux").is_err());
        assert!(platform("x86_64-pc-windows-msvc", "macos").is_err());
    }

    #[test]
    fn notary_requires_explicit_accepted_result() {
        assert!(verify_notary_response(br#"{"id":"submission","status":"Accepted"}"#).is_ok());
        for response in [
            br#"{"id":"submission","status":"Invalid"}"#.as_slice(),
            br#"{"id":"submission","status":"In Progress"}"#,
            br#"{"id":"","status":"Accepted"}"#,
            br#"{"status":"Accepted"}"#,
            br#"{"id":"submission","status":"Accepted","status":"Invalid"}"#,
            b"not JSON",
        ] {
            assert!(verify_notary_response(response).is_err());
        }
    }

    #[test]
    fn apple_requires_timestamp_and_hardened_runtime() {
        let valid = b"CodeDirectory v=20500 flags=0x10000(runtime)\nTimestamp=Sep 8, 2026\n";
        assert!(verify_apple_detail(valid).is_ok());
        for invalid in [
            b"".as_slice(),
            b"Timestamp=now\n",
            b"CodeDirectory flags=0x10000(runtime)\n",
            b"CodeDirectory flags=0x10000(runtime)\nTimestamp=\n",
        ] {
            assert!(verify_apple_detail(invalid).is_err());
        }
    }

    #[test]
    fn missing_signing_configuration_fails_closed() {
        assert!(required("KITROVE_TEST_NONEXISTENT_SIGNING_CONFIGURATION").is_err());
    }
}
