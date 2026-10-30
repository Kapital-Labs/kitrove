//! Closed read-only ticket caller over shared private lifecycle/output mechanics.
use std::path::Path;
use std::process::Command;

mod deadline;
#[cfg(target_os = "macos")]
mod macos;
mod owner;
#[cfg(target_os = "macos")]
pub(super) fn validate(file: &Path) -> Result<std::process::Output, Refused> {
    macos::validate(file)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    Deadline,
    #[cfg(target_os = "macos")]
    Native,
}

fn command(file: &Path) -> Command {
    let mut command = super::ticket_command("validate", file, true);
    closed_environment(&mut command);
    command
}

fn closed_environment(command: &mut Command) {
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn command_is_validation_only_with_closed_environment() {
        let request = command(Path::new("fixed-image.dmg"));
        assert_eq!(request.get_program(), OsStr::new("/usr/bin/xcrun"));
        assert_eq!(
            request.get_args().collect::<Vec<_>>(),
            ["stapler", "validate", "-v", "fixed-image.dmg"].map(OsStr::new)
        );
        let environment = request.get_envs().collect::<Vec<_>>();
        assert_eq!(
            environment,
            [
                (OsStr::new("LC_ALL"), Some(OsStr::new("C"))),
                (
                    OsStr::new("PATH"),
                    Some(OsStr::new("/usr/bin:/bin:/usr/sbin:/sbin"))
                ),
            ]
        );
    }
}
