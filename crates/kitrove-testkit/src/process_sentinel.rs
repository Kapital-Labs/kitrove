use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

thread_local! {
    static EVENTS: RefCell<Vec<SentinelEvent>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelEvent {
    ProcessSpawned,
    NetworkAccessed,
    FilesystemWrite,
}

/// Records attempted side effects without performing them.
///
/// The contract harness installs a fresh recorder before it calls policy methods. Synthetic
/// policies can mark a forbidden behavior directly, so contract tests never need to launch a
/// process, open a socket, or write an external sentinel file to prove rejection.
#[derive(Clone, Debug, Default)]
pub struct ProcessSentinel {
    start: usize,
}

impl ProcessSentinel {
    /// Starts a fresh, thread-local observation window.
    #[must_use]
    pub fn install() -> Self {
        EVENTS.with(|events| events.borrow_mut().clear());
        Self { start: 0 }
    }

    /// Marks a forbidden process-spawn attempt.
    pub fn record_process_spawn() {
        Self::record(SentinelEvent::ProcessSpawned);
    }

    /// Marks a forbidden network-access attempt.
    pub fn record_network_access() {
        Self::record(SentinelEvent::NetworkAccessed);
    }

    /// Marks a forbidden filesystem-write attempt.
    pub fn record_filesystem_write() {
        Self::record(SentinelEvent::FilesystemWrite);
    }

    /// Returns a process environment that callers can apply to a separately spawned test command.
    ///
    /// This function only constructs values; it does not mutate this process environment.
    #[must_use]
    pub fn environment(root: &Path) -> BTreeMap<OsString, OsString> {
        let marker = root.join(".kitrove-testkit-sentinel");
        BTreeMap::from([(
            OsString::from("KITROVE_TESTKIT_SENTINEL_DIR"),
            marker.into_os_string(),
        )])
    }

    /// Returns side-effect events observed since installation.
    #[must_use]
    pub fn events(&self) -> Vec<SentinelEvent> {
        EVENTS.with(|events| events.borrow()[self.start..].to_vec())
    }

    fn record(event: SentinelEvent) {
        EVENTS.with(|events| events.borrow_mut().push(event));
    }
}

/// Builds the marker location advertised to subprocess test fixtures.
#[must_use]
pub fn sentinel_marker(root: &Path) -> PathBuf {
    root.join(".kitrove-testkit-sentinel")
}
