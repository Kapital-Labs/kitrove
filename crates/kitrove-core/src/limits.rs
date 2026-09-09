use kitrove_adapter_api::{RootHookMeter, ScanLimits};
use kitrove_agent_skills::{CaptureLimits, CaptureMeter, CaptureUsage, DirectoryWalkMeter};

/// Request-global capacity shared by discovery and later source capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanBudget {
    limits: ScanLimits,
    roots: usize,
    hook_inputs: usize,
    discovery_entries: usize,
    candidates: usize,
    capture_usage: CaptureUsage,
    report_entries: usize,
    report_findings: usize,
}

impl DirectoryWalkMeter for ScanBudget {
    fn try_discovery_entry(&mut self) -> bool {
        self.reserve_discovery_entry()
    }

    fn remaining_discovery_entries(&self) -> usize {
        ScanBudget::remaining_discovery_entries(self)
    }
}

impl RootHookMeter for ScanBudget {
    fn try_root_input(&mut self) -> bool {
        if self.hook_inputs >= self.limits.max_roots {
            return false;
        }
        self.hook_inputs = self.hook_inputs.saturating_add(1);
        true
    }
}

impl CaptureMeter for ScanBudget {
    fn try_file_attempt(&mut self) -> bool {
        self.begin_capture_file()
    }

    fn remaining_bytes(&self) -> u64 {
        self.remaining_capture_bytes()
    }

    fn try_charge_bytes(&mut self, bytes: u64) -> bool {
        if bytes > self.remaining_capture_bytes() {
            return false;
        }
        self.charge_capture_bytes(bytes);
        true
    }
}

impl ScanBudget {
    /// Starts a new request budget from the caller-selected limits.
    #[must_use]
    pub fn new(limits: ScanLimits) -> Self {
        Self {
            limits,
            roots: 0,
            hook_inputs: 0,
            discovery_entries: 0,
            candidates: 0,
            capture_usage: CaptureUsage::default(),
            report_entries: 0,
            report_findings: 0,
        }
    }

    /// Resumes all externally visible request usage for a later composition stage.
    #[must_use]
    pub fn with_usage(
        limits: ScanLimits,
        capture_usage: CaptureUsage,
        report_entries: usize,
        report_findings: usize,
    ) -> Option<Self> {
        if capture_usage.file_attempts > limits.max_capture_files
            || capture_usage.bytes_read > limits.max_capture_bytes
            || report_entries > limits.max_report_entries
            || report_findings > limits.max_findings
        {
            return None;
        }
        let mut budget = Self::new(limits);
        budget.capture_usage = capture_usage;
        budget.report_entries = report_entries;
        budget.report_findings = report_findings;
        Some(budget)
    }

    /// Reserves one later-stage report entry and all findings attached to it.
    pub fn try_report_entry(&mut self, finding_count: usize) -> bool {
        self.reserve_report_entry(finding_count)
    }

    /// Reserves later-stage report-level findings.
    pub fn try_report_findings(&mut self, count: usize) -> bool {
        self.reserve_report_findings(count)
    }

    /// Returns the immutable limits backing this request-global budget.
    #[must_use]
    pub const fn limits(&self) -> &ScanLimits {
        &self.limits
    }

    /// Returns aggregate capture work charged so far, including failed work.
    #[must_use]
    pub const fn capture_usage(&self) -> &CaptureUsage {
        &self.capture_usage
    }

    /// Returns the per-candidate limits narrowed to remaining request capacity.
    #[must_use]
    pub fn remaining_capture_limits(&self) -> CaptureLimits {
        CaptureLimits {
            max_files: self.limits.capture.max_files.min(
                self.limits
                    .max_capture_files
                    .saturating_sub(self.capture_usage.file_attempts),
            ),
            max_file_bytes: self.limits.capture.max_file_bytes,
            max_total_bytes: self.limits.capture.max_total_bytes.min(
                self.limits
                    .max_capture_bytes
                    .saturating_sub(self.capture_usage.bytes_read),
            ),
        }
    }

    pub(crate) fn reserve_root(&mut self) -> bool {
        if self.roots >= self.limits.max_roots {
            return false;
        }
        self.roots += 1;
        true
    }

    pub(crate) fn reserve_discovery_entry(&mut self) -> bool {
        if self.discovery_entries >= self.limits.max_discovery_entries {
            return false;
        }
        self.discovery_entries += 1;
        true
    }

    /// Returns the number of directory entries reserved by this request.
    #[must_use]
    pub const fn discovery_entries(&self) -> usize {
        self.discovery_entries
    }

    pub(crate) fn remaining_discovery_entries(&self) -> usize {
        self.limits
            .max_discovery_entries
            .saturating_sub(self.discovery_entries)
    }

    pub(crate) fn discovery_exhausted(&self) -> bool {
        self.discovery_entries >= self.limits.max_discovery_entries
    }

    pub(crate) fn exhaust_discovery(&mut self) {
        self.discovery_entries = self.limits.max_discovery_entries;
    }

    pub(crate) fn reserve_candidate(&mut self) -> bool {
        if self.candidates >= self.limits.max_candidates {
            return false;
        }
        self.candidates += 1;
        true
    }

    pub(crate) fn reserve_report_entry(&mut self, findings: usize) -> bool {
        let Some(next_entries) = self.report_entries.checked_add(1) else {
            return false;
        };
        let Some(next_findings) = self.report_findings.checked_add(findings) else {
            return false;
        };
        if next_entries > self.limits.max_report_entries || next_findings > self.limits.max_findings
        {
            return false;
        }
        self.report_entries = next_entries;
        self.report_findings = next_findings;
        true
    }

    pub(crate) fn reserve_report_findings(&mut self, findings: usize) -> bool {
        let Some(next) = self.report_findings.checked_add(findings) else {
            return false;
        };
        if next > self.limits.max_findings {
            return false;
        }
        self.report_findings = next;
        true
    }

    pub(crate) fn remaining_report_findings(&self) -> usize {
        self.limits
            .max_findings
            .saturating_sub(self.report_findings)
    }

    pub(crate) fn release_report_entry(&mut self, findings: usize) {
        self.report_entries = self.report_entries.saturating_sub(1);
        self.report_findings = self.report_findings.saturating_sub(findings);
    }

    pub(crate) fn begin_capture_file(&mut self) -> bool {
        if self.capture_usage.file_attempts >= self.limits.max_capture_files {
            return false;
        }
        self.capture_usage.file_attempts += 1;
        true
    }

    pub(crate) fn remaining_capture_bytes(&self) -> u64 {
        self.limits
            .max_capture_bytes
            .saturating_sub(self.capture_usage.bytes_read)
    }

    pub(crate) fn charge_capture_bytes(&mut self, bytes: u64) {
        self.capture_usage.bytes_read = self.capture_usage.bytes_read.saturating_add(bytes);
    }
}
