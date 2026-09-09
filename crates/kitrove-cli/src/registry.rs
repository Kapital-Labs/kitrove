use kitrove_adapter_api::{NativeRootKey, PolicyLine};
use kitrove_adapter_claude::ClaudeObservationPolicy;
use kitrove_adapter_codex::CodexObservationPolicy;
use kitrove_adapter_opencode::OpenCodeObservationPolicy;
use kitrove_adapter_pi::PiObservationPolicy;
use kitrove_core::{PolicyCatalog, PolicyRegistration, PolicyRegistry};

/// Constructs the exact stable tier-one scan policy order.
#[must_use]
pub fn tier_one_registry() -> PolicyRegistry {
    try_tier_one_registry().expect("the compiled tier-one policy registry is conflict-free")
}

pub(crate) fn try_tier_one_registry() -> kitrove_adapter_api::AdapterResult<PolicyRegistry> {
    PolicyRegistry::new_catalogued(vec![
        registration(
            Box::new(ClaudeObservationPolicy::new()),
            vec![PolicyLine::ClaudeCurrent],
            &[
                "claude.enterprise",
                "claude.plugin",
                "claude.additional",
                "claude.bundled",
            ],
        ),
        registration(
            Box::new(CodexObservationPolicy::new()),
            vec![PolicyLine::CodexCurrent],
            &["codex.bundled"],
        ),
        registration(
            Box::new(PiObservationPolicy::new()),
            vec![PolicyLine::PiLatest],
            &[],
        ),
        registration(
            Box::new(OpenCodeObservationPolicy::new()),
            vec![PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            &["opencode-v2.built-in"],
        ),
    ])
}

fn registration(
    policy: Box<dyn kitrove_adapter_api::HarnessObservationPolicy>,
    lines: Vec<PolicyLine>,
    native_root_keys: &[&str],
) -> PolicyRegistration {
    PolicyRegistration::new(
        policy,
        PolicyCatalog::new(
            lines,
            native_root_keys
                .iter()
                .map(|key| NativeRootKey::parse(*key).expect("compiled native-root key is valid"))
                .collect(),
        ),
    )
}
