#![forbid(unsafe_code)]

use std::path::Path;

use kitrove_agent_skills::{CaptureLimits, capture_skill};
use kitrove_model::ContentClass;
use kitrove_testkit::AgentSkillFixture;

#[test]
fn fixture_locator_maps_each_variant_to_its_literal_directory() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("agent-skills");
    let cases = [
        (
            AgentSkillFixture::StandardBasic,
            fixture_root.join("standard-basic"),
        ),
        (
            AgentSkillFixture::ClaudeExtended,
            fixture_root.join("claude-extended"),
        ),
        (
            AgentSkillFixture::ScriptBearing,
            fixture_root.join("script-bearing"),
        ),
    ];

    for (fixture, expected_directory) in cases {
        assert_eq!(fixture.directory(), expected_directory);
    }
}

#[test]
fn checked_in_agent_skill_fixtures_capture_with_expected_classification() {
    let cases = [
        (AgentSkillFixture::StandardBasic, ContentClass::AgentActive),
        (AgentSkillFixture::ClaudeExtended, ContentClass::Executable),
        (AgentSkillFixture::ScriptBearing, ContentClass::Executable),
    ];

    for (fixture, expected_classification) in cases {
        let directory = fixture.directory();
        assert!(
            directory.is_dir(),
            "fixture directory must exist: {directory:?}"
        );
        assert!(
            directory.join("SKILL.md").is_file(),
            "fixture SKILL.md must exist: {directory:?}"
        );

        let snapshot = capture_skill(&directory, CaptureLimits::default())
            .expect("checked-in fixture must capture without executing content");

        assert_eq!(snapshot.content_class, expected_classification);
    }
}
