#![forbid(unsafe_code)]
//! Harness-neutral Agent Skills parsing and bounded capture primitives.

mod capture;
mod directory_entries;
mod error;
mod frontmatter;
mod limits;
mod native_object;
mod observed;
mod projection;
mod risk;
mod source;
mod stored_tree;
mod tree;

pub use capture::{SkillSnapshot, capture_skill};
pub use directory_entries::{BoundedDirectoryEntries, collect_bounded_sorted_directory_entries};
pub use error::SkillError;
pub use frontmatter::{
    ParsedSkillDocument, SkillManifest, is_standard_skill_description, is_standard_skill_name,
    parse_observed_skill_document, parse_skill_document,
};
pub use kitrove_risk::is_credential_shaped;
pub use limits::{CaptureLimits, DEFAULT_MAX_CAPTURE_FILES};
pub use native_object::NativeSkillObject;
pub use observed::{BoundedYamlValue, ObservedSkillDocument};
pub use projection::{PortableProjection, project_skill_source};
pub use risk::{
    assess_native_executable_tree_risk, assess_native_skill_object_risk, assess_portable_tree_risk,
};
pub use source::{
    CaptureMeter, CaptureUsage, CapturedSkillSource, SkillSource, SkillSourceLayout,
    capture_skill_source, capture_skill_source_metered, capture_skill_source_with_meter,
    hash_skill_source,
};
pub use stored_tree::StoredSkillTree;
pub use tree::{
    CaptureHandleValidator, CapturedFile, CapturedTree, DirectoryWalkControl, DirectoryWalkMeter,
    DirectoryWalkReport, FileMode, MAX_CAPTURE_DEPTH, MAX_CAPTURE_DIRECTORIES,
    capture_standalone_tree, capture_standalone_tree_from_dir, capture_standalone_tree_metered,
    capture_tree, capture_tree_from_dir, capture_tree_from_dir_with_validator,
    capture_tree_metered, hash_tree, walk_directories_nofollow,
};

/// Returns whether a source-relative candidate is one direct child of its root.
#[must_use]
pub fn is_direct_child_source_path(relative: &str) -> bool {
    !relative.is_empty() && !relative.contains(['/', '\\'])
}
