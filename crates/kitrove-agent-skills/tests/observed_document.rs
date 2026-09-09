#![forbid(unsafe_code)]

use std::path::Path;

use kitrove_agent_skills::{BoundedYamlValue, parse_observed_skill_document};

#[test]
fn observed_document_retains_standard_and_native_fields_without_requiring_them() {
    let parsed = parse_observed_skill_document(
        Path::new("review.md"),
        b"---\nlicense: MIT\ncompatibility: codex\nmetadata:\n  owner: team\nallowed-tools: Read\nx-native: true\n---\nBody\n",
    )
    .expect("observed documents do not require portable fields");

    assert_eq!(parsed.license.as_deref(), Some("MIT"));
    assert_eq!(parsed.compatibility.as_deref(), Some("codex"));
    assert_eq!(
        parsed
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("owner"))
            .map(String::as_str),
        Some("team")
    );
    assert_eq!(parsed.allowed_tools.as_deref(), Some("Read"));
    assert!(parsed.native_fields.contains("x-native"));
    assert_eq!(parsed.declared_name, None);
    assert_eq!(parsed.description, None);
    assert_eq!(
        parsed.frontmatter.get("x-native"),
        Some(&BoundedYamlValue::Boolean(true))
    );
}

#[test]
fn observed_document_keeps_non_portable_frontmatter_as_bounded_values() {
    let parsed = parse_observed_skill_document(
        Path::new("review.md"),
        b"---\nx-native:\n  list: [one, 2, null]\n---\nBody\n",
    )
    .expect("native values remain observable");

    assert_eq!(
        parsed.frontmatter.get("x-native"),
        Some(&BoundedYamlValue::Mapping(
            [(
                "list".to_owned(),
                BoundedYamlValue::Sequence(vec![
                    BoundedYamlValue::String("one".to_owned()),
                    BoundedYamlValue::Number("2".to_owned()),
                    BoundedYamlValue::Null,
                ])
            )]
            .into_iter()
            .collect(),
        ))
    );
}

#[test]
fn observed_document_without_frontmatter_preserves_the_complete_body() {
    let source = b"# Native-only document\n";

    let parsed = parse_observed_skill_document(Path::new("review.md"), source)
        .expect("frontmatter is optional for observed documents");

    assert!(parsed.frontmatter.is_empty());
    assert_eq!(parsed.body, "# Native-only document\n");
}
