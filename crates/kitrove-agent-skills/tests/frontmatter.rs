#![forbid(unsafe_code)]

use std::path::Path;

use kitrove_agent_skills::parse_skill_document;

#[test]
fn preserves_standard_fields_and_reports_native_field_names() {
    let source = br#"---
name: code-review
description: Review a change and explain concrete risks.
license: MIT
compatibility: Requires Git.
metadata:
  owner: kitrove
allowed-tools: Read Grep
disable-model-invocation: true
hooks:
  Stop: ./scripts/stop.sh
---
# Code review
"#;

    let parsed = parse_skill_document(Path::new("SKILL.md"), source).expect("valid skill document");

    assert_eq!(parsed.manifest.name.as_str(), "code-review");
    assert_eq!(
        parsed.manifest.description,
        "Review a change and explain concrete risks."
    );
    assert_eq!(parsed.manifest.license.as_deref(), Some("MIT"));
    assert_eq!(
        parsed.manifest.compatibility.as_deref(),
        Some("Requires Git.")
    );
    assert_eq!(parsed.manifest.metadata["owner"], "kitrove");
    assert_eq!(parsed.manifest.allowed_tools.as_deref(), Some("Read Grep"));
    assert_eq!(
        parsed.native_fields.into_iter().collect::<Vec<_>>(),
        ["disable-model-invocation", "hooks"]
    );
    assert_eq!(parsed.body, "# Code review\n");
}

#[test]
fn rejects_missing_or_malformed_standard_fields_without_echoing_authored_values() {
    let cases = [
        (
            b"# missing frontmatter".as_slice(),
            "skill.frontmatter_missing",
            "missing frontmatter",
        ),
        (
            b"---\nname: Bad_Name\ndescription: valid\n---\n",
            "skill.name_invalid",
            "Bad_Name",
        ),
        (
            b"---\nname: valid\ndescription: ''\n---\n",
            "skill.description_invalid",
            "description: ''",
        ),
        (
            b"---\nname: valid\ndescription: ok\nmetadata: [bad]\n---\n",
            "skill.metadata_invalid",
            "metadata: [bad]",
        ),
    ];

    for (source, expected_code, authored_value) in cases {
        let error = parse_skill_document(Path::new("SKILL.md"), source)
            .expect_err("malformed standard field must be rejected");

        assert_eq!(error.code(), expected_code);
        assert!(!error.to_string().contains(authored_value));
    }
}

#[test]
fn accepts_name_and_description_at_the_documented_limits() {
    let name = "a".repeat(64);
    let description = "d".repeat(1_024);
    let source = format!("---\nname: {name}\ndescription: {description}\n---\n");

    let parsed = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
        .expect("64-byte name and 1,024-character description are valid");

    assert_eq!(parsed.manifest.name.as_str(), name);
    assert_eq!(parsed.manifest.description, description);
}

#[test]
fn rejects_names_that_break_agent_skills_identifier_rules() {
    let cases = [
        ("a".repeat(65), "name longer than 64 bytes"),
        ("-leading".to_owned(), "name with a leading hyphen"),
        ("trailing-".to_owned(), "name with a trailing hyphen"),
        ("double--hyphen".to_owned(), "name with consecutive hyphens"),
    ];

    for (name, break_description) in cases {
        let source = format!("---\nname: {name}\ndescription: valid\n---\n");
        let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
            .expect_err(break_description);

        assert_eq!(error.code(), "skill.name_invalid");
        assert!(!error.to_string().contains(&name));
    }
}

#[test]
fn rejects_descriptions_that_fall_outside_the_documented_range() {
    let empty = b"---\nname: valid\ndescription: ''\n---\n";
    let too_long = format!(
        "---\nname: valid\ndescription: {}\n---\n",
        "d".repeat(1_025)
    );

    for (source, break_description) in [
        (empty.as_slice(), "empty description"),
        (
            too_long.as_bytes(),
            "description longer than 1,024 characters",
        ),
    ] {
        let error =
            parse_skill_document(Path::new("SKILL.md"), source).expect_err(break_description);

        assert_eq!(error.code(), "skill.description_invalid");
    }
}

#[test]
fn accepts_compatibility_at_500_characters() {
    let compatibility = "c".repeat(500);
    let source =
        format!("---\nname: valid\ndescription: valid\ncompatibility: {compatibility}\n---\n");

    let parsed = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
        .expect("500-character compatibility is valid");

    assert_eq!(
        parsed.manifest.compatibility.as_deref(),
        Some(compatibility.as_str())
    );
}

#[test]
fn rejects_a_present_empty_compatibility_without_echoing_authored_content() {
    let canary = "KITROVE_C1_COMPATIBILITY_EMPTY_CANARY_2f937bb1";
    let source = format!("---\nname: valid\ndescription: {canary}\ncompatibility: ''\n---\n");

    let result = parse_skill_document(Path::new("SKILL.md"), source.as_bytes());
    let Err(error) = result else {
        panic!("a present empty compatibility was accepted");
    };

    assert_eq!(error.code(), "skill.compatibility_invalid");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn rejects_compatibility_longer_than_500_characters_without_echoing_it() {
    let compatibility = "c".repeat(501);
    let source =
        format!("---\nname: valid\ndescription: valid\ncompatibility: {compatibility}\n---\n");

    let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
        .expect_err("compatibility longer than 500 characters must be rejected");

    assert_eq!(error.code(), "skill.compatibility_invalid");
    assert!(!error.to_string().contains(&compatibility));
}

#[test]
fn rejects_oversized_direct_parser_input_before_yaml_materialization() {
    let canary = "KITROVE_C1_DIRECT_PARSE_SIZE_CANARY_44da6af8";
    let mut source = format!("---\nname: valid\ndescription: valid\n---\n{canary}\n").into_bytes();
    source.resize(4 * 1024 * 1024 + 1, b'x');

    let result = parse_skill_document(Path::new("SKILL.md"), &source);
    let Err(error) = result else {
        panic!("direct parser input above the capture per-file limit was accepted");
    };

    assert_eq!(error.code(), "skill.document_size_limit");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn accepts_direct_parser_input_at_the_four_mibibyte_boundary() {
    let canary = "KITROVE_C1_DIRECT_PARSE_BOUNDARY_CANARY_188d37f9";
    let mut source = format!("---\nname: valid\ndescription: valid\n---\n{canary}\n").into_bytes();
    source.resize(4 * 1024 * 1024, b'x');

    let parsed = parse_skill_document(Path::new("SKILL.md"), &source)
        .expect("direct parser input at the per-file boundary is valid");

    assert_eq!(parsed.manifest.name.as_str(), "valid");
    assert!(parsed.body.starts_with(canary));
}

#[test]
fn rejects_frontmatter_nesting_beyond_the_explicit_depth_limit() {
    let canary = "KITROVE_C1_YAML_DEPTH_CANARY_b1e0c348";
    let nesting = 65;
    let source = format!(
        "---\nname: valid\ndescription: valid\nnative: {}'{canary}'{}\n---\n",
        "[".repeat(nesting),
        "]".repeat(nesting)
    );

    let result = parse_skill_document(Path::new("SKILL.md"), source.as_bytes());
    let Err(error) = result else {
        panic!("frontmatter beyond the explicit nesting limit was accepted");
    };

    assert_eq!(error.code(), "skill.frontmatter_depth_limit");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn rejects_frontmatter_beyond_the_explicit_node_limit() {
    let canary = "KITROVE_C1_YAML_NODE_CANARY_d3cd2567";
    let nodes = std::iter::repeat_n("0", 5_000)
        .collect::<Vec<_>>()
        .join(",");
    let source =
        format!("---\nname: valid\ndescription: valid\nnative: ['{canary}',{nodes}]\n---\n");

    let result = parse_skill_document(Path::new("SKILL.md"), source.as_bytes());
    let Err(error) = result else {
        panic!("frontmatter beyond the explicit node limit was accepted");
    };

    assert_eq!(error.code(), "skill.frontmatter_node_limit");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn rejects_yaml_alias_amplification_before_materializing_native_values() {
    let canary = "KITROVE_C1_YAML_ALIAS_CANARY_eb49bf54";
    let source = format!(
        "---\n\
         name: valid\n\
         description: valid\n\
         seed: &seed ['{canary}','{canary}','{canary}','{canary}','{canary}','{canary}','{canary}','{canary}']\n\
         level-one: &level_one [*seed,*seed,*seed,*seed,*seed,*seed,*seed,*seed]\n\
         level-two: &level_two [*level_one,*level_one,*level_one,*level_one,*level_one,*level_one,*level_one,*level_one]\n\
         level-three: &level_three [*level_two,*level_two,*level_two,*level_two,*level_two,*level_two,*level_two,*level_two]\n\
         native: [*level_three,*level_three]\n\
         ---\n"
    );

    let result = parse_skill_document(Path::new("SKILL.md"), source.as_bytes());
    let Err(error) = result else {
        panic!("amplified YAML aliases were accepted");
    };

    assert_eq!(error.code(), "skill.frontmatter_alias_limit");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn block_scalar_alias_like_text_does_not_relabel_node_budget_failures() {
    let nodes = std::iter::repeat_n("0", 5_000)
        .collect::<Vec<_>>()
        .join(",");
    let cases = [
        ("|", "KITROVE_C1_LITERAL_BLOCK_CANARY_b9c38e76"),
        ("|-2", "KITROVE_C1_LITERAL_CHOMP_INDENT_CANARY_b22e419c"),
        ("|2+", "KITROVE_C1_LITERAL_INDENT_CHOMP_CANARY_a4be1e3b"),
        (">", "KITROVE_C1_FOLDED_BLOCK_CANARY_63e0e85f"),
        (">+2", "KITROVE_C1_FOLDED_CHOMP_INDENT_CANARY_bf95fc7b"),
        (">2-", "KITROVE_C1_FOLDED_INDENT_CHOMP_CANARY_a90be4d2"),
    ];

    for (header, canary) in cases {
        let source = format!(
            "---\nname: valid\ndescription: valid\nnative-text: {header}\n  *{canary}\nnative-nodes: [{nodes}]\n---\n"
        );

        let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
            .expect_err("non-alias block-scalar text must still exhaust the plain node budget");

        assert_eq!(error.code(), "skill.frontmatter_node_limit", "{header}");
        assert!(!error.message().contains(canary), "{header}");
        assert!(!error.to_string().contains(canary), "{header}");
    }
}

#[test]
fn compact_sequence_block_scalars_resume_alias_scanning_at_dedented_siblings() {
    let nodes = std::iter::repeat_n("0", 5_000)
        .collect::<Vec<_>>()
        .join(",");
    let cases = [
        (
            "|-2",
            "KITROVE_C1_COMPACT_LITERAL_CHOMP_INDENT_ALIAS_CANARY_4d388827",
        ),
        (
            "|2+",
            "KITROVE_C1_COMPACT_LITERAL_INDENT_CHOMP_ALIAS_CANARY_e40ac275",
        ),
        (
            ">+2",
            "KITROVE_C1_COMPACT_FOLDED_CHOMP_INDENT_ALIAS_CANARY_7e00bd64",
        ),
        (
            ">2-",
            "KITROVE_C1_COMPACT_FOLDED_INDENT_CHOMP_ALIAS_CANARY_ae9a2442",
        ),
    ];

    for (header, canary) in cases {
        let source = format!(
            "---\nname: valid\ndescription: valid\nseed: &seed [0]\nnative:\n  - text: {header}\n      *{canary}\n    sibling: *seed\nnative-nodes: [{nodes}]\n---\n"
        );

        let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
            .expect_err("a real alias in the dedented sibling must use the alias budget");

        assert_eq!(error.code(), "skill.frontmatter_alias_limit", "{header}");
        assert!(!error.message().contains(canary), "{header}");
        assert!(!error.to_string().contains(canary), "{header}");
    }
}

#[test]
fn compact_sequence_block_scalar_alias_text_does_not_count_as_a_real_alias() {
    let nodes = std::iter::repeat_n("0", 5_000)
        .collect::<Vec<_>>()
        .join(",");
    let cases = [
        (
            "|-2",
            "KITROVE_C1_COMPACT_LITERAL_CHOMP_INDENT_TEXT_CANARY_9d98af51",
        ),
        (
            "|2+",
            "KITROVE_C1_COMPACT_LITERAL_INDENT_CHOMP_TEXT_CANARY_91a763ec",
        ),
        (
            ">+2",
            "KITROVE_C1_COMPACT_FOLDED_CHOMP_INDENT_TEXT_CANARY_0c56f676",
        ),
        (
            ">2-",
            "KITROVE_C1_COMPACT_FOLDED_INDENT_CHOMP_TEXT_CANARY_b095f156",
        ),
    ];

    for (header, canary) in cases {
        let source = format!(
            "---\nname: valid\ndescription: valid\nnative:\n  - text: {header}\n      *{canary}\n    sibling: ordinary\nnative-nodes: [{nodes}]\n---\n"
        );

        let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
            .expect_err("alias-shaped block-scalar text must use the plain node budget");

        assert_eq!(error.code(), "skill.frontmatter_node_limit", "{header}");
        assert!(!error.message().contains(canary), "{header}");
        assert!(!error.to_string().contains(canary), "{header}");
    }
}

#[test]
fn rejects_duplicate_top_level_keys_before_yaml_mapping_overwrites_them() {
    let source = b"---\nname: valid\nname: other\ndescription: valid\n---\n";

    let error = parse_skill_document(Path::new("SKILL.md"), source)
        .expect_err("duplicate top-level name must not be silently overwritten");

    assert_eq!(error.code(), "skill.frontmatter_duplicate_key");
    assert!(!error.to_string().contains("valid"));
    assert!(!error.to_string().contains("other"));
}

#[test]
fn rejects_same_value_duplicate_metadata_keys_without_disclosing_authored_scalars() {
    let key_canary = "owner-KITROVE-C1-DUPLICATE-METADATA-KEY-CANARY-69b26222";
    let value_canary = "KITROVE_C1_DUPLICATE_METADATA_SAME_VALUE_CANARY_403953db";
    let source = format!(
        "---\nname: valid\ndescription: valid\nmetadata:\n  {key_canary}: {value_canary}\n  {key_canary}: {value_canary}\n---\n"
    );

    let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
        .expect_err("a same-value duplicate metadata key must not be overwritten");

    assert_eq!(error.code(), "skill.metadata_duplicate_key");
    for authored_scalar in [key_canary, value_canary] {
        assert!(!error.message().contains(authored_scalar));
        assert!(!error.to_string().contains(authored_scalar));
    }
}

#[test]
fn rejects_different_value_duplicate_metadata_keys_without_disclosing_authored_scalars() {
    let key_canary = "owner-KITROVE-C1-DUPLICATE-METADATA-KEY-CANARY-98713106";
    let first_value_canary = "KITROVE_C1_DUPLICATE_METADATA_FIRST_VALUE_CANARY_6b6db6f9";
    let second_value_canary = "KITROVE_C1_DUPLICATE_METADATA_SECOND_VALUE_CANARY_69358663";
    let source = format!(
        "---\nname: valid\ndescription: valid\nmetadata:\n  {key_canary}: {first_value_canary}\n  {key_canary}: {second_value_canary}\n---\n"
    );

    let error = parse_skill_document(Path::new("SKILL.md"), source.as_bytes())
        .expect_err("a different-value duplicate metadata key must not be overwritten");

    assert_eq!(error.code(), "skill.metadata_duplicate_key");
    for authored_scalar in [key_canary, first_value_canary, second_value_canary] {
        assert!(!error.message().contains(authored_scalar));
        assert!(!error.to_string().contains(authored_scalar));
    }
}

#[test]
fn rejects_non_string_metadata_keys_and_values_without_echoing_them() {
    let cases = [
        (
            b"---\nname: valid\ndescription: valid\nmetadata:\n  1: owner\n---\n".as_slice(),
            "non-string metadata key",
            "owner",
        ),
        (
            b"---\nname: valid\ndescription: valid\nmetadata:\n  owner: true\n---\n".as_slice(),
            "non-string metadata value",
            "true",
        ),
    ];

    for (source, break_description, authored_value) in cases {
        let error =
            parse_skill_document(Path::new("SKILL.md"), source).expect_err(break_description);

        assert_eq!(error.code(), "skill.metadata_invalid");
        assert!(!error.to_string().contains(authored_value));
    }
}

#[test]
fn rejects_secret_like_metadata_keys_under_separator_insensitive_ascii_normalization() {
    let cases = [
        ("token", "KITROVE_C1_METADATA_TOKEN_CANARY_ccf59134"),
        ("Secret", "KITROVE_C1_METADATA_SECRET_CANARY_57ad84fb"),
        ("pass-word", "KITROVE_C1_METADATA_PASSWORD_CANARY_519f18a5"),
        (
            "credential",
            "KITROVE_C1_METADATA_CREDENTIAL_CANARY_aa03622a",
        ),
        (
            "private_key",
            "KITROVE_C1_METADATA_PRIVATE_KEY_CANARY_15d2c063",
        ),
        ("API-Key", "KITROVE_C1_METADATA_API_KEY_CANARY_49272c31"),
        (
            "access_token",
            "KITROVE_C1_METADATA_ACCESS_TOKEN_CANARY_3143eb38",
        ),
        (
            "auth_token",
            "KITROVE_C1_METADATA_AUTH_TOKEN_CANARY_911c3b56",
        ),
        (
            "client_secret",
            "KITROVE_C1_METADATA_CLIENT_SECRET_CANARY_99057dfb",
        ),
        (
            "openai_api_key",
            "KITROVE_C1_METADATA_OPENAI_API_KEY_CANARY_160fb8c1",
        ),
    ];

    for (key, canary) in cases {
        let source =
            format!("---\nname: valid\ndescription: valid\nmetadata:\n  {key}: {canary}\n---\n");

        let result = parse_skill_document(Path::new("SKILL.md"), source.as_bytes());
        let Err(error) = result else {
            panic!("secret-like metadata was accepted for key {key}");
        };

        assert_eq!(error.code(), "skill.credential_metadata", "{key}");
        assert!(!error.message().contains(canary), "{key}");
        assert!(!error.to_string().contains(canary), "{key}");
    }
}

#[test]
fn metadata_secret_key_matching_does_not_use_substrings() {
    let source = b"---\nname: valid\ndescription: valid\nmetadata:\n  tokenizer: text\n  secretary: person\n  password-policy: documented\n---\n";

    let parsed = parse_skill_document(Path::new("SKILL.md"), source)
        .expect("benign metadata key substrings must remain portable");

    assert_eq!(parsed.manifest.metadata["tokenizer"], "text");
    assert_eq!(parsed.manifest.metadata["secretary"], "person");
    assert_eq!(parsed.manifest.metadata["password-policy"], "documented");
}

#[test]
fn rejects_invalid_utf8_without_copying_raw_bytes_into_the_error() {
    let source = b"---\nname: valid\ndescription: valid\n---\n\xFF";

    let error = parse_skill_document(Path::new("SKILL.md"), source)
        .expect_err("invalid UTF-8 must not enter the parser");

    assert_eq!(error.code(), "skill.frontmatter_invalid");
    assert!(!error.to_string().contains('\u{FFFD}'));
}

#[test]
fn recognizes_crlf_frontmatter_delimiters_without_rewriting_the_body() {
    let source = b"---\r\nname: valid\r\ndescription: valid\r\n---\r\n# Body\r\n";

    let parsed = parse_skill_document(Path::new("SKILL.md"), source)
        .expect("CRLF frontmatter delimiters are valid");

    assert_eq!(parsed.manifest.name.as_str(), "valid");
    assert_eq!(parsed.body, "# Body\r\n");
}
