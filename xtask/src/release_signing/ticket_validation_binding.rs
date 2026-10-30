//! Evidence metadata only: never signing, execution or publication permission.
pub(in crate::release_archive::signing) fn bound_source(
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<String>, ()> {
    if env("KITROVE_APPLE_TICKET_DIAGNOSTIC").is_some() {
        return super::super::ticket_diagnostic::context(env).map_err(|_| ());
    }
    let Some(source) = env("KITROVE_NOTARY_SOURCE_COMMIT") else {
        return Ok(None);
    };
    if source.len() != 40
        || !source
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    match env("DIST_TARGET").as_deref() {
        Some("aarch64-apple-darwin") => {}
        Some("x86_64-apple-darwin") => return Ok(None),
        _ => return Err(()),
    }
    if env("GITHUB_SHA").is_some_and(|actual| actual != source) {
        return Err(());
    }
    match env("GITHUB_ACTIONS").as_deref() {
        None => {}
        Some("true")
            if env("GITHUB_SHA").as_deref() == Some(&source)
                && env("GITHUB_REPOSITORY").as_deref() == Some("Kapital-Labs/kitrove") => {}
        _ => return Err(()),
    }
    Ok(Some(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn local() -> BTreeMap<String, String> {
        [
            ("KITROVE_NOTARY_SOURCE_COMMIT".into(), "a".repeat(40)),
            ("DIST_TARGET".into(), "aarch64-apple-darwin".into()),
        ]
        .into()
    }

    #[test]
    fn explicit_local_source_is_metadata_and_unbound_input_keeps_single_attempt() {
        assert_eq!(bound_source(|_| None), Ok(None));
        let env = local();
        assert_eq!(
            bound_source(|key| env.get(key).cloned()),
            Ok(Some("a".repeat(40)))
        );
    }

    #[test]
    fn ordinary_hosted_metadata_requires_exact_source_and_public_repository() {
        let mut env = local();
        env.extend([
            ("GITHUB_ACTIONS".into(), "true".into()),
            ("GITHUB_SHA".into(), "a".repeat(40)),
            ("GITHUB_REPOSITORY".into(), "Kapital-Labs/kitrove".into()),
        ]);
        assert_eq!(
            bound_source(|key| env.get(key).cloned()),
            Ok(Some("a".repeat(40)))
        );
        for (key, value) in [
            ("GITHUB_SHA", "b".repeat(40)),
            ("GITHUB_REPOSITORY", "unapproved/repository".into()),
            ("GITHUB_ACTIONS", "false".into()),
        ] {
            let mut invalid = env.clone();
            invalid.insert(key.into(), value);
            assert!(bound_source(|key| invalid.get(key).cloned()).is_err());
        }
    }

    #[test]
    fn malformed_or_ambiguous_source_refuses_without_a_native_request() {
        for value in [
            "",
            "A",
            "not-a-source",
            "/private/synthetic",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        ] {
            let mut env = local();
            env.insert("KITROVE_NOTARY_SOURCE_COMMIT".into(), value.into());
            assert!(bound_source(|key| env.get(key).cloned()).is_err());
        }
        let mut env = local();
        env.remove("DIST_TARGET");
        assert!(bound_source(|key| env.get(key).cloned()).is_err());
        env.insert("DIST_TARGET".into(), "x86_64-apple-darwin".into());
        assert_eq!(bound_source(|key| env.get(key).cloned()), Ok(None));
        env.insert("DIST_TARGET".into(), "unknown-target".into());
        assert!(bound_source(|key| env.get(key).cloned()).is_err());
    }

    #[test]
    fn diagnostic_metadata_keeps_all_existing_strict_context_requirements() {
        let source = "a".repeat(40);
        let mut env = local();
        env.extend([("KITROVE_APPLE_TICKET_DIAGNOSTIC".into(), "1".into()),
            ("GITHUB_SHA".into(), source.clone()), ("GITHUB_ACTIONS".into(), "true".into()),
            ("RUNNER_ENVIRONMENT".into(), "github-hosted".into()), ("RUNNER_ARCH".into(), "ARM64".into()),
            ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
            ("GITHUB_REPOSITORY".into(), "Kapital-Labs/kitrove".into()),
            ("GITHUB_REF".into(), "refs/heads/main".into()), ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
            ("GITHUB_WORKFLOW_REF".into(), "Kapital-Labs/kitrove/.github/workflows/apple-ticket-diagnostic.yml@refs/heads/main".into()),
            ("KITROVE_SIGNING_REHEARSAL_SHA".into(), source.clone()),
            ("KITROVE_DIAGNOSTIC_EXPECTED_SOURCE".into(), source.clone())]);
        assert_eq!(bound_source(|key| env.get(key).cloned()), Ok(Some(source)));
        env.insert("KITROVE_HOSTED_SIGNING_READY".into(), "true".into());
        assert!(bound_source(|key| env.get(key).cloned()).is_err());
    }
}
