//! Closed cross-language framing. These records prove cleanup, never readiness.
pub(super) fn record(ordinal: u8, finished: bool) -> Option<String> {
    if !(1..=8).contains(&ordinal) {
        return None;
    }
    let event = if finished { "finish" } else { "start" };
    let cleanup = if finished {
        ",\"cleanup_confirmed\":true"
    } else {
        ""
    };
    Some(format!(
        "KITROVE_APPLE_OWNER_V1 {{\"schema_version\":1,\"ordinal\":{ordinal},\"event\":\"{event}\"{cleanup}}}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_matches_cross_language_consumer_corpus() {
        let corpus: Vec<String> = serde_json::from_str(include_str!(
            "../../../scripts/fixtures/apple-owner-v1.json"
        ))
        .unwrap();
        let actual: Vec<_> = (1..=8)
            .flat_map(|ordinal| {
                [
                    record(ordinal, false).unwrap(),
                    record(ordinal, true).unwrap(),
                ]
            })
            .collect();
        assert_eq!(actual, corpus);
    }

    #[test]
    fn exact_closed_start_finish_records_and_ordinal_limit() {
        assert_eq!(
            record(1, false).as_deref(),
            Some("KITROVE_APPLE_OWNER_V1 {\"schema_version\":1,\"ordinal\":1,\"event\":\"start\"}")
        );
        assert_eq!(
            record(8, true).as_deref(),
            Some(
                "KITROVE_APPLE_OWNER_V1 {\"schema_version\":1,\"ordinal\":8,\"event\":\"finish\",\"cleanup_confirmed\":true}"
            )
        );
        assert!(record(0, false).is_none());
        assert!(record(9, true).is_none());
    }
}
