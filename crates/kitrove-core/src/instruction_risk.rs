/// Conservatively identifies commonly issued credential shapes in instruction text.
///
/// The tokenizer is shared by adoption and materialization so both authority boundaries enforce
/// the same rule without retaining or reporting the matched value.
pub(crate) fn contains_credential_shaped_value(text: &str) -> bool {
    kitrove_risk::contains_credential_shaped_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_delimited_credentials_without_matching_normal_prose() {
        assert!(contains_credential_shaped_value(
            "Authenticate with `sk-live-12345678901234567890`; then continue."
        ));
        assert!(!contains_credential_shaped_value(
            "Ask before accessing credentials or private keys."
        ));
    }
}
