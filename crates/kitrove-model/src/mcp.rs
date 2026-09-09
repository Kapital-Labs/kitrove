const MAX_PORTABLE_MCP_SERVER_NAME_BYTES: usize = 63;

/// Returns whether a logical MCP key is portable across the supported native registries.
#[must_use]
pub fn is_portable_mcp_server_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PORTABLE_MCP_SERVER_NAME_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes.last() != Some(&b'-')
        && !value.contains("--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_mcp_names_use_one_bounded_conservative_grammar() {
        for accepted in ["a", "company-tools", "mcp2"] {
            assert!(is_portable_mcp_server_name(accepted));
        }
        for rejected in ["", "Company", "company_tools", "company--tools", "tools-"] {
            assert!(!is_portable_mcp_server_name(rejected));
        }
        assert!(!is_portable_mcp_server_name(&"a".repeat(64)));
    }
}
