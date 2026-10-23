//! Closed diagnostic records; these never grant signing or publication authority.
use std::ffi::OsString;

use serde::{Deserialize, Serialize};

const PREFIX: &str = "KITROVE_NOTARY_RECEIPT_V1 ";
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Serialize)]
pub(super) struct Context {
    artifact_sha256: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_commit: Option<String>,
}

impl Context {
    pub(super) fn new(
        submitted: &[u8],
        target: &str,
        source_commit: Option<OsString>,
    ) -> Result<Self, String> {
        if !matches!(target, "aarch64-apple-darwin" | "x86_64-apple-darwin") {
            return Err("invalid Apple notarization target".to_owned());
        }
        let source_commit = source_commit
            .map(|source| {
                source
                    .into_string()
                    .ok()
                    .filter(|source| {
                        source.len() == 40
                            && source
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                    .ok_or_else(|| "invalid Apple notarization source context".to_owned())
            })
            .transpose()?;
        Ok(Self {
            artifact_sha256: super::super::sha256_hex(submitted),
            target: target.to_owned(),
            source_commit,
        })
    }
}

#[derive(Deserialize)]
struct Submission {
    id: String,
    #[serde(default, deserialize_with = "deserialize_status")]
    status: Option<Status>,
}

fn deserialize_status<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Status>, D::Error> {
    // An absent field means status was unavailable; an explicitly null or
    // malformed status is invalid provider output, not absence.
    Status::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
enum Status {
    Accepted,
    Invalid,
    Rejected,
    #[serde(rename = "In Progress")]
    InProgress,
    #[serde(skip_deserializing)]
    Unavailable,
}

#[derive(Serialize)]
struct Receipt {
    schema_version: u8,
    submission_id: String,
    status: Status,
    #[serde(flatten)]
    context: Context,
}

fn valid_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

pub(super) fn interpret(
    response: &[u8],
    command_succeeded: bool,
    context: Context,
) -> (Option<String>, Result<(), String>) {
    let invalid = || "Apple notarization returned an invalid result".to_owned();
    if response.len() > MAX_RESPONSE_BYTES {
        return (None, Err(invalid()));
    }
    let Ok(submission) = serde_json::from_slice::<Submission>(response) else {
        return (None, Err(invalid()));
    };
    if !valid_uuid(&submission.id) {
        return (None, Err(invalid()));
    }
    let accepted = submission.status == Some(Status::Accepted);
    let receipt = Receipt {
        schema_version: 1,
        submission_id: submission.id.to_ascii_lowercase(),
        status: submission.status.unwrap_or(Status::Unavailable),
        context,
    };
    // Only allowlisted fields reach this serialization; provider messages and
    // account/configuration fields from the input are deliberately discarded.
    let Ok(json) = serde_json::to_string(&receipt) else {
        return (None, Err(invalid()));
    };
    let result = if !command_succeeded {
        Err("Apple notarization (a timeout may leave a pending Apple submission) failed; no release archive was prepared".to_owned())
    } else if !accepted {
        Err("Apple notarization was not Accepted; release preparation stopped".to_owned())
    } else {
        Ok(())
    };
    (Some(format!("{PREFIX}{json}")), result)
}

#[cfg(test)]
#[path = "notary_receipt/tests.rs"]
mod tests;
