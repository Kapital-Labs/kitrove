use kitrove_adapter_api::{RootId, RootTier};
use kitrove_model::{ContentHash, HarnessId, HarnessScope};

/// Complete compiled origin and exact source identity for one whole-file observation.
pub(crate) struct WholeFileObservationIdentity<'a> {
    pub domain: &'a [u8],
    pub harness: &'a HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: &'a RootId,
    pub policy_rank: u32,
    pub source_document: &'a str,
    pub exact_hash: &'a ContentHash,
    pub dialect_tag: u8,
}

impl WholeFileObservationIdentity<'_> {
    /// Hashes every authority-bearing field in one stable length-prefixed record.
    pub fn digest(self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.domain);
        for value in [
            self.harness.as_str(),
            self.scope.as_str(),
            self.root_tier.as_str(),
            self.logical_root.as_str(),
            self.source_document,
            self.exact_hash.as_str(),
        ] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update(&self.policy_rank.to_be_bytes());
        hasher.update(&[self.dialect_tag]);
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid content hash")
    }
}
