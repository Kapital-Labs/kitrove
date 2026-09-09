#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// A YAML value retained from an observed skill document within parser limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundedYamlValue {
    Null,
    Boolean(bool),
    Number(String),
    String(String),
    Sequence(Vec<Self>),
    Mapping(BTreeMap<String, Self>),
}

/// A loss-aware view of a skill document before portable-policy validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedSkillDocument {
    pub frontmatter: BTreeMap<String, BoundedYamlValue>,
    pub declared_name: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub compatibility: Option<String>,
    pub metadata: Option<BTreeMap<String, String>>,
    pub allowed_tools: Option<String>,
    pub body: String,
    pub native_fields: BTreeSet<String>,
}
