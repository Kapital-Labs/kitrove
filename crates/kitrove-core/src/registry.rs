use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::path::{Component, Path};

use kitrove_adapter_api::{
    AdapterError, AdapterResult, HarnessObservationPolicy, NativeRootKey, PolicyLine,
    PolicyRuntimeAuthority, RootAuthority, RootIdAuthority, RootPathAuthority, VersionObservation,
};
use kitrove_model::HarnessId;

/// Enumerable claims owned by one compiled observation policy.
///
/// Catalog metadata is supplied by the composition root so the harness-neutral core can reject
/// collisions without importing concrete adapter crates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyCatalog {
    policy_lines: Vec<PolicyLine>,
    native_root_keys: Vec<NativeRootKey>,
}

impl PolicyCatalog {
    #[must_use]
    pub fn new(policy_lines: Vec<PolicyLine>, native_root_keys: Vec<NativeRootKey>) -> Self {
        Self {
            policy_lines,
            native_root_keys,
        }
    }
}

/// One owned policy and the catalog claims validated with it.
pub struct PolicyRegistration {
    policy: Box<dyn HarnessObservationPolicy>,
    catalog: PolicyCatalog,
    runtime_authority: PolicyRuntimeAuthority,
}

impl PolicyRegistration {
    #[must_use]
    pub fn new(policy: Box<dyn HarnessObservationPolicy>, catalog: PolicyCatalog) -> Self {
        let runtime_authority = policy.runtime_authority();
        Self {
            policy,
            catalog,
            runtime_authority,
        }
    }
}

/// An ordered, validated collection of compiled observation policies.
pub struct PolicyRegistry {
    registrations: Vec<PolicyRegistration>,
    harness_ids: Vec<HarnessId>,
}

impl PolicyRegistry {
    /// Creates a registry for policies whose only exposed line is their unknown-version profile.
    ///
    /// Composition roots with native-root descriptors or more than one policy line use
    /// [`Self::new_catalogued`] so every compiled claim participates in collision validation.
    pub fn new(policies: Vec<Box<dyn HarnessObservationPolicy>>) -> AdapterResult<Self> {
        let registrations = policies
            .into_iter()
            .map(|policy| {
                let profile = policy.profile(VersionObservation::Unknown)?;
                Ok(PolicyRegistration::new(
                    policy,
                    PolicyCatalog::new(vec![profile.line()], vec![]),
                ))
            })
            .collect::<AdapterResult<Vec<_>>>()?;
        Self::new_catalogued(registrations)
    }

    /// Creates a registry and rejects every duplicate or internally inconsistent catalog claim.
    pub fn new_catalogued(registrations: Vec<PolicyRegistration>) -> AdapterResult<Self> {
        if registrations.is_empty() {
            return Err(AdapterError::new(
                "scan.registry_empty",
                "the compiled scan registry must contain at least one observation policy",
            ));
        }

        let mut harnesses = BTreeSet::new();
        let mut policy_lines = BTreeSet::new();
        let mut native_root_keys = BTreeSet::new();
        let mut harness_ids = Vec::with_capacity(registrations.len());

        for registration in &registrations {
            let harness = registration.policy.harness();
            if !harnesses.insert(harness.clone()) {
                return Err(AdapterError::new(
                    "scan.registry_duplicate_harness",
                    "the compiled scan registry contains a duplicate harness",
                ));
            }
            harness_ids.push(harness);

            for line in &registration.catalog.policy_lines {
                if !policy_lines.insert(*line) {
                    return Err(AdapterError::new(
                        "scan.registry_policy_line_catalog_conflict",
                        "compiled policies claim the same version-policy line",
                    ));
                }
            }
            for key in &registration.catalog.native_root_keys {
                if !native_root_keys.insert(key.clone()) {
                    return Err(AdapterError::new(
                        "scan.registry_native_root_catalog_conflict",
                        "compiled policies claim the same native-root descriptor key",
                    ));
                }
            }
        }

        for registration in &registrations {
            let harness = registration.policy.harness();
            validate_runtime_authority(&harness, &registration.runtime_authority)?;
            let Ok(profile) = registration.policy.profile(VersionObservation::Unknown) else {
                return Err(AdapterError::new(
                    "scan.registry_policy_line_catalog_invalid",
                    "a compiled policy must provide its unknown-version profile",
                ));
            };
            if profile.harness() != &harness
                || profile.line().harness() != harness
                || registration.catalog.policy_lines.is_empty()
                || !registration.catalog.policy_lines.contains(&profile.line())
                || registration
                    .catalog
                    .policy_lines
                    .iter()
                    .any(|line| line.harness() != harness)
            {
                return Err(AdapterError::new(
                    "scan.registry_policy_line_catalog_invalid",
                    "a compiled policy catalog must contain its matching unknown-version profile line and only lines for its harness",
                ));
            }
            if runtime_native_keys(&registration.runtime_authority)
                .iter()
                .any(|key| !registration.catalog.native_root_keys.contains(key))
            {
                return Err(AdapterError::new(
                    "scan.registry_runtime_authority_invalid",
                    "runtime native-root authority must be declared in the compiled policy catalog",
                ));
            }
        }

        Ok(Self {
            registrations,
            harness_ids,
        })
    }

    /// Returns harness IDs in the stable caller-supplied registry order.
    #[must_use]
    pub fn harness_ids(&self) -> Vec<HarnessId> {
        self.harness_ids.clone()
    }

    /// Borrows the validated policies in stable registry order.
    #[must_use]
    pub fn policies(&self) -> Vec<&dyn HarnessObservationPolicy> {
        self.registrations
            .iter()
            .map(|registration| registration.policy.as_ref())
            .collect()
    }

    /// Returns the retained, enumerable runtime authority catalog for one harness.
    #[must_use]
    pub fn runtime_authority(&self, harness: &HarnessId) -> Option<&PolicyRuntimeAuthority> {
        self.registrations
            .iter()
            .find(|registration| registration.policy.harness() == *harness)
            .map(|registration| &registration.runtime_authority)
    }

    pub(crate) fn runtime_policies(
        &self,
    ) -> Vec<(&dyn HarnessObservationPolicy, &PolicyRuntimeAuthority)> {
        self.registrations
            .iter()
            .map(|registration| {
                (
                    registration.policy.as_ref(),
                    &registration.runtime_authority,
                )
            })
            .collect()
    }
}

pub(crate) fn validate_runtime_authority(
    harness: &HarnessId,
    authority: &PolicyRuntimeAuthority,
) -> AdapterResult<()> {
    for root in &authority.roots {
        if !valid_root_authority(root, harness, true) {
            return Err(AdapterError::new(
                "scan.runtime_authority_invalid",
                "runtime candidate-root authority contains an invalid closed claim",
            ));
        }
    }
    for related in &authority.related_roots {
        if !valid_root_authority(&related.root, harness, false) {
            return Err(AdapterError::new(
                "scan.runtime_authority_invalid",
                "runtime related-root authority contains an invalid closed claim",
            ));
        }
    }
    for receipt in &authority.receipt_anchors {
        if matches!(receipt.path, RootPathAuthority::ExplicitFileRequest)
            || !valid_path_authority(&receipt.path)
        {
            return Err(AdapterError::new(
                "scan.runtime_authority_invalid",
                "runtime receipt authority contains an invalid closed path claim",
            ));
        }
    }
    Ok(())
}

fn valid_root_authority(root: &RootAuthority, harness: &HarnessId, candidate: bool) -> bool {
    let id_valid = match &root.logical_id {
        RootIdAuthority::Exact(_) => true,
        RootIdAuthority::Prefix(prefix)
        | RootIdAuthority::IndexedPrefix(prefix)
        | RootIdAuthority::IndexedPrefixWithEncodedFile(prefix) => !prefix.is_empty(),
        RootIdAuthority::IndexedPrefixWithSuffixes { prefix, suffixes } => {
            !prefix.is_empty()
                && !suffixes.is_empty()
                && suffixes.iter().all(|item| !item.is_empty())
        }
    };
    let layouts_valid = if candidate {
        !root.layouts.is_empty()
            && root
                .layouts
                .iter()
                .all(|(line, layouts)| line.harness() == *harness && !layouts.is_empty())
    } else {
        root.layouts.is_empty()
    };
    let request_item_pair = matches!(
        (&root.path, &root.logical_id),
        (
            RootPathAuthority::ExplicitFileRequest,
            RootIdAuthority::IndexedPrefixWithEncodedFile(_)
        )
    );
    let has_no_request_item_authority =
        !matches!(&root.path, RootPathAuthority::ExplicitFileRequest)
            && !matches!(
                &root.logical_id,
                RootIdAuthority::IndexedPrefixWithEncodedFile(_)
            );
    let request_item_valid = if candidate {
        request_item_pair || has_no_request_item_authority
    } else {
        has_no_request_item_authority
    };
    id_valid
        && request_item_valid
        && !root.scopes.is_empty()
        && layouts_valid
        && valid_path_authority(&root.path)
}

fn valid_path_authority(path: &RootPathAuthority) -> bool {
    match path {
        RootPathAuthority::Exact(path) => !path.as_os_str().is_empty(),
        RootPathAuthority::HomeRelative(path)
        | RootPathAuthority::WorkingRelative(path)
        | RootPathAuthority::ProjectAncestorRelative { relative: path, .. }
        | RootPathAuthority::WorkingDescendant { suffix: path, .. } => valid_relative(path),
        RootPathAuthority::SuppliedNative(_)
        | RootPathAuthority::ExplicitDirectory
        | RootPathAuthority::ExplicitFileRequest => true,
    }
}

fn valid_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn runtime_native_keys(authority: &PolicyRuntimeAuthority) -> BTreeSet<NativeRootKey> {
    authority
        .roots
        .iter()
        .chain(authority.related_roots.iter().map(|related| &related.root))
        .filter_map(|root| match &root.path {
            RootPathAuthority::SuppliedNative(key) => Some(key.clone()),
            _ => None,
        })
        .collect()
}

impl Debug for PolicyRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyRegistry")
            .field("harness_ids", &self.harness_ids)
            .finish_non_exhaustive()
    }
}
