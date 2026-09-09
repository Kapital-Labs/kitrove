use std::path::Path;

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocalRootHookMeter,
    LocatorDecision, NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile,
    PortablePolicyDecision, ReceiptAnchor, RelatedRoot, RootContext, RootHookMeter, RootHookReport,
    RootTier, ScanFinding, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{
    CapturedSkillSource, SkillSourceLayout, is_direct_child_source_path as is_direct_child,
    is_standard_skill_description as valid_standard_description,
    is_standard_skill_name as valid_standard_name,
};
use kitrove_model::{AssetId, FidelityReason, HarnessId};

use crate::roots::{
    ADDITIONAL_EVIDENCE, PRECEDENCE_EVIDENCE, PROFILE_EVIDENCE, agent_roots, command_roots,
    is_additional_root, is_plugin_root, nested_qualifier, standard_receipt_anchors, standard_roots,
    unusual_roots,
};

/// Read-only Claude Code Agent Skills observation policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeObservationPolicy;

impl ClaudeObservationPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HarnessObservationPolicy for ClaudeObservationPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn runtime_authority(&self) -> kitrove_adapter_api::PolicyRuntimeAuthority {
        crate::roots::runtime_authority()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            VersionObservationOwned::from(version),
            evidence(PROFILE_EVIDENCE),
        )
    }

    fn roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        standard_roots(context)
    }

    fn discover_unusual_roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        let mut meter = LocalRootHookMeter::new(context.limits);
        Ok(unusual_roots(
            context,
            matches!(profile.version(), VersionObservationOwned::Unknown),
            &mut meter,
        ))
    }

    fn discover_unusual_roots_bounded(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
        meter: &mut dyn RootHookMeter,
    ) -> AdapterResult<RootHookReport> {
        Ok(unusual_roots(
            context,
            matches!(profile.version(), VersionObservationOwned::Unknown),
            meter,
        ))
    }

    fn related_roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        let mut roots = command_roots(context);
        roots.extend(agent_roots(context));
        Ok(roots)
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory if is_direct_child(&locator.source_relative_path) => {
                LocatorDecision::Capture
            }
            SkillSourceLayout::Directory => LocatorDecision::Ignore,
            SkillSourceLayout::Standalone
                if is_direct_child(&locator.source_relative_path)
                    && locator.original_document_name.ends_with(".md") =>
            {
                LocatorDecision::Unsupported {
                    finding: ScanFinding::new(
                        "scan.layout_unsupported",
                        FindingSeverity::Attention,
                        FindingSubject::Root(root.logical_id.clone()),
                        vec![root.evidence.clone()],
                        "place Claude skills in directory packages containing SKILL.md",
                    ),
                }
            }
            SkillSourceLayout::Standalone => LocatorDecision::Ignore,
        }
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        let directory_id = Path::new(&locator.source_relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&locator.source_relative_path);
        let Some(native_id) = native_id(directory_id, root) else {
            return Ok(CandidateDecision::new(
                NativeAcceptance::Rejected,
                None,
                PortablePolicyDecision::Unavailable {
                    reasons: vec![FidelityReason::new(
                        "claude.plugin_namespace_unavailable",
                        "the plugin root does not provide an exact safe UTF-8 namespace",
                    )],
                },
                vec![candidate_finding(
                    root,
                    "claude.plugin_namespace_unavailable",
                    "supply the plugin skills root beneath its exact UTF-8 namespace directory",
                )],
            )
            .expect("the rejected Claude plugin namespace decision is valid"));
        };
        if native_id.is_empty() || native_id.len() > 256 || native_id.chars().any(char::is_control)
        {
            return Ok(CandidateDecision::new(
                NativeAcceptance::Rejected,
                None,
                PortablePolicyDecision::Unavailable {
                    reasons: vec![FidelityReason::new(
                        "claude.native_id_unavailable",
                        "the directory or qualified nested path is not a bounded Claude identity",
                    )],
                },
                vec![candidate_finding(
                    root,
                    "claude.native_id_unavailable",
                    "shorten or rename the Claude skill directory",
                )],
            )
            .expect("the rejected Claude identity decision is valid"));
        }

        let mut reasons = Vec::new();
        if candidate
            .document
            .declared_name
            .as_deref()
            .is_some_and(|declared| declared != directory_id)
        {
            reasons.push(FidelityReason::new(
                "claude.display_name_differs",
                "Claude uses the directory identity while the declared name remains a display label",
            ));
        }

        let portable_name = valid_standard_name(directory_id).then(|| {
            AssetId::parse(directory_id.to_owned()).expect("validated name is an asset ID")
        });
        let description = candidate
            .document
            .description
            .as_deref()
            .filter(|description| valid_standard_description(description))
            .map(str::to_owned)
            .or_else(|| {
                first_markdown_paragraph(&candidate.document.body)
                    .filter(|description| valid_standard_description(description))
                    .map(|description| {
                        reasons.push(FidelityReason::new(
                            "claude.description_first_paragraph",
                            "the portable description uses Claude's unmodified first-paragraph fallback",
                        ));
                        description.to_owned()
                    })
            });

        let portable = match (portable_name, description) {
            (Some(name), Some(description)) => PortablePolicyDecision::Project {
                name,
                description,
                reasons,
            },
            (name, description) => {
                if name.is_none() {
                    reasons.push(FidelityReason::new(
                        "claude.portable_name_unavailable",
                        "the Claude directory identity is not a standard Agent Skills name",
                    ));
                }
                if description.is_none() {
                    reasons.push(FidelityReason::new(
                        "claude.portable_description_unavailable",
                        "neither an authored description nor the unmodified first Markdown paragraph is standard-valid",
                    ));
                }
                PortablePolicyDecision::Unavailable { reasons }
            }
        };
        let findings = matches!(portable, PortablePolicyDecision::Unavailable { .. })
            .then(|| {
                candidate_finding(
                    root,
                    "claude.portable_projection_unavailable",
                    "add a standard-valid directory name and authored description",
                )
            })
            .into_iter()
            .collect();

        Ok(CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(native_id),
            portable,
            findings,
        )
        .expect("compiled Claude candidate decisions satisfy adapter invariants"))
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        if group.len() < 2 {
            return Ok(DuplicateDecision::Coexist);
        }
        if group
            .iter()
            .any(|candidate| is_additional_root(&candidate.logical_root))
        {
            return Ok(ambiguous_duplicate(ADDITIONAL_EVIDENCE));
        }
        if group
            .iter()
            .any(|candidate| is_plugin_root(&candidate.logical_root))
        {
            return Ok(ambiguous_duplicate("claude.docs.skills.plugin"));
        }

        let best_precedence = group
            .iter()
            .map(|candidate| precedence(candidate.root_tier))
            .min()
            .expect("a duplicate group is non-empty");
        let mut winners = group
            .iter()
            .filter(|candidate| precedence(candidate.root_tier) == best_precedence);
        let winner = winners.next().expect("the minimum precedence has a member");
        if winners.next().is_some() || best_precedence == u8::MAX {
            return Ok(ambiguous_duplicate(PRECEDENCE_EVIDENCE));
        }
        Ok(DuplicateDecision::Winner {
            observation_id: winner.observation_id.clone(),
            reason: evidence(PRECEDENCE_EVIDENCE),
        })
    }

    fn receipt_anchors(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(standard_receipt_anchors(context))
    }
}

fn native_id(directory_id: &str, root: &ObservedRoot) -> Option<String> {
    if let Some(qualifier) = nested_qualifier(&root.logical_id) {
        return Some(format!("{qualifier}/{directory_id}"));
    }
    if is_plugin_root(&root.logical_id) {
        let namespace = plugin_namespace(&root.path)?;
        return Some(format!("{namespace}:{directory_id}"));
    }
    Some(directory_id.to_owned())
}

fn plugin_namespace(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let namespace = if name == "skills" {
        path.parent()?.file_name()?.to_str()
    } else {
        Some(name)
    }?;
    (!namespace.is_empty() && !namespace.chars().any(char::is_control)).then_some(namespace)
}

fn first_markdown_paragraph(body: &str) -> Option<&str> {
    let mut paragraph_start = None;
    let mut paragraph_end = 0_usize;
    let mut line_start = 0_usize;
    for line in body.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.trim().is_empty() {
            if let Some(start) = paragraph_start {
                let block = body.get(start..paragraph_end)?;
                if is_markdown_paragraph(block) {
                    return Some(block);
                }
                paragraph_start = None;
            }
        } else {
            if paragraph_start.is_none() {
                paragraph_start = Some(line_start);
            }
            paragraph_end = line_start.saturating_add(content.len());
        }
        line_start = line_start.saturating_add(line.len());
    }
    paragraph_start
        .and_then(|start| body.get(start..paragraph_end))
        .filter(|block| is_markdown_paragraph(block))
}

fn is_markdown_paragraph(block: &str) -> bool {
    let mut lines = block.lines().map(|line| line.trim_end_matches('\r'));
    let Some(first) = lines.next() else {
        return false;
    };
    let trimmed = first.trim_start();
    if indentation_columns(first) >= 4
        || trimmed.starts_with(['#', '>', '|'])
        || trimmed.starts_with("```")
        || trimmed.starts_with("~~~")
        || unordered_list_marker(trimmed)
        || thematic_break(trimmed)
        || ordered_list_marker(trimmed)
        || html_block_start(trimmed)
        || link_reference_definition(trimmed)
    {
        return false;
    }
    !lines.next().is_some_and(|second| {
        let underline = second.trim();
        (underline.len() >= 3
            && (underline.bytes().all(|byte| byte == b'=')
                || underline.bytes().all(|byte| byte == b'-')))
            || table_delimiter(underline)
    })
}

fn indentation_columns(line: &str) -> usize {
    line.chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .fold(0_usize, |column, character| match character {
            '\t' => column.saturating_add(4 - (column % 4)),
            _ => column.saturating_add(1),
        })
}

fn thematic_break(line: &str) -> bool {
    let line = line.trim();
    let Some(marker) = line
        .chars()
        .find(|character| !matches!(character, ' ' | '\t'))
    else {
        return false;
    };
    if !matches!(marker, '*' | '-' | '_') {
        return false;
    }
    let mut count = 0_usize;
    for character in line.chars() {
        if character == marker {
            count = count.saturating_add(1);
        } else if !matches!(character, ' ' | '\t') {
            return false;
        }
    }
    count >= 3
}

fn html_block_start(line: &str) -> bool {
    if line.starts_with("<!--")
        || line.starts_with("<?")
        || line.starts_with("<![CDATA[")
        || line
            .strip_prefix("<!")
            .and_then(|rest| rest.chars().next())
            .is_some_and(|character| character.is_ascii_uppercase())
    {
        return true;
    }
    let Some((tag, tag_tail)) = line
        .strip_prefix('<')
        .and_then(|rest| rest.strip_prefix('/').or(Some(rest)))
        .and_then(|rest| {
            let length = rest
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                .count();
            (length > 0).then(|| (&rest[..length], &rest[length..]))
        })
    else {
        return false;
    };
    const BLOCK_TAGS: &str = "address article aside base basefont blockquote body caption center col \
        colgroup dd details dialog dir div dl dt fieldset figcaption figure footer form frame \
        frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link main menu menuitem nav \
        noframes ol optgroup option p param pre script search section style summary table tbody td \
        textarea tfoot th thead title tr track ul";
    BLOCK_TAGS
        .split_ascii_whitespace()
        .any(|block_tag| tag.eq_ignore_ascii_case(block_tag))
        || tag_tail.chars().next().is_some_and(|character| {
            character.is_ascii_whitespace() || matches!(character, '/' | '>')
        }) && tag_tail
            .find('>')
            .is_some_and(|closing| tag_tail[closing.saturating_add(1)..].trim().is_empty())
}

fn link_reference_definition(line: &str) -> bool {
    line.strip_prefix('[')
        .and_then(|rest| rest.find("]:"))
        .is_some_and(|closing| closing > 0)
}

fn table_delimiter(line: &str) -> bool {
    let line = line.trim_matches('|');
    line.contains('|')
        && line.split('|').all(|cell| {
            let cell = cell.trim().trim_matches(':');
            cell.len() >= 3 && cell.bytes().all(|byte| byte == b'-')
        })
}

fn unordered_list_marker(line: &str) -> bool {
    line.as_bytes().first().is_some_and(|marker| {
        matches!(marker, b'-' | b'*' | b'+')
            && line
                .as_bytes()
                .get(1)
                .is_none_or(|next| next.is_ascii_whitespace())
    })
}

fn ordered_list_marker(line: &str) -> bool {
    let digit_count = line.bytes().take_while(u8::is_ascii_digit).count();
    (1..=9).contains(&digit_count)
        && line
            .as_bytes()
            .get(digit_count)
            .is_some_and(|marker| matches!(marker, b'.' | b')'))
        && line
            .as_bytes()
            .get(digit_count.saturating_add(1))
            .is_none_or(u8::is_ascii_whitespace)
}

fn precedence(tier: RootTier) -> u8 {
    match tier {
        RootTier::Admin => 0,
        RootTier::User => 1,
        RootTier::Project => 2,
        RootTier::System => 3,
        RootTier::Compatibility | RootTier::Explicit => u8::MAX,
    }
}

fn ambiguous_duplicate(evidence_ref: &str) -> DuplicateDecision {
    DuplicateDecision::Ambiguous {
        reason: ScanFinding::new(
            "scan.duplicate_ambiguous",
            FindingSeverity::Attention,
            FindingSubject::Harness(HarnessId::Claude),
            vec![evidence(evidence_ref)],
            "choose a unique Claude native identity or select a source explicitly",
        ),
    }
}

fn candidate_finding(root: &ObservedRoot, code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        vec![root.evidence.clone()],
        action,
    )
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Claude evidence references are valid")
}
