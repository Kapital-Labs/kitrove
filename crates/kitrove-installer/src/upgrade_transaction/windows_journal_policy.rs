use super::windows_recovery_plan::{JournalStage, Layout};
use crate::{InstallerStageError, NativeFileIdentity};

pub(super) const MAX_RECORD_BYTES: usize = 2048;
pub(super) const PHASES: [JournalStage; 6] = [
    JournalStage::PriorRetained,
    JournalStage::Published,
    JournalStage::Verified,
    JournalStage::Committed,
    JournalStage::RestoreRequested,
    JournalStage::RolledBack,
];

#[derive(Clone, Copy)]
pub(crate) struct Binding {
    preparation: [u8; 32],
    candidate: NativeFileIdentity,
    prior: NativeFileIdentity,
}

impl Binding {
    pub(crate) fn new(
        preparation: [u8; 32],
        candidate: NativeFileIdentity,
        prior: NativeFileIdentity,
    ) -> Result<Self, InstallerStageError> {
        if candidate == prior
            || [candidate, prior]
                .iter()
                .any(|id| !id.is_valid() || !id.matches_target("x86_64-pc-windows-msvc"))
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(Self {
            preparation,
            candidate,
            prior,
        })
    }

    pub(super) fn bytes(self, phase: JournalStage) -> Result<Vec<u8>, InstallerStageError> {
        #[derive(serde::Serialize)]
        struct Record {
            schema: u32,
            protocol: &'static str,
            phase: &'static str,
            preparation_sha256: String,
            candidate_identity: NativeFileIdentity,
            prior_identity: NativeFileIdentity,
        }
        let bytes = serde_json::to_vec(&Record {
            schema: 1,
            protocol: "windows_two_move",
            phase: tag(phase)?,
            preparation_sha256: crate::record::encode_hex(&self.preparation),
            candidate_identity: self.candidate,
            prior_identity: self.prior,
        })
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(bytes)
    }
}

pub(super) fn tag(phase: JournalStage) -> Result<&'static str, InstallerStageError> {
    Ok(match phase {
        JournalStage::Prepared => return Err(InstallerStageError::RecoveryRequired),
        JournalStage::PriorRetained => "prior-retained",
        JournalStage::Published => "published",
        JournalStage::Verified => "verified",
        JournalStage::Committed => "committed",
        JournalStage::RestoreRequested => "restore-requested",
        JournalStage::RolledBack => "rolled-back",
    })
}

pub(super) fn name(phase: JournalStage, pending: bool) -> Result<String, InstallerStageError> {
    Ok(format!(
        "windows-upgrade-{}.{}",
        tag(phase)?,
        if pending { "pending" } else { "json" }
    ))
}

/// Shape only: current filesystem layout and fresh release evidence remain required.
pub(super) fn validate_history(
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<(), InstallerStageError> {
    use JournalStage::*;
    for phases in [complete, pending] {
        if phases.len() > PHASES.len()
            || phases
                .iter()
                .enumerate()
                .any(|(i, phase)| *phase == Prepared || phases[..i].contains(phase))
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
    }
    if complete.iter().any(|phase| pending.contains(phase)) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let mut prefix = 0;
    for phase in &PHASES[..4] {
        if complete.contains(phase) {
            prefix += 1;
        } else {
            break;
        }
    }
    if PHASES[prefix..4]
        .iter()
        .any(|phase| complete.contains(phase))
        || PHASES[..4]
            .iter()
            .enumerate()
            .any(|(i, phase)| pending.contains(phase) && i != prefix)
        || ((complete.contains(&RolledBack) || pending.contains(&RolledBack))
            && !complete.contains(&RestoreRequested))
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(())
}

pub(super) fn stage(
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<JournalStage, InstallerStageError> {
    validate_history(complete, pending)?;
    // An unfinished restoration request must be completed, never ignored to probe forward.
    if pending.contains(&JournalStage::RestoreRequested) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(PHASES
        .iter()
        .rev()
        .copied()
        .find(|phase| complete.contains(phase))
        .unwrap_or(JournalStage::Prepared))
}

/// Recording placement is not execution evidence. Verified/committed records require
/// the contained-probe capability and cannot be written by this boundary.
pub(super) fn require_write(
    layout: Layout,
    complete: &[JournalStage],
    pending: &[JournalStage],
    phase: JournalStage,
) -> Result<(), InstallerStageError> {
    use JournalStage::*;
    validate_history(complete, pending)?;
    if complete.contains(&phase) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let restoring = complete.contains(&RestoreRequested) || pending.contains(&RestoreRequested);
    let allowed = match phase {
        PriorRetained => layout == Layout::Gap && !restoring && complete.is_empty(),
        Published => layout == Layout::Published && !restoring && complete == [PriorRetained],
        RestoreRequested => {
            matches!(layout, Layout::Gap | Layout::Published)
                && !complete.contains(&RestoreRequested)
        }
        RolledBack => layout == Layout::Original && complete.contains(&RestoreRequested),
        Prepared | Verified | Committed => false,
    };
    if !allowed {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let mut proposed = pending.to_vec();
    if !proposed.contains(&phase) {
        proposed.push(phase);
    }
    validate_history(complete, &proposed)
}

/// Reject contradictory physical evidence before exposing a reopened owner. Pending
/// forward records may survive restoration, but cannot stand in for completed intent.
pub(crate) fn require_layout(
    layout: Layout,
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<(), InstallerStageError> {
    use JournalStage::*;
    validate_history(complete, pending)?;
    let restored = complete.contains(&RolledBack) || pending.contains(&RolledBack);
    let restoring = complete.contains(&RestoreRequested);
    let forward = complete
        .iter()
        .copied()
        .filter(|phase| PHASES[..4].contains(phase))
        .collect::<Vec<_>>();
    let forward_pending = pending
        .iter()
        .copied()
        .filter(|phase| PHASES[..4].contains(phase))
        .collect::<Vec<_>>();
    let allowed = match layout {
        Layout::Original => restoring || (complete.is_empty() && pending.is_empty()),
        Layout::Gap => {
            !restored
                && (restoring
                    || (forward.is_empty()
                        && forward_pending.iter().all(|phase| *phase == PriorRetained))
                    || (forward == [PriorRetained] && forward_pending.is_empty()))
        }
        Layout::Published => !restored && !forward.is_empty(),
    };
    if allowed {
        Ok(())
    } else {
        Err(InstallerStageError::RecoveryRequired)
    }
}

pub(crate) fn terminal_layout(
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<Layout, InstallerStageError> {
    use JournalStage::*;
    let layout = if complete.contains(&RolledBack) {
        Layout::Original
    } else if complete.contains(&Committed)
        && !complete.contains(&RestoreRequested)
        && !pending.contains(&RestoreRequested)
    {
        Layout::Published
    } else {
        return Err(InstallerStageError::RecoveryRequired);
    };
    require_layout(layout, complete, pending)?;
    Ok(layout)
}

/// Pending restoration intent must be completed before considering forward history.
pub(super) fn placement_recovery_step(
    layout: Layout,
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<super::windows_recovery_plan::RecoveryStep, InstallerStageError> {
    use super::windows_recovery_plan::{RecoveryStep, next_step_for_layout};
    require_layout(layout, complete, pending)?;
    if pending.contains(&JournalStage::RestoreRequested) {
        return Ok(RecoveryStep::RecordRestorationIntent);
    }
    next_step_for_layout(layout, stage(complete, pending)?)
}

pub(super) fn require_move(
    layout: Layout,
    next: Layout,
    complete: &[JournalStage],
    pending: &[JournalStage],
) -> Result<(), InstallerStageError> {
    use JournalStage::*;
    validate_history(complete, pending)?;
    let restoring = complete.contains(&RestoreRequested) && !complete.contains(&RolledBack);
    let allowed = match (layout, next) {
        (Layout::Original, Layout::Gap) => complete.is_empty() && pending.is_empty(),
        (Layout::Gap, Layout::Published) => complete == [PriorRetained] && pending.is_empty(),
        (Layout::Published, Layout::Gap) | (Layout::Gap, Layout::Original) => {
            restoring && !pending.contains(&RestoreRequested) && !pending.contains(&RolledBack)
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(InstallerStageError::RecoveryRequired)
    }
}

/// Only the owning fresh-probe boundary may invoke this grammar for a write.
pub(super) fn require_probe_write(
    layout: Layout,
    complete: &[JournalStage],
    pending: &[JournalStage],
    phase: JournalStage,
) -> Result<(), InstallerStageError> {
    use JournalStage::*;
    require_layout(layout, complete, pending)?;
    let prefix: &[JournalStage] = match phase {
        Verified => &[PriorRetained, Published],
        Committed => &[PriorRetained, Published, Verified],
        _ => return Err(InstallerStageError::RecoveryRequired),
    };
    if layout != Layout::Published
        || complete != prefix
        || pending.iter().any(|item| *item != phase)
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_history_never_hides_pending_restoration_or_incomplete_rollback() {
        use JournalStage::*;
        let committed = [PriorRetained, Published, Verified, Committed];
        assert_eq!(terminal_layout(&committed, &[]).unwrap(), Layout::Published);
        assert!(terminal_layout(&committed, &[RestoreRequested]).is_err());
        assert!(terminal_layout(&[PriorRetained, Published, RestoreRequested], &[]).is_err());
        assert!(terminal_layout(&[RestoreRequested], &[RolledBack]).is_err());
        assert!(terminal_layout(&[RolledBack], &[]).is_err());
        assert_eq!(
            terminal_layout(&[RestoreRequested, RolledBack], &[PriorRetained]).unwrap(),
            Layout::Original
        );
        assert!(terminal_layout(&[], &[]).is_err());
    }

    #[test]
    fn probe_write_requires_exact_forward_prefix_without_restoration() {
        use JournalStage::*;
        for (phase, complete) in [
            (Verified, vec![PriorRetained, Published]),
            (Committed, vec![PriorRetained, Published, Verified]),
        ] {
            require_probe_write(Layout::Published, &complete, &[], phase).unwrap();
            require_probe_write(Layout::Published, &complete, &[phase], phase).unwrap();
            for layout in [Layout::Original, Layout::Gap] {
                assert!(require_probe_write(layout, &complete, &[], phase).is_err());
            }
            assert!(
                require_probe_write(Layout::Published, &complete, &[RestoreRequested], phase)
                    .is_err()
            );
            let mut restoring = complete.clone();
            restoring.push(RestoreRequested);
            assert!(require_probe_write(Layout::Published, &restoring, &[], phase).is_err());
            assert!(require_write(Layout::Published, &complete, &[], phase).is_err());
        }
        for phase in [
            Prepared,
            PriorRetained,
            Published,
            RestoreRequested,
            RolledBack,
        ] {
            assert!(
                require_probe_write(Layout::Published, &[PriorRetained, Published], &[], phase)
                    .is_err()
            );
        }
        assert!(require_probe_write(Layout::Published, &[PriorRetained], &[], Verified).is_err());
    }

    #[test]
    fn placement_recovery_is_closed_and_restoration_intent_always_wins() {
        use super::super::windows_recovery_plan::RecoveryStep;
        for complete_mask in 0..64 {
            for pending_mask in 0..64 {
                let select = |mask: usize| {
                    PHASES
                        .iter()
                        .enumerate()
                        .filter_map(|(i, phase)| (mask & (1 << i) != 0).then_some(*phase))
                        .collect::<Vec<_>>()
                };
                let complete = select(complete_mask);
                let pending = select(pending_mask);
                for layout in [Layout::Original, Layout::Gap, Layout::Published] {
                    let result = placement_recovery_step(layout, &complete, &pending);
                    assert_eq!(
                        result.is_ok(),
                        require_layout(layout, &complete, &pending).is_ok()
                    );
                    if let Ok(step) = result {
                        if pending.contains(&JournalStage::RestoreRequested) {
                            assert_eq!(step, RecoveryStep::RecordRestorationIntent);
                        } else if complete.contains(&JournalStage::RestoreRequested) {
                            assert!(matches!(
                                step,
                                RecoveryStep::WithdrawCandidate
                                    | RecoveryStep::RestorePrior
                                    | RecoveryStep::CompleteRestoration
                                    | RecoveryStep::Restored
                            ));
                        }
                        if layout == Layout::Gap {
                            assert!(matches!(
                                step,
                                RecoveryStep::RecordRestorationIntent | RecoveryStep::RestorePrior
                            ));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn recovery_layout_rejects_contradictory_phase_and_pending_evidence() {
        use JournalStage::*;
        require_layout(Layout::Original, &[], &[]).unwrap();
        for pending in [
            vec![],
            vec![PriorRetained],
            vec![RestoreRequested],
            vec![PriorRetained, RestoreRequested],
        ] {
            require_layout(Layout::Gap, &[], &pending).unwrap();
        }
        require_layout(Layout::Published, &[PriorRetained], &[Published]).unwrap();
        require_layout(
            Layout::Published,
            &[PriorRetained],
            &[Published, RestoreRequested],
        )
        .unwrap();
        require_layout(
            Layout::Gap,
            &[PriorRetained, Published, RestoreRequested],
            &[Verified],
        )
        .unwrap();
        require_layout(
            Layout::Original,
            &[RestoreRequested],
            &[PriorRetained, RolledBack],
        )
        .unwrap();
        for (layout, complete, pending) in [
            (Layout::Original, vec![], vec![PriorRetained]),
            (Layout::Original, vec![], vec![RestoreRequested]),
            (Layout::Original, vec![PriorRetained], vec![]),
            (Layout::Gap, vec![PriorRetained], vec![Published]),
            (
                Layout::Gap,
                vec![PriorRetained, Published],
                vec![RestoreRequested],
            ),
            (Layout::Gap, vec![RestoreRequested], vec![RolledBack]),
            (Layout::Published, vec![], vec![]),
            (Layout::Published, vec![RestoreRequested], vec![]),
            (
                Layout::Published,
                vec![PriorRetained, RestoreRequested, RolledBack],
                vec![],
            ),
        ] {
            assert!(require_layout(layout, &complete, &pending).is_err());
        }
    }

    #[test]
    fn placement_mutation_requires_durable_history_and_never_invents_probe_evidence() {
        use JournalStage::*;
        use Layout::{Gap, Original};
        require_move(Original, Gap, &[], &[]).unwrap();
        assert!(require_move(Original, Gap, &[], &[PriorRetained]).is_err());
        assert!(require_move(Gap, Layout::Published, &[], &[PriorRetained]).is_err());
        require_move(Gap, Layout::Published, &[PriorRetained], &[]).unwrap();
        require_write(Gap, &[], &[PriorRetained], PriorRetained).unwrap();
        require_write(Layout::Published, &[PriorRetained], &[Published], Published).unwrap();
        for length in 0..=4 {
            let forward = &PHASES[..length];
            for pending in [
                Vec::new(),
                if length < 4 {
                    vec![PHASES[length]]
                } else {
                    Vec::new()
                },
            ] {
                for layout in [Gap, Layout::Published] {
                    require_write(layout, forward, &pending, RestoreRequested).unwrap();
                    let mut intent_pending = pending.clone();
                    intent_pending.push(RestoreRequested);
                    require_write(layout, forward, &intent_pending, RestoreRequested).unwrap();
                    assert!(require_move(layout, Original, forward, &intent_pending).is_err());
                    assert!(require_move(layout, Gap, forward, &intent_pending).is_err());
                }
                let mut restoring = forward.to_vec();
                restoring.push(RestoreRequested);
                require_move(Layout::Published, Gap, &restoring, &pending).unwrap();
                require_move(Gap, Original, &restoring, &pending).unwrap();
                require_write(Original, &restoring, &pending, RolledBack).unwrap();
                let mut rollback_pending = pending.clone();
                rollback_pending.push(RolledBack);
                assert!(require_move(Gap, Original, &restoring, &rollback_pending).is_err());
                assert!(
                    require_move(Layout::Published, Gap, &restoring, &rollback_pending).is_err()
                );
                for phase in &PHASES[..4] {
                    for layout in [Original, Gap, Layout::Published] {
                        assert!(require_write(layout, &restoring, &pending, *phase).is_err());
                    }
                }
            }
        }
        for complete_mask in 0..64 {
            for pending_mask in 0..64 {
                let selected = |mask| {
                    PHASES
                        .iter()
                        .enumerate()
                        .filter_map(|(i, phase)| (mask & (1 << i) != 0).then_some(*phase))
                        .collect::<Vec<_>>()
                };
                let complete = selected(complete_mask);
                let pending = selected(pending_mask);
                for layout in [Original, Gap, Layout::Published] {
                    for phase in [Prepared, Verified, Committed] {
                        assert!(require_write(layout, &complete, &pending, phase).is_err());
                    }
                    if validate_history(&complete, &pending).is_err() {
                        for phase in PHASES {
                            assert!(require_write(layout, &complete, &pending, phase).is_err());
                        }
                        for next in [Original, Gap, Layout::Published] {
                            assert!(require_move(layout, next, &complete, &pending).is_err());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn history_rejects_gaps_duplicates_and_restoration_escalation() {
        use JournalStage::*;
        for length in 0..=4 {
            let complete = &PHASES[..length];
            validate_history(complete, &[]).unwrap();
            for phase in PHASES {
                let allowed = (length < 4 && phase == PHASES[length]) || phase == RestoreRequested;
                assert_eq!(validate_history(complete, &[phase]).is_ok(), allowed);
            }
            let mut restored = complete.to_vec();
            restored.push(RestoreRequested);
            validate_history(&restored, &[RolledBack]).unwrap();
            restored.push(RolledBack);
            assert_eq!(stage(&restored, &[]).unwrap(), RolledBack);
        }
        for phases in [
            vec![Prepared],
            vec![Published],
            vec![PriorRetained, PriorRetained],
            vec![Verified, Committed],
            vec![RolledBack],
        ] {
            assert!(validate_history(&phases, &[]).is_err());
        }
        assert!(stage(&[PriorRetained, Published], &[RestoreRequested]).is_err());
        assert!(validate_history(&[PriorRetained], &[PriorRetained]).is_err());
    }

    #[test]
    fn canonical_records_bind_every_authority_field_and_closed_phase() {
        fn id(byte: u8) -> NativeFileIdentity {
            let file_id = [byte; 16];
            serde_json::from_value(
                serde_json::json!({"platform":"windows","filesystem_id":7,"file_id":file_id}),
            )
            .unwrap()
        }
        let binding = Binding::new([3; 32], id(1), id(2)).unwrap();
        assert!(Binding::new([3; 32], id(1), id(1)).is_err());
        assert!(binding.bytes(JournalStage::Prepared).is_err());
        for phase in PHASES {
            let bytes = binding.bytes(phase).unwrap();
            assert!(bytes.len() <= MAX_RECORD_BYTES);
            assert_eq!(bytes, binding.bytes(phase).unwrap());
            for changed in [
                Binding::new([4; 32], id(1), id(2)).unwrap(),
                Binding::new([3; 32], id(4), id(2)).unwrap(),
                Binding::new([3; 32], id(1), id(4)).unwrap(),
            ] {
                assert_ne!(bytes, changed.bytes(phase).unwrap());
            }
            for other in PHASES {
                if other != phase {
                    assert_ne!(bytes, binding.bytes(other).unwrap());
                }
            }
            assert_ne!(name(phase, true).unwrap(), name(phase, false).unwrap());
        }
    }
}
