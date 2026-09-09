pub(crate) const WORK_PORTION_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuarantineCleanupLimits {
    max_roots: usize,
    max_top_level_entries: usize,
    max_descendant_visits: usize,
    max_depth: usize,
}

impl QuarantineCleanupLimits {
    pub(crate) const fn try_new(
        max_roots: usize,
        max_top_level_entries: usize,
        max_descendant_visits: usize,
        max_depth: usize,
    ) -> Result<Self, QuarantineBudgetError> {
        if max_roots == 0
            || max_top_level_entries == 0
            || max_descendant_visits == 0
            || max_depth == 0
        {
            return Err(QuarantineBudgetError::InvalidLimits);
        }
        Ok(Self {
            max_roots,
            max_top_level_entries,
            max_descendant_visits,
            max_depth,
        })
    }

    const fn work_limit(self) -> TombstoneWork {
        TombstoneWork::new(
            self.max_top_level_entries,
            self.max_descendant_visits,
            self.max_depth,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TombstoneWork {
    top_level_entries: usize,
    descendant_visits: usize,
    max_depth: usize,
}

impl TombstoneWork {
    pub(crate) const fn new(
        top_level_entries: usize,
        descendant_visits: usize,
        max_depth: usize,
    ) -> Self {
        Self {
            top_level_entries,
            descendant_visits,
            max_depth,
        }
    }

    pub(crate) const fn descendant_visits(self) -> usize {
        self.descendant_visits
    }

    pub(crate) const fn top_level_entries(self) -> usize {
        self.top_level_entries
    }

    pub(crate) const fn max_depth(self) -> usize {
        self.max_depth
    }

    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            top_level_entries: self
                .top_level_entries
                .checked_add(other.top_level_entries)?,
            descendant_visits: self
                .descendant_visits
                .checked_add(other.descendant_visits)?,
            max_depth: self.max_depth.max(other.max_depth),
        })
    }

    const fn is_reservation_coherent(self) -> bool {
        if self.descendant_visits == 0 {
            return self.max_depth == 0;
        }
        self.max_depth > 0 && self.max_depth <= self.descendant_visits
    }

    const fn is_charge_coherent(self) -> bool {
        (self.descendant_visits == 0 && self.max_depth == 0)
            || (self.descendant_visits > 0 && self.max_depth > 0)
    }

    pub(crate) const fn fits_within(self, limit: Self) -> bool {
        self.top_level_entries <= limit.top_level_entries
            && self.descendant_visits <= limit.descendant_visits
            && self.max_depth <= limit.max_depth
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanupPassWork {
    inspection: TombstoneWork,
    validation: TombstoneWork,
    deletion: TombstoneWork,
}

impl CleanupPassWork {
    pub(crate) const fn new(
        inspection: TombstoneWork,
        validation: TombstoneWork,
        deletion: TombstoneWork,
    ) -> Self {
        Self {
            inspection,
            validation,
            deletion,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineWorkPortion {
    CleanupInspection,
    CleanupValidation,
    CleanupDeletion,
    Forward,
    Rollback,
}

impl QuarantineWorkPortion {
    const fn index(self) -> usize {
        match self {
            Self::CleanupInspection => 0,
            Self::CleanupValidation => 1,
            Self::CleanupDeletion => 2,
            Self::Forward => 3,
            Self::Rollback => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineBudgetError {
    InvalidLimits,
    InvalidWork,
    ArithmeticOverflow,
    LimitExceeded,
    RootReservationExceeded,
    ReservationExceeded(QuarantineWorkPortion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuarantineCleanupReservation {
    roots: usize,
    work: [TombstoneWork; WORK_PORTION_COUNT],
}

impl QuarantineCleanupReservation {
    pub(crate) fn try_new(
        limits: QuarantineCleanupLimits,
        roots: usize,
        cleanup: CleanupPassWork,
        forward: TombstoneWork,
        rollback: TombstoneWork,
    ) -> Result<Self, QuarantineBudgetError> {
        let mut work = [TombstoneWork::default(); WORK_PORTION_COUNT];
        for (portion, reserved) in [
            (QuarantineWorkPortion::CleanupInspection, cleanup.inspection),
            (QuarantineWorkPortion::CleanupValidation, cleanup.validation),
            (QuarantineWorkPortion::CleanupDeletion, cleanup.deletion),
            (QuarantineWorkPortion::Forward, forward),
            (QuarantineWorkPortion::Rollback, rollback),
        ] {
            work[portion.index()] = reserved;
        }
        if work.iter().any(|work| !work.is_reservation_coherent()) {
            return Err(QuarantineBudgetError::InvalidWork);
        }
        let total = work
            .iter()
            .try_fold(TombstoneWork::default(), |total, work| {
                total.checked_add(*work)
            });
        let total = total.ok_or(QuarantineBudgetError::ArithmeticOverflow)?;
        if roots > limits.max_roots || !total.fits_within(limits.work_limit()) {
            return Err(QuarantineBudgetError::LimitExceeded);
        }
        Ok(Self { roots, work })
    }

    const fn work(self, portion: QuarantineWorkPortion) -> TombstoneWork {
        self.work[portion.index()]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuarantineCleanupBudget {
    reservation: QuarantineCleanupReservation,
    roots: usize,
    consumed: [TombstoneWork; WORK_PORTION_COUNT],
}

impl QuarantineCleanupBudget {
    pub(crate) const fn new(reservation: QuarantineCleanupReservation) -> Self {
        Self {
            reservation,
            roots: 0,
            consumed: [TombstoneWork::new(0, 0, 0); WORK_PORTION_COUNT],
        }
    }

    pub(crate) fn try_root(&mut self) -> Result<(), QuarantineBudgetError> {
        let roots = self
            .roots
            .checked_add(1)
            .ok_or(QuarantineBudgetError::ArithmeticOverflow)?;
        if roots > self.reservation.roots {
            return Err(QuarantineBudgetError::RootReservationExceeded);
        }
        self.roots = roots;
        Ok(())
    }

    pub(crate) const fn remaining_top_level_entries(
        &self,
        portion: QuarantineWorkPortion,
    ) -> usize {
        let reserved = self.reservation.work(portion).top_level_entries;
        reserved - self.consumed[portion.index()].top_level_entries
    }

    pub(crate) const fn remaining_descendant_visits(
        &self,
        portion: QuarantineWorkPortion,
    ) -> usize {
        let reserved = self.reservation.work(portion).descendant_visits;
        reserved - self.consumed[portion.index()].descendant_visits
    }

    #[cfg(test)]
    pub(crate) const fn max_depth(&self, portion: QuarantineWorkPortion) -> usize {
        self.reservation.work(portion).max_depth
    }

    pub(crate) fn try_top_level_entry(
        &mut self,
        portion: QuarantineWorkPortion,
    ) -> Result<(), QuarantineBudgetError> {
        self.try_consume(portion, TombstoneWork::new(1, 0, 0))
    }

    pub(crate) fn try_descendant(
        &mut self,
        portion: QuarantineWorkPortion,
        depth: usize,
    ) -> Result<(), QuarantineBudgetError> {
        self.try_consume(portion, TombstoneWork::new(0, 1, depth))
    }

    pub(crate) fn try_consume(
        &mut self,
        portion: QuarantineWorkPortion,
        work: TombstoneWork,
    ) -> Result<(), QuarantineBudgetError> {
        if !work.is_charge_coherent() {
            return Err(QuarantineBudgetError::InvalidWork);
        }
        let index = portion.index();
        let next = self.consumed[index]
            .checked_add(work)
            .ok_or(QuarantineBudgetError::ArithmeticOverflow)?;
        if !next.fits_within(self.reservation.work(portion)) {
            return Err(QuarantineBudgetError::ReservationExceeded(portion));
        }
        self.consumed[index] = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> QuarantineCleanupLimits {
        QuarantineCleanupLimits::try_new(3, 20, 60, 4).unwrap()
    }

    fn cleanup(
        inspection: TombstoneWork,
        validation: TombstoneWork,
        deletion: TombstoneWork,
    ) -> CleanupPassWork {
        CleanupPassWork::new(inspection, validation, deletion)
    }

    fn reservation(
        roots: usize,
        cleanup: CleanupPassWork,
        forward: TombstoneWork,
        rollback: TombstoneWork,
    ) -> Result<QuarantineCleanupReservation, QuarantineBudgetError> {
        QuarantineCleanupReservation::try_new(limits(), roots, cleanup, forward, rollback)
    }

    #[test]
    fn exact_aggregate_limit_is_accepted() {
        let per_pass = TombstoneWork::new(4, 12, 4);
        let reservation =
            reservation(3, cleanup(per_pass, per_pass, per_pass), per_pass, per_pass).unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);

        for _ in 0..3 {
            budget.try_root().unwrap();
        }
        for portion in [
            QuarantineWorkPortion::CleanupInspection,
            QuarantineWorkPortion::CleanupValidation,
            QuarantineWorkPortion::CleanupDeletion,
            QuarantineWorkPortion::Forward,
            QuarantineWorkPortion::Rollback,
        ] {
            budget.try_consume(portion, per_pass).unwrap();
        }
    }

    #[test]
    fn aggregate_plus_one_is_rejected_before_budget_creation() {
        let per_pass = TombstoneWork::new(4, 12, 4);
        assert_eq!(
            reservation(
                3,
                cleanup(per_pass, per_pass, per_pass),
                per_pass,
                TombstoneWork::new(5, 12, 4),
            ),
            Err(QuarantineBudgetError::LimitExceeded)
        );
        assert_eq!(
            reservation(4, cleanup(per_pass, per_pass, per_pass), per_pass, per_pass,),
            Err(QuarantineBudgetError::LimitExceeded)
        );
    }

    #[test]
    fn checked_reservation_overflow_is_rejected() {
        let enormous = TombstoneWork::new(usize::MAX, usize::MAX, 1);
        assert_eq!(
            reservation(
                1,
                cleanup(
                    enormous,
                    TombstoneWork::new(1, 1, 1),
                    TombstoneWork::default(),
                ),
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            Err(QuarantineBudgetError::ArithmeticOverflow)
        );
    }

    #[test]
    fn zero_limits_are_invalid() {
        assert_eq!(
            QuarantineCleanupLimits::try_new(0, 1, 1, 1),
            Err(QuarantineBudgetError::InvalidLimits)
        );
        assert_eq!(
            QuarantineCleanupLimits::try_new(1, 0, 1, 1),
            Err(QuarantineBudgetError::InvalidLimits)
        );
        assert_eq!(
            QuarantineCleanupLimits::try_new(1, 1, 0, 1),
            Err(QuarantineBudgetError::InvalidLimits)
        );
        assert_eq!(
            QuarantineCleanupLimits::try_new(1, 1, 1, 0),
            Err(QuarantineBudgetError::InvalidLimits)
        );
    }

    #[test]
    fn incoherent_depth_work_is_rejected() {
        for invalid in [
            TombstoneWork::new(1, 0, 1),
            TombstoneWork::new(0, 1, 0),
            TombstoneWork::new(0, 1, 2),
        ] {
            assert_eq!(
                reservation(
                    1,
                    cleanup(invalid, TombstoneWork::default(), TombstoneWork::default()),
                    TombstoneWork::default(),
                    TombstoneWork::default(),
                ),
                Err(QuarantineBudgetError::InvalidWork)
            );
        }
    }

    #[test]
    fn cleanup_passes_and_rollback_cannot_spend_each_others_capacity() {
        let per_pass = TombstoneWork::new(2, 2, 2);
        let reservation =
            reservation(1, cleanup(per_pass, per_pass, per_pass), per_pass, per_pass).unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);

        budget
            .try_consume(QuarantineWorkPortion::CleanupInspection, per_pass)
            .unwrap();
        assert_eq!(
            budget.try_top_level_entry(QuarantineWorkPortion::CleanupInspection),
            Err(QuarantineBudgetError::ReservationExceeded(
                QuarantineWorkPortion::CleanupInspection
            ))
        );
        for portion in [
            QuarantineWorkPortion::CleanupValidation,
            QuarantineWorkPortion::CleanupDeletion,
            QuarantineWorkPortion::Forward,
            QuarantineWorkPortion::Rollback,
        ] {
            budget.try_consume(portion, per_pass).unwrap();
        }
        assert_eq!(
            budget.try_top_level_entry(QuarantineWorkPortion::Forward),
            Err(QuarantineBudgetError::ReservationExceeded(
                QuarantineWorkPortion::Forward
            ))
        );
    }

    #[test]
    fn bounded_traversal_can_query_and_charge_incrementally() {
        let reservation = reservation(
            1,
            cleanup(
                TombstoneWork::new(1, 2, 2),
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            TombstoneWork::default(),
            TombstoneWork::default(),
        )
        .unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);
        let portion = QuarantineWorkPortion::CleanupInspection;

        assert_eq!(budget.remaining_top_level_entries(portion), 1);
        assert_eq!(budget.remaining_descendant_visits(portion), 2);
        assert_eq!(budget.max_depth(portion), 2);
        budget.try_top_level_entry(portion).unwrap();
        budget.try_descendant(portion, 1).unwrap();
        budget.try_descendant(portion, 2).unwrap();
        assert_eq!(budget.remaining_top_level_entries(portion), 0);
        assert_eq!(budget.remaining_descendant_visits(portion), 0);
        assert_eq!(
            budget.try_descendant(portion, 1),
            Err(QuarantineBudgetError::ReservationExceeded(portion))
        );
    }

    #[test]
    fn failed_consumption_is_atomic() {
        let reservation = reservation(
            1,
            cleanup(
                TombstoneWork::new(2, 2, 2),
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            TombstoneWork::default(),
            TombstoneWork::default(),
        )
        .unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);
        let portion = QuarantineWorkPortion::CleanupInspection;

        assert_eq!(
            budget.try_consume(portion, TombstoneWork::new(3, 2, 2)),
            Err(QuarantineBudgetError::ReservationExceeded(portion))
        );
        assert_eq!(budget.remaining_top_level_entries(portion), 2);
        assert_eq!(budget.remaining_descendant_visits(portion), 2);
    }

    #[test]
    fn roots_share_one_transaction_global_counter() {
        let reservation = reservation(
            2,
            cleanup(
                TombstoneWork::default(),
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            TombstoneWork::default(),
            TombstoneWork::default(),
        )
        .unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);

        budget.try_root().unwrap();
        budget.try_root().unwrap();
        assert_eq!(
            budget.try_root(),
            Err(QuarantineBudgetError::RootReservationExceeded)
        );
    }

    #[test]
    fn representative_large_reservation_uses_checked_exact_arithmetic() {
        const ROOTS: usize = 97;
        const TOP_LEVEL_ENTRIES_PER_PASS: usize = 997;
        const DESCENDANTS_PER_TOP_LEVEL_ENTRY: usize = 257;
        const DEPTH: usize = 17;
        let per_pass_descendants = TOP_LEVEL_ENTRIES_PER_PASS * DESCENDANTS_PER_TOP_LEVEL_ENTRY;
        let total_top = TOP_LEVEL_ENTRIES_PER_PASS * WORK_PORTION_COUNT;
        let total_descendants = per_pass_descendants * WORK_PORTION_COUNT;
        let limits =
            QuarantineCleanupLimits::try_new(ROOTS, total_top, total_descendants, DEPTH).unwrap();
        let per_pass = TombstoneWork::new(TOP_LEVEL_ENTRIES_PER_PASS, per_pass_descendants, DEPTH);

        QuarantineCleanupReservation::try_new(
            limits,
            ROOTS,
            cleanup(per_pass, per_pass, per_pass),
            per_pass,
            per_pass,
        )
        .unwrap();
        assert_eq!(
            QuarantineCleanupReservation::try_new(
                limits,
                ROOTS,
                cleanup(per_pass, per_pass, per_pass),
                per_pass,
                TombstoneWork::new(TOP_LEVEL_ENTRIES_PER_PASS + 1, per_pass_descendants, DEPTH,),
            ),
            Err(QuarantineBudgetError::LimitExceeded)
        );
    }

    #[test]
    fn consumption_overflow_is_reported_without_mutation() {
        let limits = QuarantineCleanupLimits::try_new(1, usize::MAX, 1, 1).unwrap();
        let reservation = QuarantineCleanupReservation::try_new(
            limits,
            1,
            cleanup(
                TombstoneWork::new(usize::MAX, 0, 0),
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            TombstoneWork::default(),
            TombstoneWork::default(),
        )
        .unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);
        let portion = QuarantineWorkPortion::CleanupInspection;
        budget
            .try_consume(portion, TombstoneWork::new(usize::MAX, 0, 0))
            .unwrap();

        assert_eq!(
            budget.try_top_level_entry(portion),
            Err(QuarantineBudgetError::ArithmeticOverflow)
        );
        assert_eq!(budget.remaining_top_level_entries(portion), 0);
    }
}
