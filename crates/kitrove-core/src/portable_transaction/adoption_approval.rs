use super::*;

// Keep every public entry point typed to its matching plan and observation.
// Only the recovery policy differs from the existing interactive coordinator.
macro_rules! approved_adoption {
    ($name:ident, $plan:ty, $observation:ty, $plan_variant:ident, $observation_variant:ident) => {
        /// Commits a caller-approved exact plan, refusing pending recovery under lock.
        ///
        /// The caller must compare the plan digest with explicit approval first.
        pub fn $name(
            plan: &$plan,
            observation: &$observation,
            root: &Path,
            limits: CaptureLimits,
        ) -> Result<AdoptionCommitOutcome, PortableTransactionError> {
            commit_adoption_authority_with_recovery(
                AdoptionPlanRef::$plan_variant(plan),
                AdoptionObservationRef::$observation_variant(observation),
                root,
                limits,
                None,
                RecoveryPolicy::Refuse,
            )
        }
    };
}

approved_adoption!(
    commit_approved_adoption,
    AdoptionPlan,
    AcceptedObservedCandidate,
    Skill,
    Skill
);
approved_adoption!(
    commit_approved_instruction_adoption,
    InstructionAdoptionPlan,
    InstructionDocumentObservation,
    Instruction,
    Instruction
);
approved_adoption!(
    commit_approved_prompt_command_adoption,
    PromptCommandAdoptionPlan,
    PromptCommandObservation,
    PromptCommand,
    PromptCommand
);
approved_adoption!(
    commit_approved_agent_adoption,
    AgentAdoptionPlan,
    AgentObservation,
    Agent,
    Agent
);
approved_adoption!(
    commit_approved_mcp_adoption,
    McpAdoptionPlan,
    McpDocumentObservation,
    Mcp,
    Mcp
);

macro_rules! approved_replacement {
    ($name:ident, $plan:ty, $observation:ty, $plan_variant:ident, $observation_variant:ident) => {
        /// Commits a caller-approved replacement without implicit recovery or local receipt changes.
        ///
        /// The caller must compare the plan digest with explicit approval first.
        pub fn $name(
            plan: &$plan,
            observation: &$observation,
            root: &Path,
            limits: CaptureLimits,
        ) -> Result<UpdateCommitOutcome, PortableTransactionError> {
            commit_adoption_authority_with_recovery(
                AdoptionPlanRef::$plan_variant(plan),
                AdoptionObservationRef::$observation_variant(observation),
                root,
                limits,
                None,
                RecoveryPolicy::Refuse,
            )
            .map(|_| UpdateCommitOutcome::CommittedWithoutReceipt)
        }
    };
}

approved_replacement!(
    commit_approved_mcp_update,
    McpUpdatePlan,
    McpDocumentObservation,
    McpUpdate,
    Mcp
);
approved_replacement!(
    commit_approved_prompt_command_update,
    PromptCommandUpdatePlan,
    PromptCommandObservation,
    PromptCommandUpdate,
    PromptCommand
);
approved_replacement!(
    commit_approved_agent_update,
    AgentUpdatePlan,
    AgentObservation,
    AgentUpdate,
    Agent
);

macro_rules! approved_update {
    ($name:ident, $plan:ty, $observation:ty, $variant:ident) => {
        /// Commits a caller-approved update, refusing pending recovery under the existing locks.
        ///
        /// Requires an initialized local-state directory. The caller must compare
        /// the plan digest with explicit approval first.
        pub fn $name(
            plan: &$plan,
            observation: &$observation,
            root: &Path,
            state: &Path,
            limits: CaptureLimits,
        ) -> Result<UpdateCommitOutcome, PortableTransactionError> {
            commit_update_authority_with_recovery(
                UpdatePlanRef::$variant(plan),
                UpdateObservationRef::$variant(observation),
                root,
                state,
                limits,
                None,
                RecoveryPolicy::Refuse,
            )
        }
    };
}

approved_update!(
    commit_approved_update_adoption,
    UpdatePlan,
    AcceptedObservedCandidate,
    Skill
);
approved_update!(
    commit_approved_instruction_update,
    InstructionUpdatePlan,
    InstructionDocumentObservation,
    Instruction
);
