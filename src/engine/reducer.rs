use serde::{Deserialize, Serialize};

use crate::delivery_runtime::ValidatedImplementationPublication;
use crate::domain::ids::{OperationId, ProjectId, Revision, TicketRunId};
use crate::domain::types::{Role, TicketStatus};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Planning,
    Preparing,
    Implementing,
    Publishing,
    Reviewing,
    Assessing,
    WaitingHuman,
    AwaitingMerge,
    Operating,
    Postmortem,
    Completing,
    Done,
    Canceled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    Ready,
    Running,
    Waiting,
    Blocked,
    Paused,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TicketRun {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub revision: Revision,
    pub phase: Phase,
    pub activity: Activity,
    pub external_status: TicketStatus,
    pub required_review_revision: Option<Revision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Input {
    Dispatch,
    PlanAccepted,
    WorktreesPrepared,
    EvidenceSubmitted,
    ImplementationPublished(ValidatedImplementationPublication),
    CorrectionsRemain,
    ReviewConverged,
    RequireHumanReview,
    HumanReviewApproved,
    HumanReviewRevisionRequested,
    MergeVerified,
    OperationFailed,
    OperationsSucceeded,
    OperationsNotRequired,
    KnowledgePublished,
    CompletionObserved,
    ExternalCanceled,
    Pause,
    Resume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectIntent {
    pub operation_id: OperationId,
    pub kind: EffectKind,
    pub logical_key: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    PublishTicketStatus,
    TicketCreate,
    TicketDuplicateComment,
    TicketCancelDuplicate,
    TicketResolveDuplicate,
    PrepareWorktrees,
    PublishImplementation,
    RequestHumanReview,
    Merge,
    Operation,
    StartPostmortem,
    PublishKnowledge,
    PublishProfile,
    CompleteTicket,
    StartAgent,
    StartProfileTrial,
    StopOwnedRuns,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WakeInput {
    pub target: WakeTarget,
    pub source_revision: Revision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeTarget {
    Supervisor,
    TicketRole(Role),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub ticket_run: TicketRun,
    pub source_revision: Revision,
    pub effects: Vec<EffectKind>,
    pub wakes: Vec<WakeTarget>,
}

pub fn reduce(
    current: &TicketRun,
    expected_revision: Revision,
    input: Input,
) -> Result<Decision, String> {
    if current.revision != expected_revision {
        return Err("ticket run revision conflict".into());
    }
    if matches!(current.phase, Phase::Done | Phase::Canceled) {
        return Err("terminal ticket run cannot transition".into());
    }

    let mut next = current.clone();
    let mut effects = Vec::new();
    let mut wakes = Vec::new();
    match input {
        Input::Dispatch if current.phase == Phase::Queued => {
            next.phase = Phase::Planning;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Coordinator));
            if current.external_status != TicketStatus::InProgress {
                effects.push(EffectKind::PublishTicketStatus);
            }
        }
        Input::PlanAccepted if current.phase == Phase::Planning => {
            next.phase = Phase::Preparing;
            next.activity = Activity::Running;
            effects.push(EffectKind::PrepareWorktrees);
        }
        Input::WorktreesPrepared if current.phase == Phase::Preparing => {
            next.phase = Phase::Implementing;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Worker));
        }
        Input::EvidenceSubmitted if current.phase == Phase::Implementing => {
            next.phase = Phase::Publishing;
            next.activity = Activity::Running;
            effects.push(EffectKind::PublishImplementation);
        }
        Input::ImplementationPublished(receipt)
            if current.phase == Phase::Publishing && receipt.matches(current) =>
        {
            next.phase = Phase::Reviewing;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Reviewer));
        }
        Input::CorrectionsRemain if current.phase == Phase::Reviewing => {
            next.phase = Phase::Implementing;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Worker));
        }
        Input::ReviewConverged if current.phase == Phase::Reviewing => {
            next.phase = Phase::Assessing;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::MergeDecision));
        }
        Input::RequireHumanReview if current.phase == Phase::Assessing => {
            next.phase = Phase::WaitingHuman;
            next.activity = Activity::Waiting;
            next.external_status = TicketStatus::InReview;
            next.required_review_revision = Some(current.revision);
            effects.push(EffectKind::RequestHumanReview);
            effects.push(EffectKind::PublishTicketStatus);
        }
        Input::HumanReviewApproved
            if current.phase == Phase::WaitingHuman
                && current.required_review_revision == Some(current.revision) =>
        {
            next.phase = Phase::AwaitingMerge;
            next.activity = Activity::Running;
            next.required_review_revision = None;
            next.external_status = TicketStatus::InProgress;
            effects.push(EffectKind::Merge);
            effects.push(EffectKind::PublishTicketStatus);
        }
        Input::HumanReviewRevisionRequested
            if current.phase == Phase::WaitingHuman
                && current.required_review_revision == Some(current.revision) =>
        {
            next.phase = Phase::Planning;
            next.activity = Activity::Running;
            next.required_review_revision = None;
            next.external_status = TicketStatus::InProgress;
            wakes.push(WakeTarget::TicketRole(Role::Coordinator));
            effects.push(EffectKind::PublishTicketStatus);
        }
        Input::MergeVerified if current.phase == Phase::AwaitingMerge => {
            next.phase = Phase::Operating;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Operator));
        }
        Input::OperationFailed if current.phase == Phase::Operating => {
            next.activity = Activity::Blocked;
            wakes.push(WakeTarget::Supervisor);
        }
        Input::OperationsSucceeded | Input::OperationsNotRequired
            if current.phase == Phase::Operating =>
        {
            next.phase = Phase::Postmortem;
            next.activity = Activity::Running;
            wakes.push(WakeTarget::TicketRole(Role::Postmortem));
        }
        Input::KnowledgePublished if current.phase == Phase::Postmortem => {
            next.phase = Phase::Completing;
            next.activity = Activity::Running;
            effects.push(EffectKind::CompleteTicket);
        }
        Input::CompletionObserved if current.phase == Phase::Completing => {
            next.phase = Phase::Done;
            next.activity = Activity::Ready;
            next.external_status = TicketStatus::Done;
            effects.push(EffectKind::PublishTicketStatus);
        }
        Input::ExternalCanceled => {
            next.phase = Phase::Canceled;
            next.activity = Activity::Ready;
            next.external_status = TicketStatus::Canceled;
            next.required_review_revision = None;
            effects.push(EffectKind::StopOwnedRuns);
            effects.push(EffectKind::PublishTicketStatus);
        }
        Input::Pause => {
            next.activity = Activity::Paused;
            effects.push(EffectKind::StopOwnedRuns);
        }
        Input::Resume if current.activity == Activity::Paused => {
            next.activity = Activity::Ready;
            wakes.push(WakeTarget::TicketRole(Role::Coordinator));
        }
        _ => return Err("input is not valid in the current ticket run state".into()),
    }

    next.revision = Revision(
        current
            .revision
            .0
            .checked_add(1)
            .ok_or_else(|| "ticket run revision is exhausted".to_owned())?,
    );
    if next.phase == Phase::WaitingHuman {
        next.required_review_revision = Some(next.revision);
    }
    if next.phase != Phase::WaitingHuman {
        next.external_status = match next.phase {
            Phase::Queued | Phase::Done => next.external_status,
            Phase::Canceled => TicketStatus::Canceled,
            _ => TicketStatus::InProgress,
        };
    }
    Ok(Decision {
        ticket_run: next,
        source_revision: current.revision,
        effects,
        wakes,
    })
}

pub fn bind_effects(decision: &Decision, ids: &[OperationId]) -> Result<Vec<EffectIntent>, String> {
    if ids.len() != decision.effects.len() {
        return Err("one stable operation ID is required for each effect".into());
    }
    Ok(decision
        .effects
        .iter()
        .zip(ids)
        .map(|(kind, operation_id)| EffectIntent {
            operation_id: operation_id.clone(),
            kind: *kind,
            logical_key: format!(
                "{}:{}:{}",
                decision.ticket_run.ticket_run_id,
                decision.source_revision.0,
                effect_name(kind)
            ),
        })
        .collect())
}

pub const fn effect_name(kind: &EffectKind) -> &'static str {
    match kind {
        EffectKind::PublishTicketStatus => "publish_ticket_status",
        EffectKind::TicketCreate => "ticket_create",
        EffectKind::TicketDuplicateComment => "ticket_duplicate_comment",
        EffectKind::TicketCancelDuplicate => "ticket_cancel_duplicate",
        EffectKind::TicketResolveDuplicate => "ticket_resolve_duplicate",
        EffectKind::PrepareWorktrees => "prepare_worktrees",
        EffectKind::PublishImplementation => "publish_implementation",
        EffectKind::RequestHumanReview => "request_human_review",
        EffectKind::Merge => "merge",
        EffectKind::Operation => "operation",
        EffectKind::StartPostmortem => "start_postmortem",
        EffectKind::PublishKnowledge => "publish_knowledge",
        EffectKind::PublishProfile => "publish_profile",
        EffectKind::CompleteTicket => "complete_ticket",
        EffectKind::StartAgent => "start_agent",
        EffectKind::StartProfileTrial => "start_profile_trial",
        EffectKind::StopOwnedRuns => "stop_owned_runs",
    }
}

pub fn wake_inputs(decision: &Decision) -> Vec<WakeInput> {
    decision
        .wakes
        .iter()
        .map(|target| WakeInput {
            target: *target,
            source_revision: decision.ticket_run.revision,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Activity, EffectKind, Input, Phase, TicketRun, WakeTarget, reduce};
    use crate::domain::ids::{ProjectId, Revision, TicketRunId};
    use crate::domain::types::{Role, TicketStatus};

    fn run() -> TicketRun {
        TicketRun {
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: TicketRunId::parse("ticket-run-1").unwrap(),
            revision: Revision(1),
            phase: Phase::Queued,
            activity: Activity::Ready,
            external_status: TicketStatus::Ready,
            required_review_revision: None,
        }
    }

    #[test]
    fn implementation_review_cannot_start_before_host_delivery_receipt() {
        let mut implementing = run();
        implementing.phase = Phase::Implementing;
        implementing.activity = Activity::Running;
        let publish = reduce(
            &implementing,
            implementing.revision,
            Input::EvidenceSubmitted,
        )
        .unwrap();
        assert_eq!(publish.ticket_run.phase, Phase::Publishing);
        assert_eq!(publish.effects, vec![EffectKind::PublishImplementation]);
    }

    #[test]
    fn rejects_stale_revision_without_changing_the_subject() {
        let current = run();
        let decision = reduce(&current, Revision(0), Input::Dispatch);
        assert_eq!(decision.unwrap_err(), "ticket run revision conflict");
        assert_eq!(current.revision, Revision(1));
        assert_eq!(current.phase, Phase::Queued);
    }

    #[test]
    fn dispatch_returns_effect_intent_without_running_a_role() {
        let decision = reduce(&run(), Revision(1), Input::Dispatch).unwrap();
        assert_eq!(decision.ticket_run.phase, Phase::Planning);
        assert_eq!(decision.ticket_run.revision, Revision(2));
        assert_eq!(decision.effects, [EffectKind::PublishTicketStatus]);
        assert_eq!(
            decision.wakes,
            [WakeTarget::TicketRole(
                crate::domain::types::Role::Coordinator
            )]
        );
    }

    #[test]
    fn role_work_is_always_durably_routed_as_a_wake() {
        let cases = [
            (Phase::Queued, Input::Dispatch, Role::Coordinator),
            (Phase::Preparing, Input::WorktreesPrepared, Role::Worker),
            (Phase::Reviewing, Input::CorrectionsRemain, Role::Worker),
            (
                Phase::Reviewing,
                Input::ReviewConverged,
                Role::MergeDecision,
            ),
            (Phase::AwaitingMerge, Input::MergeVerified, Role::Operator),
            (
                Phase::Operating,
                Input::OperationsSucceeded,
                Role::Postmortem,
            ),
        ];
        for (phase, input, target) in cases {
            let mut current = run();
            current.phase = phase;
            current.activity = Activity::Running;
            let decision = reduce(&current, current.revision, input).unwrap();
            assert_eq!(decision.wakes, [WakeTarget::TicketRole(target)]);
            assert!(
                decision
                    .effects
                    .iter()
                    .all(|effect| *effect == EffectKind::PublishTicketStatus)
            );
        }
        let mut implementing = run();
        implementing.phase = Phase::Implementing;
        implementing.activity = Activity::Running;
        let publication = reduce(
            &implementing,
            implementing.revision,
            Input::EvidenceSubmitted,
        )
        .unwrap();
        assert_eq!(publication.ticket_run.phase, Phase::Publishing);
        assert!(publication.wakes.is_empty());
    }

    #[test]
    fn in_review_is_emitted_only_for_required_current_subject_review() {
        let mut current = run();
        current.phase = Phase::Assessing;
        current.activity = Activity::Running;
        current.external_status = TicketStatus::InProgress;
        let pending = reduce(&current, Revision(1), Input::RequireHumanReview).unwrap();
        assert_eq!(pending.ticket_run.external_status, TicketStatus::InReview);
        assert_eq!(
            pending.ticket_run.required_review_revision,
            Some(Revision(2))
        );

        let approved =
            reduce(&pending.ticket_run, Revision(2), Input::HumanReviewApproved).unwrap();
        assert_eq!(
            approved.ticket_run.external_status,
            TicketStatus::InProgress
        );
        assert_eq!(approved.ticket_run.phase, Phase::AwaitingMerge);
    }

    #[test]
    fn non_review_human_wait_does_not_change_external_status() {
        let mut current = run();
        current.phase = Phase::Planning;
        current.activity = Activity::Running;
        current.external_status = TicketStatus::InProgress;
        let mut assessing = current.clone();
        assessing.phase = Phase::Assessing;
        let waiting = reduce(&assessing, Revision(1), Input::RequireHumanReview);
        assert_eq!(
            waiting.unwrap().ticket_run.external_status,
            TicketStatus::InReview
        );

        let paused = reduce(&current, Revision(1), Input::Pause).unwrap();
        assert_eq!(paused.ticket_run.external_status, TicketStatus::InProgress);
        assert_eq!(paused.ticket_run.activity, Activity::Paused);
    }

    #[test]
    fn invalid_transition_and_revision_exhaustion_are_rejected() {
        assert!(reduce(&run(), Revision(1), Input::EvidenceSubmitted).is_err());
        let mut exhausted = run();
        exhausted.revision = Revision(u64::MAX);
        assert_eq!(
            reduce(&exhausted, Revision(u64::MAX), Input::Dispatch).unwrap_err(),
            "ticket run revision is exhausted"
        );
    }
}
