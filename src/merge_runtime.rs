//! Host construction of trusted MergeDecision evidence.
//!
//! This module converts an authenticated role result into the bounded risk inputs used by the
//! pure merge policy evaluator. Forge observations and repository policy remain host-owned; the
//! Agent can only raise uncertainty or provide risk ratings for those exact observed subjects.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::ids::Digest;
use crate::engine::orchestration::{
    GateOutcome, MergeAssessmentPayload, MergeConfidence as AgentConfidence,
    RiskDimension as AgentRiskDimension,
};
use crate::merge_policy::{
    Confidence, EvidenceState, MergeAssessment, MergeEvidenceSnapshot, MergePolicy, RiskDimension,
    RiskRating, evaluate_merge_policy,
};
use sha2::Digest as _;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostMergeAssessment {
    pub publication_set_digest: Digest,
    pub pull_request_reference: String,
    pub evidence: MergeEvidenceSnapshot,
    pub assessment: MergeAssessment,
    pub policy_digest: Digest,
    pub source_result_digest: Digest,
    pub baseline_issue_comments: Vec<crate::forge::IssueComment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeEvidenceObservation {
    pub publication_set_digest: Digest,
    pub pull_request_reference: String,
    /// Exact body from the same fresh Forge snapshot as `evidence`.
    pub current_pr_body: Option<String>,
    pub evidence: MergeEvidenceSnapshot,
    pub policy: MergePolicy,
    pub baseline_issue_comments: Vec<crate::forge::IssueComment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeAssessmentError {
    PullRequestReferenceMismatch(String),
    InvalidAgentClaim(String),
    Host(String),
}

impl std::fmt::Display for MergeAssessmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PullRequestReferenceMismatch(message)
            | Self::InvalidAgentClaim(message)
            | Self::Host(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for MergeAssessmentError {}

pub fn assess_merge_claim(
    claim: &MergeAssessmentPayload,
    result_digest: &Digest,
    observation: &MergeEvidenceObservation,
) -> Result<HostMergeAssessment, MergeAssessmentError> {
    let evidence = &observation.evidence;
    let policy = &observation.policy;
    if evidence.subject != evidence.current_subject {
        return Err(MergeAssessmentError::Host(
            "cannot assess a stale host-observed merge subject".into(),
        ));
    }
    if claim.subject_digest != observation.publication_set_digest {
        return Err(MergeAssessmentError::InvalidAgentClaim(
            "MergeDecision result names a different accepted publication subject".into(),
        ));
    }
    let claimed_refs = claim
        .pr_references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if claimed_refs.len() != claim.pr_references.len()
        || claimed_refs != BTreeSet::from([observation.pull_request_reference.as_str()])
    {
        return Err(MergeAssessmentError::PullRequestReferenceMismatch(
            "MergeDecision result does not identify the exact accepted pull request".into(),
        ));
    }
    let host_gates = evidence
        .gates
        .iter()
        .map(|gate| (gate.key.as_str(), gate.state))
        .collect::<BTreeMap<_, _>>();
    let mut claim_gates = BTreeMap::new();
    for gate in &claim.deterministic_gate_evidence {
        let state = match gate.outcome {
            GateOutcome::Pass => EvidenceState::Pass,
            GateOutcome::Fail => EvidenceState::Fail,
            GateOutcome::Unknown => EvidenceState::Unknown,
        };
        if claim_gates.insert(gate.gate_id.as_str(), state).is_some() {
            return Err(MergeAssessmentError::InvalidAgentClaim(
                "MergeDecision repeats deterministic gate evidence".into(),
            ));
        }
    }
    let host_gate_ids = host_gates.keys().copied().collect::<BTreeSet<_>>();
    let claimed_gate_ids = claim_gates.keys().copied().collect::<BTreeSet<_>>();
    let gate_disagreement = host_gate_ids != claimed_gate_ids
        || host_gates
            .iter()
            .any(|(key, state)| claim_gates.get(key) != Some(state));

    let mut ratings = Vec::with_capacity(claim.ratings.len());
    for (dimension, rating) in &claim.ratings {
        ratings.push(RiskRating {
            dimension: map_risk_dimension(*dimension),
            rating: Some(rating.rating),
            rationale: format!("{} (source: {})", rating.rationale, rating.source),
        });
    }
    let mut trusted_evidence = evidence.clone();
    trusted_evidence.risk = ratings;
    trusted_evidence.confidence = match claim.confidence {
        AgentConfidence::Low => Confidence::Low,
        AgentConfidence::Medium => Confidence::Medium,
        AgentConfidence::High => Confidence::High,
    };
    // A disagreement with host-observed gates, any non-affirmative disposition, or uncertainty
    // attached to an Agent rating can only make the outcome more conservative.
    trusted_evidence.human_review_required |= gate_disagreement
        || claim.disposition.trim() != "eligible_for_automatic_merge"
        || claim
            .ratings
            .values()
            .any(|rating| rating.uncertainty.is_some());
    if claim.rationale.trim().is_empty() {
        trusted_evidence.human_review_required = true;
    }
    let assessment = evaluate_merge_policy(policy, &trusted_evidence)
        .map_err(|error| MergeAssessmentError::Host(error.to_string()))?;
    let policy_digest = crate::forge::canonical_digest(policy)
        .map_err(|error| MergeAssessmentError::Host(error.to_string()))?;
    Ok(HostMergeAssessment {
        publication_set_digest: observation.publication_set_digest.clone(),
        pull_request_reference: observation.pull_request_reference.clone(),
        evidence: trusted_evidence,
        assessment,
        policy_digest,
        source_result_digest: result_digest.clone(),
        baseline_issue_comments: observation.baseline_issue_comments.clone(),
    })
}

fn map_risk_dimension(value: AgentRiskDimension) -> RiskDimension {
    match value {
        AgentRiskDimension::ChangeImpact => RiskDimension::ChangeImpact,
        AgentRiskDimension::Complexity => RiskDimension::Complexity,
        AgentRiskDimension::VerificationGaps => RiskDimension::VerificationGaps,
        AgentRiskDimension::ReviewUncertainty => RiskDimension::ReviewUncertainty,
        AgentRiskDimension::OperationalExposure => RiskDimension::OperationalExposure,
    }
}

/// The host-visible assessment identity used in the same-revision continuation wake.
pub fn assessment_id(
    project_id: &crate::domain::ids::ProjectId,
    ticket_run_id: &crate::domain::ids::TicketRunId,
    revision: crate::domain::ids::Revision,
    source_evidence_id: &str,
    result_digest: &Digest,
    evidence: &MergeEvidenceSnapshot,
) -> Result<Digest, String> {
    let evidence_digest = crate::merge_policy::digest_merge_evidence(evidence)?;
    let input = crate::store::canonical_json(&(
        "rex-projects-merge-assessment-v1",
        project_id,
        ticket_run_id,
        revision,
        source_evidence_id,
        result_digest,
        evidence_digest,
    ))?;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(input.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{MergeExecutor, MergeMethod};
    use crate::engine::orchestration::{DeterministicGateEvidence, RiskFactorAssessment};
    use crate::merge_policy::{GateEvidence, MergeSubject, RiskWeights};

    fn fixture() -> (MergeAssessmentPayload, MergeEvidenceObservation, Digest) {
        let d = |n: u8| Digest::parse(format!("{n:02x}",).repeat(32)).unwrap();
        let subject = MergeSubject {
            repository_id: "repo".into(),
            forge: "github".into(),
            forge_host: "github.com".into(),
            forge_repository_id: 7,
            pull_request_id: "9".into(),
            pull_request_node_id: "PR_node".into(),
            head_sha: "a".repeat(40),
            base_ref: "main".into(),
            base_sha: "b".repeat(40),
            config_digest: d(1),
            instruction_digest: d(2),
            hooks_digest: d(3),
            remote_checks_digest: d(4),
            diff_digest: d(5),
            merge_comments_digest: d(6),
            base_guard_digest: Some(d(7)),
            review_digest: d(8),
            prepared_body_digest: Some(d(9)),
        };
        let evidence = MergeEvidenceSnapshot {
            subject: subject.clone(),
            current_subject: subject.clone(),
            gates: vec![GateEvidence {
                key: "check:unit".into(),
                state: EvidenceState::Pass,
                required: true,
                detail: "observed at exact head".into(),
            }],
            risk: Vec::new(),
            confidence: Confidence::High,
            human_review_required: false,
            execution_time_base_guard: EvidenceState::Pass,
        };
        let policy = MergePolicy {
            auto_merge_enabled: true,
            minimum_reliability_score: 80,
            method: MergeMethod::Squash,
            executor: MergeExecutor::Direct,
            required_checks: vec!["unit".into()],
            required_approving_reviews: Some(1),
            risk_weights: RiskWeights::default(),
        };
        let subject_digest = d(11);
        let publication_digest = subject_digest.clone();
        let pr_reference = "https://github.com/civitaspo/rex-projects/pull/9".to_owned();
        let claim = MergeAssessmentPayload {
            pr_references: vec![pr_reference.clone()],
            subject_digest,
            deterministic_gate_evidence: vec![DeterministicGateEvidence {
                gate_id: "check:unit".into(),
                outcome: GateOutcome::Pass,
                evidence_references: Vec::new(),
            }],
            ratings: BTreeMap::from([(
                AgentRiskDimension::Complexity,
                RiskFactorAssessment {
                    rating: 1,
                    source: "diff review".into(),
                    rationale: "small change".into(),
                    evidence_references: Vec::new(),
                    uncertainty: None,
                },
            )]),
            confidence: AgentConfidence::High,
            rationale: "reviewed exact head".into(),
            disposition: "eligible_for_automatic_merge".into(),
        };
        (
            claim,
            MergeEvidenceObservation {
                publication_set_digest: publication_digest,
                pull_request_reference: pr_reference,
                current_pr_body: Some(String::new()),
                evidence,
                policy,
                baseline_issue_comments: Vec::new(),
            },
            d(10),
        )
    }

    #[test]
    fn assessment_uses_host_gates_and_agent_can_only_raise_human_review() {
        let (claim, observation, result_digest) = fixture();
        let assessment = assess_merge_claim(&claim, &result_digest, &observation).unwrap();
        assert!(!assessment.evidence.human_review_required);
        assert_eq!(assessment.assessment.subject, observation.evidence.subject);
        assert_eq!(assessment.source_result_digest, result_digest);

        let mut disagreement = claim;
        disagreement.deterministic_gate_evidence[0].outcome = GateOutcome::Fail;
        let conservative = assess_merge_claim(&disagreement, &result_digest, &observation).unwrap();
        assert!(conservative.evidence.human_review_required);
        assert_eq!(conservative.evidence.gates, observation.evidence.gates);
    }

    #[test]
    fn stale_agent_subject_is_rejected_before_assessment() {
        let (mut claim, observation, result_digest) = fixture();
        claim.subject_digest = Digest::parse("f".repeat(64)).unwrap();
        assert!(assess_merge_claim(&claim, &result_digest, &observation).is_err());
    }

    #[test]
    fn arbitrary_disposition_cannot_enable_automatic_merge() {
        let (mut claim, observation, result_digest) = fixture();
        claim.disposition = "merge now".into();
        let conservative = assess_merge_claim(&claim, &result_digest, &observation).unwrap();
        assert!(conservative.evidence.human_review_required);
    }
}
