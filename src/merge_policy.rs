//! Pure merge eligibility and procedure validation.
//!
//! This module deliberately has no forge, filesystem, process, or persistence effects. Callers
//! snapshot remote evidence, then persist the returned assessment and execute its typed steps.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::Digest;
use crate::domain::types::{MergeExecutor, MergeMethod};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeSubject {
    pub repository_id: String,
    pub forge: String,
    pub forge_host: String,
    pub forge_repository_id: u64,
    pub pull_request_id: String,
    pub pull_request_node_id: String,
    pub head_sha: String,
    pub base_ref: String,
    pub base_sha: String,
    pub config_digest: Digest,
    pub instruction_digest: Digest,
    pub hooks_digest: Digest,
    pub remote_checks_digest: Digest,
    pub diff_digest: Digest,
    pub merge_comments_digest: Digest,
    /// Digest of repository rules or adapter capability that guards the assessed base.
    pub base_guard_digest: Option<Digest>,
    pub review_digest: Digest,
    pub prepared_body_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GateEvidence {
    pub key: String,
    pub state: EvidenceState,
    pub required: bool,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDimension {
    ChangeImpact,
    Complexity,
    VerificationGaps,
    ReviewUncertainty,
    OperationalExposure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskRating {
    pub dimension: RiskDimension,
    /// Integer judgment from 0 (low) through 4 (high).
    pub rating: Option<u8>,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeEvidenceSnapshot {
    pub subject: MergeSubject,
    /// Re-observed subject at the point of evaluation. A mismatch means the result is stale.
    pub current_subject: MergeSubject,
    pub gates: Vec<GateEvidence>,
    pub risk: Vec<RiskRating>,
    pub confidence: Confidence,
    pub human_review_required: bool,
    /// Verified forge/server capability that enforces the assessed base predicate at execution.
    pub execution_time_base_guard: EvidenceState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskWeights {
    pub change_impact: u8,
    pub complexity: u8,
    pub verification_gaps: u8,
    pub review_uncertainty: u8,
    pub operational_exposure: u8,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            change_impact: 30,
            complexity: 20,
            verification_gaps: 20,
            review_uncertainty: 15,
            operational_exposure: 15,
        }
    }
}

impl RiskWeights {
    pub fn validate(&self) -> Result<(), String> {
        let total = self.change_impact as u16
            + self.complexity as u16
            + self.verification_gaps as u16
            + self.review_uncertainty as u16
            + self.operational_exposure as u16;
        if total != 100 {
            return Err(format!("risk weights must sum to 100, got {total}"));
        }
        Ok(())
    }

    fn get(&self, dimension: RiskDimension) -> u8 {
        match dimension {
            RiskDimension::ChangeImpact => self.change_impact,
            RiskDimension::Complexity => self.complexity,
            RiskDimension::VerificationGaps => self.verification_gaps,
            RiskDimension::ReviewUncertainty => self.review_uncertainty,
            RiskDimension::OperationalExposure => self.operational_exposure,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergePolicy {
    pub auto_merge_enabled: bool,
    pub minimum_reliability_score: u8,
    pub method: MergeMethod,
    pub executor: MergeExecutor,
    pub required_checks: Vec<String>,
    /// Server-enforced minimum for direct merges; `None` means the repository policy requires none.
    pub required_approving_reviews: Option<u64>,
    pub risk_weights: RiskWeights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeDisposition {
    EligibleForAutomaticMerge,
    HumanRequired,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeAssessment {
    pub subject: MergeSubject,
    /// Canonical digest of the complete semantic evidence and risk ratings used by this result.
    pub evidence_digest: Digest,
    pub disposition: MergeDisposition,
    pub risk_index: Option<u8>,
    pub reliability_score: Option<u8>,
    pub reasons: Vec<String>,
}

pub fn evaluate_merge_policy(
    policy: &MergePolicy,
    evidence: &MergeEvidenceSnapshot,
) -> Result<MergeAssessment, String> {
    policy.risk_weights.validate()?;
    if !(0..=100).contains(&policy.minimum_reliability_score) {
        return Err("minimum reliability score must be between 0 and 100".into());
    }

    let evidence_digest = digest_merge_evidence(evidence)?;
    let mut reasons = Vec::new();
    let mut blocked = false;
    let mut human = false;
    for required in &policy.required_checks {
        let key = format!("check:{required}");
        if !evidence.gates.iter().any(|gate| gate.key == key) {
            human = true;
            reasons.push(format!(
                "required check `{required}` has no revision-bound evidence"
            ));
        }
    }
    if evidence.subject != evidence.current_subject {
        blocked = true;
        reasons.push("assessment subject is stale".into());
    }
    for gate in &evidence.gates {
        match gate.state {
            EvidenceState::Pass => (),
            EvidenceState::Fail if gate.required => {
                blocked = true;
                reasons.push(format!(
                    "required gate `{}` failed: {}",
                    gate.key, gate.detail
                ));
            }
            EvidenceState::Fail => {
                human = true;
                reasons.push(format!("gate `{}` failed: {}", gate.key, gate.detail));
            }
            EvidenceState::Unknown if gate.required => {
                human = true;
                reasons.push(format!(
                    "required gate `{}` is unknown: {}",
                    gate.key, gate.detail
                ));
            }
            EvidenceState::Unknown => {
                human = true;
                reasons.push(format!("gate `{}` is unknown: {}", gate.key, gate.detail));
            }
        }
    }
    if evidence.human_review_required {
        human = true;
        reasons.push("repository policy requires human review".into());
    }
    if evidence.confidence != Confidence::High {
        human = true;
        reasons.push("risk assessment confidence is not high".into());
    }

    let ratings = validate_ratings(&evidence.risk)?;
    let mut weighted_sum = 0u16;
    let mut unknown_risk = false;
    let mut severe_risk = false;
    for dimension in [
        RiskDimension::ChangeImpact,
        RiskDimension::Complexity,
        RiskDimension::VerificationGaps,
        RiskDimension::ReviewUncertainty,
        RiskDimension::OperationalExposure,
    ] {
        match ratings[&dimension] {
            Some(value) => {
                weighted_sum += policy.risk_weights.get(dimension) as u16 * value as u16;
                severe_risk |= value == 4;
            }
            None => unknown_risk = true,
        }
    }
    let (risk_index, reliability_score) = if unknown_risk {
        human = true;
        reasons.push("one or more risk dimensions are unknown".into());
        (None, None)
    } else {
        let risk_index = weighted_sum.div_ceil(4) as u8;
        (Some(risk_index), Some(100 - risk_index))
    };
    if severe_risk {
        human = true;
        reasons.push("a risk dimension is rated at the maximum level".into());
    }
    if reliability_score.is_some_and(|score| score < policy.minimum_reliability_score) {
        human = true;
        reasons.push("reliability score is below the repository threshold".into());
    }

    match evidence.execution_time_base_guard {
        EvidenceState::Pass => (),
        EvidenceState::Fail => {
            blocked = true;
            reasons.push("merge executor lacks an execution-time base guard".into());
        }
        EvidenceState::Unknown => {
            human = true;
            reasons.push("execution-time base guard is unverified".into());
        }
    }
    if !policy.auto_merge_enabled {
        human = true;
        reasons.push("automatic merge is disabled by repository policy".into());
    }

    let disposition = if blocked {
        MergeDisposition::Blocked
    } else if human {
        MergeDisposition::HumanRequired
    } else {
        MergeDisposition::EligibleForAutomaticMerge
    };
    Ok(MergeAssessment {
        subject: evidence.subject.clone(),
        evidence_digest,
        disposition,
        risk_index,
        reliability_score,
        reasons,
    })
}

pub fn digest_merge_evidence(snapshot: &MergeEvidenceSnapshot) -> Result<Digest, String> {
    let mut canonical = snapshot.clone();
    canonical.gates.sort_by(|a, b| a.key.cmp(&b.key));
    canonical.risk.sort_by_key(|item| item.dimension);
    if canonical
        .gates
        .windows(2)
        .any(|pair| pair[0].key == pair[1].key)
    {
        return Err("gate evidence keys must be unique".into());
    }
    let bytes = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
    let hash = Sha256::digest(bytes);
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Digest::parse(hex)
}

fn validate_ratings(ratings: &[RiskRating]) -> Result<BTreeMap<RiskDimension, Option<u8>>, String> {
    let mut result = BTreeMap::new();
    for rating in ratings {
        if rating.rating.is_some_and(|value| value > 4) {
            return Err(format!(
                "risk rating for {:?} must be 0 through 4",
                rating.dimension
            ));
        }
        if result.insert(rating.dimension, rating.rating).is_some() {
            return Err(format!("duplicate risk dimension {:?}", rating.dimension));
        }
    }
    for dimension in [
        RiskDimension::ChangeImpact,
        RiskDimension::Complexity,
        RiskDimension::VerificationGaps,
        RiskDimension::ReviewUncertainty,
        RiskDimension::OperationalExposure,
    ] {
        result.entry(dimension).or_insert(None);
    }
    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeProcedure {
    pub method: MergeMethod,
    pub executor: MergeExecutor,
    pub steps: Vec<MergeProcedureStep>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MergeProcedureStep {
    /// Stable key used by the durable layer as an idempotency/receipt key.
    pub key: String,
    pub prerequisites: Vec<String>,
    pub operation: MergeProcedureOperation,
    /// Hash of trusted, resolved instructions. Instructions are never executable shell text.
    pub instruction_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MergeProcedureOperation {
    UpdatePullRequestBody {
        expected_prior_body_digest: Digest,
        approved_body_digest: Digest,
    },
    RequestMerge {
        exact_comment: String,
    },
    ExecuteMerge {
        expected_head_sha: String,
        base_guard_rule_digest: Digest,
    },
    VerifyMergeCommit {
        expected_trailers: Vec<String>,
    },
}

pub fn build_merge_procedure(
    method: MergeMethod,
    executor: MergeExecutor,
    steps: Vec<MergeProcedureStep>,
    subject: &MergeSubject,
) -> Result<MergeProcedure, String> {
    if steps.len() < 2 {
        return Err("procedure must contain a merge operation and post-merge verification".into());
    }
    let mut seen = BTreeMap::new();
    let mut merge_seen = false;
    let mut merge_key = None;
    let mut body_key = None;
    let mut verify_seen = false;
    for (index, step) in steps.iter().enumerate() {
        if step.key.is_empty() || seen.insert(step.key.as_str(), index).is_some() {
            return Err("procedure step keys must be non-empty and unique".into());
        }
        if step.instruction_digest != subject.instruction_digest {
            return Err(format!(
                "step `{}` uses instructions outside the approved subject",
                step.key
            ));
        }
        if step
            .prerequisites
            .iter()
            .any(|key| !seen.contains_key(key.as_str()) || seen[key.as_str()] >= index)
        {
            return Err(format!(
                "step `{}` has a missing or forward prerequisite",
                step.key
            ));
        }
        match &step.operation {
            MergeProcedureOperation::UpdatePullRequestBody {
                approved_body_digest,
                ..
            } => {
                if index != 0 || merge_seen || verify_seen {
                    return Err("body update must be the first procedure step".into());
                }
                if subject.prepared_body_digest.as_ref() != Some(approved_body_digest) {
                    return Err("body update digest is outside the approved body scope".into());
                }
                body_key = Some(step.key.as_str());
            }
            MergeProcedureOperation::RequestMerge { exact_comment } => {
                if executor != MergeExecutor::Request
                    || merge_seen
                    || verify_seen
                    || exact_comment.trim().is_empty()
                {
                    return Err("invalid merge request step for executor".into());
                }
                if body_key.is_some_and(|key| !step.prerequisites.iter().any(|item| item == key)) {
                    return Err("merge request must depend on the prepared body update".into());
                }
                merge_seen = true;
                merge_key = Some(step.key.as_str());
            }
            MergeProcedureOperation::ExecuteMerge {
                expected_head_sha,
                base_guard_rule_digest,
            } => {
                if executor != MergeExecutor::Direct
                    || merge_seen
                    || verify_seen
                    || expected_head_sha != &subject.head_sha
                {
                    return Err("direct merge step does not match approved head or executor".into());
                }
                if subject.base_guard_digest.as_ref() != Some(base_guard_rule_digest) {
                    return Err("direct merge base guard is outside the approved subject".into());
                }
                if body_key.is_some_and(|key| !step.prerequisites.iter().any(|item| item == key)) {
                    return Err("direct merge must depend on the prepared body update".into());
                }
                merge_seen = true;
                merge_key = Some(step.key.as_str());
            }
            MergeProcedureOperation::VerifyMergeCommit { expected_trailers } => {
                if !merge_seen || verify_seen || index + 1 != steps.len() {
                    return Err("merge commit verification must occur once and be last".into());
                }
                if expected_trailers.is_empty()
                    || expected_trailers
                        .iter()
                        .any(|line| !line.starts_with("Co-authored-by: "))
                {
                    return Err(
                        "merge verification requires a non-empty, supported trailer block".into(),
                    );
                }
                let mut unique = expected_trailers.clone();
                unique.sort();
                unique.dedup();
                if unique.len() != expected_trailers.len() {
                    return Err("merge verification trailer lines must be unique".into());
                }
                if !merge_key.is_some_and(|key| step.prerequisites.iter().any(|item| item == key)) {
                    return Err("merge commit verification must depend on the merge step".into());
                }
                verify_seen = true;
            }
        }
    }
    if !merge_seen || !verify_seen {
        return Err(
            "procedure requires exactly one merge step followed by commit verification".into(),
        );
    }
    Ok(MergeProcedure {
        method,
        executor,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(c: char) -> Digest {
        Digest::parse(c.to_string().repeat(64)).unwrap()
    }
    fn subject() -> MergeSubject {
        MergeSubject {
            repository_id: "repo-a".into(),
            forge: "github".into(),
            forge_host: "github.com".into(),
            forge_repository_id: 123,
            pull_request_id: "17".into(),
            pull_request_node_id: "PR_kw123".into(),
            head_sha: "head-1".into(),
            base_ref: "main".into(),
            base_sha: "base-1".into(),
            config_digest: digest('a'),
            instruction_digest: digest('b'),
            hooks_digest: digest('c'),
            remote_checks_digest: digest('d'),
            diff_digest: digest('7'),
            merge_comments_digest: digest('8'),
            base_guard_digest: Some(digest('9')),
            review_digest: digest('e'),
            prepared_body_digest: Some(digest('f')),
        }
    }
    fn evidence() -> MergeEvidenceSnapshot {
        let risk = [
            RiskDimension::ChangeImpact,
            RiskDimension::Complexity,
            RiskDimension::VerificationGaps,
            RiskDimension::ReviewUncertainty,
            RiskDimension::OperationalExposure,
        ]
        .into_iter()
        .map(|dimension| RiskRating {
            dimension,
            rating: Some(0),
            rationale: "fixture".into(),
        })
        .collect();
        MergeEvidenceSnapshot {
            subject: subject(),
            current_subject: subject(),
            gates: vec![GateEvidence {
                key: "check:ci".into(),
                state: EvidenceState::Pass,
                required: true,
                detail: "all pass".into(),
            }],
            risk,
            confidence: Confidence::High,
            human_review_required: false,
            execution_time_base_guard: EvidenceState::Pass,
        }
    }
    fn policy(executor: MergeExecutor) -> MergePolicy {
        MergePolicy {
            auto_merge_enabled: true,
            minimum_reliability_score: 85,
            method: MergeMethod::Squash,
            executor,
            required_checks: vec!["ci".into()],
            required_approving_reviews: None,
            risk_weights: RiskWeights::default(),
        }
    }
    fn step(
        key: &str,
        prerequisites: Vec<&str>,
        operation: MergeProcedureOperation,
    ) -> MergeProcedureStep {
        MergeProcedureStep {
            key: key.into(),
            prerequisites: prerequisites.into_iter().map(str::to_owned).collect(),
            operation,
            instruction_digest: digest('b'),
        }
    }

    #[test]
    fn fully_evidenced_low_risk_snapshot_is_eligible() {
        let assessment =
            evaluate_merge_policy(&policy(MergeExecutor::Direct), &evidence()).unwrap();
        assert_eq!(
            assessment.disposition,
            MergeDisposition::EligibleForAutomaticMerge
        );
        assert_eq!(assessment.reliability_score, Some(100));
    }
    #[test]
    fn score_cannot_cancel_required_gate_failure() {
        let mut input = evidence();
        input.gates[0].state = EvidenceState::Fail;
        let result = evaluate_merge_policy(&policy(MergeExecutor::Direct), &input).unwrap();
        assert_eq!(result.reliability_score, Some(100));
        assert_eq!(result.disposition, MergeDisposition::Blocked);
    }

    #[test]
    fn configured_required_check_without_exact_evidence_requires_human() {
        let mut input = evidence();
        input.gates.clear();
        let result = evaluate_merge_policy(&policy(MergeExecutor::Direct), &input).unwrap();
        assert_eq!(result.disposition, MergeDisposition::HumanRequired);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.contains("check `ci`"))
        );
    }
    #[test]
    fn unknown_and_stale_evidence_never_pass() {
        let mut input = evidence();
        input.risk[0].rating = None;
        assert_eq!(
            evaluate_merge_policy(&policy(MergeExecutor::Direct), &input)
                .unwrap()
                .disposition,
            MergeDisposition::HumanRequired
        );
        let mut input = evidence();
        input.current_subject.head_sha = "head-2".into();
        assert_eq!(
            evaluate_merge_policy(&policy(MergeExecutor::Direct), &input)
                .unwrap()
                .disposition,
            MergeDisposition::Blocked
        );
    }
    #[test]
    fn risk_weights_must_total_one_hundred() {
        let mut invalid = policy(MergeExecutor::Direct);
        invalid.risk_weights.change_impact = 29;
        assert!(evaluate_merge_policy(&invalid, &evidence()).is_err());
    }

    #[test]
    fn repository_specific_thresholds_produce_distinct_decisions() {
        let mut input = evidence();
        input.risk[0].rating = Some(2);
        let permissive = policy(MergeExecutor::Direct);
        let mut conservative = policy(MergeExecutor::Direct);
        conservative.minimum_reliability_score = 95;
        assert_eq!(
            evaluate_merge_policy(&permissive, &input)
                .unwrap()
                .disposition,
            MergeDisposition::EligibleForAutomaticMerge
        );
        assert_eq!(
            evaluate_merge_policy(&conservative, &input)
                .unwrap()
                .disposition,
            MergeDisposition::HumanRequired
        );
    }
    #[test]
    fn procedure_supports_body_then_direct_merge_then_verification() {
        let s = subject();
        let steps = vec![
            step(
                "body",
                vec![],
                MergeProcedureOperation::UpdatePullRequestBody {
                    expected_prior_body_digest: digest('4'),
                    approved_body_digest: digest('f'),
                },
            ),
            step(
                "merge",
                vec!["body"],
                MergeProcedureOperation::ExecuteMerge {
                    expected_head_sha: "head-1".into(),
                    base_guard_rule_digest: digest('9'),
                },
            ),
            step(
                "verify",
                vec!["merge"],
                MergeProcedureOperation::VerifyMergeCommit {
                    expected_trailers: vec!["Co-authored-by: Agent <agent@example.com>".into()],
                },
            ),
        ];
        assert!(
            build_merge_procedure(MergeMethod::Squash, MergeExecutor::Direct, steps, &s).is_ok()
        );
    }
    #[test]
    fn procedure_supports_repository_request_comment_and_rejects_wrong_body_scope() {
        let s = subject();
        let steps = vec![
            step(
                "request",
                vec![],
                MergeProcedureOperation::RequestMerge {
                    exact_comment: "/merge".into(),
                },
            ),
            step(
                "verify",
                vec!["request"],
                MergeProcedureOperation::VerifyMergeCommit {
                    expected_trailers: vec!["Co-authored-by: Agent <agent@example.com>".into()],
                },
            ),
        ];
        assert!(
            build_merge_procedure(MergeMethod::Merge, MergeExecutor::Request, steps, &s).is_ok()
        );
        let bad = vec![
            step(
                "body",
                vec![],
                MergeProcedureOperation::UpdatePullRequestBody {
                    expected_prior_body_digest: digest('4'),
                    approved_body_digest: digest('0'),
                },
            ),
            step(
                "request",
                vec!["body"],
                MergeProcedureOperation::RequestMerge {
                    exact_comment: "/merge".into(),
                },
            ),
            step(
                "verify",
                vec!["request"],
                MergeProcedureOperation::VerifyMergeCommit {
                    expected_trailers: vec!["Co-authored-by: Agent <agent@example.com>".into()],
                },
            ),
        ];
        assert!(
            build_merge_procedure(MergeMethod::Merge, MergeExecutor::Request, bad, &s).is_err()
        );
    }

    #[test]
    fn procedure_requires_each_effect_to_depend_on_its_predecessor() {
        let s = subject();
        let steps = vec![
            step(
                "body",
                vec![],
                MergeProcedureOperation::UpdatePullRequestBody {
                    expected_prior_body_digest: digest('4'),
                    approved_body_digest: digest('f'),
                },
            ),
            step(
                "request",
                vec![],
                MergeProcedureOperation::RequestMerge {
                    exact_comment: "/merge".into(),
                },
            ),
            step(
                "verify",
                vec!["request"],
                MergeProcedureOperation::VerifyMergeCommit {
                    expected_trailers: vec![],
                },
            ),
        ];
        assert!(
            build_merge_procedure(MergeMethod::Merge, MergeExecutor::Request, steps, &s).is_err()
        );
    }
}
