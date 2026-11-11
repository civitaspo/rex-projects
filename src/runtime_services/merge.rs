//! Fresh host-side merge evidence for an immutable MergeWorkItem.
//!
//! This module deliberately rebuilds the Forge adapter from the captured host environment for
//! each observation. It never trusts a MergeDecision claim as the source of current PR state.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::config::{AppliedConfig, RepositoryConfig};
use crate::domain::ids::Digest;
use crate::domain::types::{CommitConclusion, MergeExecutor, MergeMethod};
use crate::forge::github::GitHubCliForge;
use crate::forge::{Forge, ForgeObservation, PullRequestRef, RepositoryRef};
use crate::merge_policy::{EvidenceState, GateEvidence, MergeEvidenceSnapshot, MergePolicy};

const GH_TIMEOUT: Duration = Duration::from_secs(45);
const GH_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const GH_STDOUT_LIMIT: usize = 32 * 1024 * 1024;
const GH_STDERR_TAIL_LIMIT: usize = 64 * 1024;
const GH_PAGE_LIMIT: u16 = 100;

pub(super) struct RuntimeMergeEvidenceSource {
    applied_config: AppliedConfig,
    search_path: Vec<std::path::PathBuf>,
    host_environment: BTreeMap<OsString, OsString>,
    github_runner: std::sync::Arc<dyn crate::forge::github::GitHubCommandRunner>,
}

impl RuntimeMergeEvidenceSource {
    pub(super) fn prepare_body_proposal(
        &self,
        project_id: &crate::domain::ids::ProjectId,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        assessment_id: &crate::domain::ids::Digest,
        observation: &crate::merge_runtime::MergeEvidenceObservation,
    ) -> Result<crate::store::merge_work::PreparedMergeBodyProposal, String> {
        let publication_set_digest = subject.digest()?;
        if publication_set_digest != observation.publication_set_digest {
            return Err(
                "Merge body proposal observation belongs to another publication set".into(),
            );
        }
        let trailers = worker_authorship_trailers(&self.applied_config, project_id, accepted_plan)?;
        let prior_body_digest = Some(sha256_digest(
            observation
                .current_pr_body
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        )?);
        let exact_target_body = append_trailers(
            observation.current_pr_body.as_deref().unwrap_or_default(),
            &trailers,
        );
        let target_body_digest = sha256_digest(exact_target_body.as_bytes())?;
        Ok(crate::store::merge_work::PreparedMergeBodyProposal {
            schema_version: 1,
            assessment_id: assessment_id.clone(),
            publication_set_digest,
            prior_body_present: observation.current_pr_body.is_some(),
            prior_body_digest,
            exact_target_body,
            target_body_digest,
            expected_trailers: trailers,
        })
    }

    pub(super) fn prepare_merge_work_document(
        &self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        assessment: &crate::store::merge_work::TrustedMergeAssessment,
        intent: &crate::engine::orchestration::MergeIntentPayload,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<crate::store::merge_work::MergeWorkDocument, String> {
        use crate::engine::orchestration::MergeProcedureStepKind as AgentStep;
        use crate::merge_policy::{MergeProcedureOperation as Operation, MergeProcedureStep};

        assessment.validate()?;
        let observation = self
            .observe_publication_subject(subject, result)
            .map_err(|error| error.to_string())?;
        if observation.publication_set_digest != assessment.publication_set_digest
            || observation.evidence.subject != assessment.evidence.subject
            || observation.policy != assessment.policy
            || observation.baseline_issue_comments != assessment.baseline_issue_comments
        {
            return Err(
                "fresh Forge evidence no longer matches the exact trusted MergeAssessment".into(),
            );
        }
        if assessment.assessment.disposition == crate::merge_policy::MergeDisposition::Blocked {
            return Err("host MergeAssessment blocks this merge procedure".into());
        }

        let repository_id = crate::domain::ids::RepositoryId::parse(
            assessment.evidence.subject.repository_id.clone(),
        )?;
        let repository = self
            .applied_config
            .config
            .repositories
            .get(&repository_id)
            .ok_or("MergeIntent repository is absent from the applied configuration")?;
        let instruction_sources =
            instruction_sources(&self.applied_config, &repository_id, repository)?;
        let policy_digest = crate::forge::canonical_digest(&assessment.policy)
            .map_err(|error| error.to_string())?;
        if policy_digest != intent.policy_digest {
            return Err("MergeIntent policy digest differs from the host repository policy".into());
        }
        let current_body_present = observation.current_pr_body.is_some();
        let current_body = observation.current_pr_body.clone().unwrap_or_default();
        let current_body_digest = Some(sha256_digest(current_body.as_bytes())?);
        let proposal = assessment
            .prepared_body_proposal
            .as_ref()
            .ok_or("MergeIntent has no host-prepared PR body proposal")?;
        if current_body_present != proposal.prior_body_present
            || current_body_digest != proposal.prior_body_digest
            || proposal.prior_body_digest != assessment.evidence.subject.prepared_body_digest
        {
            return Err("PR body changed after its MergeAssessment".into());
        }
        let trailers = worker_authorship_trailers(
            &self.applied_config,
            &result.validated.binding.project_id,
            accepted_plan,
        )?;
        let target_body = proposal.exact_target_body.clone();
        if trailers != proposal.expected_trailers
            || append_trailers(&current_body, &trailers) != target_body
        {
            return Err(
                "host-prepared PR body proposal no longer matches repository authorship rules"
                    .into(),
            );
        }
        let target_digest = sha256_digest(target_body.as_bytes())?;
        if target_digest != proposal.target_body_digest
            || target_digest != intent.prepared_body_digest
        {
            return Err(
                "MergeIntent prepared body digest differs from the immutable host proposal".into(),
            );
        }
        let body_update_requested = intent
            .steps
            .iter()
            .any(|step| step.kind == AgentStep::UpdatePullRequestBody);
        if target_body != current_body && !body_update_requested {
            return Err(
                "MergeIntent omits the required exact PR body update for repository trailers"
                    .into(),
            );
        }
        let mut steps = Vec::with_capacity(intent.steps.len());
        let mut request_comment_proofs = Vec::new();
        for (index, claimed) in intent.steps.iter().enumerate() {
            let source =
                find_instruction_source(&instruction_sources, &claimed.instruction_reference)?;
            let key = match claimed.kind {
                AgentStep::UpdatePullRequestBody => "update_pull_request_body",
                AgentStep::RequestMerge => "request_merge",
                AgentStep::DirectMerge => "direct_merge",
                AgentStep::VerifyMergeCommit => "verify_merge_commit",
            };
            let operation = match claimed.kind {
                AgentStep::UpdatePullRequestBody if index == 0 => {
                    Operation::UpdatePullRequestBody {
                        expected_prior_body_digest: current_body_digest
                            .clone()
                            .ok_or("PR body update requires an observed current body digest")?,
                        approved_body_digest: target_digest.clone(),
                    }
                }
                AgentStep::RequestMerge => {
                    if assessment.policy.executor != MergeExecutor::Request {
                        return Err(
                            "request-merge step conflicts with the configured executor".into()
                        );
                    }
                    let command = trusted_request_command(source)?;
                    request_comment_proofs.push(command.1);
                    Operation::RequestMerge {
                        exact_comment: command.0,
                    }
                }
                AgentStep::DirectMerge => {
                    if assessment.policy.executor != MergeExecutor::Direct {
                        return Err(
                            "direct-merge step conflicts with the configured executor".into()
                        );
                    }
                    let base_guard_rule_digest = assessment
                        .evidence
                        .subject
                        .base_guard_digest
                        .clone()
                        .ok_or("direct merge has no trusted base-guard digest")?;
                    Operation::ExecuteMerge {
                        expected_head_sha: assessment.evidence.subject.head_sha.clone(),
                        base_guard_rule_digest,
                    }
                }
                AgentStep::VerifyMergeCommit if index + 1 == intent.steps.len() => {
                    Operation::VerifyMergeCommit {
                        expected_trailers: trailers.clone(),
                    }
                }
                _ => {
                    return Err(
                        "MergeIntent procedure has an unsupported or out-of-order step".into(),
                    );
                }
            };
            steps.push(MergeProcedureStep {
                key: format!("{index}-{key}"),
                prerequisites: steps
                    .last()
                    .map(|step: &MergeProcedureStep| vec![step.key.clone()])
                    .unwrap_or_default(),
                operation,
                instruction_digest: assessment.evidence.subject.instruction_digest.clone(),
            });
        }
        for check in &intent.post_merge_verification {
            let _ = find_instruction_source(&instruction_sources, &check.instruction_reference)?;
        }
        if intent.post_merge_verification.iter().any(|check| {
            check.kind
                != crate::engine::orchestration::PostMergeVerificationKind::MergeCommitRecorded
        }) || !intent.post_merge_verification.iter().any(|check| {
            check.kind
                == crate::engine::orchestration::PostMergeVerificationKind::MergeCommitRecorded
        }) {
            return Err(
                "host currently supports only verified merge-commit post-merge evidence".into(),
            );
        }
        let procedure = crate::merge_policy::build_merge_procedure(
            assessment.policy.method,
            assessment.policy.executor,
            steps,
            &assessment.evidence.subject,
        )?;
        let authority = crate::merge_executor::ResolvedMergeAuthority {
            policy_digest: policy_digest.clone(),
            instruction_digest: assessment.evidence.subject.instruction_digest.clone(),
            sources: instruction_sources,
            request_comment_proofs,
            execution_time_base_guard: assessment.evidence.execution_time_base_guard,
            base_guard_digest: assessment.evidence.subject.base_guard_digest.clone(),
        };
        let prepared_body = procedure
            .steps
            .iter()
            .any(|step| matches!(step.operation, Operation::UpdatePullRequestBody { .. }))
            .then_some(target_body);
        let document = crate::store::merge_work::MergeWorkDocument {
            schema_version: 1,
            assessment_id: assessment.assessment_id.as_str().to_owned(),
            assessment_evidence_id: assessment.source_evidence_id.clone(),
            assessment_result_digest: assessment.source_result_digest.clone(),
            intent_evidence_id: result.receipt.evidence_id().to_owned(),
            intent_result_digest: result.validated.result_digest.clone(),
            policy: assessment.policy.clone(),
            evidence: assessment.evidence.clone(),
            baseline_issue_comments: assessment.baseline_issue_comments.clone(),
            assessment: assessment.assessment.clone(),
            intent: intent.clone(),
            authority,
            procedure,
            prepared_body,
        };
        document.validate_for(
            &assessment.configuration_digest,
            assessment.assessment_id.as_str(),
        )?;
        Ok(document)
    }

    pub(super) fn observe_publication_subject(
        &self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<
        crate::merge_runtime::MergeEvidenceObservation,
        crate::merge_runtime::MergeObservationError,
    > {
        let fact = subject
            .publications
            .first()
            .ok_or("MergeDecision currently requires one published pull request")?;
        let repo = self
            .applied_config
            .config
            .repositories
            .get(&fact.repository_id)
            .ok_or("accepted publication repository is absent from the applied configuration")?;
        if repo.forge != "github" {
            return Err(
                "the configured forge adapter does not support MergeDecision observation yet"
                    .into(),
            );
        }
        let gh = crate::process::resolve_executable(Path::new("gh"), &self.search_path)
            .ok_or("configured host environment has no GitHub CLI")?;
        let adapter = GitHubCliForge::new(
            self.github_runner.clone(),
            gh,
            "github.com",
            self.host_environment.clone(),
            GH_TIMEOUT,
            GH_SHUTDOWN_GRACE,
            GH_STDOUT_LIMIT,
            GH_STDERR_TAIL_LIMIT,
            GH_PAGE_LIMIT,
        )
        .map_err(|error| error.to_string())?;
        self.observe_publication_subject_with_instruction_digest(
            subject,
            &result.validated.binding.instruction_digest,
            &adapter,
        )
    }

    pub(super) fn observe_recovery_publication_subject(
        &self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        instruction_digest: &Digest,
    ) -> Result<
        crate::merge_runtime::MergeEvidenceObservation,
        crate::merge_runtime::MergeObservationError,
    > {
        let gh = crate::process::resolve_executable(Path::new("gh"), &self.search_path)
            .ok_or("configured host environment has no GitHub CLI")?;
        let adapter = GitHubCliForge::new(
            self.github_runner.clone(),
            gh,
            "github.com",
            self.host_environment.clone(),
            GH_TIMEOUT,
            GH_SHUTDOWN_GRACE,
            GH_STDOUT_LIMIT,
            GH_STDERR_TAIL_LIMIT,
            GH_PAGE_LIMIT,
        )
        .map_err(|error| error.to_string())?;
        self.observe_publication_subject_with_instruction_digest(
            subject,
            instruction_digest,
            &adapter,
        )
    }

    fn observe_publication_subject_with_instruction_digest(
        &self,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        instruction_digest: &Digest,
        adapter: &impl Forge,
    ) -> Result<
        crate::merge_runtime::MergeEvidenceObservation,
        crate::merge_runtime::MergeObservationError,
    > {
        if subject.publications.len() != 1 {
            return Err("MergeDecision currently requires exactly one published pull request per assessment".into());
        }
        let fact = &subject.publications[0];
        let repo_id = fact.repository_id.clone();
        let repo = self
            .applied_config
            .config
            .repositories
            .get(&repo_id)
            .ok_or("accepted publication repository is absent from the applied configuration")?;
        let (owner, name) = github_repository(&repo.clone_url)?;
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                owner: owner.clone(),
                name: name.clone(),
                expected_id: None,
            },
            number: fact.pull_request_number,
            expected_node_id: Some(fact.pull_request_node_id.clone()),
        };
        let observed = adapter.observe(&pull).map_err(|error| match error.kind {
            crate::forge::ForgeFailureKind::Permanent => {
                crate::merge_runtime::MergeObservationError::Permanent(error.message)
            }
            crate::forge::ForgeFailureKind::Retryable(failure) => {
                crate::merge_runtime::MergeObservationError::Retryable(failure)
            }
        })?;
        let repository = match &observed.repository {
            crate::forge::Observed::Complete { value, .. } => value,
            crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone().into()),
        };
        let pr = match &observed.pull_request {
            crate::forge::Observed::Complete { value, .. } => value,
            crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone().into()),
        };
        if pr.repository_id != repository.id
            || pr.number != fact.pull_request_number
            || pr.node_id != fact.pull_request_node_id
            || pr.head_sha != fact.published_head
            || pr.head_sha != fact.pull_request_head
            || pr.merged
            || pr.draft
            || pr.state != crate::forge::PullRequestState::Open
        {
            return Err(
                "accepted publication no longer identifies the current open pull request head"
                    .into(),
            );
        }
        if let Some(failure) = observed.retryable_failure() {
            return Err(crate::merge_runtime::MergeObservationError::Retryable(
                failure,
            ));
        }
        let digests = observed
            .semantic_digests()
            .map_err(|error| error.to_string())?;
        let policy = policy_for(repo);
        let gates = host_gates(repo, &observed, &pull)?;
        let instruction_digest =
            merge_instruction_digest(&self.applied_config, &repo_id, repo, instruction_digest)?;
        let hooks_digest = crate::forge::canonical_digest(&repo.rex_projects_hooks)
            .map_err(|error| error.to_string())?;
        let subject_digest = subject
            .digest()
            .map_err(|error| format!("accepted publication subject digest failed: {error}"))?;
        let merge_subject = crate::merge_policy::MergeSubject {
            repository_id: repo_id.as_str().to_owned(),
            forge: "github".into(),
            forge_host: "github.com".into(),
            forge_repository_id: repository.id,
            pull_request_id: pr.number.to_string(),
            pull_request_node_id: pr.node_id.clone(),
            head_sha: pr.head_sha.clone(),
            base_ref: pr.base_ref.clone(),
            base_sha: pr.base_sha.clone(),
            config_digest: self.applied_config.digest.clone(),
            instruction_digest,
            hooks_digest,
            remote_checks_digest: digests.checks,
            diff_digest: digests.diff,
            merge_comments_digest: digests.merge_comments,
            base_guard_digest: Some(digests.base_guard),
            review_digest: digests.reviews,
            prepared_body_digest: Some(sha256_digest(
                pr.body.as_deref().unwrap_or_default().as_bytes(),
            )?),
        };
        let baseline_issue_comments = match &observed.issue_comments {
            crate::forge::Observed::Complete { value, .. } => {
                let mut comments = value.clone();
                comments.sort_by_key(|comment| comment.id);
                comments
            }
            crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone().into()),
        };
        let evidence = MergeEvidenceSnapshot {
            subject: merge_subject.clone(),
            current_subject: merge_subject,
            gates,
            risk: Vec::new(),
            confidence: crate::merge_policy::Confidence::Low,
            human_review_required: !policy.auto_merge_enabled,
            execution_time_base_guard: execution_time_base_guard(repo, &observed),
        };
        let reference = format!("https://github.com/{owner}/{name}/pull/{}", pr.number);
        let publication_set_digest = subject_digest;
        Ok(crate::merge_runtime::MergeEvidenceObservation {
            publication_set_digest,
            pull_request_reference: reference,
            current_pr_body: pr.body.clone(),
            evidence,
            policy,
            baseline_issue_comments,
        })
    }

    pub(super) fn new(
        applied_config: AppliedConfig,
        search_path: Vec<std::path::PathBuf>,
        host_environment: BTreeMap<OsString, OsString>,
    ) -> Self {
        Self {
            applied_config,
            search_path,
            host_environment,
            github_runner: std::sync::Arc::new(crate::forge::github::SystemGitHubCommandRunner),
        }
    }

    #[cfg(test)]
    fn with_github_runner(
        applied_config: AppliedConfig,
        search_path: Vec<std::path::PathBuf>,
        host_environment: BTreeMap<OsString, OsString>,
        github_runner: std::sync::Arc<dyn crate::forge::github::GitHubCommandRunner>,
    ) -> Self {
        Self {
            applied_config,
            search_path,
            host_environment,
            github_runner,
        }
    }

    fn observe_merge_item(
        &self,
        item: &crate::store::merge_work::MergeWorkItem,
    ) -> Result<(MergeEvidenceSnapshot, ForgeObservation), String> {
        let repo_id = crate::domain::ids::RepositoryId::parse(
            item.document.evidence.subject.repository_id.clone(),
        )?;
        let repo = self
            .applied_config
            .config
            .repositories
            .get(&repo_id)
            .ok_or("merge work repository is missing from the active configuration")?;
        if self.applied_config.digest != item.configuration_digest {
            return Err("merge work item belongs to a stale Project configuration".into());
        }
        let (owner, name) = github_repository(&repo.clone_url)?;
        let gh = crate::process::resolve_executable(Path::new("gh"), &self.search_path)
            .ok_or("configured host environment has no GitHub CLI")?;
        let adapter = GitHubCliForge::new(
            self.github_runner.clone(),
            gh,
            "github.com",
            self.host_environment.clone(),
            GH_TIMEOUT,
            GH_SHUTDOWN_GRACE,
            GH_STDOUT_LIMIT,
            GH_STDERR_TAIL_LIMIT,
            GH_PAGE_LIMIT,
        )
        .map_err(|error| error.to_string())?;
        let subject = &item.document.evidence.subject;
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: subject.forge_host.clone(),
                owner,
                name,
                expected_id: Some(subject.forge_repository_id),
            },
            number: subject
                .pull_request_id
                .parse()
                .map_err(|_| "MergeWorkItem PR identity is invalid")?,
            expected_node_id: Some(subject.pull_request_node_id.clone()),
        };
        let observed = adapter.observe(&pull).map_err(|error| error.to_string())?;
        observed
            .verify_subject_identity_core(&pull, subject)
            .map_err(|error| error.to_string())?;
        let mut fresh = item.document.evidence.clone();
        let digests = observed
            .semantic_digests()
            .map_err(|error| error.to_string())?;
        let pr = match &observed.pull_request {
            crate::forge::Observed::Complete { value, .. } => value,
            crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
        };
        let mut current = subject.clone();
        current.head_sha = pr.head_sha.clone();
        current.base_ref = pr.base_ref.clone();
        current.base_sha = pr.base_sha.clone();
        current.diff_digest = digests.diff;
        current.remote_checks_digest = digests.checks;
        current.review_digest = digests.reviews;
        current.merge_comments_digest = digests.merge_comments;
        current.base_guard_digest = Some(digests.base_guard);
        current.prepared_body_digest = Some(sha256_digest(
            pr.body.as_deref().unwrap_or_default().as_bytes(),
        )?);
        fresh.current_subject = current.clone();
        fresh.subject = current;
        fresh.gates = host_gates(repo, &observed, &pull)?;
        fresh.execution_time_base_guard = execution_time_base_guard(repo, &observed);
        // Risk, confidence, and the conservative human-review bit are retained from the
        // immutable host assessment. Only live forge evidence is refreshed here.
        Ok((fresh, observed))
    }

    pub(super) fn effect_handler(self: &std::sync::Arc<Self>) -> MergeEffectHandler {
        MergeEffectHandler {
            source: self.clone(),
        }
    }

    fn forge_for_item(
        &self,
        item: &crate::store::merge_work::MergeWorkItem,
    ) -> Result<
        (
            GitHubCliForge<std::sync::Arc<dyn crate::forge::github::GitHubCommandRunner>>,
            PullRequestRef,
        ),
        String,
    > {
        let subject = &item.document.evidence.subject;
        let repo_id = crate::domain::ids::RepositoryId::parse(subject.repository_id.clone())?;
        let repo = self
            .applied_config
            .config
            .repositories
            .get(&repo_id)
            .ok_or("merge work repository is missing from the active configuration")?;
        let (owner, name) = github_repository(&repo.clone_url)?;
        let gh = crate::process::resolve_executable(Path::new("gh"), &self.search_path)
            .ok_or("configured host environment has no GitHub CLI")?;
        let adapter = GitHubCliForge::new(
            self.github_runner.clone(),
            gh,
            "github.com",
            self.host_environment.clone(),
            GH_TIMEOUT,
            GH_SHUTDOWN_GRACE,
            GH_STDOUT_LIMIT,
            GH_STDERR_TAIL_LIMIT,
            GH_PAGE_LIMIT,
        )
        .map_err(|error| error.to_string())?;
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: subject.forge_host.clone(),
                owner,
                name,
                expected_id: Some(subject.forge_repository_id),
            },
            number: subject
                .pull_request_id
                .parse()
                .map_err(|_| "MergeWorkItem PR identity is invalid")?,
            expected_node_id: Some(subject.pull_request_node_id.clone()),
        };
        Ok((adapter, pull))
    }

    fn run_merge_step(
        &self,
        mode: crate::effects::EffectMode,
        request: &crate::effects::EffectRequest,
        context: &mut crate::effects::EffectContext<'_>,
    ) -> Result<crate::effects::EffectObservation, String> {
        use crate::effects::{EffectKind, EffectObservation};
        use crate::merge_executor::{
            MergeProcedureExecutor, MergeStepEffectRequest, StepIntent, StepOutcome,
        };

        if request.intent.kind != crate::engine::reducer::effect_name(&EffectKind::Merge)
            || request.intent.subject_type != "ticket_run"
            || request.intent.expected_revision.is_none()
        {
            return Err("merge effect has the wrong durable subject or revision".into());
        }
        let step_request: MergeStepEffectRequest =
            serde_json::from_str(&request.intent.request_json)
                .map_err(|error| format!("merge step request is invalid: {error}"))?;
        if step_request.schema_version != 1
            || step_request.awaiting_merge_revision.0
                != request.intent.expected_revision.unwrap_or_default()
        {
            return Err("merge step request differs from its durable outbox revision".into());
        }
        let ticket_run_id =
            crate::domain::ids::TicketRunId::parse(request.intent.subject_id.clone())
                .map_err(|error| error.to_string())?;
        let work_item = context
            .store
            .merge_work_item(
                &request.intent.project_id,
                &ticket_run_id,
                step_request.awaiting_merge_revision,
            )?
            .ok_or("merge work item for durable step is absent")?;
        if work_item.work_id != step_request.work_id
            || work_item.assessed_revision != step_request.assessed_revision
            || work_item.awaiting_merge_revision != step_request.awaiting_merge_revision
        {
            return Err("merge step does not match its immutable MergeWorkItem".into());
        }
        let mut offset = 0;
        let current = loop {
            let page = context.store.active_ticket_runs_page_for_project(
                context.owner_generation,
                &request.intent.project_id,
                offset,
                256,
            )?;
            let page_len = page.len();
            if let Some(run) = page
                .into_iter()
                .find(|run| run.ticket_run_id == ticket_run_id)
            {
                break run;
            }
            if page_len < 256 {
                return Err("TicketRun for merge effect is no longer active".into());
            }
            offset += page_len as u64;
        };
        if current.phase != crate::engine::reducer::Phase::AwaitingMerge
            || current.revision != step_request.awaiting_merge_revision.0
            || current.project_id != request.intent.project_id
        {
            return Err("merge effect is stale or outside AwaitingMerge".into());
        }
        let request_id = crate::domain::ids::HumanRequestId::parse(format!(
            "merge-review-{}",
            work_item.document.intent_evidence_id
        ))?;
        let now = u64::try_from(context.now_unix)
            .map_err(|_| "controller clock is before the Unix epoch")?;
        let Some(accepted) =
            context
                .store
                .accepted_merge_work_review_approval(&request_id, &work_item, now)?
        else {
            return Err("exact human MergeWorkItem approval is absent, stale, or rejected".into());
        };
        let assessment = &work_item.document.assessment;
        // A body effect can have crossed the provider boundary before the
        // execution-time base guard rejected our local attempt. Reconciliation
        // must still run against the immutable operation key even if the base
        // has moved since assessment; no new mutation is allowed in this mode.
        let reconcile_exact_first_body = mode == crate::effects::EffectMode::Reconcile
            && step_request.prior_receipts.is_empty()
            && work_item
                .document
                .procedure
                .steps
                .first()
                .is_some_and(|step| {
                    step.key == step_request.step_key
                        && matches!(
                            step.operation,
                            crate::merge_policy::MergeProcedureOperation::UpdatePullRequestBody { .. }
                        )
                });
        let evidence_now = if reconcile_exact_first_body {
            work_item.document.evidence.clone()
        } else {
            self.observe_merge_item(&work_item)?.0
        };
        let (forge, pull) = self.forge_for_item(&work_item)?;
        let approval = crate::merge_executor::HumanMergeApproval::from_host_validated_receipt(
            accepted.receipt(),
            &request_id,
            accepted.receipt().subject_digest(),
            &work_item.document.policy,
            assessment,
            &work_item.document.procedure,
        )
        .map_err(|error| error.to_string())?;
        let step = work_item
            .document
            .procedure
            .steps
            .iter()
            .find(|step| step.key == step_request.step_key)
            .ok_or("merge step key is absent from the approved procedure")?;
        let actor = if matches!(
            step.operation,
            crate::merge_policy::MergeProcedureOperation::RequestMerge { .. }
        ) {
            forge
                .current_actor(&pull.repository)
                .map_err(|error| error.to_string())?
        } else {
            String::new()
        };
        let attempt_started_unix = u64::try_from(request.created_at_unix)
            .map_err(|_| "merge effect creation time is invalid")?;
        let intent = StepIntent {
            operation_key: format!("{}:{}", request.intent.operation_id, step.key),
            authenticated_actor: actor,
            attempt_started_unix,
            exact_prepared_body: work_item.document.prepared_body.clone(),
        };
        if mode == crate::effects::EffectMode::Reconcile {
            if matches!(
                step.operation,
                crate::merge_policy::MergeProcedureOperation::VerifyMergeCommit { .. }
            ) {
                let outcome = MergeProcedureExecutor::new(forge)
                    .execute_one(
                        &pull,
                        &work_item.document.policy,
                        assessment,
                        &work_item.document.evidence,
                        &evidence_now,
                        Some(&approval),
                        &work_item.document.authority,
                        &work_item.document.procedure,
                        &work_item.document.baseline_issue_comments,
                        &step_request.step_key,
                        &intent,
                        &step_request.prior_receipts,
                    )
                    .map_err(|error| error.to_string())?;
                return match outcome {
                    StepOutcome::Verified(verified) => Ok(EffectObservation::Applied {
                        receipt: crate::store::canonical_json(&verified)?,
                    }),
                    StepOutcome::Pending(message) => {
                        Ok(EffectObservation::Pending { receipt: message })
                    }
                    StepOutcome::Effect { .. } => {
                        Err("verification step unexpectedly produced a mutation".into())
                    }
                };
            }
            let live = forge.observe(&pull).map_err(|error| error.to_string())?;
            let live_body = match live.pull_request {
                crate::forge::Observed::Complete { value, .. } => value.body.unwrap_or_default(),
                crate::forge::Observed::Unknown { reason, .. } => {
                    return Ok(EffectObservation::Pending { receipt: reason });
                }
            };
            let step_effect = crate::merge_executor::reconciliation_intent(
                &work_item,
                step,
                &pull,
                &intent,
                accepted.receipt().request_expires_at_unix(),
                attempt_started_unix,
                &live_body,
            )?;
            return match MergeProcedureExecutor::new(forge)
                .reconcile_one(&step_effect)
                .map_err(|error| error.to_string())?
            {
                crate::forge::Reconciliation::Recovered(acknowledgement) => {
                    let certainty = acknowledgement.certainty;
                    let receipt = crate::merge_executor::MergeStepReceipt {
                        step_key: step.key.clone(),
                        operation_key: intent.operation_key,
                        certainty,
                        request_digest: step_effect.request_digest.clone(),
                        effect_intent: step_effect,
                        acknowledgement,
                    };
                    Ok(EffectObservation::Applied {
                        receipt: crate::store::canonical_json(&receipt)?,
                    })
                }
                crate::forge::Reconciliation::DefinitelyAbsent => {
                    Ok(EffectObservation::AuthoritativelyAbsent {
                        proof: crate::effects::AbsentProof::from_authoritative_lookup(
                            EffectKind::Merge,
                            request,
                            "GitHub Forge reconciliation",
                            format!(
                                "no matching `{}` mutation exists for the exact operation key",
                                step.key
                            ),
                        )?,
                    })
                }
                crate::forge::Reconciliation::Unknown(reason) => {
                    Ok(EffectObservation::Pending { receipt: reason })
                }
            };
        }
        let outcome = MergeProcedureExecutor::new(forge)
            .execute_one(
                &pull,
                &work_item.document.policy,
                assessment,
                &work_item.document.evidence,
                &evidence_now,
                Some(&approval),
                &work_item.document.authority,
                &work_item.document.procedure,
                &work_item.document.baseline_issue_comments,
                &step_request.step_key,
                &intent,
                &step_request.prior_receipts,
            )
            .map_err(|error| error.to_string())?;
        match outcome {
            StepOutcome::Effect {
                effect_intent,
                acknowledgement,
            } => {
                let certainty = acknowledgement.certainty;
                let step_receipt = crate::merge_executor::MergeStepReceipt {
                    step_key: step.key.clone(),
                    operation_key: intent.operation_key,
                    certainty,
                    request_digest: effect_intent.request_digest.clone(),
                    effect_intent: *effect_intent,
                    acknowledgement,
                };
                match step_receipt.certainty {
                    crate::forge::EffectCertainty::Applied
                    | crate::forge::EffectCertainty::Recovered => Ok(EffectObservation::Applied {
                        receipt: crate::store::canonical_json(&step_receipt)?,
                    }),
                    crate::forge::EffectCertainty::DefinitelyAbsent => {
                        Ok(EffectObservation::Rejected {
                            receipt: crate::store::canonical_json(&step_receipt)?,
                        })
                    }
                    crate::forge::EffectCertainty::Unknown => Ok(EffectObservation::Pending {
                        receipt: crate::store::canonical_json(&step_receipt)?,
                    }),
                }
            }
            StepOutcome::Verified(verified) => Ok(EffectObservation::Applied {
                receipt: crate::store::canonical_json(&verified)?,
            }),
            StepOutcome::Pending(message) => Ok(EffectObservation::Pending { receipt: message }),
        }
    }
}

pub(super) struct MergeEffectHandler {
    source: std::sync::Arc<RuntimeMergeEvidenceSource>,
}

impl crate::effects::EffectHandler for MergeEffectHandler {
    fn kind(&self) -> crate::effects::EffectKind {
        crate::effects::EffectKind::Merge
    }

    fn handle(
        &self,
        mode: crate::effects::EffectMode,
        request: &crate::effects::EffectRequest,
        context: &mut crate::effects::EffectContext<'_>,
    ) -> Result<crate::effects::EffectObservation, String> {
        self.source.run_merge_step(mode, request, context)
    }
}

fn instruction_sources(
    applied: &AppliedConfig,
    repository_id: &crate::domain::ids::RepositoryId,
    repository: &RepositoryConfig,
) -> Result<BTreeMap<String, crate::merge_executor::TrustedInstructionSource>, String> {
    use crate::domain::types::Role;
    let mut files = repository.instruction_files.clone();
    files.extend(
        repository
            .role_instruction_files
            .get(&Role::MergeDecision)
            .into_iter()
            .flatten()
            .cloned(),
    );
    files.extend(repository.merge.instruction_files.clone());
    files.sort();
    files.dedup();
    let mut sources = BTreeMap::new();
    if let Some(instructions) = &repository.merge.instructions {
        let key = format!("repository:{repository_id}:merge");
        sources.insert(
            key.clone(),
            crate::merge_executor::TrustedInstructionSource {
                key,
                digest: sha256_digest(instructions.as_bytes())?,
                bytes: instructions.as_bytes().to_vec(),
            },
        );
    }
    for path in files {
        let source = applied.source_files.iter().find(|source| source.path == path)
            .ok_or_else(|| format!("configured merge instruction `{path}` for repository `{repository_id}` is absent from the applied source manifest"))?;
        let bytes = source.contents.as_bytes().to_vec();
        sources.insert(
            path.clone(),
            crate::merge_executor::TrustedInstructionSource {
                key: path,
                digest: source.sha256.clone(),
                bytes,
            },
        );
    }
    if sources.is_empty() {
        return Err("MergeIntent has no trusted repository instruction sources".into());
    }
    Ok(sources)
}

fn find_instruction_source<'a>(
    sources: &'a BTreeMap<String, crate::merge_executor::TrustedInstructionSource>,
    reference: &str,
) -> Result<&'a crate::merge_executor::TrustedInstructionSource, String> {
    let (name, fragment) = reference
        .split_once('#')
        .ok_or("MergeIntent instruction reference must name a source fragment")?;
    if fragment.trim().is_empty() {
        return Err("MergeIntent instruction reference has an empty fragment".into());
    }
    let matches = sources
        .values()
        .filter(|source| {
            source.key == name
                || source.key.strip_prefix("inline:") == Some(name)
                || Path::new(&source.key)
                    .file_name()
                    .and_then(|value| value.to_str())
                    == Some(name)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(
            "MergeIntent instruction reference does not identify exactly one trusted source".into(),
        );
    }
    Ok(matches[0])
}

fn trusted_request_command(
    source: &crate::merge_executor::TrustedInstructionSource,
) -> Result<(String, crate::merge_executor::RequestCommentProof), String> {
    let text = std::str::from_utf8(&source.bytes)
        .map_err(|_| "trusted merge instructions are not UTF-8")?;
    let mut offsets = text
        .match_indices("/merge")
        .filter_map(|(offset, command)| {
            let line_start = text[..offset].rfind('\n').map_or(0, |value| value + 1);
            let line_end = text[offset..]
                .find('\n')
                .map_or(text.len(), |value| offset + value);
            (&text[line_start..line_end] == command).then_some(offset)
        });
    let command_offset = offsets
        .next()
        .ok_or("trusted instructions contain no literal `/merge` command")?;
    if offsets.next().is_some() {
        return Err("trusted instructions contain multiple ambiguous `/merge` commands".into());
    }
    let byte_start = text[..command_offset]
        .rfind('\n')
        .map_or(0, |value| value + 1);
    Ok((
        "/merge".into(),
        crate::merge_executor::RequestCommentProof {
            source_key: source.key.clone(),
            source_digest: source.digest.clone(),
            byte_start,
            exact_comment: "/merge".into(),
        },
    ))
}

pub(super) fn worker_authorship_trailers(
    applied: &AppliedConfig,
    project_id: &crate::domain::ids::ProjectId,
    plan: &crate::engine::orchestration::WorkPlan,
) -> Result<Vec<String>, String> {
    let project = applied
        .config
        .projects
        .get(project_id)
        .ok_or("MergeIntent Project is absent from the applied configuration")?;
    let worker_profile = project
        .roles
        .get(&crate::domain::types::Role::Worker)
        .ok_or("MergeIntent Project has no Worker profile")?;
    let profile = applied
        .profiles
        .get(worker_profile)
        .ok_or("MergeIntent Worker profile is absent from the applied manifest")?;
    let trailer = match profile.adapter {
        crate::domain::types::AgentAdapter::Codex => "Co-authored-by: Codex <noreply@openai.com>",
        crate::domain::types::AgentAdapter::ClaudeCode => {
            "Co-authored-by: Claude <noreply@anthropic.com>"
        }
    };
    if !plan.nodes.iter().any(|node| !node.investigation) {
        return Err("MergeIntent accepted plan has no implementation Worker node".into());
    }
    Ok(vec![trailer.to_owned()])
}

pub(super) fn append_trailers(body: &str, trailers: &[String]) -> String {
    let mut lines = body.lines().map(str::to_owned).collect::<Vec<_>>();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if lines.ends_with(trailers) {
        lines.truncate(lines.len() - trailers.len());
        while lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
    }
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push_str("\n\n");
    }
    body.push_str(&trailers.join("\n"));
    body
}

pub(super) fn policy_for(repo: &RepositoryConfig) -> MergePolicy {
    MergePolicy {
        auto_merge_enabled: repo.merge.auto_merge,
        minimum_reliability_score: repo.merge.minimum_reliability_score,
        method: repo.merge.method.unwrap_or(MergeMethod::Squash),
        executor: repo.merge.executor.unwrap_or(MergeExecutor::Direct),
        required_checks: repo.merge.required_checks.clone(),
        required_approving_reviews: (repo.merge.required_approvals > 0)
            .then_some(u64::from(repo.merge.required_approvals)),
        risk_weights: crate::merge_policy::RiskWeights::default(),
    }
}

fn host_gates(
    repo: &RepositoryConfig,
    observed: &ForgeObservation,
    pull: &PullRequestRef,
) -> Result<Vec<GateEvidence>, String> {
    let pr = match &observed.pull_request {
        crate::forge::Observed::Complete { value, .. } => value,
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    let checks = match &observed.check_runs {
        crate::forge::Observed::Complete { value, .. } => value,
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    let statuses = match &observed.statuses {
        crate::forge::Observed::Complete { value, .. } => value,
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    let reviews = match &observed.reviews {
        crate::forge::Observed::Complete { value, .. } => value,
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    let protection = match &observed.branch_protection {
        crate::forge::Observed::Complete { value, .. } => value,
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    let allowed = repo
        .merge
        .allowed_check_conclusions
        .iter()
        .map(conclusion_name)
        .collect::<Vec<_>>();
    let mut gates = Vec::new();
    for required in &repo.merge.required_checks {
        let check_rows = checks
            .iter()
            .filter(|row| row.name == *required && row.head_sha == pr.head_sha)
            .collect::<Vec<_>>();
        let status_rows = statuses
            .iter()
            .filter(|row| row.context == *required && row.sha == pr.head_sha)
            .collect::<Vec<_>>();
        let latest_checks = latest_check_runs(&check_rows);
        let check_state = if check_rows.is_empty() {
            None
        } else {
            Some(match latest_checks {
                None => EvidenceState::Unknown,
                Some(latest)
                    if latest.iter().any(|row| {
                        row.status != "completed"
                            || !row
                                .conclusion
                                .as_deref()
                                .is_some_and(|conclusion| allowed.contains(&conclusion))
                    }) =>
                {
                    EvidenceState::Fail
                }
                Some(_) => EvidenceState::Pass,
            })
        };
        let (status_state, status_uncertainty) = if status_rows.is_empty() {
            (None, None)
        } else {
            match commit_status_state(&status_rows) {
                Ok(state) => (Some(state), None),
                Err(reason) => (Some(EvidenceState::Unknown), Some(reason)),
            }
        };
        let state = match (check_state, status_state) {
            (Some(EvidenceState::Fail), _) | (_, Some(EvidenceState::Fail)) => EvidenceState::Fail,
            (Some(EvidenceState::Unknown), _) | (_, Some(EvidenceState::Unknown)) => {
                EvidenceState::Unknown
            }
            (Some(EvidenceState::Pass), _) | (_, Some(EvidenceState::Pass)) => EvidenceState::Pass,
            (None, None) => EvidenceState::Unknown,
        };
        gates.push(GateEvidence {
            key: format!("check:{required}"),
            state,
            required: true,
            detail: status_uncertainty
                .map(|reason| format!("Commit Status evidence is ambiguous: {reason}"))
                .or_else(|| {
                    (check_state == Some(EvidenceState::Unknown))
                        .then(|| "Check Run workflow evidence is incomplete or ambiguous".into())
                })
                .unwrap_or_else(|| format!("observed required check at head {}", pr.head_sha)),
        });
    }
    if repo.merge.required_approvals > 0 {
        let (approval_state, approvals, uncertainty) =
            current_head_approval_gate(reviews, &pr.head_sha, repo.merge.required_approvals);
        gates.push(GateEvidence {
            key: "approvals".into(),
            state: approval_state,
            required: true,
            detail: uncertainty.unwrap_or_else(|| {
                format!("{approvals} distinct latest approvals at exact current head")
            }),
        });
    }
    gates.push(GateEvidence {
        key: "pull_request_open".into(),
        state: if pr.state == crate::forge::PullRequestState::Open && !pr.merged && !pr.draft {
            EvidenceState::Pass
        } else {
            EvidenceState::Fail
        },
        required: true,
        detail: format!("PR {} state checked at current head", pull.number),
    });
    let unresolved = match &observed.review_threads {
        crate::forge::Observed::Complete { value, .. } => {
            value.iter().any(|thread| !thread.is_resolved)
        }
        crate::forge::Observed::Unknown { reason, .. } => return Err(reason.clone()),
    };
    gates.push(GateEvidence {
        key: "review_threads_resolved".into(),
        state: if unresolved {
            EvidenceState::Fail
        } else {
            EvidenceState::Pass
        },
        required: true,
        detail: if unresolved {
            "one or more review threads remain unresolved".into()
        } else {
            "all observed review threads are resolved".into()
        },
    });
    let _ = protection;
    Ok(gates)
}

fn commit_status_state(
    rows: &[&crate::forge::CommitStatus],
) -> Result<EvidenceState, &'static str> {
    let Some(freshest) = rows
        .iter()
        .map(|row| row.observation.as_ref())
        .collect::<Option<Vec<_>>>()
    else {
        return Err("freshness metadata (ID, timestamp, or source order) is missing or invalid");
    };
    let mut ids = std::collections::BTreeSet::new();
    let mut ordinals = std::collections::BTreeSet::new();
    if freshest
        .iter()
        .any(|observation| observation.created_at.is_empty())
    {
        return Err("status timestamp is missing");
    }
    if freshest
        .iter()
        .any(|observation| !ids.insert(observation.status_id))
    {
        return Err("status identity is duplicated");
    }
    if freshest
        .iter()
        .any(|observation| !ordinals.insert(observation.observed_ordinal))
    {
        return Err("source order is duplicated");
    }
    let Some(newest_ordinal) = freshest
        .iter()
        .map(|observation| observation.observed_ordinal)
        .min()
    else {
        return Err("freshest status could not be identified");
    };
    let mut newest = rows
        .iter()
        .zip(&freshest)
        .filter(|(_, observation)| observation.observed_ordinal == newest_ordinal);
    let Some((newest_row, newest_observation)) = newest.next() else {
        return Err("freshest status could not be identified");
    };
    if newest.next().is_some()
        || freshest.iter().any(|observation| {
            observation.status_id != newest_observation.status_id
                && observation.created_at == newest_observation.created_at
        })
    {
        return Err("newest status timestamp ties a different identity");
    }
    if newest_row.state == "success" {
        Ok(EvidenceState::Pass)
    } else {
        Ok(EvidenceState::Fail)
    }
}

/// Keep the latest run per GitHub Actions workflow for a required check. Check-run IDs are
/// monotonically assigned by GitHub; older runs within one workflow are history. Distinct
/// workflows remain separate evidence, and repeated non-Actions checks lack a safe lineage key.
fn latest_check_runs<'a>(
    rows: &[&'a crate::forge::CheckRun],
) -> Option<Vec<&'a crate::forge::CheckRun>> {
    let mut by_app = std::collections::BTreeMap::<u64, Vec<&'a crate::forge::CheckRun>>::new();
    let mut missing_app = Vec::new();
    for row in rows {
        let Some(app_id) = row.app_id else {
            missing_app.push(*row);
            continue;
        };
        by_app.entry(app_id).or_default().push(*row);
    }
    if missing_app.len() > 1 || (!missing_app.is_empty() && !by_app.is_empty()) {
        return None;
    }
    if missing_app.len() == 1 {
        return Some(missing_app);
    }
    let mut latest = Vec::new();
    for app_rows in by_app.into_values() {
        if app_rows.len() == 1 {
            latest.push(app_rows[0]);
            continue;
        }
        if app_rows.iter().any(|row| {
            row.app_slug.as_deref() != Some("github-actions") || row.workflow_id.is_none()
        }) {
            return None;
        }
        let mut by_workflow = std::collections::BTreeMap::<u64, &'a crate::forge::CheckRun>::new();
        for row in app_rows {
            let workflow_id = row.workflow_id?;
            match by_workflow.get(&workflow_id) {
                Some(current) if current.id == row.id && *current != row => return None,
                Some(current) if current.id >= row.id => {}
                _ => {
                    by_workflow.insert(workflow_id, row);
                }
            }
        }
        if by_workflow.is_empty() || by_workflow.keys().any(|workflow_id| *workflow_id == 0) {
            return None;
        }
        latest.extend(by_workflow.into_values());
    }
    Some(latest)
}

fn current_head_approval_gate(
    reviews: &[crate::forge::Review],
    head_sha: &str,
    required_approvals: u32,
) -> (EvidenceState, usize, Option<String>) {
    let mut latest_by_user = std::collections::BTreeMap::<String, (String, bool)>::new();
    let mut uncertain = false;
    for review in reviews {
        let approved = if review.state.eq_ignore_ascii_case("approved") {
            Some(true)
        } else if review.state.eq_ignore_ascii_case("changes_requested")
            || review.state.eq_ignore_ascii_case("dismissed")
        {
            Some(false)
        } else {
            // COMMENTED and other non-decisive events do not revoke an approval.
            None
        };
        let Some(approved) = approved else {
            continue;
        };
        let Some(commit_id) = review.commit_id.as_deref() else {
            uncertain = true;
            continue;
        };
        if !commit_id.eq_ignore_ascii_case(head_sha) {
            continue;
        }
        let Some(user) = review
            .user
            .as_deref()
            .map(str::trim)
            .filter(|user| !user.is_empty())
        else {
            uncertain = true;
            continue;
        };
        let Some(submitted_at) = review
            .submitted_at
            .as_deref()
            .and_then(github_review_timestamp_order_key)
        else {
            uncertain = true;
            continue;
        };
        let key = user.to_ascii_lowercase();
        match latest_by_user.get_mut(&key) {
            None => {
                latest_by_user.insert(key, (submitted_at, approved));
            }
            Some((latest_at, latest_approved)) if submitted_at.as_str() > latest_at.as_str() => {
                *latest_at = submitted_at;
                *latest_approved = approved;
            }
            Some((latest_at, latest_approved)) if submitted_at.as_str() == latest_at.as_str() => {
                if approved != *latest_approved {
                    uncertain = true;
                }
            }
            Some(_) => {}
        }
    }
    let count = latest_by_user
        .values()
        .filter(|(_, approved)| *approved)
        .count();
    if uncertain {
        (
            EvidenceState::Unknown,
            count,
            Some("current-head decisive reviews have missing or contradictory identity/time evidence".into()),
        )
    } else if count >= required_approvals as usize {
        (EvidenceState::Pass, count, None)
    } else {
        (EvidenceState::Fail, count, None)
    }
}

fn github_review_timestamp_order_key(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let valid_prefix = bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit);
    if !valid_prefix {
        return None;
    }
    let fraction = if bytes.get(19) == Some(&b'Z') && bytes.len() == 20 {
        ""
    } else if bytes.get(19) == Some(&b'.') && bytes.last() == Some(&b'Z') {
        let digits = value.get(20..value.len() - 1)?;
        if digits.is_empty()
            || digits.len() > 9
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        digits
    } else {
        return None;
    };
    Some(format!("{}{:0<9}", &value[..19], fraction))
}

fn execution_time_base_guard(
    repo: &RepositoryConfig,
    observed: &ForgeObservation,
) -> EvidenceState {
    match &observed.branch_protection {
        crate::forge::Observed::Complete { value, .. }
            if value.supports_execution_base_guard(
                &repo.merge.required_checks,
                (repo.merge.required_approvals > 0)
                    .then_some(u64::from(repo.merge.required_approvals)),
            ) =>
        {
            EvidenceState::Pass
        }
        crate::forge::Observed::Complete { .. } => EvidenceState::Unknown,
        crate::forge::Observed::Unknown { .. } => EvidenceState::Unknown,
    }
}

fn conclusion_name(value: &CommitConclusion) -> &'static str {
    match value {
        CommitConclusion::Success => "success",
        CommitConclusion::Failure => "failure",
        CommitConclusion::Cancelled => "cancelled",
    }
}

fn merge_instruction_digest(
    applied: &AppliedConfig,
    repository_id: &crate::domain::ids::RepositoryId,
    repository: &RepositoryConfig,
    role_instruction_digest: &Digest,
) -> Result<Digest, String> {
    let mut files = repository.instruction_files.clone();
    files.extend(
        repository
            .role_instruction_files
            .get(&crate::domain::types::Role::MergeDecision)
            .into_iter()
            .flatten()
            .cloned(),
    );
    files.extend(repository.merge.instruction_files.clone());
    files.sort();
    files.dedup();
    let mut sources = Vec::new();
    if let Some(instructions) = &repository.merge.instructions {
        sources.push((
            "inline:merge.instructions".to_owned(),
            sha256_digest(instructions.as_bytes())?,
        ));
    }
    for path in files {
        let source = applied
            .source_files
            .iter()
            .find(|source| source.path == path)
            .ok_or_else(|| {
                format!(
                    "configured merge instruction `{path}` for repository `{repository_id}` is absent from the applied source manifest"
                )
            })?;
        sources.push((path, source.sha256.clone()));
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    crate::forge::canonical_digest(&(role_instruction_digest, sources))
        .map_err(|error| error.to_string())
}

fn sha256_digest(bytes: &[u8]) -> Result<Digest, String> {
    use sha2::Digest as _;
    Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes)))
}

fn github_repository(clone_url: &str) -> Result<(String, String), String> {
    let path = if let Some(rest) = clone_url.strip_prefix("git@github.com:") {
        rest
    } else if let Some(rest) = clone_url.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = clone_url.strip_prefix("https://github.com/") {
        rest
    } else {
        return Err("merge observation requires a github.com repository URL".into());
    };
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || [owner, name].iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err("configured clone URL is not a valid GitHub repository".into());
    }
    Ok((owner.into(), name.into()))
}

impl crate::human_runtime::MergeWorkReviewSource for RuntimeMergeEvidenceSource {
    fn observe_merge_evidence(
        &self,
        item: &crate::store::merge_work::MergeWorkItem,
    ) -> Result<MergeEvidenceSnapshot, String> {
        let (evidence, _) = self.observe_merge_item(item)?;
        Ok(evidence)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    pub(crate) fn reconcile_merge_for_store_test(
        applied: AppliedConfig,
        request: &crate::effects::EffectRequest,
        context: &mut crate::effects::EffectContext<'_>,
    ) -> Result<crate::effects::EffectObservation, String> {
        RuntimeMergeEvidenceSource::new(applied, Vec::new(), BTreeMap::new()).run_merge_step(
            crate::effects::EffectMode::Reconcile,
            request,
            context,
        )
    }

    struct FixtureRunner {
        replies: Mutex<VecDeque<Vec<u8>>>,
        requests: Mutex<Vec<crate::process::ProcessRequest>>,
    }

    pub(crate) fn observe_publication_for_store_test(
        applied: crate::config::AppliedConfig,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
        replies: Vec<serde_json::Value>,
    ) -> Result<crate::merge_runtime::MergeEvidenceObservation, String> {
        let root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).map_err(|error| error.to_string())?;
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .map(|response| {
                        serde_json::to_vec(&response).map_err(|error| error.to_string())
                    })
                    .collect::<Result<_, _>>()?,
            ),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            runner.clone(),
        );
        let observation = source.observe_publication_subject(subject, result);
        assert!(
            !runner.requests.lock().unwrap().is_empty(),
            "production Forge observer must invoke gh for successful evidence"
        );
        observation.map_err(|error| error.to_string())
    }

    pub(crate) fn observe_publication_timeout_for_store_test(
        applied: crate::config::AppliedConfig,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<
        crate::merge_runtime::MergeEvidenceObservation,
        crate::merge_runtime::MergeObservationError,
    > {
        let root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).map_err(|error| error.to_string())?;
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let repository_response = serde_json::to_vec(&serde_json::json!({
            "id": 7,
            "full_name": "acme/repo-a",
            "default_branch": "main",
            "allow_merge_commit": true,
            "allow_squash_merge": true,
            "allow_rebase_merge": true
        }))
        .map_err(|error| error.to_string())?;
        let mut replies = vec![repository_response];
        replies.extend(vec![b"fixture-timeout".to_vec(); 32]);
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(VecDeque::from(replies)),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            runner.clone(),
        );
        let observation = source.observe_publication_subject(subject, result);
        let requests = runner.requests.lock().unwrap();
        assert!(
            requests.len() >= 2,
            "production Forge observer must invoke the PR endpoint"
        );
        assert!(requests[0].args.iter().any(|argument| argument == "api"));
        let expected_endpoint = format!("pulls/{}", subject.publications[0].pull_request_number);
        assert!(
            requests[1]
                .args
                .iter()
                .any(|argument| argument.to_string_lossy().contains(&expected_endpoint)),
            "second observed request should target {expected_endpoint}: {:?}",
            requests[1].args
        );
        observation
    }

    pub(crate) fn observe_publication_raw_replies_for_store_test(
        applied: crate::config::AppliedConfig,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
        replies: Vec<Vec<u8>>,
    ) -> Result<
        crate::merge_runtime::MergeEvidenceObservation,
        crate::merge_runtime::MergeObservationError,
    > {
        let root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).map_err(|error| error.to_string())?;
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(VecDeque::from(replies)),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            runner.clone(),
        );
        let observation = source.observe_publication_subject(subject, result);
        assert!(
            runner.requests.lock().unwrap().len() >= 3,
            "production Forge observer must reach a later endpoint after reading the PR identity"
        );
        observation
    }

    pub(crate) fn observe_and_prepare_for_store_test(
        applied: crate::config::AppliedConfig,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        result: &crate::store::agent_results::IngestedAgentResult,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        project_id: &crate::domain::ids::ProjectId,
        replies: Vec<serde_json::Value>,
    ) -> Result<
        (
            crate::merge_runtime::MergeEvidenceObservation,
            crate::store::merge_work::PreparedMergeBodyProposal,
        ),
        String,
    > {
        let root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).map_err(|error| error.to_string())?;
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?,
            ),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            runner,
        );
        let observation = source
            .observe_publication_subject(subject, result)
            .map_err(|error| error.to_string())?;
        let crate::engine::orchestration::RoleResultPayload::MergeAssessment(claim) =
            &result.validated.typed_payload
        else {
            return Err("fixture result is not a validated MergeAssessment".into());
        };
        let trusted = crate::merge_runtime::assess_merge_claim(
            claim,
            &result.validated.result_digest,
            &observation,
        )
        .map_err(|error| error.to_string())?;
        let ticket_run_id = result
            .validated
            .binding
            .ticket_run_id
            .as_ref()
            .ok_or("fixture MergeAssessment has no TicketRun")?;
        let revision = result
            .validated
            .binding
            .ticket_revision
            .ok_or("fixture MergeAssessment has no TicketRun revision")?;
        let assessment_id = crate::merge_runtime::assessment_id(
            project_id,
            ticket_run_id,
            revision,
            result.receipt.evidence_id(),
            &result.validated.result_digest,
            &trusted.evidence,
        )?;
        let proposal = source.prepare_body_proposal(
            project_id,
            subject,
            accepted_plan,
            &assessment_id,
            &observation,
        )?;
        Ok((observation, proposal))
    }

    pub(crate) fn prepare_merge_work_document_for_store_test(
        applied: crate::config::AppliedConfig,
        subject: &crate::delivery_runtime::ImplementationPublicationSetSubject,
        accepted_plan: &crate::engine::orchestration::WorkPlan,
        assessment: &crate::store::merge_work::TrustedMergeAssessment,
        intent: &crate::engine::orchestration::MergeIntentPayload,
        result: &crate::store::agent_results::IngestedAgentResult,
        replies: Vec<serde_json::Value>,
    ) -> Result<crate::store::merge_work::MergeWorkDocument, String> {
        let root = tempfile::tempdir().map_err(|error| error.to_string())?;
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).map_err(|error| error.to_string())?;
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?,
            ),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            runner,
        );
        source.prepare_merge_work_document(subject, accepted_plan, assessment, intent, result)
    }

    impl crate::forge::github::GitHubCommandRunner for FixtureRunner {
        fn run(
            &self,
            request: crate::process::ProcessRequest,
        ) -> Result<crate::process::ProcessOutput, crate::process::ProcessError> {
            self.requests.lock().unwrap().push(request);
            let stdout = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("fixture reply");
            if stdout == b"fixture-timeout" {
                return Ok(crate::process::ProcessOutput {
                    status: None,
                    stdout: Vec::new(),
                    stderr_tail: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: true,
                    cleanup_confirmed: true,
                });
            }
            let status = std::process::Command::new("true")
                .status()
                .map_err(crate::process::ProcessError::Start)?;
            Ok(crate::process::ProcessOutput {
                status: Some(status),
                stdout,
                stderr_tail: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
                cleanup_confirmed: true,
            })
        }
    }

    fn complete<T>(value: T) -> crate::forge::Observed<T> {
        crate::forge::Observed::Complete {
            value,
            pages: 1,
            digest: Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn source(key: &str, content: &str) -> crate::merge_executor::TrustedInstructionSource {
        crate::merge_executor::TrustedInstructionSource {
            key: key.into(),
            digest: sha256_digest(content.as_bytes()).unwrap(),
            bytes: content.as_bytes().to_vec(),
        }
    }

    #[test]
    fn request_command_is_taken_from_one_exact_trusted_literal_line() {
        let instructions = source(
            "inline:merge.instructions",
            "Request the repository merge.\n/merge\n",
        );
        let (comment, proof) = trusted_request_command(&instructions).unwrap();
        assert_eq!(comment, "/merge");
        assert_eq!(proof.source_key, instructions.key);
        assert_eq!(proof.source_digest, instructions.digest);
        assert_eq!(
            &instructions.bytes[proof.byte_start..proof.byte_start + 6],
            b"/merge"
        );
        assert_eq!(proof.byte_start, 30);
        assert!(proof.byte_start == 0 || instructions.bytes[proof.byte_start - 1] == b'\n');
        assert_eq!(
            &instructions.bytes[proof.byte_start..proof.byte_start + proof.exact_comment.len()],
            proof.exact_comment.as_bytes()
        );

        let quoted = source("inline:merge.instructions", "The command is `/merge`.\n");
        assert!(trusted_request_command(&quoted).is_err());
        let indented = source("inline:merge.instructions", "  /merge\n");
        assert!(trusted_request_command(&indented).is_err());
        let ambiguous = source(
            "inline:merge.instructions",
            "/merge\nUse /merge to merge\n/merge\n",
        );
        assert!(trusted_request_command(&ambiguous).is_err());
    }

    #[test]
    fn merge_instruction_reference_must_bind_one_source_file() {
        let instructions = source("inline:merge.instructions", "Request /merge\n");
        let sources = BTreeMap::from([(instructions.key.clone(), instructions)]);
        assert!(find_instruction_source(&sources, "merge.instructions#request").is_ok());
        assert!(find_instruction_source(&sources, "other.md#request").is_err());
        assert!(find_instruction_source(&sources, "merge.instructions#").is_err());
    }

    #[test]
    fn body_trailer_builder_adds_exact_lines_and_is_stable() {
        let trailers = vec!["Co-authored-by: Codex <noreply@openai.com>".to_owned()];
        let body = append_trailers("Fix the example.\n", &trailers);
        assert_eq!(
            body,
            "Fix the example.\n\nCo-authored-by: Codex <noreply@openai.com>"
        );
        assert_eq!(
            append_trailers("Fix the example.", &trailers),
            "Fix the example.\n\nCo-authored-by: Codex <noreply@openai.com>"
        );
        assert_eq!(
            append_trailers(
                "Fix the example.\nCo-authored-by: Codex <noreply@openai.com>",
                &trailers,
            ),
            "Fix the example.\n\nCo-authored-by: Codex <noreply@openai.com>"
        );
        let parsed = std::process::Command::new("git")
            .args(["interpret-trailers", "--parse"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        let mut child = parsed;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "Co-authored-by: Codex <noreply@openai.com>"
        );
    }

    #[test]
    fn host_observation_emits_one_pull_request_open_gate() {
        let config: crate::config::Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let repository_id = crate::domain::ids::RepositoryId::parse("example").unwrap();
        let repository = config.repositories.get(&repository_id).unwrap();
        let gates = host_gates(
            repository,
            &host_observation_with_reviews(Vec::new()),
            &test_pull_reference(),
        )
        .unwrap();
        assert_eq!(
            gates
                .iter()
                .filter(|gate| gate.key == "pull_request_open")
                .count(),
            1
        );
    }

    #[test]
    fn required_check_uses_latest_run_per_name_head_and_app_identity() {
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let repo_id = crate::domain::ids::RepositoryId::parse("example").unwrap();
        config
            .repositories
            .get_mut(&repo_id)
            .unwrap()
            .merge
            .required_checks = vec!["ci".into()];

        let gate = |check_runs: Vec<crate::forge::CheckRun>| {
            let mut observed = host_observation_with_reviews(Vec::new());
            observed.check_runs = complete(check_runs);
            host_gates(
                config.repositories.get(&repo_id).unwrap(),
                &observed,
                &test_pull_reference(),
            )
            .unwrap()
            .into_iter()
            .find(|gate| gate.key == "check:ci")
            .unwrap()
        };
        let check = |id, status: &str, conclusion: Option<&str>, app_id, workflow_id| {
            crate::forge::CheckRun {
                id,
                name: "ci".into(),
                head_sha: "head".into(),
                status: status.into(),
                conclusion: conclusion.map(str::to_owned),
                app_id,
                app_slug: app_id.map(|_| "github-actions".to_owned()),
                check_suite_id: Some(id),
                workflow_id,
            }
        };

        let historical_failure_then_success = gate(vec![
            check(
                10,
                "completed",
                Some("failure"),
                Some(15368),
                Some(405468936),
            ),
            check(
                20,
                "completed",
                Some("success"),
                Some(15368),
                Some(405468936),
            ),
        ]);
        assert_eq!(historical_failure_then_success.state, EvidenceState::Pass);

        let latest_pending = gate(vec![
            check(
                10,
                "completed",
                Some("success"),
                Some(15368),
                Some(405468936),
            ),
            check(20, "in_progress", None, Some(15368), Some(405468936)),
        ]);
        assert_eq!(latest_pending.state, EvidenceState::Fail);

        let ambiguous_missing_app = gate(vec![
            check(10, "completed", Some("failure"), None, None),
            check(20, "completed", Some("success"), None, None),
        ]);
        assert_eq!(ambiguous_missing_app.state, EvidenceState::Unknown);

        let distinct_app_failure = gate(vec![
            check(
                10,
                "completed",
                Some("success"),
                Some(15368),
                Some(405468936),
            ),
            check(
                20,
                "completed",
                Some("failure"),
                Some(99999),
                Some(405468936),
            ),
        ]);
        assert_eq!(distinct_app_failure.state, EvidenceState::Fail);

        let distinct_workflow_failure = gate(vec![
            check(
                10,
                "completed",
                Some("success"),
                Some(15368),
                Some(405468936),
            ),
            check(
                20,
                "completed",
                Some("failure"),
                Some(15368),
                Some(405468937),
            ),
        ]);
        assert_eq!(distinct_workflow_failure.state, EvidenceState::Fail);

        let missing_workflow_lineage = gate(vec![
            check(10, "completed", Some("failure"), Some(15368), None),
            check(20, "completed", Some("success"), Some(15368), None),
        ]);
        assert_eq!(missing_workflow_lineage.state, EvidenceState::Unknown);
    }

    #[test]
    fn required_commit_status_uses_freshest_status_instead_of_historical_failure() {
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        let repo_id = crate::domain::ids::RepositoryId::parse("example").unwrap();
        config
            .repositories
            .get_mut(&repo_id)
            .unwrap()
            .merge
            .required_checks = vec!["ci".into()];
        let status = |state: &str, id, created_at: &str, ordinal, context: &str, sha: &str| {
            crate::forge::CommitStatus {
                context: context.into(),
                state: state.into(),
                sha: sha.into(),
                creator: Some("bot".into()),
                observation: Some(crate::forge::CommitStatusObservation {
                    status_id: id,
                    created_at: created_at.into(),
                    observed_ordinal: ordinal,
                }),
            }
        };
        let check = |id, conclusion: &str, app_id, workflow_id| crate::forge::CheckRun {
            id,
            name: "ci".into(),
            head_sha: "head".into(),
            status: "completed".into(),
            conclusion: Some(conclusion.into()),
            app_id,
            app_slug: app_id.map(|_| "github-actions".to_owned()),
            check_suite_id: Some(id),
            workflow_id,
        };
        let gate = |statuses, checks| {
            let mut observed = host_observation_with_reviews(Vec::new());
            observed.statuses = complete(statuses);
            observed.check_runs = complete(checks);
            host_gates(
                config.repositories.get(&repo_id).unwrap(),
                &observed,
                &test_pull_reference(),
            )
            .unwrap()
            .into_iter()
            .find(|gate| gate.key == "check:ci")
            .unwrap()
        };

        assert_eq!(
            gate(
                vec![
                    status("success", 2, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("failure", 1, "2026-01-01T00:00:00Z", 2, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Pass
        );
        assert_eq!(
            gate(
                vec![
                    status("failure", 2, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("success", 1, "2026-01-01T00:00:00Z", 2, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Fail
        );
        assert_eq!(
            gate(
                vec![
                    status("success", 2, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("failure", 1, "2026-01-02T00:00:00Z", 2, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Unknown
        );
        assert_eq!(
            gate(
                vec![
                    status("success", 3, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("failure", 1, "2026-01-01T00:00:00Z", 2, "ci", "head"),
                    status("success", 2, "2026-01-01T00:00:00Z", 3, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Pass
        );
        assert_eq!(
            gate(
                vec![
                    status("success", 2, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("failure", 2, "2026-01-01T00:00:00Z", 2, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Unknown
        );
        assert_eq!(
            gate(
                vec![
                    status("success", 2, "2026-01-02T00:00:00Z", 1, "ci", "head"),
                    status("failure", 1, "2026-01-01T00:00:00Z", 1, "ci", "head"),
                ],
                Vec::new(),
            )
            .state,
            EvidenceState::Unknown
        );
        assert_eq!(
            gate(
                vec![status(
                    "success",
                    2,
                    "2026-01-02T00:00:00Z",
                    1,
                    "ci",
                    "old-head"
                )],
                Vec::new(),
            )
            .state,
            EvidenceState::Unknown
        );
        assert_eq!(
            gate(
                vec![status(
                    "success",
                    2,
                    "2026-01-02T00:00:00Z",
                    1,
                    "other",
                    "head"
                )],
                Vec::new(),
            )
            .state,
            EvidenceState::Unknown
        );
        let mut legacy_status = status("success", 2, "2026-01-02T00:00:00Z", 1, "ci", "head");
        legacy_status.observation = None;
        let missing_metadata = gate(vec![legacy_status], Vec::new());
        assert_eq!(missing_metadata.state, EvidenceState::Unknown);
        assert!(missing_metadata.detail.contains("freshness metadata"));
        assert_eq!(
            gate(
                vec![status(
                    "success",
                    2,
                    "2026-01-02T00:00:00Z",
                    1,
                    "ci",
                    "head"
                )],
                vec![check(3, "failure", Some(1), Some(4))],
            )
            .state,
            EvidenceState::Fail
        );
        assert_eq!(
            gate(
                vec![status(
                    "failure",
                    2,
                    "2026-01-02T00:00:00Z",
                    1,
                    "ci",
                    "head"
                )],
                vec![check(3, "success", Some(1), Some(4))],
            )
            .state,
            EvidenceState::Fail
        );
        assert_eq!(
            gate(
                vec![status(
                    "success",
                    2,
                    "2026-01-02T00:00:00Z",
                    1,
                    "ci",
                    "head"
                )],
                vec![
                    crate::forge::CheckRun {
                        id: 3,
                        name: "ci".into(),
                        head_sha: "head".into(),
                        status: "completed".into(),
                        conclusion: Some("failure".into()),
                        app_id: None,
                        app_slug: None,
                        check_suite_id: None,
                        workflow_id: None,
                    },
                    crate::forge::CheckRun {
                        id: 4,
                        name: "ci".into(),
                        head_sha: "head".into(),
                        status: "completed".into(),
                        conclusion: Some("success".into()),
                        app_id: None,
                        app_slug: None,
                        check_suite_id: None,
                        workflow_id: None,
                    },
                ],
            )
            .state,
            EvidenceState::Unknown
        );
    }

    #[test]
    fn commit_status_digest_binds_identity_and_ordinal_but_not_input_order() {
        let make_status = |id, ordinal| crate::forge::CommitStatus {
            context: "ci".into(),
            state: "success".into(),
            sha: "head".into(),
            creator: Some("bot".into()),
            observation: Some(crate::forge::CommitStatusObservation {
                status_id: id,
                created_at: format!("2026-01-0{id}T00:00:00Z"),
                observed_ordinal: ordinal,
            }),
        };
        let mut forward = host_observation_with_reviews(Vec::new());
        forward.statuses = complete(vec![make_status(1, 1), make_status(2, 0)]);
        let mut reverse = host_observation_with_reviews(Vec::new());
        reverse.statuses = complete(vec![make_status(2, 0), make_status(1, 1)]);
        assert_eq!(
            forward.semantic_digests().unwrap().checks,
            reverse.semantic_digests().unwrap().checks
        );

        let mut changed_ordinal = host_observation_with_reviews(Vec::new());
        changed_ordinal.statuses = complete(vec![make_status(1, 0), make_status(2, 1)]);
        assert_ne!(
            forward.semantic_digests().unwrap().checks,
            changed_ordinal.semantic_digests().unwrap().checks
        );
        let mut changed_identity = host_observation_with_reviews(Vec::new());
        changed_identity.statuses = complete(vec![make_status(1, 1), make_status(3, 0)]);
        assert_ne!(
            forward.semantic_digests().unwrap().checks,
            changed_identity.semantic_digests().unwrap().checks
        );
    }

    #[test]
    fn approval_gate_counts_only_distinct_latest_decisive_reviews_for_exact_head() {
        use crate::forge::Review;

        let review =
            |id, user: Option<&str>, state: &str, commit: Option<&str>, submitted: Option<&str>| {
                Review {
                    id,
                    user: user.map(str::to_owned),
                    state: state.into(),
                    commit_id: commit.map(str::to_owned),
                    submitted_at: submitted.map(str::to_owned),
                }
            };
        let head = "head";
        let approval_gate = |reviews| {
            let mut config: crate::config::Config =
                toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
            let repo_id = crate::domain::ids::RepositoryId::parse("example").unwrap();
            config
                .repositories
                .get_mut(&repo_id)
                .unwrap()
                .merge
                .required_approvals = 2;
            host_gates(
                config.repositories.get(&repo_id).unwrap(),
                &host_observation_with_reviews(reviews),
                &test_pull_reference(),
            )
            .unwrap()
            .into_iter()
            .find(|gate| gate.key == "approvals")
            .unwrap()
        };

        let duplicate_author = approval_gate(vec![
            review(
                1,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                2,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T11:00:00Z"),
            ),
        ]);
        assert_eq!(duplicate_author.state, EvidenceState::Fail);

        let changed_request_revokes = approval_gate(vec![
            review(
                1,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                2,
                Some("alice"),
                "CHANGES_REQUESTED",
                Some(head),
                Some("2026-01-01T11:00:00Z"),
            ),
            review(
                3,
                Some("bob"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T11:00:00Z"),
            ),
        ]);
        assert_eq!(changed_request_revokes.state, EvidenceState::Fail);

        let comments_do_not_revoke = approval_gate(vec![
            review(
                1,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                2,
                Some("alice"),
                "COMMENTED",
                Some(head),
                Some("2026-01-01T11:00:00Z"),
            ),
            review(
                3,
                Some("bob"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T11:00:00Z"),
            ),
            review(
                4,
                Some("carol"),
                "APPROVED",
                Some("old-head"),
                Some("2026-01-01T12:00:00Z"),
            ),
        ]);
        assert_eq!(comments_do_not_revoke.state, EvidenceState::Pass);

        let missing_author = approval_gate(vec![
            review(
                1,
                None,
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                2,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                3,
                Some("bob"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
        ]);
        assert_eq!(missing_author.state, EvidenceState::Unknown);

        let contradictory = approval_gate(vec![
            review(
                1,
                Some("alice"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                2,
                Some("alice"),
                "CHANGES_REQUESTED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
            review(
                3,
                Some("bob"),
                "APPROVED",
                Some(head),
                Some("2026-01-01T10:00:00Z"),
            ),
        ]);
        assert_eq!(contradictory.state, EvidenceState::Unknown);
    }

    fn test_pull_reference() -> crate::forge::PullRequestRef {
        crate::forge::PullRequestRef {
            repository: crate::forge::RepositoryRef {
                host: "github.com".into(),
                owner: "team".into(),
                name: "example".into(),
                expected_id: Some(7),
            },
            number: 42,
            expected_node_id: Some("PR_42".into()),
        }
    }

    fn host_observation_with_reviews(reviews: Vec<crate::forge::Review>) -> ForgeObservation {
        ForgeObservation {
            repository: complete(crate::forge::RepositoryIdentity {
                id: 7,
                full_name: "team/example".into(),
                default_branch: "main".into(),
                allow_merge_commit: true,
                allow_squash_merge: true,
                allow_rebase_merge: true,
            }),
            pull_request: complete(crate::forge::PullRequestObservation {
                repository_id: 7,
                node_id: "PR_42".into(),
                number: 42,
                state: crate::forge::PullRequestState::Open,
                draft: false,
                merged: false,
                head_sha: "head".into(),
                head_ref: "feature".into(),
                base_sha: "base".into(),
                base_ref: "main".into(),
                body: Some("reviewed body".into()),
                merge_commit_sha: None,
            }),
            files: complete(Vec::new()),
            check_runs: complete(Vec::new()),
            statuses: complete(Vec::new()),
            reviews: complete(reviews),
            review_comments: complete(Vec::new()),
            review_threads: complete(Vec::new()),
            issue_comments: complete(Vec::new()),
            branch_protection: complete(crate::forge::BranchProtection {
                strict_required_status_checks: false,
                required_check_contexts: Vec::new(),
                required_approving_review_count: None,
                dismiss_stale_reviews: None,
                enforce_admins: false,
                allow_force_pushes: true,
                allow_deletions: true,
                digest: Digest::parse("b".repeat(64)).unwrap(),
            }),
            merge_commit: complete(None),
            target_comparison: complete(None),
        }
    }

    #[test]
    fn github_observation_parses_exact_subject_endpoints_and_prepares_body_proposal() {
        use crate::domain::ids::{Digest, ProjectId, RepositoryId, TicketRunId};
        use crate::domain::types::Role;
        use crate::engine::orchestration::{
            AgentAssertion, PlannedWorkNode, RoleOutputKind, WorkNodeId, WorkPlan,
        };
        use crate::roles::RoleResultMessage;
        use serde_json::json;
        use sha2::{Digest as _, Sha256};

        let result = crate::store::agent_results::host_validation_fixture::host_validated_result(
            Role::MergeDecision,
            RoleResultMessage {
                schema_version: crate::engine::orchestration::ROLE_RESULT_SCHEMA_VERSION,
                message_id: "merge-assessment-source".into(),
                kind: RoleOutputKind::MergeIntent,
                assertion: AgentAssertion::Succeeded,
                structured_result: json!({
                    "assessment_id": "3".repeat(64),
                    "pr_identities": ["example#42"],
                    "policy_digest": "4".repeat(64),
                    "prepared_body_digest": "5".repeat(64),
                    "steps": [
                        {"kind":"request_merge", "instruction_reference":"merge.instructions#request", "rationale":"request the configured merge"},
                        {"kind":"verify_merge_commit", "instruction_reference":"merge.instructions#verify", "rationale":"verify the resulting commit"}
                    ],
                    "post_merge_verification": [
                        {"kind":"merge_commit_recorded", "instruction_reference":"merge.instructions#verify", "rationale":"verify the remote merge commit"}
                    ]
                }),
                result_digest: None,
                artifact_refs: Vec::new(),
            },
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        let config_text = include_str!("../../examples/fixture/config.toml").replace(
            "https://example.invalid/team/example.git",
            "https://github.com/team/example.git",
        );
        let mut config: crate::config::Config = toml::from_str(&config_text).unwrap();
        config
            .repositories
            .get_mut(&RepositoryId::parse("example").unwrap())
            .unwrap()
            .merge
            .required_approvals = 2;
        config
            .repositories
            .get_mut(&RepositoryId::parse("example").unwrap())
            .unwrap()
            .merge
            .required_checks = vec!["ci".into()];
        let worker_profile = crate::domain::ids::ProfileId::parse("worker_codex").unwrap();
        let applied = crate::config::AppliedConfig {
            config,
            profiles: [(
                worker_profile,
                crate::config::Profile {
                    adapter: crate::domain::types::AgentAdapter::Codex,
                    command: vec!["codex".into()],
                    description: None,
                    model: None,
                    effort: None,
                    turn_timeout_seconds: 60,
                    instruction_files: Vec::new(),
                    skill_paths: Vec::new(),
                    commit_mode: crate::domain::types::CommitMode::Native,
                    learned_guidance: None,
                    options: None,
                },
            )]
            .into_iter()
            .collect(),
            source_root: root.path().display().to_string(),
            source_files: Vec::new(),
            digest: result.ingested.validated.binding.config_digest.clone(),
        };
        let binary_dir = root.path().join("bin");
        std::fs::create_dir(&binary_dir).unwrap();
        let gh_path = binary_dir.join("gh");
        std::fs::write(&gh_path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let head_sha = "a".repeat(40);
        let body = "Reviewed implementation.\n";
        let responses = vec![
            json!({"id":7,"full_name":"team/example","default_branch":"main","allow_merge_commit":true,"allow_squash_merge":true,"allow_rebase_merge":true}),
            json!({"node_id":"PR_42","number":42,"state":"open","draft":false,"merged":false,"head":{"sha":head_sha,"ref":"feature","repo":{"id":7}},"base":{"sha":"b".repeat(40),"ref":"main","repo":{"id":7}},"body":body}),
            json!([]),
            json!({"check_runs":[
                {"id":129583564755_u64,"name":"ci","head_sha":head_sha,"status":"completed","conclusion":"failure","app":{"id":15368,"slug":"github-actions"},"check_suite":{"id":301}},
                {"id":129584803208_u64,"name":"ci","head_sha":head_sha,"status":"completed","conclusion":"success","app":{"id":15368,"slug":"github-actions"},"check_suite":{"id":302}}
            ]}),
            json!({"total_count":1,"workflow_runs":[{"head_sha":head_sha,"check_suite_id":301,"workflow_id":405468936}]}),
            json!({"total_count":1,"workflow_runs":[{"head_sha":head_sha,"check_suite_id":302,"workflow_id":405468936}]}),
            json!([
                {"id":42,"context":"ci","state":"success","sha":head_sha,"creator":{"login":"actions"},"created_at":"2026-01-02T00:00:00Z"},
                {"id":41,"context":"ci","state":"failure","sha":head_sha,"creator":{"login":"actions"},"created_at":"2026-01-01T00:00:00Z"}
            ]),
            json!([
                {"id":1,"user":{"login":"alice"},"state":"APPROVED","commit_id":head_sha,"submitted_at":"2026-01-01T10:00:00Z"},
                {"id":2,"user":{"login":"bob"},"state":"APPROVED","commit_id":head_sha,"submitted_at":"2026-01-01T11:00:00Z"}
            ]),
            json!([]),
            json!({"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}}),
            json!([]),
            json!([]),
            json!({"name":"main","protected":true}),
            json!({"required_status_checks":{"strict":true,"contexts":["ci"]},"required_pull_request_reviews":{"required_approving_review_count":2,"dismiss_stale_reviews":true},"enforce_admins":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false}}),
        ];
        let mut absent_body_responses = responses.clone();
        absent_body_responses[1]["body"] = serde_json::Value::Null;
        let runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                responses
                    .clone()
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let source = RuntimeMergeEvidenceSource::with_github_runner(
            applied.clone(),
            vec![binary_dir.clone()],
            BTreeMap::new(),
            runner.clone(),
        );
        let ticket_run_id = TicketRunId::parse("fixture-ticket-run").unwrap();
        let node_id = WorkNodeId::parse("worker-a").unwrap();
        let publication_subject = crate::delivery_runtime::ImplementationPublicationSetSubject {
            ticket_run_id: ticket_run_id.clone(),
            accepted_plan_digest: Digest::parse("1".repeat(64)).unwrap(),
            publications: vec![
                crate::delivery_runtime::ImplementationPublicationSubjectFact {
                    work_node_id: node_id.clone(),
                    repository_id: RepositoryId::parse("example").unwrap(),
                    pull_request_number: 42,
                    pull_request_node_id: "PR_42".into(),
                    pull_request_head: head_sha.clone(),
                    published_head: head_sha,
                    receipt_digest: "2".repeat(64),
                },
            ],
            coverage: vec![node_id.clone()],
            publication_revision: 1,
            verification: None,
        };
        let observation = source
            .observe_publication_subject(&publication_subject, &result.ingested)
            .unwrap();
        let recovery_runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                responses
                    .clone()
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let recovery_source = RuntimeMergeEvidenceSource::with_github_runner(
            applied.clone(),
            vec![binary_dir.clone()],
            BTreeMap::new(),
            recovery_runner.clone(),
        );
        let recovery_observation = recovery_source
            .observe_recovery_publication_subject(
                &publication_subject,
                &result.ingested.validated.binding.instruction_digest,
            )
            .unwrap();
        assert_eq!(
            recovery_observation.pull_request_reference,
            "https://github.com/team/example/pull/42"
        );
        assert!(
            !recovery_runner.requests.lock().unwrap().is_empty(),
            "recovery observation must invoke the configured production Forge adapter"
        );
        assert_eq!(observation.current_pr_body.as_deref(), Some(body));
        assert_eq!(
            observation
                .evidence
                .gates
                .iter()
                .find(|gate| gate.key == "approvals")
                .unwrap()
                .state,
            EvidenceState::Pass
        );
        assert_eq!(
            observation.evidence.execution_time_base_guard,
            EvidenceState::Pass
        );
        assert_eq!(
            observation
                .evidence
                .gates
                .iter()
                .find(|gate| gate.key == "check:ci")
                .unwrap()
                .state,
            EvidenceState::Pass
        );
        let mut missing_lineage_responses = responses.clone();
        missing_lineage_responses[5] = json!({"total_count":0,"workflow_runs":[]});
        let missing_lineage_runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                missing_lineage_responses
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let missing_lineage_source = RuntimeMergeEvidenceSource::with_github_runner(
            applied.clone(),
            vec![binary_dir.clone()],
            BTreeMap::new(),
            missing_lineage_runner,
        );
        assert!(
            missing_lineage_source
                .observe_publication_subject(&publication_subject, &result.ingested)
                .is_err()
        );
        let mut unprotected_responses = responses.clone();
        unprotected_responses[12] = json!({"name":"main","protected":false});
        let unprotected_runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                unprotected_responses
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let unprotected_source = RuntimeMergeEvidenceSource::with_github_runner(
            applied.clone(),
            vec![binary_dir.clone()],
            BTreeMap::new(),
            unprotected_runner.clone(),
        );
        let unprotected_observation = unprotected_source
            .observe_publication_subject(&publication_subject, &result.ingested)
            .unwrap();
        assert_eq!(
            unprotected_observation.evidence.execution_time_base_guard,
            EvidenceState::Unknown
        );
        let conservative = crate::merge_policy::evaluate_merge_policy(
            &unprotected_observation.policy,
            &unprotected_observation.evidence,
        )
        .unwrap();
        assert_eq!(
            conservative.disposition,
            crate::merge_policy::MergeDisposition::HumanRequired
        );
        let unprotected_requests = unprotected_runner.requests.lock().unwrap();
        assert_eq!(unprotected_requests.len(), 13);
        assert!(unprotected_requests.iter().any(|request| {
            request
                .args
                .iter()
                .any(|argument| argument == "repos/team/example/branches/main")
        }));
        drop(unprotected_requests);
        let requests = runner.requests.lock().unwrap();
        assert_eq!(requests.len(), 14);
        let endpoint = |request: &crate::process::ProcessRequest| {
            let args = request
                .args
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let api = args.iter().position(|argument| argument == "api").unwrap();
            args[api + 1].clone()
        };
        let endpoints = requests.iter().map(endpoint).collect::<Vec<_>>();
        for expected in [
            "repos/team/example",
            "repos/team/example/pulls/42",
            "repos/team/example/pulls/42/files",
            &format!("repos/team/example/commits/{}/check-runs", "a".repeat(40)),
            &format!(
                "repos/team/example/actions/runs?head_sha={}&check_suite_id=301",
                "a".repeat(40)
            ),
            &format!(
                "repos/team/example/actions/runs?head_sha={}&check_suite_id=302",
                "a".repeat(40)
            ),
            &format!("repos/team/example/commits/{}/statuses", "a".repeat(40)),
            "repos/team/example/pulls/42/reviews",
            "repos/team/example/pulls/42/comments",
            "graphql",
            "repos/team/example/issues/42/comments",
            "repos/team/example/rules/branches/main",
            "repos/team/example/branches/main",
            "repos/team/example/branches/main/protection",
        ] {
            assert!(
                endpoints.iter().any(|actual| actual == expected),
                "missing endpoint {expected}: {endpoints:?}"
            );
        }
        let graphql = requests
            .iter()
            .find(|request| endpoint(request) == "graphql")
            .unwrap();
        let graphql_body: serde_json::Value = serde_json::from_slice(&graphql.stdin).unwrap();
        assert_eq!(
            graphql_body
                .pointer("/variables/owner")
                .and_then(serde_json::Value::as_str),
            Some("team")
        );
        assert_eq!(
            graphql_body
                .pointer("/variables/name")
                .and_then(serde_json::Value::as_str),
            Some("example")
        );
        assert_eq!(
            graphql_body
                .pointer("/variables/number")
                .and_then(serde_json::Value::as_u64),
            Some(42)
        );
        drop(requests);
        let work_plan = WorkPlan {
            nodes: vec![PlannedWorkNode {
                id: node_id,
                repository: RepositoryId::parse("example").unwrap(),
                task: "Implement the requested change".into(),
                depends_on: Vec::new(),
                required_evidence: vec!["tests pass".into()],
                investigation: false,
            }],
            requested_investigation_children: 0,
        };
        let assessment_id = Digest::parse("3".repeat(64)).unwrap();
        let proposal = source
            .prepare_body_proposal(
                &ProjectId::parse("operations_project").unwrap(),
                &publication_subject,
                &work_plan,
                &assessment_id,
                &observation,
            )
            .unwrap();
        assert_eq!(
            proposal.prior_body_digest.as_ref(),
            observation.evidence.subject.prepared_body_digest.as_ref()
        );
        assert_eq!(
            proposal.exact_target_body,
            append_trailers(body, &proposal.expected_trailers)
        );
        assert_eq!(
            proposal.target_body_digest.as_str(),
            format!(
                "{:x}",
                Sha256::digest(proposal.exact_target_body.as_bytes())
            )
        );

        let initial_body = super::super::finalize_worker_publication_body(
            &source.applied_config,
            &ProjectId::parse("operations_project").unwrap(),
            &work_plan,
            body,
        )
        .unwrap();
        let mut initial_responses = responses.clone();
        initial_responses[1]["body"] = json!(initial_body);
        let initial_runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                initial_responses
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let initial_source = RuntimeMergeEvidenceSource::with_github_runner(
            source.applied_config.clone(),
            vec![binary_dir.clone()],
            BTreeMap::new(),
            initial_runner,
        );
        let initial_observation = initial_source
            .observe_publication_subject(&publication_subject, &result.ingested)
            .unwrap();
        let initial_proposal = initial_source
            .prepare_body_proposal(
                &ProjectId::parse("operations_project").unwrap(),
                &publication_subject,
                &work_plan,
                &assessment_id,
                &initial_observation,
            )
            .unwrap();
        assert_eq!(initial_proposal.exact_target_body, initial_body);
        assert_eq!(
            initial_proposal.target_body_digest,
            initial_proposal.prior_body_digest.unwrap()
        );

        let absent_runner = std::sync::Arc::new(FixtureRunner {
            replies: Mutex::new(
                absent_body_responses
                    .into_iter()
                    .map(|response| serde_json::to_vec(&response).unwrap())
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        });
        let absent_source = RuntimeMergeEvidenceSource::with_github_runner(
            applied,
            vec![binary_dir],
            BTreeMap::new(),
            absent_runner,
        );
        let absent_observation = absent_source
            .observe_publication_subject(&publication_subject, &result.ingested)
            .unwrap();
        assert_eq!(absent_observation.current_pr_body, None);
        let absent_proposal = absent_source
            .prepare_body_proposal(
                &ProjectId::parse("operations_project").unwrap(),
                &publication_subject,
                &work_plan,
                &assessment_id,
                &absent_observation,
            )
            .unwrap();
        assert!(!absent_proposal.prior_body_present);
        assert_eq!(
            absent_proposal.prior_body_digest.as_ref(),
            Some(&sha256_digest(b"").unwrap())
        );
        assert_eq!(
            absent_proposal.exact_target_body,
            append_trailers("", &absent_proposal.expected_trailers)
        );
    }
}
