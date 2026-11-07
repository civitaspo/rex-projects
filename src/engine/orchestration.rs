use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{Config, OperationRecipe, ProjectConfig, SuccessPredicate};
use crate::domain::ids::{ProjectId, RepositoryId, TicketId, TicketNamespace, TicketRunId};
use crate::domain::types::{ProjectMode, RecipeStage, Role, TicketStatus};
use crate::engine::reducer::Input;

/// Stable plan-local identity for a task in a TicketRun DAG.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkNodeId(String);

impl<'de> Deserialize<'de> for WorkNodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl WorkNodeId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 80
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("work node ID must be 1-80 ASCII letters, digits, '.', '_' or '-'".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalTicket {
    pub namespace: TicketNamespace,
    pub id: TicketId,
    pub revision: String,
    pub status: TicketStatus,
    pub labels: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchDecision {
    Ignore { reason: DispatchIgnore },
    Dispatch { priority: TicketPriority },
    ReconcileExternalTerminal { status: TicketStatus },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchIgnore {
    NotConfiguredReady,
    ExistingRunOwnsTicket,
    ProjectPausedOrStopped,
    UnsupportedDispatchState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketPriority {
    Default,
}

/// Normal dispatch never promotes Triage or Backlog. Their explicit triage or
/// prioritization input must first move them to a configured execution state.
pub fn dispatch_decision(
    project: &ProjectConfig,
    status: TicketStatus,
    has_active_run: bool,
    project_is_runnable: bool,
) -> DispatchDecision {
    if matches!(status, TicketStatus::Done | TicketStatus::Canceled) {
        return DispatchDecision::ReconcileExternalTerminal { status };
    }
    if !project_is_runnable {
        return DispatchDecision::Ignore {
            reason: DispatchIgnore::ProjectPausedOrStopped,
        };
    }
    if has_active_run {
        return DispatchDecision::Ignore {
            reason: DispatchIgnore::ExistingRunOwnsTicket,
        };
    }
    if status != TicketStatus::Ready || !project.dispatch_states.contains(&status) {
        return DispatchDecision::Ignore {
            reason: if status == TicketStatus::Ready {
                DispatchIgnore::NotConfiguredReady
            } else {
                DispatchIgnore::UnsupportedDispatchState
            },
        };
    }
    DispatchDecision::Dispatch {
        priority: TicketPriority::Default,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalCreationBudget {
    pub goal_revision: u64,
    pub reserved_attempts: u64,
    pub maximum_attempts: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GoalGap {
    pub key: String,
    pub title: String,
    pub body: String,
    pub acceptance: Vec<String>,
    pub parent: Option<TicketId>,
    pub dependencies: Vec<TicketId>,
    pub priority_rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketIntent {
    pub project_id: ProjectId,
    pub goal_revision: u64,
    pub stable_key: String,
    pub gap: GoalGap,
    /// Must be persisted in the same transaction as this intent, before invoke.
    pub reserved_attempt_number: u64,
}

/// Reserves the configured unit before a remote create is called. Callers must
/// atomically persist both the incremented budget and the returned intent.
pub fn reserve_goal_ticket(
    project_id: &ProjectId,
    project: &ProjectConfig,
    budget: &GoalCreationBudget,
    gap: GoalGap,
) -> Result<(GoalCreationBudget, GoalTicketIntent), String> {
    if project.mode != ProjectMode::Goal {
        return Err("operations Projects cannot create goal tickets".into());
    }
    let goal = project
        .goal
        .as_ref()
        .ok_or_else(|| "goal Project has no configured goal".to_owned())?;
    if goal.revision != budget.goal_revision {
        return Err("creation budget is for a stale goal revision".into());
    }
    validate_gap(&gap)?;
    let configured_max = u64::try_from(project.max_created_tickets_per_goal_revision)
        .map_err(|_| "goal ticket limit exceeds supported range".to_owned())?;
    let maximum = budget.maximum_attempts.min(configured_max);
    let attempt = budget
        .reserved_attempts
        .checked_add(1)
        .ok_or_else(|| "goal ticket reservation count exhausted".to_owned())?;
    if attempt > maximum {
        return Err("per-goal-revision ticket creation budget is exhausted".into());
    }
    let next = GoalCreationBudget {
        goal_revision: budget.goal_revision,
        reserved_attempts: attempt,
        maximum_attempts: maximum,
    };
    let intent = GoalTicketIntent {
        project_id: project_id.clone(),
        goal_revision: goal.revision,
        stable_key: goal_ticket_key(project_id, goal.revision, &gap.key),
        gap,
        reserved_attempt_number: attempt,
    };
    Ok((next, intent))
}

fn validate_gap(gap: &GoalGap) -> Result<(), String> {
    if gap.key.trim().is_empty()
        || gap.key.len() > 200
        || gap.key.chars().any(char::is_control)
        || gap.title.trim().is_empty()
        || gap.body.trim().is_empty()
        || gap.acceptance.is_empty()
        || gap.acceptance.iter().any(|item| item.trim().is_empty())
    {
        return Err(
            "goal gap requires a stable key, title, body, and nonempty acceptance items".into(),
        );
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &gap.dependencies {
        if !dependencies.insert(dependency) {
            return Err("goal gap contains a duplicate dependency".into());
        }
    }
    Ok(())
}

fn goal_ticket_key(project_id: &ProjectId, revision: u64, gap_key: &str) -> String {
    let digest = Sha256::digest(gap_key.as_bytes());
    format!("rex-projects:{project_id}:goal:{revision}:gap:{digest:x}")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalTicketObservation {
    pub id: TicketId,
    pub created_at_unix_millis: i64,
    pub active_run: bool,
    pub substantive_work: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DuplicateResolution {
    NoDuplicates,
    Canonical {
        ticket_id: TicketId,
        annotate_and_cancel: Vec<TicketId>,
    },
    HumanRequired {
        candidates: Vec<TicketId>,
        reason: String,
    },
}

/// Preserve a previously committed canonical ticket. Without one, select by
/// stable creation time and external ID. Uncertain/in-progress duplicates need
/// human judgment rather than automatic cancellation.
pub fn resolve_goal_duplicates(
    observations: &[GoalTicketObservation],
    previous_canonical: Option<&TicketId>,
) -> DuplicateResolution {
    let mut by_id = BTreeMap::new();
    for item in observations {
        by_id
            .entry(item.id.clone())
            .and_modify(|existing: &mut AggregatedTicketObservation| {
                existing.active_run |= item.active_run;
                existing.substantive_work |= item.substantive_work;
                existing.created_at_conflicts |=
                    existing.created_at_unix_millis != item.created_at_unix_millis;
            })
            .or_insert_with(|| AggregatedTicketObservation {
                created_at_unix_millis: item.created_at_unix_millis,
                active_run: item.active_run,
                substantive_work: item.substantive_work,
                created_at_conflicts: false,
            });
    }
    let candidates: Vec<_> = by_id
        .iter()
        .map(|(id, observation)| GoalTicketObservation {
            id: id.clone(),
            created_at_unix_millis: observation.created_at_unix_millis,
            active_run: observation.active_run,
            substantive_work: observation.substantive_work,
        })
        .collect();
    if candidates.is_empty() && previous_canonical.is_none() {
        return DuplicateResolution::NoDuplicates;
    }
    if by_id
        .values()
        .any(|observation| observation.created_at_conflicts)
    {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "one ticket has conflicting creation timestamps".into(),
        };
    }
    let canonical_id = previous_canonical.cloned().or_else(|| {
        candidates
            .iter()
            .min_by(|left, right| {
                left.created_at_unix_millis
                    .cmp(&right.created_at_unix_millis)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|item| item.id.clone())
    });
    let Some(canonical_id) = canonical_id else {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "no canonical ticket could be selected".into(),
        };
    };
    let conflicting = candidates
        .iter()
        .any(|item| item.id != canonical_id && (item.active_run || item.substantive_work));
    if conflicting {
        return DuplicateResolution::HumanRequired {
            candidates: candidates.iter().map(|item| item.id.clone()).collect(),
            reason: "a possible duplicate already has an active run or substantive work".into(),
        };
    }
    DuplicateResolution::Canonical {
        ticket_id: canonical_id.clone(),
        annotate_and_cancel: candidates
            .iter()
            .filter(|item| item.id != canonical_id)
            .map(|item| item.id.clone())
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregatedTicketObservation {
    created_at_unix_millis: i64,
    active_run: bool,
    substantive_work: bool,
    created_at_conflicts: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeSelection {
    pub recipe_id: Option<String>,
    pub decision: RecipeDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipeDecision {
    Selected,
    HumanRequiredNoMatch,
    HumanRequiredAmbiguous,
    HumanRequiredUnknownRecipe,
    HumanRequiredInvalidRepositoryPolicy,
}

/// Select exactly one declared label rule. A ticket with no rule or multiple
/// matching rules waits for a human; TOML order never silently decides policy.
pub fn select_operation_recipe(
    config: &Config,
    project: &ProjectConfig,
    labels: &BTreeSet<String>,
) -> RecipeSelection {
    let matches: Vec<_> = project
        .operation_matches
        .iter()
        .filter(|rule| rule.labels_all.iter().all(|label| labels.contains(label)))
        .collect();
    if matches.is_empty() {
        return RecipeSelection {
            recipe_id: None,
            decision: RecipeDecision::HumanRequiredNoMatch,
        };
    }
    if matches.len() > 1 {
        return RecipeSelection {
            recipe_id: None,
            decision: RecipeDecision::HumanRequiredAmbiguous,
        };
    }
    let recipe_id = &matches[0].recipe;
    let Some(recipe) = config.operation_recipes.get(recipe_id) else {
        return RecipeSelection {
            recipe_id: Some(recipe_id.clone()),
            decision: RecipeDecision::HumanRequiredUnknownRecipe,
        };
    };
    if !recipe_valid_for_project(config, project, recipe) {
        return RecipeSelection {
            recipe_id: Some(recipe_id.clone()),
            decision: RecipeDecision::HumanRequiredInvalidRepositoryPolicy,
        };
    }
    RecipeSelection {
        recipe_id: Some(recipe_id.clone()),
        decision: RecipeDecision::Selected,
    }
}

fn recipe_valid_for_project(
    config: &Config,
    project: &ProjectConfig,
    recipe: &OperationRecipe,
) -> bool {
    let project_repositories: BTreeSet<_> = project.repositories.iter().collect();
    if recipe.targets.iter().any(|target| {
        !project_repositories.contains(&target.repository)
            || config
                .repositories
                .get(&target.repository)
                .is_none_or(|repository| {
                    repository
                        .operations
                        .as_ref()
                        .is_none_or(|policy| !policy.allowed_actions.contains(&target.action))
                })
            || !config.operation_actions.contains_key(&target.action)
    }) {
        return false;
    }
    if recipe.required_stages.contains(&RecipeStage::Operations)
        && recipe.targets.is_empty()
        && recipe
            .not_required_reason
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return false;
    }
    if recipe.targets.is_empty()
        && recipe
            .not_required_reason
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return false;
    }
    if recipe
        .targets
        .iter()
        .any(|target| match &target.success_predicate {
            SuccessPredicate::ExplicitNotRequired { reason, evidence } => {
                reason.trim().is_empty()
                    || evidence.is_empty()
                    || evidence.iter().any(|item| item.trim().is_empty())
            }
            _ => false,
        })
    {
        return false;
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlannedWorkNode {
    pub id: WorkNodeId,
    pub repository: RepositoryId,
    pub task: String,
    pub depends_on: Vec<WorkDependency>,
    pub required_evidence: Vec<String>,
    /// True creates a read-only investigation run. Implementation nodes always
    /// execute with the Worker role; Coordinator never gets source-write authority.
    pub investigation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkDependency {
    pub node: WorkNodeId,
    pub kind: WorkDependencyKind,
    pub affected_evidence: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkDependencyKind {
    GitBase,
    Delivery,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkPlan {
    pub nodes: Vec<PlannedWorkNode>,
    pub requested_investigation_children: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkNode {
    pub id: WorkNodeId,
    pub repository: RepositoryId,
    pub base: WorkBaseSource,
    pub task: String,
    pub depends_on: Vec<WorkDependency>,
    pub required_evidence: Vec<String>,
    pub role: Role,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkBaseSource {
    ControllerObservedCommit {
        commit: String,
    },
    /// Resolve from the predecessor's accepted exact HEAD after it completes;
    /// never substitute the repository's controller-observed trunk base.
    PredecessorWorkNodeHead {
        node: WorkNodeId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPlan {
    pub ticket_run_id: TicketRunId,
    pub nodes_in_execution_order: Vec<ValidatedWorkNode>,
    pub spawned_investigation_children: usize,
}

pub fn validate_work_plan(
    ticket_run_id: &TicketRunId,
    project: &ProjectConfig,
    plan: WorkPlan,
    observed_bases: &BTreeMap<RepositoryId, String>,
) -> Result<ValidatedPlan, String> {
    if plan.nodes.is_empty() {
        return Err("a delivery plan must contain at least one work node".into());
    }
    if plan.requested_investigation_children > project.max_investigation_children {
        return Err("plan exceeds the Project investigation-child limit".into());
    }
    let allowed_repositories: BTreeSet<_> = project.repositories.iter().collect();
    let mut nodes = BTreeMap::new();
    for node in plan.nodes {
        if node.task.trim().is_empty() || node.task.len() > 32_000 {
            return Err(format!(
                "work node {} has an empty or oversized task",
                node.id
            ));
        }
        if !allowed_repositories.contains(&node.repository) {
            return Err(format!(
                "work node {} names an unregistered repository",
                node.id
            ));
        }
        if nodes.insert(node.id.clone(), node).is_some() {
            return Err("work plan contains duplicate node IDs".into());
        }
    }
    let mut indegree: BTreeMap<WorkNodeId, usize> =
        nodes.keys().cloned().map(|id| (id, 0)).collect();
    let mut children: BTreeMap<WorkNodeId, BTreeSet<WorkNodeId>> = BTreeMap::new();
    for node in nodes.values() {
        let mut dependencies = BTreeSet::new();
        for dependency in &node.depends_on {
            if dependency.node == node.id {
                return Err(format!("work node {} depends on itself", node.id));
            }
            if !nodes.contains_key(&dependency.node) {
                return Err(format!(
                    "work node {} depends on unknown node {}",
                    node.id, dependency.node
                ));
            }
            let predecessor = nodes.get(&dependency.node).expect("dependency exists");
            if dependency.kind == WorkDependencyKind::GitBase
                && predecessor.repository != node.repository
            {
                return Err(format!(
                    "git-base dependency for work node {} crosses repositories",
                    node.id
                ));
            }
            if dependency.kind == WorkDependencyKind::GitBase && predecessor.investigation {
                return Err(format!(
                    "git-base dependency for work node {} cannot use a read-only investigation",
                    node.id
                ));
            }
            if dependency.affected_evidence.is_empty()
                || dependency
                    .affected_evidence
                    .iter()
                    .any(|evidence| evidence.trim().is_empty())
            {
                return Err(format!(
                    "dependency for work node {} must identify affected evidence",
                    node.id
                ));
            }
            if !dependencies.insert(&dependency.node) {
                return Err(format!("work node {} repeats a dependency", node.id));
            }
            *indegree.get_mut(&node.id).expect("indexed node exists") += 1;
            children
                .entry(dependency.node.clone())
                .or_default()
                .insert(node.id.clone());
        }
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(next) = ready.pop_first() {
        order.push(next.clone());
        if let Some(dependents) = children.get(&next) {
            for child in dependents {
                let count = indegree.get_mut(child).expect("indexed child exists");
                *count -= 1;
                if *count == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err("work plan dependency graph contains a cycle".into());
    }
    let actual_investigations = nodes.values().filter(|node| node.investigation).count();
    if actual_investigations != plan.requested_investigation_children {
        return Err("investigation child count does not match the plan nodes".into());
    }
    if actual_investigations == nodes.len() {
        return Err("a delivery plan requires at least one implementation node".into());
    }
    let mut validated = Vec::with_capacity(order.len());
    for id in order {
        let node = nodes.remove(&id).expect("topological node exists");
        let git_base_dependencies: Vec<_> = node
            .depends_on
            .iter()
            .filter(|dependency| dependency.kind == WorkDependencyKind::GitBase)
            .collect();
        if git_base_dependencies.len() > 1 {
            return Err(format!(
                "work node {} has more than one Git base predecessor",
                node.id
            ));
        }
        let base = if let Some(dependency) = git_base_dependencies.first() {
            WorkBaseSource::PredecessorWorkNodeHead {
                node: dependency.node.clone(),
            }
        } else {
            let commit = observed_bases.get(&node.repository).ok_or_else(|| {
                format!(
                    "no controller-observed base for repository {}",
                    node.repository
                )
            })?;
            validate_git_commit(commit)?;
            WorkBaseSource::ControllerObservedCommit {
                commit: commit.clone(),
            }
        };
        let role = if node.investigation {
            Role::Planner
        } else {
            Role::Worker
        };
        if !node.investigation && node.required_evidence.is_empty() {
            return Err(format!(
                "implementation node {} has no required evidence",
                node.id
            ));
        }
        if node.investigation && !node.required_evidence.is_empty() {
            return Err(format!(
                "read-only investigation node {} cannot require implementation evidence",
                node.id
            ));
        }
        validated.push(ValidatedWorkNode {
            id: node.id,
            repository: node.repository,
            base,
            task: node.task,
            depends_on: node.depends_on,
            required_evidence: node.required_evidence,
            role,
        });
    }
    Ok(ValidatedPlan {
        ticket_run_id: ticket_run_id.clone(),
        nodes_in_execution_order: validated,
        spawned_investigation_children: plan.requested_investigation_children,
    })
}

fn validate_git_commit(value: &str) -> Result<(), String> {
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("controller-observed base must be a full Git commit ID".into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewProgress {
    pub completed_rounds: usize,
    pub maximum_rounds: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDisposition {
    StartCorrectionWorker,
    StartMergeDecision,
    HumanRequiredAtRoundLimit,
}

pub fn review_disposition(
    progress: ReviewProgress,
    has_unresolved_findings: bool,
) -> Result<ReviewDisposition, String> {
    if progress.maximum_rounds == 0 {
        return Err("maximum review rounds must be positive".into());
    }
    if has_unresolved_findings {
        if progress.completed_rounds >= progress.maximum_rounds {
            Ok(ReviewDisposition::HumanRequiredAtRoundLimit)
        } else {
            Ok(ReviewDisposition::StartCorrectionWorker)
        }
    } else {
        Ok(ReviewDisposition::StartMergeDecision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanComplexity {
    Routine,
    Complex,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerSelection {
    CoordinatorPlansDirectly,
    LaunchPlanner {
        profile_id: crate::domain::ids::ProfileId,
    },
    HumanClarificationRequired,
}

pub fn select_planner(project: &ProjectConfig, complexity: PlanComplexity) -> PlannerSelection {
    match complexity {
        PlanComplexity::Routine => PlannerSelection::CoordinatorPlansDirectly,
        PlanComplexity::Complex => project
            .roles
            .get(&Role::Planner)
            .cloned()
            .map_or(PlannerSelection::CoordinatorPlansDirectly, |profile_id| {
                PlannerSelection::LaunchPlanner { profile_id }
            }),
        PlanComplexity::Uncertain => PlannerSelection::HumanClarificationRequired,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalCompletionEvidence {
    pub satisfied_acceptance: Vec<String>,
    pub incomplete_ticket_ids: Vec<TicketId>,
    pub deferred_risks: Vec<String>,
    pub operation_results: Vec<String>,
    pub subject_digest: crate::domain::ids::Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoalCompletionDecision {
    NotSatisfied { missing_evidence: Vec<String> },
    RequestHumanConfirmation { evidence: GoalCompletionEvidence },
}

/// Agents can request confirmation; only a human response can complete a goal.
pub fn propose_goal_completion(
    project: &ProjectConfig,
    evidence: GoalCompletionEvidence,
    all_acceptance_ids: &BTreeSet<String>,
    active_ticket_runs: usize,
) -> GoalCompletionDecision {
    if project.mode != ProjectMode::Goal {
        return GoalCompletionDecision::NotSatisfied {
            missing_evidence: vec!["project is not goal-driven".into()],
        };
    }
    let observed: BTreeSet<_> = evidence.satisfied_acceptance.iter().cloned().collect();
    let missing: Vec<_> = all_acceptance_ids.difference(&observed).cloned().collect();
    if !missing.is_empty() || active_ticket_runs > 0 || !evidence.incomplete_ticket_ids.is_empty() {
        return GoalCompletionDecision::NotSatisfied {
            missing_evidence: missing,
        };
    }
    GoalCompletionDecision::RequestHumanConfirmation { evidence }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanIntervention {
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub expected_revision: u64,
    pub message: String,
    pub fence_active_work: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterventionRoute {
    pub target: Role,
    pub notify: Role,
    pub fence_active_work: bool,
}

pub fn route_human_intervention(
    intervention: &HumanIntervention,
    current_revision: u64,
) -> Result<InterventionRoute, String> {
    if intervention.expected_revision != current_revision {
        return Err("human intervention targets a stale TicketRun revision".into());
    }
    if intervention.message.trim().is_empty() || intervention.message.len() > 32_000 {
        return Err("human intervention must contain a bounded nonempty instruction".into());
    }
    Ok(InterventionRoute {
        target: Role::Coordinator,
        notify: Role::Supervisor,
        fence_active_work: intervention.fence_active_work,
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WakeSessionKey {
    pub project_id: ProjectId,
    pub ticket_run_id: Option<TicketRunId>,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeCause {
    StopOrPolicyFence,
    HumanResponse,
    CoordinatorInstruction,
    ChildResult,
    WorkflowTransition,
    ExternalObservation,
    DueRetry,
    PeriodicSupervisorReview,
}

impl WakeCause {
    fn precedence(self) -> u8 {
        match self {
            Self::StopOrPolicyFence => 0,
            Self::HumanResponse | Self::CoordinatorInstruction => 1,
            Self::ChildResult | Self::WorkflowTransition => 2,
            Self::ExternalObservation => 3,
            Self::DueRetry | Self::PeriodicSupervisorReview => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeEvent {
    pub event_id: String,
    pub session: WakeSessionKey,
    pub source_revision: u64,
    pub observed_at_unix_millis: i64,
    pub cause: WakeCause,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescedWake {
    pub session: WakeSessionKey,
    pub current_revision: u64,
    pub event_ids_in_precedence_order: Vec<String>,
}

/// Prepare one finite next-turn snapshot. Persist the original wake events
/// separately before scheduling; this function only creates the projection.
pub fn coalesce_wakes(events: &[WakeEvent]) -> Result<Option<CoalescedWake>, String> {
    let Some(first) = events.first() else {
        return Ok(None);
    };
    if events.iter().any(|event| event.session != first.session) {
        return Err("wake batch contains more than one logical role session".into());
    }
    let mut unique = BTreeMap::new();
    for event in events {
        if event.event_id.trim().is_empty() {
            return Err("wake event ID cannot be empty".into());
        }
        match unique.get(&event.event_id) {
            Some(previous) if previous != event => {
                return Err("wake event ID was reused with changed content".into());
            }
            Some(_) => {}
            None => {
                unique.insert(event.event_id.clone(), event.clone());
            }
        }
    }
    let mut unique: Vec<_> = unique.into_values().collect();
    unique.sort_by(|left, right| {
        left.cause
            .precedence()
            .cmp(&right.cause.precedence())
            .then_with(|| right.source_revision.cmp(&left.source_revision))
            .then_with(|| {
                left.observed_at_unix_millis
                    .cmp(&right.observed_at_unix_millis)
            })
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let current_revision = unique
        .iter()
        .map(|event| event.source_revision)
        .max()
        .unwrap_or(0);
    Ok(Some(CoalescedWake {
        session: first.session.clone(),
        current_revision,
        event_ids_in_precedence_order: unique.into_iter().map(|event| event.event_id).collect(),
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleRequest {
    CoordinatorPlanAccepted,
    CoordinatorAskPlanner,
    CoordinatorPrepareWorktrees,
    CoordinatorStartWorker,
    CoordinatorStartReviewer,
    CoordinatorStartMergeDecision,
    CoordinatorStartOperator,
    CoordinatorStartPostmortem,
    CoordinatorHumanRequest,
    PlannerSubmitPlan,
    PlannerRequestReadOnlyInvestigation,
    WorkerSubmitEvidence,
    WorkerReportIrregularity,
    ReviewerSubmitFindings,
    ReviewerRequestReadOnlyInvestigation,
    MergeDecisionSubmitAssessment,
    MergeDecisionRequestMerge,
    MergeDecisionRequestHuman,
    OperatorRequestDeclaredOperation,
    OperatorSubmitResult,
    PostmortemSubmitPublication,
    SupervisorProposeTicket,
    SupervisorDispatchTicket,
    SupervisorIntervene,
    SupervisorRequestHuman,
    SupervisorProposeGoalComplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedRequest {
    Transition(Input),
    SpawnRole(Role),
    ReserveGoalTicket,
    QueueHumanRequest,
    RequestDeclaredMerge,
    RequestDeclaredOperation,
    ReportIrregularity,
    PublishKnowledge,
    SubmitPlan,
    SubmitWorkerEvidence,
    SubmitReview,
    SubmitMergeAssessment,
    SubmitOperationEvidence,
}

/// This is the controller's authority check; prompts are explanatory only.
pub fn authorize_role_request(
    role: Role,
    request: RoleRequest,
) -> Result<AuthorizedRequest, String> {
    use AuthorizedRequest as A;
    use RoleRequest as R;
    let authorized = match (role, request.clone()) {
        (Role::Coordinator, R::CoordinatorPlanAccepted) => A::Transition(Input::PlanAccepted),
        (Role::Coordinator, R::CoordinatorAskPlanner) => A::SpawnRole(Role::Planner),
        (Role::Coordinator, R::CoordinatorPrepareWorktrees) => {
            A::Transition(Input::WorktreesPrepared)
        }
        (Role::Coordinator, R::CoordinatorStartWorker) => A::SpawnRole(Role::Worker),
        (Role::Coordinator, R::CoordinatorStartReviewer) => A::SpawnRole(Role::Reviewer),
        (Role::Coordinator, R::CoordinatorStartMergeDecision) => A::SpawnRole(Role::MergeDecision),
        (Role::Coordinator, R::CoordinatorStartOperator) => A::SpawnRole(Role::Operator),
        (Role::Coordinator, R::CoordinatorStartPostmortem) => A::SpawnRole(Role::Postmortem),
        (Role::Coordinator, R::CoordinatorHumanRequest) => A::QueueHumanRequest,
        (Role::Planner, R::PlannerSubmitPlan) => A::SubmitPlan,
        (Role::Planner, R::PlannerRequestReadOnlyInvestigation) => A::SpawnRole(Role::Planner),
        (Role::Worker, R::WorkerSubmitEvidence) => A::SubmitWorkerEvidence,
        (Role::Worker, R::WorkerReportIrregularity) => A::ReportIrregularity,
        (Role::Reviewer, R::ReviewerSubmitFindings) => A::SubmitReview,
        (Role::Reviewer, R::ReviewerRequestReadOnlyInvestigation) => A::SpawnRole(Role::Reviewer),
        (Role::MergeDecision, R::MergeDecisionSubmitAssessment) => A::SubmitMergeAssessment,
        (Role::MergeDecision, R::MergeDecisionRequestMerge) => A::RequestDeclaredMerge,
        (Role::MergeDecision, R::MergeDecisionRequestHuman) => A::QueueHumanRequest,
        (Role::Operator, R::OperatorRequestDeclaredOperation) => A::RequestDeclaredOperation,
        (Role::Operator, R::OperatorSubmitResult) => A::SubmitOperationEvidence,
        (Role::Postmortem, R::PostmortemSubmitPublication) => A::PublishKnowledge,
        (Role::Supervisor, R::SupervisorProposeTicket) => A::ReserveGoalTicket,
        (Role::Supervisor, R::SupervisorDispatchTicket) => A::Transition(Input::Dispatch),
        (Role::Supervisor, R::SupervisorIntervene) => A::ReportIrregularity,
        (Role::Supervisor, R::SupervisorRequestHuman) => A::QueueHumanRequest,
        (Role::Supervisor, R::SupervisorProposeGoalComplete) => A::QueueHumanRequest,
        _ => return Err(format!("role {role:?} cannot issue request {request:?}")),
    };
    Ok(authorized)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrregularitySeverity {
    Recoverable,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PauseScope {
    WorkNode,
    TicketRun,
    Project,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrregularityDecision {
    pub scope: PauseScope,
    pub fence_current_work: bool,
    pub notify: Vec<Role>,
    pub request_human: bool,
}

pub fn handle_irregularity(
    severity: IrregularitySeverity,
    can_safely_isolate_work_node: bool,
) -> IrregularityDecision {
    match severity {
        IrregularitySeverity::Recoverable if can_safely_isolate_work_node => IrregularityDecision {
            scope: PauseScope::WorkNode,
            fence_current_work: true,
            notify: vec![Role::Coordinator],
            request_human: false,
        },
        IrregularitySeverity::Recoverable => IrregularityDecision {
            scope: PauseScope::TicketRun,
            fence_current_work: true,
            notify: vec![Role::Coordinator],
            request_human: false,
        },
        IrregularitySeverity::High => IrregularityDecision {
            scope: PauseScope::TicketRun,
            fence_current_work: true,
            notify: vec![Role::Coordinator, Role::Supervisor],
            request_human: true,
        },
        IrregularitySeverity::Critical => IrregularityDecision {
            scope: PauseScope::Project,
            fence_current_work: true,
            notify: vec![Role::Coordinator, Role::Supervisor],
            request_human: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::config::{GoalConfig, OperationMatch};
    use crate::domain::ids::{AdapterId, TicketId};
    use crate::domain::types::RecipeStage;

    fn goal_project() -> ProjectConfig {
        ProjectConfig {
            mode: ProjectMode::Goal,
            ticket_adapter: AdapterId::parse("tickets").unwrap(),
            ticket_scope: BTreeMap::new(),
            dispatch_states: vec![TicketStatus::Ready],
            repositories: vec![RepositoryId::parse("repo-a").unwrap()],
            auto_merge: false,
            max_active_tickets: 2,
            max_created_tickets_per_goal_revision: 2,
            max_review_rounds: 2,
            max_investigation_children: 1,
            max_effect_retries: 1,
            goal: Some(GoalConfig {
                revision: 7,
                statement: "deliver".into(),
                acceptance: vec!["works".into()],
            }),
            roles: BTreeMap::new(),
            role_defaults_from: None,
            operation_matches: Vec::new(),
        }
    }

    fn operations_config() -> (Config, ProjectConfig) {
        let project = ProjectConfig {
            mode: ProjectMode::Operations,
            goal: None,
            operation_matches: vec![
                OperationMatch {
                    labels_all: vec!["docs".into()],
                    recipe: "docs_only".into(),
                },
                OperationMatch {
                    labels_all: vec!["service".into()],
                    recipe: "service".into(),
                },
            ],
            ..goal_project()
        };
        let mut config: Config =
            toml::from_str(include_str!("../../examples/fixture/config.toml")).unwrap();
        config.operation_recipes.insert(
            "docs_only".into(),
            OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: vec![RecipeStage::Review],
                required_evidence: vec!["review".into()],
                targets: vec![],
                not_required_reason: Some("docs only".into()),
            },
        );
        config.operation_recipes.insert(
            "service".into(),
            OperationRecipe {
                roles: BTreeMap::new(),
                required_stages: vec![RecipeStage::Operations],
                required_evidence: vec!["deploy".into()],
                targets: vec![],
                not_required_reason: Some("skip explicitly".into()),
            },
        );
        (config, project)
    }

    #[test]
    fn goal_ticket_budget_is_reserved_before_create_and_survives_uncertainty() {
        let project_id = ProjectId::parse("project-a").unwrap();
        let project = goal_project();
        let budget = GoalCreationBudget {
            goal_revision: 7,
            reserved_attempts: 1,
            maximum_attempts: 10,
        };
        let gap = GoalGap {
            key: "api-migration".into(),
            title: "Migrate API".into(),
            body: "Implement the missing interface".into(),
            acceptance: vec!["contract tests pass".into()],
            parent: None,
            dependencies: vec![],
            priority_rationale: "blocks goal".into(),
        };
        let (next, intent) = reserve_goal_ticket(&project_id, &project, &budget, gap).unwrap();
        assert_eq!(next.reserved_attempts, 2);
        assert_eq!(intent.reserved_attempt_number, 2);
        assert_eq!(
            intent.stable_key,
            "rex-projects:project-a:goal:7:gap:9df20b60d1a7fb25b681a2e64af468340d6543741bb200bd64a196ae2dd2132a"
        );
        let exhausted = reserve_goal_ticket(
            &project_id,
            &project,
            &next,
            GoalGap {
                key: "another".into(),
                title: "Another".into(),
                body: "Body".into(),
                acceptance: vec!["done".into()],
                parent: None,
                dependencies: vec![],
                priority_rationale: "".into(),
            },
        );
        assert!(exhausted.is_err());
    }

    #[test]
    fn operations_recipe_ambiguity_and_missing_are_human_gated() {
        let (config, project) = operations_config();
        assert_eq!(
            select_operation_recipe(&config, &project, &BTreeSet::new()).decision,
            RecipeDecision::HumanRequiredNoMatch
        );
        assert_eq!(
            select_operation_recipe(&config, &project, &BTreeSet::from(["docs".into()])).decision,
            RecipeDecision::Selected
        );
        assert_eq!(
            select_operation_recipe(
                &config,
                &project,
                &BTreeSet::from(["docs".into(), "service".into()])
            )
            .decision,
            RecipeDecision::HumanRequiredAmbiguous
        );
    }

    #[test]
    fn duplicate_resolution_is_stable_and_never_discards_active_work() {
        let a = TicketId::parse("external-A").unwrap();
        let b = TicketId::parse("external-B").unwrap();
        let candidates = vec![
            GoalTicketObservation {
                id: a.clone(),
                created_at_unix_millis: 1767225601000,
                active_run: false,
                substantive_work: false,
            },
            GoalTicketObservation {
                id: b.clone(),
                created_at_unix_millis: 1767225602000,
                active_run: false,
                substantive_work: false,
            },
        ];
        assert_eq!(
            resolve_goal_duplicates(&candidates, None),
            DuplicateResolution::Canonical {
                ticket_id: a.clone(),
                annotate_and_cancel: vec![b.clone()]
            }
        );
        assert_eq!(
            resolve_goal_duplicates(&candidates, Some(&b)),
            DuplicateResolution::Canonical {
                ticket_id: b.clone(),
                annotate_and_cancel: vec![a]
            }
        );
        let active = vec![
            candidates[0].clone(),
            GoalTicketObservation {
                id: TicketId::parse("external-C").unwrap(),
                active_run: true,
                ..candidates[1].clone()
            },
        ];
        assert!(matches!(
            resolve_goal_duplicates(&active, None),
            DuplicateResolution::HumanRequired { .. }
        ));
        assert_eq!(
            resolve_goal_duplicates(&[], Some(&b)),
            DuplicateResolution::Canonical {
                ticket_id: b,
                annotate_and_cancel: vec![]
            }
        );
    }

    #[test]
    fn work_plan_deserialization_rejects_invalid_work_node_ids() {
        let template = serde_json::json!({
            "nodes": [{
                "id": "valid-node",
                "repository": "repo-a",
                "task": "implement feature",
                "depends_on": [],
                "required_evidence": ["tests"],
                "investigation": false
            }],
            "requested_investigation_children": 0
        });
        let oversized = "x".repeat(81);
        for invalid in [
            "../outside",
            "folder/node",
            "bad\u{0007}id",
            oversized.as_str(),
        ] {
            let mut value = template.clone();
            value["nodes"][0]["id"] = serde_json::Value::String(invalid.into());
            assert!(
                serde_json::from_value::<WorkPlan>(value).is_err(),
                "accepted invalid work node ID {invalid:?}"
            );
        }
    }

    #[test]
    fn duplicate_observations_merge_conservatively_and_ignore_input_order() {
        let canonical = GoalTicketObservation {
            id: TicketId::parse("canonical").unwrap(),
            created_at_unix_millis: 1,
            active_run: false,
            substantive_work: false,
        };
        let stale_duplicate = GoalTicketObservation {
            id: TicketId::parse("duplicate").unwrap(),
            created_at_unix_millis: 2,
            active_run: false,
            substantive_work: false,
        };
        let current_duplicate = GoalTicketObservation {
            active_run: true,
            substantive_work: true,
            ..stale_duplicate.clone()
        };
        let stale_then_current = vec![
            canonical.clone(),
            stale_duplicate.clone(),
            current_duplicate.clone(),
        ];
        let current_then_stale = vec![canonical, current_duplicate, stale_duplicate];
        let forward = resolve_goal_duplicates(&stale_then_current, None);
        let reverse = resolve_goal_duplicates(&current_then_stale, None);
        assert_eq!(forward, reverse);
        assert!(matches!(
            forward,
            DuplicateResolution::HumanRequired { candidates, .. }
                if candidates == vec![
                    TicketId::parse("canonical").unwrap(),
                    TicketId::parse("duplicate").unwrap()
                ]
        ));
    }

    #[test]
    fn conflicting_creation_timestamps_require_human_without_cancellation() {
        let id = TicketId::parse("duplicate").unwrap();
        let observations = [
            GoalTicketObservation {
                id: id.clone(),
                created_at_unix_millis: 2,
                active_run: false,
                substantive_work: false,
            },
            GoalTicketObservation {
                created_at_unix_millis: 3,
                ..GoalTicketObservation {
                    id: id.clone(),
                    created_at_unix_millis: 2,
                    active_run: false,
                    substantive_work: false,
                }
            },
        ];
        let forward = resolve_goal_duplicates(&observations, None);
        let reverse =
            resolve_goal_duplicates(&observations.into_iter().rev().collect::<Vec<_>>(), None);
        assert_eq!(forward, reverse);
        assert!(matches!(
            forward,
            DuplicateResolution::HumanRequired { candidates, reason }
                if candidates == vec![id] && reason.contains("creation timestamps")
        ));
    }

    #[test]
    fn multi_repository_plan_is_acyclic_and_only_worker_can_implement() {
        let project = goal_project();
        let repo_a = RepositoryId::parse("repo-a").unwrap();
        let repo_b = RepositoryId::parse("repo-b").unwrap();
        let mut project = project;
        project.repositories.push(repo_b.clone());
        let base = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let plan = WorkPlan {
            nodes: vec![
                PlannedWorkNode {
                    id: WorkNodeId::parse("api").unwrap(),
                    repository: repo_a.clone(),
                    task: "update API".into(),
                    depends_on: vec![],
                    required_evidence: vec!["tests".into()],
                    investigation: false,
                },
                PlannedWorkNode {
                    id: WorkNodeId::parse("docs").unwrap(),
                    repository: repo_b.clone(),
                    task: "update docs".into(),
                    depends_on: vec![WorkDependency {
                        node: WorkNodeId::parse("api").unwrap(),
                        kind: WorkDependencyKind::Delivery,
                        affected_evidence: BTreeSet::from(["tests".into(), "review".into()]),
                    }],
                    required_evidence: vec!["docs check".into()],
                    investigation: false,
                },
                PlannedWorkNode {
                    id: WorkNodeId::parse("api-integration").unwrap(),
                    repository: repo_a.clone(),
                    task: "integrate the API branch".into(),
                    depends_on: vec![WorkDependency {
                        node: WorkNodeId::parse("api").unwrap(),
                        kind: WorkDependencyKind::GitBase,
                        affected_evidence: BTreeSet::from(["tests".into(), "review".into()]),
                    }],
                    required_evidence: vec!["integration tests".into()],
                    investigation: false,
                },
            ],
            requested_investigation_children: 0,
        };
        let bases = BTreeMap::from([
            (repo_a.clone(), base.clone()),
            (repo_b.clone(), base.clone()),
        ]);
        let result = validate_work_plan(
            &TicketRunId::parse("run-1").unwrap(),
            &project,
            plan.clone(),
            &bases,
        )
        .unwrap();
        assert_eq!(result.nodes_in_execution_order[0].id.as_str(), "api");
        assert_eq!(result.nodes_in_execution_order[0].role, Role::Worker);
        assert_eq!(
            result.nodes_in_execution_order[1].id.as_str(),
            "api-integration"
        );
        assert_eq!(
            result.nodes_in_execution_order[1].base,
            WorkBaseSource::PredecessorWorkNodeHead {
                node: WorkNodeId::parse("api").unwrap()
            }
        );
        assert_eq!(result.nodes_in_execution_order[2].role, Role::Worker);
        let mut cyclic = plan;
        cyclic.nodes[0].depends_on.push(WorkDependency {
            node: WorkNodeId::parse("docs").unwrap(),
            kind: WorkDependencyKind::Delivery,
            affected_evidence: BTreeSet::from(["integration".into()]),
        });
        assert!(
            validate_work_plan(
                &TicketRunId::parse("run-1").unwrap(),
                &project,
                cyclic,
                &bases
            )
            .is_err()
        );
    }

    #[test]
    fn review_iterations_stop_at_the_configured_bound() {
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 0,
                    maximum_rounds: 2
                },
                true
            )
            .unwrap(),
            ReviewDisposition::StartCorrectionWorker
        );
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 2,
                    maximum_rounds: 2
                },
                true
            )
            .unwrap(),
            ReviewDisposition::HumanRequiredAtRoundLimit
        );
        assert_eq!(
            review_disposition(
                ReviewProgress {
                    completed_rounds: 2,
                    maximum_rounds: 2
                },
                false
            )
            .unwrap(),
            ReviewDisposition::StartMergeDecision
        );
    }

    #[test]
    fn coordinator_cannot_submit_a_worker_result_and_worker_cannot_publish() {
        assert!(
            authorize_role_request(Role::Coordinator, RoleRequest::WorkerSubmitEvidence).is_err()
        );
        assert!(
            authorize_role_request(Role::Worker, RoleRequest::SupervisorProposeTicket).is_err()
        );
        assert!(
            authorize_role_request(Role::Worker, RoleRequest::MergeDecisionRequestMerge).is_err()
        );
        assert!(
            authorize_role_request(Role::Coordinator, RoleRequest::CoordinatorStartWorker).is_ok()
        );
    }

    #[test]
    fn dispatch_only_uses_configured_ready_state_and_deduplicates_by_active_claim() {
        let project = goal_project();
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, false, true),
            DispatchDecision::Dispatch { .. }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Triage, false, true),
            DispatchDecision::Ignore { .. }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, true, true),
            DispatchDecision::Ignore {
                reason: DispatchIgnore::ExistingRunOwnsTicket
            }
        ));
        assert!(matches!(
            dispatch_decision(&project, TicketStatus::Ready, false, false),
            DispatchDecision::Ignore {
                reason: DispatchIgnore::ProjectPausedOrStopped
            }
        ));
    }

    #[test]
    fn a_previously_selected_canonical_survives_an_incomplete_search_page() {
        let old = TicketId::parse("canonical-old").unwrap();
        let late_duplicate = GoalTicketObservation {
            id: TicketId::parse("duplicate-late").unwrap(),
            created_at_unix_millis: 1767225602000,
            active_run: false,
            substantive_work: false,
        };
        assert_eq!(
            resolve_goal_duplicates(std::slice::from_ref(&late_duplicate), Some(&old)),
            DuplicateResolution::Canonical {
                ticket_id: old,
                annotate_and_cancel: vec![late_duplicate.id],
            }
        );
    }

    #[test]
    fn goal_completion_always_waits_for_human_confirmation() {
        let project = goal_project();
        let evidence = GoalCompletionEvidence {
            satisfied_acceptance: vec!["api".into()],
            incomplete_ticket_ids: vec![],
            deferred_risks: vec![],
            operation_results: vec!["deployed".into()],
            subject_digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        };
        assert!(matches!(
            propose_goal_completion(
                &project,
                evidence.clone(),
                &BTreeSet::from(["api".into()]),
                0
            ),
            GoalCompletionDecision::RequestHumanConfirmation { .. }
        ));
        assert!(matches!(
            propose_goal_completion(&project, evidence, &BTreeSet::from(["api".into()]), 1),
            GoalCompletionDecision::NotSatisfied { .. }
        ));
    }

    #[test]
    fn wake_coalescing_preserves_all_ids_and_orders_stop_before_human_before_observation() {
        let session = WakeSessionKey {
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: Some(TicketRunId::parse("run-1").unwrap()),
            role: Role::Coordinator,
        };
        let events = vec![
            WakeEvent {
                event_id: "observation".into(),
                session: session.clone(),
                source_revision: 3,
                observed_at_unix_millis: 30,
                cause: WakeCause::ExternalObservation,
            },
            WakeEvent {
                event_id: "human".into(),
                session: session.clone(),
                source_revision: 2,
                observed_at_unix_millis: 20,
                cause: WakeCause::HumanResponse,
            },
            WakeEvent {
                event_id: "fence".into(),
                session: session.clone(),
                source_revision: 1,
                observed_at_unix_millis: 10,
                cause: WakeCause::StopOrPolicyFence,
            },
            WakeEvent {
                event_id: "human".into(),
                session,
                source_revision: 2,
                observed_at_unix_millis: 20,
                cause: WakeCause::HumanResponse,
            },
        ];
        let coalesced = coalesce_wakes(&events).unwrap().unwrap();
        assert_eq!(coalesced.current_revision, 3);
        assert_eq!(
            coalesced.event_ids_in_precedence_order,
            vec!["fence", "human", "observation"]
        );
    }

    #[test]
    fn intervention_is_revision_bound_and_routes_via_coordinator() {
        let intervention = HumanIntervention {
            project_id: ProjectId::parse("project-a").unwrap(),
            ticket_run_id: TicketRunId::parse("run-1").unwrap(),
            expected_revision: 4,
            message: "Use the narrower migration plan".into(),
            fence_active_work: true,
        };
        assert!(route_human_intervention(&intervention, 3).is_err());
        assert_eq!(
            route_human_intervention(&intervention, 4).unwrap(),
            InterventionRoute {
                target: Role::Coordinator,
                notify: Role::Supervisor,
                fence_active_work: true,
            }
        );
    }

    #[test]
    fn planner_is_optional_for_routine_work_and_required_for_complexity_only_when_configured() {
        let mut project = goal_project();
        assert_eq!(
            select_planner(&project, PlanComplexity::Routine),
            PlannerSelection::CoordinatorPlansDirectly
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Complex),
            PlannerSelection::CoordinatorPlansDirectly
        );
        project.roles.insert(
            Role::Planner,
            crate::domain::ids::ProfileId::parse("planner").unwrap(),
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Complex),
            PlannerSelection::LaunchPlanner {
                profile_id: crate::domain::ids::ProfileId::parse("planner").unwrap()
            }
        );
        assert_eq!(
            select_planner(&project, PlanComplexity::Uncertain),
            PlannerSelection::HumanClarificationRequired
        );
    }
}
