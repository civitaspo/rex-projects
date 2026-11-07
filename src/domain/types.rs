use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Supervisor,
    Coordinator,
    Planner,
    Worker,
    Reviewer,
    MergeDecision,
    Operator,
    Postmortem,
}

impl Role {
    pub const ALL: [Self; 8] = [
        Self::Supervisor,
        Self::Coordinator,
        Self::Planner,
        Self::Worker,
        Self::Reviewer,
        Self::MergeDecision,
        Self::Operator,
        Self::Postmortem,
    ];
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectMode {
    Goal,
    Operations,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Triage,
    Backlog,
    Ready,
    InProgress,
    InReview,
    Done,
    Canceled,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitMode {
    #[default]
    Auto,
    Native,
    Host,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAdapter {
    Codex,
    ClaudeCode,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeStage {
    Planning,
    Implementation,
    Review,
    Merge,
    Operations,
    Postmortem,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    RepositoryPolicy,
    Always,
    NotRequired,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationSource(String);

impl OperationSource {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let valid_planned = value
            .strip_prefix("planned:")
            .is_some_and(|id| !id.is_empty() && valid_local_id(id));
        if value != "merge_commit" && !valid_planned {
            return Err("source must be `merge_commit` or `planned:<revision-id>`".into());
        }
        Ok(Self(value))
    }
}

fn valid_local_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl<'de> Deserialize<'de> for OperationSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::OperationSource;

    #[test]
    fn operation_sources_are_closed_and_support_named_planned_revisions() {
        assert!(OperationSource::parse("merge_commit").is_ok());
        assert!(OperationSource::parse("planned:release-2").is_ok());
        assert!(OperationSource::parse("shell:echo").is_err());
        assert!(OperationSource::parse("planned:../escape").is_err());
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Pending,
    Succeeded,
    Failed,
    Unknown,
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitConclusion {
    Success,
    Failure,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeMethod {
    Merge,
    Squash,
    Rebase,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeExecutor {
    Direct,
    Request,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAction {
    ForgeObservation,
    Command { command: Vec<String> },
}
