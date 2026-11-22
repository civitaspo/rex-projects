//! Human-owned per-project policy, loaded from `policy.toml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The autonomy level supported by the current runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Autonomy {
    #[serde(rename = "A0")]
    A0,
    #[serde(rename = "A1")]
    A1,
}

/// Who may decide an Approval of a given kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approver {
    Human,
    Nobody,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBudgets {
    pub helpers: Option<u32>,
    pub minutes: Option<u32>,
}

/// The effective policy snapshotted into a Ticket when it is dispatched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub autonomy: Autonomy,
    #[serde(default)]
    pub required_approvals: Vec<String>,
    #[serde(default = "default_verification_attempts")]
    pub verification_attempts: u32,
    #[serde(default)]
    pub approvers: BTreeMap<String, Approver>,
    #[serde(default)]
    pub budgets: PolicyBudgets,
}

fn default_verification_attempts() -> u32 {
    3
}

impl Policy {
    /// Return the approver for a kind. Unconfigured kinds require a human.
    pub fn approver(&self, kind: &str) -> Approver {
        self.approvers.get(kind).copied().unwrap_or(Approver::Human)
    }

    fn validate(&self, project_id: &str) -> Result<()> {
        if self.verification_attempts == 0 {
            bail!(
                "policy for project {project_id:?}: verification_attempts must be greater than zero"
            );
        }
        if self.required_approvals.iter().any(String::is_empty) {
            bail!(
                "policy for project {project_id:?}: required_approvals cannot contain an empty kind"
            );
        }
        if self.approvers.iter().any(|(kind, _)| kind.is_empty()) {
            bail!("policy for project {project_id:?}: approver kinds cannot be empty");
        }
        if self.autonomy == Autonomy::A0
            && self
                .approvers
                .values()
                .any(|approver| *approver != Approver::Human)
        {
            bail!("policy for project {project_id:?}: A0 requires every approver to be human");
        }
        if self.autonomy == Autonomy::A1 && self.approver("plan") != Approver::Human {
            bail!("policy for project {project_id:?}: A1 requires the plan approver to be human");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    projects: BTreeMap<String, Policy>,
}

/// Load the policy for one project. Missing files and projects preserve the
/// legacy behavior and therefore return `None`.
pub fn load(config_dir: &Path, project_id: &str) -> Result<Option<Policy>> {
    let path = config_dir.join("policy.toml");
    load_from_path(&path, project_id)
}

/// Path-taking variant used by tests and callers that already resolved the
/// policy file location.
pub fn load_from_path(path: &Path, project_id: &str) -> Result<Option<Policy>> {
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read policy {}", path.display())),
    };
    let file: PolicyFile =
        toml::from_str(&source).with_context(|| format!("parse policy {}", path.display()))?;
    let Some(policy) = file.projects.get(project_id).cloned() else {
        return Ok(None);
    };
    policy
        .validate(project_id)
        .with_context(|| format!("validate policy {}", path.display()))?;
    Ok(Some(policy))
}

/// Resolve a project policy from a config directory, useful to keep the
/// policy file path explicit at the CLI boundary.
pub fn file_path(config_dir: &Path) -> PathBuf {
    config_dir.join("policy.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_policy(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn loads_project_policy_and_defaults_unknown_approvers_to_human() {
        let (_dir, path) =
            write_policy("[projects.demo]\nautonomy='A1'\nrequired_approvals=['plan']\n");
        let policy = load_from_path(&path, "demo").unwrap().unwrap();
        assert_eq!(policy.verification_attempts, 3);
        assert_eq!(policy.approver("plan"), Approver::Human);
        assert_eq!(policy.approver("release"), Approver::Human);
    }

    #[test]
    fn missing_file_or_project_means_no_policy() {
        let dir = tempdir().unwrap();
        assert_eq!(load(dir.path(), "demo").unwrap(), None);
        let (_dir, path) = write_policy("[projects.other]\nautonomy='A0'\n");
        assert_eq!(load_from_path(&path, "demo").unwrap(), None);
    }

    #[test]
    fn rejects_unknown_keys_and_unsupported_autonomy() {
        let (_dir, path) = write_policy("[projects.demo]\nautonomy='A2'\n");
        assert!(load_from_path(&path, "demo").is_err());
        let (_dir, path) = write_policy("[projects.demo]\nautonomy='A0'\nunknown=true\n");
        assert!(load_from_path(&path, "demo").is_err());
    }

    #[test]
    fn validates_approvers_by_autonomy_and_attempt_count() {
        let (_dir, path) = write_policy(
            "[projects.demo]\nautonomy='A0'\n[projects.demo.approvers]\nplan='nobody'\n",
        );
        assert!(format!("{:#}", load_from_path(&path, "demo").unwrap_err()).contains("A0"));
        let (_dir, path) = write_policy(
            "[projects.demo]\nautonomy='A1'\n[projects.demo.approvers]\nplan='nobody'\n",
        );
        assert!(format!("{:#}", load_from_path(&path, "demo").unwrap_err()).contains("plan"));
        let (_dir, path) =
            write_policy("[projects.demo]\nautonomy='A1'\nverification_attempts=0\n");
        assert!(
            format!("{:#}", load_from_path(&path, "demo").unwrap_err())
                .contains("verification_attempts")
        );
    }

    #[test]
    fn a1_can_delegate_non_plan_approvals() {
        let (_dir, path) = write_policy(
            "[projects.demo]\nautonomy='A1'\n[projects.demo.approvers]\nplan='human'\nrelease='nobody'\n",
        );
        let policy = load_from_path(&path, "demo").unwrap().unwrap();
        assert_eq!(policy.approver("release"), Approver::Nobody);
    }
}
