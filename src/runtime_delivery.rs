//! Construction of host-owned repository delivery adapters from applied configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{AppliedConfig, RepositoryConfig};
use crate::delivery_forge::validate_github_clone_url;
use crate::delivery_runtime::{RepositoryDeliveryEffectConfig, RepositoryDeliveryEffects};
use crate::domain::ids::{ProjectId, RepositoryId};
use crate::effects::EffectHandler;
use crate::process::{self, ProcessRequest, resolve_executable};
use crate::worktrees::GitOptions;

const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const GH_TIMEOUT: Duration = Duration::from_secs(120);
const TOOL_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Repository effect handlers and the observer used to detect out-of-band publication.
pub struct RuntimeDelivery {
    handlers: Vec<Box<dyn EffectHandler>>,
    effects: std::sync::Arc<RepositoryDeliveryEffects>,
    git_executable: PathBuf,
    git_environment: BTreeMap<OsString, OsString>,
    repositories: BTreeMap<RepositoryId, RepositoryConfig>,
}

impl RuntimeDelivery {
    pub fn handlers(&self) -> Vec<&dyn EffectHandler> {
        self.handlers.iter().map(Box::as_ref).collect()
    }

    pub fn effects(&self) -> &RepositoryDeliveryEffects {
        &self.effects
    }

    /// Resolve each configured base branch to its current remote commit without cloning or
    /// mutating a managed repository. The returned map is a single bounded read pass.
    pub fn observe_base_heads(&self) -> Result<BTreeMap<RepositoryId, String>, String> {
        let mut heads = BTreeMap::new();
        for (repository_id, repository) in &self.repositories {
            let reference = format!("refs/heads/{}", repository.base_branch);
            let output = process::run(ProcessRequest {
                executable: self.git_executable.clone(),
                args: vec![
                    OsString::from("ls-remote"),
                    OsString::from("--heads"),
                    OsString::from(&repository.clone_url),
                    OsString::from(&reference),
                ],
                stdin: Vec::new(),
                cwd: None,
                clear_environment: true,
                environment: self.git_environment.clone(),
                timeout: GIT_TIMEOUT,
                shutdown_grace: TOOL_SHUTDOWN_GRACE,
                stdout_limit: 64 * 1024,
                stderr_tail_limit: 16 * 1024,
            })
            .map_err(|error| format!("could not observe `{repository_id}` base branch: {error}"))?;
            if !output.status.is_some_and(|status| status.success())
                || output.timed_out
                || !output.cleanup_confirmed
                || output.stdout_truncated
            {
                return Err(format!(
                    "could not establish the remote base head for `{repository_id}`"
                ));
            }
            let text = std::str::from_utf8(&output.stdout)
                .map_err(|_| format!("Git returned non-UTF-8 output for `{repository_id}`"))?;
            let mut rows = text.lines();
            let line = rows
                .next()
                .ok_or_else(|| format!("configured base branch is absent for `{repository_id}`"))?;
            if rows.next().is_some() {
                return Err(format!(
                    "Git returned multiple remote refs for `{repository_id}`"
                ));
            }
            let (sha, observed_reference) = line
                .split_once('\t')
                .ok_or_else(|| format!("Git returned a malformed ref for `{repository_id}`"))?;
            if observed_reference != reference || !valid_git_sha(sha) {
                return Err(format!(
                    "Git returned an unexpected remote ref for `{repository_id}`"
                ));
            }
            heads.insert(repository_id.clone(), sha.to_owned());
        }
        Ok(heads)
    }
}

/// Resolve host tools from the environment captured for this Rex controller, then build the
/// real repository delivery handlers over the same managed state root used by the controller.
pub fn build(
    applied_config: &AppliedConfig,
    state_root: &Path,
    captured_host_env: &BTreeMap<OsString, OsString>,
) -> Result<RuntimeDelivery, String> {
    if !state_root.is_absolute() {
        return Err("repository delivery state root must be absolute".into());
    }
    let search_path = captured_host_env
        .get(OsStr::new("PATH"))
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if search_path.is_empty() {
        return Err("captured host environment has no usable PATH".into());
    }
    let git = resolve_executable(Path::new("git"), &search_path)
        .ok_or("git executable is unavailable in the captured host PATH")?;
    let gh = resolve_executable(Path::new("gh"), &search_path)
        .ok_or("gh executable is unavailable in the captured host PATH")?;

    let mut repositories = BTreeMap::<RepositoryId, RepositoryConfig>::new();
    for (repository_id, repository) in &applied_config.config.repositories {
        validate_repository(repository_id, repository)?;
        repositories.insert(repository_id.clone(), repository.clone());
    }
    let mut project_repositories = BTreeMap::<ProjectId, BTreeSet<RepositoryId>>::new();
    for (project_id, project) in &applied_config.config.projects {
        let selected = project
            .repositories
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for repository_id in &selected {
            let repository = repositories.get(repository_id).ok_or_else(|| {
                format!("Project `{project_id}` references unknown repository `{repository_id}`")
            })?;
            if repository.forge != "github" {
                return Err(format!(
                    "repository `{repository_id}` uses unsupported delivery forge `{}`; this runtime supports GitHub",
                    repository.forge
                ));
            }
        }
        project_repositories.insert(project_id.clone(), selected);
    }

    let effects = RepositoryDeliveryEffects::new(RepositoryDeliveryEffectConfig {
        state_root: state_root.to_owned(),
        git: GitOptions {
            executable: git.clone(),
            environment: captured_host_env.clone(),
            timeout: GIT_TIMEOUT,
        },
        inherited_environment: captured_host_env.clone(),
        gh_executable: gh,
        gh_environment: captured_host_env.clone(),
        timeout: GH_TIMEOUT,
        configuration_digest: applied_config.digest.clone(),
        repositories: repositories.clone(),
        project_repositories,
        max_global_hook_jobs: applied_config.config.runtime.max_rex_projects_hook_runs,
        max_hook_attempts: maximum_project_hook_attempts(&applied_config.config)?,
    })?;
    let handlers: Vec<Box<dyn EffectHandler>> = vec![
        Box::new(effects.prepare_worktrees_handler()),
        Box::new(effects.publish_implementation_handler()),
    ];
    Ok(RuntimeDelivery {
        handlers,
        effects,
        git_executable: git,
        git_environment: captured_host_env.clone(),
        repositories,
    })
}

fn valid_git_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn maximum_project_hook_attempts(config: &crate::config::Config) -> Result<u32, String> {
    let retries = config
        .projects
        .values()
        .map(|project| project.max_effect_retries)
        .max()
        .unwrap_or(0);
    u32::try_from(retries.saturating_add(1))
        .map_err(|_| "project hook retry limit exceeds the supported range".into())
}

fn validate_repository(
    repository_id: &RepositoryId,
    repository: &RepositoryConfig,
) -> Result<(), String> {
    if repository.forge != "github" {
        return Err(format!(
            "repository `{repository_id}` uses unsupported delivery forge `{}`; this runtime supports GitHub",
            repository.forge
        ));
    }
    validate_github_clone_url(&repository.clone_url).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn applied_config(clone_url: &str, forge: &str) -> AppliedConfig {
        let value = serde_json::json!({
            "schema_version": 1,
            "adapters": {"tickets": {
                "kind": "command",
                "command": ["ticket-cli"],
                "status_values": {
                    "triage":"Triage", "backlog":"Backlog", "ready":"ToDo",
                    "in_progress":"In Progress", "in_review":"In Review",
                    "done":"Done", "canceled":"Canceled"
                }
            }},
            "repositories": {"repo": {
                "clone_url": clone_url, "base_branch":"main", "forge":forge
            }},
            "projects": {"project": {
                "mode":"operations", "ticket_adapter":"tickets", "repositories":["repo"]
            }}
        });
        AppliedConfig {
            config: serde_json::from_value(value).unwrap(),
            profiles: BTreeMap::new(),
            source_root: String::new(),
            source_files: Vec::new(),
            digest: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
        }
    }

    fn tool_path(root: &Path) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        for name in ["git", "gh"] {
            let path = root.join(name);
            let body = if name == "git" {
                "#!/bin/sh\nprintf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\trefs/heads/main\\n'\n"
            } else {
                "#!/bin/sh\nexit 0\n"
            };
            fs::write(&path, body).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
        root.to_owned()
    }

    #[test]
    fn builds_delivery_handlers_from_captured_path_and_managed_state() {
        let temp = tempfile::tempdir().unwrap();
        let bin = tool_path(&temp.path().join("bin"));
        let env = BTreeMap::from([(OsString::from("PATH"), bin.into_os_string())]);
        let delivery = build(
            &applied_config("git@github.com:acme/demo.git", "github"),
            temp.path(),
            &env,
        )
        .unwrap();
        let kinds = delivery
            .handlers()
            .iter()
            .map(|handler| crate::engine::reducer::effect_name(&handler.kind()).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(kinds, ["prepare_worktrees", "publish_implementation"]);
        assert!(temp.path().join("repos").is_dir());
        assert_eq!(
            delivery.observe_base_heads().unwrap()[&RepositoryId::parse("repo").unwrap()],
            "a".repeat(40)
        );
    }

    #[test]
    fn rejects_missing_tools_and_unsupported_forge_before_creating_state() {
        let temp = tempfile::tempdir().unwrap();
        let empty_env = BTreeMap::from([(OsString::from("PATH"), OsString::new())]);
        assert!(
            build(
                &applied_config("git@github.com:acme/demo.git", "github"),
                temp.path(),
                &empty_env,
            )
            .is_err()
        );
        assert!(!temp.path().join("delivery").exists());

        let bin = tool_path(&temp.path().join("bin"));
        let env = BTreeMap::from([(OsString::from("PATH"), bin.into_os_string())]);
        assert!(
            build(
                &applied_config("ssh://git@example.invalid/acme/demo.git", "forgejo"),
                temp.path(),
                &env,
            )
            .is_err()
        );
        assert!(!temp.path().join("delivery").exists());
    }
}
