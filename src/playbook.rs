//! Playbook discovery, validation, and immutable dispatch snapshots.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{config::ProjectConfig, paths::Paths};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookSnapshot {
    pub name: String,
    pub sha256: String,
    pub body: String,
    pub spec: Option<PlaybookSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketPreparation {
    pub base_commit: String,
    pub playbook: Option<PlaybookSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlaybookSpec {
    #[serde(default)]
    pub stages: Vec<String>,
    /// None means every Role is allowed.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub gates: std::collections::BTreeMap<String, String>,
    pub verification: Option<VerificationSpec>,
    pub budgets: Option<BudgetSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSpec {
    #[serde(default)]
    pub checks: Vec<CheckSpec>,
    pub verifier: Option<VerifierSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSpec {
    pub name: String,
    pub argv: Vec<String>,
    pub timeout_minutes: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierSpec {
    pub role: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpec {
    pub helpers: Option<u32>,
    pub minutes: Option<u32>,
}

#[derive(Deserialize)]
struct Frontmatter {
    #[serde(rename = "rex-projects")]
    rex_projects: Option<PlaybookSpec>,
}

impl<'de> Deserialize<'de> for PlaybookSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            stages: Vec<String>,
            roles: Option<Vec<String>>,
            #[serde(default)]
            gates: std::collections::BTreeMap<String, String>,
            verification: Option<VerificationSpec>,
            budgets: Option<BudgetSpec>,
        }
        let raw = Raw::deserialize(deserializer)?;
        if let Some(roles) = &raw.roles {
            validate_names("roles", roles).map_err(serde::de::Error::custom)?;
        }
        validate_names("stages", &raw.stages).map_err(serde::de::Error::custom)?;
        for (stage, kind) in &raw.gates {
            if stage.trim().is_empty() {
                return Err(serde::de::Error::custom("gates stage must not be empty"));
            }
            if kind.trim().is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "gates.{stage} must not be empty"
                )));
            }
        }
        if let Some(v) = &raw.verification {
            for check in &v.checks {
                if check.name.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "verification.checks.name must not be empty",
                    ));
                }
                if check.argv.is_empty() || check.argv[0].trim().is_empty() {
                    return Err(serde::de::Error::custom(format!(
                        "verification.checks.{}.argv must not be empty",
                        check.name
                    )));
                }
                if check.timeout_minutes == Some(0) {
                    return Err(serde::de::Error::custom(format!(
                        "verification.checks.{}.timeout_minutes must be positive",
                        check.name
                    )));
                }
            }
        }
        Ok(Self {
            stages: raw.stages,
            roles: raw.roles,
            gates: raw.gates,
            verification: raw.verification,
            budgets: raw.budgets,
        })
    }
}

fn validate_names(field: &str, names: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for name in names {
        if name.trim().is_empty() {
            bail!("{field} entries must not be empty");
        }
        if !seen.insert(name) {
            bail!("{field} contains duplicate {name:?}");
        }
    }
    Ok(())
}

/// Removes frontmatter and returns the YAML metadata, body, and raw boundary.
fn split_markdown(text: &str) -> Result<(Option<Frontmatter>, &str)> {
    let Some(after_open) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return Ok((None, text));
    };
    let mut offset = 0;
    for line in after_open.split_inclusive('\n') {
        offset += line.len();
        if line.trim_end_matches(['\r', '\n']) == "---" {
            let yaml = &after_open[..offset - line.len()];
            let body = after_open[offset..].trim_start_matches(['\n', '\r']);
            let fm: Frontmatter = serde_yaml::from_str(yaml).context("invalid YAML frontmatter")?;
            return Ok((Some(fm), body));
        }
    }
    bail!("unterminated YAML frontmatter (missing closing ---)")
}

pub fn parse(name: &str, raw: &str, source: &Path) -> Result<PlaybookSnapshot> {
    let (frontmatter, body) = split_markdown(raw)
        .with_context(|| format!("playbook {} frontmatter", source.display()))?;
    let spec = frontmatter.and_then(|fm| fm.rex_projects);
    Ok(PlaybookSnapshot {
        name: name.to_owned(),
        sha256: format!("{:x}", Sha256::digest(raw.as_bytes())),
        body: body.to_owned(),
        spec,
    })
}

pub fn selected_name(ticket_choice: Option<&str>, default_choice: Option<&str>) -> Option<String> {
    ticket_choice.or(default_choice).map(str::to_owned)
}

pub fn resolve(paths: &Paths, project: &ProjectConfig, name: &str) -> Result<PlaybookSnapshot> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        bail!("invalid playbook name {name:?}; expected one directory name");
    }
    let candidates = [
        project.repo.join(".rex-projects/playbooks"),
        paths.config_dir.join("playbooks"),
    ]
    .map(|dir| dir.join(name).join("SKILL.md"));
    let path = candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .with_context(|| {
            format!(
                "playbook {name:?} not found in {} or {}",
                candidates[0].display(),
                candidates[1].display()
            )
        })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read playbook {}", path.display()))?;
    parse(name, &raw, path)
}

pub fn resolve_for_ticket(
    paths: &Paths,
    project: &ProjectConfig,
    choice: Option<&str>,
) -> Result<Option<PlaybookSnapshot>> {
    let Some(name) = selected_name(choice, project.default_playbook.as_deref()) else {
        return Ok(None);
    };
    resolve(paths, project, &name).map(Some)
}

pub fn source_path(paths: &Paths, project: &ProjectConfig, name: &str) -> PathBuf {
    let primary = project
        .repo
        .join(".rex-projects/playbooks")
        .join(name)
        .join("SKILL.md");
    if primary.is_file() {
        primary
    } else {
        paths
            .config_dir
            .join("playbooks")
            .join(name)
            .join("SKILL.md")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpx_block_and_strips_frontmatter() {
        let raw = "---\nname: feature\nrex-projects:\n  stages: [plan, implement]\n  roles: [worker, reviewer]\n  gates:\n    implement: plan\n  verification:\n    checks:\n      - name: test\n        argv: [cargo, test]\n  budgets:\n    helpers: 4\n---\nDo the work.\n";
        let snap = parse("feature", raw, Path::new("feature/SKILL.md")).unwrap();
        assert_eq!(snap.body, "Do the work.\n");
        let spec = snap.spec.unwrap();
        assert_eq!(spec.stages, ["plan", "implement"]);
        assert_eq!(spec.roles.unwrap(), ["worker", "reviewer"]);
        assert_eq!(spec.gates["implement"], "plan");
        assert_eq!(spec.verification.unwrap().checks[0].argv, ["cargo", "test"]);
        assert_eq!(snap.sha256.len(), 64);
    }

    #[test]
    fn missing_frontmatter_preserves_entire_markdown() {
        let snap = parse(
            "legacy",
            "# Existing playbook\n",
            Path::new("legacy/SKILL.md"),
        )
        .unwrap();
        assert_eq!(snap.body, "# Existing playbook\n");
        assert!(snap.spec.is_none());
    }

    #[test]
    fn rejects_unknown_keys_and_names_source_and_field() {
        let raw = "---\nrex-projects:\n  rolse: [worker]\n---\nbody";
        let err = format!(
            "{:#}",
            parse("feature", raw, Path::new("feature/SKILL.md")).unwrap_err()
        );
        assert!(err.contains("feature/SKILL.md"));
        assert!(err.contains("rolse"));
    }

    #[test]
    fn ticket_choice_precedes_project_default() {
        assert_eq!(
            selected_name(Some("ticket"), Some("default")),
            Some("ticket".into())
        );
        assert_eq!(selected_name(None, Some("default")), Some("default".into()));
    }
}
