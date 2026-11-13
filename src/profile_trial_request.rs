//! Host-derived, immutable inputs for staging one human profile-trial request.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::config::{AppliedConfig, Profile};
use crate::domain::ids::{Digest, HumanRequestId, ProfileId, ProjectId, Revision};
use crate::domain::types::Role;
use crate::learning_trials::{
    FrozenTrialInput, FrozenTrialSkillTree, InlineFixtureV1, ProfileTrialAuthorization,
    TrialEvaluator, TrialPairSpec, TrialProfileSnapshot,
};

const POLICY: &[u8] = b"rex-profile-trial-request-policy-v1\0pairs=10;distinct_inputs=5;attempts_per_side=1;approval_ttl_seconds=86400;fixture=inline_fixture_v1;evaluator=structured_assertions_v1";
pub const APPROVAL_TTL_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRequestMatrix {
    pub inputs: Vec<TrialMatrixInput>,
    pub pairs: Vec<TrialPairSpec>,
    #[serde(default)]
    pub scoped_exception: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrialMatrixInput {
    pub input_id: String,
    pub input: Value,
    #[serde(default)]
    pub fixture: InlineFixtureV1,
    #[serde(default)]
    pub assertions: Vec<crate::learning_trials::TrialAssertion>,
}

pub struct TrialAuthorizationSeed {
    pub project_id: ProjectId,
    pub role: Role,
    pub candidate_id: String,
    pub candidate_digest: Digest,
    pub base_profile_id: ProfileId,
    pub config_revision: Revision,
    pub config_digest: Digest,
    pub baseline_qualification_digest: Digest,
    pub candidate_qualification_digest: Digest,
    pub request_key: String,
    pub now_unix: u64,
}

pub struct FrozenTrialMatrix {
    pub baseline: TrialProfileSnapshot,
    pub candidate: TrialProfileSnapshot,
    pub inputs: Vec<FrozenTrialInput>,
    pub pairs: Vec<TrialPairSpec>,
    pub scoped_exception: Option<String>,
}

impl TrialRequestMatrix {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::learning_trials::INLINE_FIXTURE_MATRIX_MAX_BYTES {
            return Err("trial request matrix exceeds the 512 KiB limit".into());
        }
        crate::protocol::parse_unique(bytes)
    }

    pub fn freeze(&self) -> Result<Vec<FrozenTrialInput>, String> {
        if self.inputs.len() < crate::learning::MIN_DISTINCT_INPUTS
            || self.inputs.len() > crate::learning::MAX_TRIAL_PAIRS_PER_REVISION
        {
            return Err("trial request requires 5 to 10 distinct inputs".into());
        }
        let mut seen = BTreeSet::new();
        self.inputs
            .iter()
            .map(|input| {
                if input.input_id.is_empty()
                    || input.input_id.len() > 128
                    || input.input_id.chars().any(char::is_control)
                    || !seen.insert(input.input_id.as_str())
                {
                    return Err("trial input IDs must be unique bounded tokens".into());
                }
                let input_json = serde_json::to_string(&input.input).map_err(|e| e.to_string())?;
                if input_json.len() > crate::learning_trials::MAX_FROZEN_INPUT_BYTES {
                    return Err("trial input exceeds the frozen input size limit".into());
                }
                input.fixture.validate()?;
                let evaluator = TrialEvaluator::StructuredAssertionsV1 {
                    assertions: input.assertions.clone(),
                };
                let evaluator_revision = evaluator.digest()?;
                let fixture_revision =
                    Digest::parse(format!("{:x}", Sha256::digest(b"inline_fixture_v1")))?;
                let input_digest =
                    Digest::parse(format!("{:x}", Sha256::digest(input_json.as_bytes())))?;
                Ok(FrozenTrialInput {
                    input_id: input.input_id.clone(),
                    input_digest,
                    input_json,
                    fixture_id: crate::learning_trials::INLINE_FIXTURE_ID.into(),
                    fixture_revision,
                    workspace_seed_digest: input.fixture.digest()?,
                    fixture_seed: input.fixture.clone(),
                    evaluator_id: evaluator.implementation_id().into(),
                    evaluator_revision,
                    evaluator,
                })
            })
            .collect()
    }
}

pub fn stable_ids(
    project: &ProjectId,
    request_key: &str,
) -> Result<(String, HumanRequestId), String> {
    if request_key.is_empty()
        || request_key.len() > 200
        || request_key.chars().any(char::is_control)
    {
        return Err("request key must be a nonempty bounded printable value".into());
    }
    let mut digest = b"rex-profile-trial-request-key-v1\0".to_vec();
    digest.extend(serde_json::to_vec(&(project, request_key)).map_err(|e| e.to_string())?);
    let hex = format!("{:x}", Sha256::digest(digest));
    let authorization = format!("profile-trial-{}", &hex[..40]);
    let human = HumanRequestId::parse(format!("profile-trial-{}", &hex[40..]))?;
    Ok((authorization, human))
}

pub fn canonical_profile(profile: &Profile) -> Result<String, String> {
    crate::store::canonical_json(profile)
}

pub fn profile_snapshot(
    applied: &AppliedConfig,
    profile_id: &ProfileId,
    source_profile_id: &ProfileId,
    profile: &Profile,
    package_files: Option<&BTreeMap<String, Vec<u8>>>,
    external_sources: Option<&BTreeMap<String, String>>,
) -> Result<TrialProfileSnapshot, String> {
    let logical_root = std::path::PathBuf::from(&applied.source_root)
        .join("profiles")
        .join(source_profile_id.as_str());
    let source_dir = applied
        .source_files
        .iter()
        .find(|source| {
            matches!(source.kind, crate::config::SourceKind::Directory)
                && std::path::Path::new(&source.path) == logical_root
        })
        .ok_or_else(|| {
            format!("profile `{profile_id}` is absent from the captured source manifest")
        })?;
    let canonical_root = std::path::PathBuf::from(&source_dir.canonical_path);
    let mut files = BTreeMap::new();
    let mut paths = profile.instruction_files.clone();
    paths.push("instructions.md".into());
    if let Some(guidance) = &profile.learned_guidance {
        paths.push(guidance.file.clone());
    }
    paths.sort();
    paths.dedup();
    for configured_path in paths {
        let configured = std::path::Path::new(&configured_path);
        let (snapshot_path, source) = if configured.is_absolute() {
            let source = applied.source_files.iter().find(|source| {
                matches!(source.kind, crate::config::SourceKind::File)
                    && std::path::Path::new(&source.path) == configured
            });
            let source = source.ok_or_else(|| {
                format!(
                    "absolute profile instruction `{configured_path}` is absent from the captured source manifest"
                )
            })?;
            let canonical = std::path::Path::new(&source.canonical_path);
            canonical.strip_prefix(&canonical_root).map_err(|_| {
                format!(
                    "absolute profile instruction `{configured_path}` escapes its captured profile directory"
                )
            })?;
            let lexical_relative = std::path::Path::new(&source.path)
                .strip_prefix(&canonical_root)
                .or_else(|_| std::path::Path::new(&source.path).strip_prefix(&logical_root))
                .or_else(|_| configured.strip_prefix(&canonical_root))
                .or_else(|_| configured.strip_prefix(&logical_root))
                .map_err(|_| format!("absolute profile instruction `{configured_path}` is outside its captured profile directory"))?;
            if lexical_relative.as_os_str().is_empty() {
                return Err(format!(
                    "absolute profile instruction `{configured_path}` does not name a file"
                ));
            }
            (
                lexical_relative.to_string_lossy().into_owned(),
                Some(source),
            )
        } else {
            let logical = logical_root.join(configured);
            let canonical = canonical_root.join(configured);
            let source = applied.source_files.iter().find(|source| {
                matches!(source.kind, crate::config::SourceKind::File)
                    && (std::path::Path::new(&source.path) == logical
                        || std::path::Path::new(&source.path) == canonical
                        || std::path::Path::new(&source.canonical_path) == canonical)
            });
            (configured_path.clone(), source)
        };
        let bytes = if let Some(package) = package_files {
            let package_key = source
                .and_then(|source| {
                    external_sources.and_then(|mapping| mapping.get(&source.canonical_path))
                })
                .cloned()
                .or_else(|| {
                    source.and_then(|source| {
                        std::path::Path::new(&source.path)
                            .strip_prefix(&canonical_root)
                            .or_else(|_| {
                                std::path::Path::new(&source.path).strip_prefix(&logical_root)
                            })
                            .ok()
                            .map(|path| path.to_string_lossy().into_owned())
                    })
                })
                .unwrap_or_else(|| snapshot_path.clone());
            package.get(&package_key).cloned()
        } else {
            source.map(|source| source.contents.as_bytes().to_vec())
        };
        if let Some(bytes) = bytes {
            files.insert(snapshot_path, bytes);
        } else if profile.instruction_files.contains(&configured_path)
            || profile
                .learned_guidance
                .as_ref()
                .is_some_and(|guidance| guidance.file == configured_path)
        {
            return Err(format!(
                "captured profile is missing required instruction `{configured_path}`"
            ));
        }
    }
    let profile_digest = crate::store::agent_profile_digest(profile)?;
    let instruction_digest = Digest::parse(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&files).map_err(|e| e.to_string())?)
    ))?;
    let skill_trees = freeze_skill_trees(
        applied,
        profile,
        &canonical_root,
        &logical_root,
        package_files,
        external_sources,
    )?;
    let snapshot = TrialProfileSnapshot {
        profile_id: profile_id.clone(),
        profile_digest,
        instruction_digest,
        profile_config_json: canonical_profile(profile)?,
        instruction_files: files,
        skill_trees,
    };
    crate::learning_trials::validate_trial_profile_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn freeze_skill_trees(
    applied: &AppliedConfig,
    profile: &Profile,
    canonical_profile_root: &std::path::Path,
    logical_profile_root: &std::path::Path,
    package_files: Option<&BTreeMap<String, Vec<u8>>>,
    external_sources: Option<&BTreeMap<String, String>>,
) -> Result<BTreeMap<String, FrozenTrialSkillTree>, String> {
    let mut trees = BTreeMap::new();
    let mut canonical_roots = BTreeSet::new();
    for configured in &profile.skill_paths {
        let configured_path = std::path::Path::new(configured);
        let logical_root = if configured_path.is_absolute() {
            configured_path.to_path_buf()
        } else {
            canonical_profile_root.join(configured_path)
        };
        let logical_root = logical_root.display().to_string();
        let root_source = applied.source_files.iter().find(|source| {
            matches!(source.kind, crate::config::SourceKind::Directory)
                && source.path == logical_root
        }).ok_or_else(|| format!("selected skill root `{configured}` is absent from the captured source manifest or is not a directory"))?;
        let canonical_root = std::path::PathBuf::from(&root_source.canonical_path);
        let directory_name = canonical_root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("captured skill root has no UTF-8 directory name")?
            .to_owned();
        if !configured_path.is_absolute() && !canonical_root.starts_with(canonical_profile_root) {
            return Err(format!(
                "relative selected skill root `{configured}` escapes its captured profile directory"
            ));
        }
        if !canonical_roots.insert(canonical_root.clone()) {
            return Err("selected skill roots alias the same captured directory".into());
        }
        let mut files: BTreeMap<String, (std::path::PathBuf, String)> = BTreeMap::new();
        for source in &applied.source_files {
            if !matches!(source.kind, crate::config::SourceKind::File) {
                continue;
            }
            let canonical = std::path::Path::new(&source.canonical_path);
            let Ok(relative) = canonical.strip_prefix(&canonical_root) else {
                continue;
            };
            if relative.as_os_str().is_empty() {
                return Err(format!(
                    "selected skill root `{configured}` is not a directory"
                ));
            }
            let relative = relative
                .to_str()
                .ok_or("captured skill path is not UTF-8")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if !crate::learning_trials::valid_trial_relative_path(&relative) {
                return Err("captured skill path is unsafe".into());
            }
            let captured = source.contents.as_bytes();
            if captured.len() as u64 != source.bytes
                || Digest::parse(format!("{:x}", Sha256::digest(captured)))? != source.sha256
            {
                return Err(format!(
                    "captured skill `{relative}` does not match its source manifest"
                ));
            }
            let bytes = if let Some(package) = package_files {
                let package_key = if let Some(external) =
                    external_sources.and_then(|mapping| mapping.get(&source.canonical_path))
                {
                    external.clone()
                } else {
                    canonical
                        .strip_prefix(canonical_profile_root)
                        .or_else(|_| std::path::Path::new(&source.path).strip_prefix(logical_profile_root))
                        .ok()
                        .and_then(|path| path.to_str())
                        .ok_or_else(|| format!("candidate package has no exact mapping for selected skill `{relative}`"))?
                        .replace(std::path::MAIN_SEPARATOR, "/")
                };
                if !crate::learning_trials::valid_trial_relative_path(&package_key) {
                    return Err(format!(
                        "candidate package mapping for selected skill `{relative}` is unsafe"
                    ));
                }
                let bytes = package.get(&package_key).ok_or_else(|| {
                    format!("candidate package is missing selected skill `{relative}`")
                })?;
                if bytes.len() as u64 != source.bytes
                    || Digest::parse(format!("{:x}", Sha256::digest(bytes)))? != source.sha256
                {
                    return Err(format!(
                        "candidate package substituted selected skill `{relative}`"
                    ));
                }
                bytes.clone()
            } else {
                captured.to_vec()
            };
            let contents = String::from_utf8(bytes)
                .map_err(|_| format!("selected skill `{relative}` is not UTF-8"))?;
            if let Some((existing_canonical, existing_contents)) = files.get(&relative) {
                if existing_canonical != canonical || existing_contents != &contents {
                    return Err(format!(
                        "selected skill contains conflicting path `{relative}`"
                    ));
                }
            } else {
                files.insert(relative, (canonical.to_owned(), contents));
            }
        }
        if !files.contains_key("SKILL.md") {
            return Err(format!(
                "selected skill `{configured}` must be a directory containing SKILL.md"
            ));
        }
        let root_key = crate::learning_trials::trial_skill_root_key(configured)?;
        if trees
            .insert(
                root_key,
                FrozenTrialSkillTree {
                    directory_name,
                    files: files
                        .into_iter()
                        .map(|(relative, (_, contents))| (relative, contents))
                        .collect(),
                },
            )
            .is_some()
        {
            return Err("selected skill roots have duplicate identities".into());
        }
    }
    Ok(trees)
}

pub fn make_authorization(
    seed: TrialAuthorizationSeed,
    matrix: FrozenTrialMatrix,
) -> Result<ProfileTrialAuthorization, String> {
    let (authorization_id, human_request_id) = stable_ids(&seed.project_id, &seed.request_key)?;
    let policy_digest = Digest::parse(format!("{:x}", Sha256::digest(POLICY)))?;
    let auth = ProfileTrialAuthorization {
        schema_version: crate::learning_trials::PROFILE_TRIAL_CAPSULE_SCHEMA_VERSION,
        authorization_id,
        project_id: seed.project_id,
        role: seed.role,
        candidate_id: seed.candidate_id,
        candidate_digest: seed.candidate_digest,
        base_profile_id: seed.base_profile_id,
        base_profile_digest: matrix.baseline.profile_digest.clone(),
        config_revision: seed.config_revision,
        config_digest: seed.config_digest.clone(),
        baseline_qualification_digest: seed.baseline_qualification_digest,
        candidate_qualification_digest: seed.candidate_qualification_digest,
        trial_policy_digest: policy_digest.clone(),
        baseline: matrix.baseline,
        candidate: matrix.candidate,
        inputs: matrix.inputs,
        pairs: matrix.pairs,
        scoped_exception: matrix.scoped_exception,
        human_request_id,
        human_subject_digest: Digest::parse("0".repeat(64))?,
        human_configuration_digest: seed.config_digest,
        human_policy_digest: policy_digest,
        human_response_receipt_digest: Digest::parse("0".repeat(64))?,
        authorized_at_unix: seed.now_unix,
        max_attempts_per_side: 1,
        expires_at_unix: seed.now_unix.saturating_add(APPROVAL_TTL_SECONDS),
    };
    auth.validate()?;
    Ok(auth)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    fn snapshot_fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixture");
        std::fs::copy(fixture.join("config.toml"), temp.path().join("config.toml")).unwrap();
        for id in ["worker_codex", "judgment_claude"] {
            let source = fixture.join("profiles").join(id);
            let target = temp.path().join("profiles").join(id);
            std::fs::create_dir_all(&target).unwrap();
            for file in ["config.toml", "instructions.md"] {
                std::fs::copy(source.join(file), target.join(file)).unwrap();
            }
        }
        temp
    }

    #[cfg(unix)]
    fn prepend_profile_fields(root: &std::path::Path, id: &str, fields: &str) {
        let path = root.join("profiles").join(id).join("config.toml");
        let original = std::fs::read_to_string(&path).unwrap();
        std::fs::write(path, format!("{fields}\n{original}")).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn captured_skill_root_uses_exact_logical_path_after_symlink_changes() {
        let temp = snapshot_fixture();
        let root = temp.path();
        let profile_root = root.join("profiles/worker_codex").canonicalize().unwrap();
        std::fs::create_dir_all(profile_root.join("nested/child")).unwrap();
        for (directory, marker) in [("nested/ops", "NESTED"), ("ops", "TOP")] {
            let directory = profile_root.join(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("SKILL.md"), marker).unwrap();
        }
        let alias = profile_root.join("zlink");
        std::os::unix::fs::symlink(profile_root.join("nested/child"), &alias).unwrap();
        prepend_profile_fields(root, "worker_codex", "skill_paths = [\"zlink/../ops\"]");
        prepend_profile_fields(
            root,
            "judgment_claude",
            &format!(
                "skill_paths = [{:?}]",
                profile_root.join("ops").display().to_string()
            ),
        );
        let applied = crate::config::load(&root.join("config.toml")).unwrap();
        std::fs::remove_file(alias).unwrap();
        let id = super::ProfileId::parse("worker_codex").unwrap();
        let profile = &applied.profiles[&id];
        let snapshot = super::profile_snapshot(&applied, &id, &id, profile, None, None).unwrap();
        let key = crate::learning_trials::trial_skill_root_key("zlink/../ops").unwrap();
        assert_eq!(snapshot.skill_trees[&key].files["SKILL.md"], "NESTED");
    }

    #[test]
    #[cfg(unix)]
    fn captured_skill_root_rejects_relative_profile_escape() {
        let temp = snapshot_fixture();
        let root = temp.path();
        let outside = root.join("external/ops");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("SKILL.md"), "outside skill").unwrap();
        prepend_profile_fields(
            root,
            "worker_codex",
            "skill_paths = [\"../../external/ops\"]",
        );
        let applied = crate::config::load(&root.join("config.toml")).unwrap();
        let id = super::ProfileId::parse("worker_codex").unwrap();
        let error = super::profile_snapshot(&applied, &id, &id, &applied.profiles[&id], None, None)
            .unwrap_err();
        assert!(
            error.contains("escapes its captured profile directory"),
            "{error}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn captured_skill_files_coalesce_verified_instruction_aliases() {
        use sha2::{Digest as _, Sha256};

        let temp = snapshot_fixture();
        let root = temp.path();
        let profile_root = root.join("profiles/worker_codex").canonicalize().unwrap();
        std::fs::create_dir_all(profile_root.join("ops/references")).unwrap();
        std::fs::write(profile_root.join("ops/SKILL.md"), "skill body").unwrap();
        std::fs::write(
            profile_root.join("ops/references/checks.md"),
            "shared reference",
        )
        .unwrap();
        let alias = profile_root.join("instruction-alias.md");
        std::os::unix::fs::symlink(profile_root.join("ops/references/checks.md"), &alias).unwrap();
        prepend_profile_fields(
            root,
            "worker_codex",
            "skill_paths = [\"ops\"]\ninstruction_files = [\"instruction-alias.md\"]",
        );
        let applied = crate::config::load(&root.join("config.toml")).unwrap();
        let id = super::ProfileId::parse("worker_codex").unwrap();
        let profile = &applied.profiles[&id];
        let snapshot = super::profile_snapshot(&applied, &id, &id, profile, None, None).unwrap();
        let key = crate::learning_trials::trial_skill_root_key("ops").unwrap();
        assert_eq!(snapshot.skill_trees[&key].files.len(), 2);
        assert_eq!(
            snapshot.skill_trees[&key].files["references/checks.md"],
            "shared reference"
        );
        let package = applied
            .source_files
            .iter()
            .filter_map(|source| {
                if source.kind != crate::config::SourceKind::File {
                    return None;
                }
                let relative = std::path::Path::new(&source.path)
                    .strip_prefix(&profile_root)
                    .ok()?;
                Some((
                    relative.to_str().unwrap().to_owned(),
                    source.contents.as_bytes().to_vec(),
                ))
            })
            .collect();
        let candidate =
            super::profile_snapshot(&applied, &id, &id, profile, Some(&package), None).unwrap();
        assert_eq!(candidate.skill_trees, snapshot.skill_trees);

        let mut invalid = applied.clone();
        let source = invalid
            .source_files
            .iter_mut()
            .find(|source| source.path == alias.display().to_string())
            .unwrap();
        source.contents = "unverified reference".into();
        assert!(
            super::profile_snapshot(&invalid, &id, &id, profile, None, None)
                .unwrap_err()
                .contains("does not match its source manifest")
        );

        let mut conflicting = applied.clone();
        let source = conflicting
            .source_files
            .iter_mut()
            .find(|source| source.path == alias.display().to_string())
            .unwrap();
        source.contents = "conflicting reference".into();
        source.bytes = source.contents.len() as u64;
        source.sha256 =
            super::Digest::parse(format!("{:x}", Sha256::digest(source.contents.as_bytes())))
                .unwrap();
        assert!(
            super::profile_snapshot(&conflicting, &id, &id, profile, None, None)
                .unwrap_err()
                .contains("conflicting path")
        );
    }

    #[test]
    fn documented_matrix_has_valid_frozen_inputs_and_standard_coverage() {
        let matrix = super::TrialRequestMatrix::parse(include_bytes!(
            "../examples/profile-trial-matrix.json"
        ))
        .unwrap();
        let inputs = matrix.freeze().unwrap();
        assert_eq!(inputs.len(), 5);
        assert_eq!(matrix.pairs.len(), 10);
        for input in inputs {
            assert_eq!(
                matrix
                    .pairs
                    .iter()
                    .filter(|pair| pair.input_id == input.input_id)
                    .count(),
                2
            );
        }
    }
}
