//! Finite Rex-block wrapper used only to bootstrap provider qualification.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::adapters::rex::{RexCliTransport, RexQualificationSessionReceipt};
use crate::config::Profile;
use crate::domain::ids::{Digest, ProjectId};
use crate::domain::types::Role;
use crate::environment::EnvironmentHandoff;
use crate::run_step::{
    CleanupState, DisposableQualificationContext, ProviderQualificationStatus, RunDescriptor,
    RunReceipt, SystemProcessObserver, TurnOutcome, TurnRequest, issue_qualification_permit,
    run_qualification_turn,
};

const MAX_PACKAGE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationRunPackage {
    pub schema_version: u32,
    pub request_id: String,
    pub request_digest: Digest,
    pub config_revision: u64,
    pub config_digest: Digest,
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: crate::domain::ids::ProfileId,
    pub profile_digest: Digest,
    pub environment_snapshot_id: Digest,
    pub profile: Profile,
    pub descriptor: RunDescriptor,
    pub role_contract: String,
    pub prompt: String,
    pub workspace_root: PathBuf,
    pub environment_handoff: PathBuf,
    pub environment_operation_id: String,
    pub result_path: PathBuf,
    pub marker_probe_path: PathBuf,
    pub marker_probe_challenge: String,
    pub runtime_binary_path: PathBuf,
    pub runtime_binary_digest: Digest,
    pub rex_cli_path: PathBuf,
    pub rex_search_path: Vec<PathBuf>,
    pub rex_receipt: RexQualificationSessionReceipt,
    pub deadline_seconds: u64,
    pub shutdown_grace_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MarkerProbeReport {
    pub schema_version: u32,
    pub request_id: String,
    pub request_digest: Digest,
    pub project_id: ProjectId,
    pub role: Role,
    pub profile_id: crate::domain::ids::ProfileId,
    pub run_id: String,
    pub profile_digest: Digest,
    pub config_revision: u64,
    pub config_digest: Digest,
    pub challenge_digest: Digest,
    pub tool_pid: u32,
    pub tool_parent_pid: u32,
    pub descendant_pid: u32,
    pub tool_binary_digest: Digest,
    pub tool_shell_marker_hashes: BTreeMap<String, Digest>,
    pub descendant_marker_hashes: BTreeMap<String, Digest>,
}

pub(crate) struct VerifiedMarkerProbe {
    pub tool_shell_markers_present: std::collections::BTreeSet<String>,
    pub descendant_markers_present: std::collections::BTreeSet<String>,
    pub tool_shell_marker_digest: Digest,
    pub descendant_marker_digest: Digest,
}

#[derive(Debug, Eq, PartialEq)]
struct MarkerProbeBinding<'a> {
    request_id: &'a str,
    request_digest: &'a Digest,
    project_id: &'a ProjectId,
    role: Role,
    profile_id: &'a crate::domain::ids::ProfileId,
    run_id: &'a str,
    profile_digest: &'a Digest,
    config_revision: u64,
    config_digest: &'a Digest,
    challenge_digest: Digest,
    tool_binary_digest: &'a Digest,
}

impl<'a> MarkerProbeBinding<'a> {
    fn for_package(package: &'a QualificationRunPackage) -> Result<Self, String> {
        Ok(Self {
            request_id: &package.request_id,
            request_digest: &package.request_digest,
            project_id: &package.project_id,
            role: package.role,
            profile_id: &package.profile_id,
            run_id: package.descriptor.run_id.as_str(),
            profile_digest: &package.profile_digest,
            config_revision: package.config_revision,
            config_digest: &package.config_digest,
            challenge_digest: digest(package.marker_probe_challenge.as_bytes())?,
            tool_binary_digest: &package.runtime_binary_digest,
        })
    }

    fn for_report(report: &'a MarkerProbeReport) -> Self {
        Self {
            request_id: &report.request_id,
            request_digest: &report.request_digest,
            project_id: &report.project_id,
            role: report.role,
            profile_id: &report.profile_id,
            run_id: &report.run_id,
            profile_digest: &report.profile_digest,
            config_revision: report.config_revision,
            config_digest: &report.config_digest,
            challenge_digest: report.challenge_digest.clone(),
            tool_binary_digest: &report.tool_binary_digest,
        }
    }
}

pub(crate) fn verify_marker_probe(
    package: &QualificationRunPackage,
    report: &MarkerProbeReport,
) -> Result<VerifiedMarkerProbe, String> {
    let expected = expected_marker_values(package);
    if report.schema_version != 1
        || MarkerProbeBinding::for_package(package)? != MarkerProbeBinding::for_report(report)
    {
        return Err("qualification marker probe report is missing, mismatched, or unbound".into());
    }
    validate_marker_hashes(&expected, &report.tool_shell_marker_hashes)?;
    validate_marker_hashes(&expected, &report.descendant_marker_hashes)?;
    let tool_shell_marker_digest = digest(
        &serde_json::to_vec(&report.tool_shell_marker_hashes).map_err(|error| error.to_string())?,
    )?;
    let descendant_marker_digest = digest(
        &serde_json::to_vec(&report.descendant_marker_hashes).map_err(|error| error.to_string())?,
    )?;
    let present: std::collections::BTreeSet<String> = expected.keys().cloned().collect();
    Ok(VerifiedMarkerProbe {
        tool_shell_markers_present: present.clone(),
        descendant_markers_present: present,
        tool_shell_marker_digest,
        descendant_marker_digest,
    })
}

pub(crate) const REQUIRED_AGENT_MARKERS: [&str; 5] = [
    "REX_PROJECTS_AGENT",
    "REX_PROJECTS_CONTEXT",
    "REX_PROJECTS_PROJECT_ID",
    "REX_PROJECTS_ROLE",
    "REX_PROJECTS_RUN_ID",
];

pub(crate) fn qualification_role_name(role: Role) -> &'static str {
    match role {
        Role::Supervisor => "supervisor",
        Role::Coordinator => "coordinator",
        Role::Planner => "planner",
        Role::Worker => "worker",
        Role::Reviewer => "reviewer",
        Role::MergeDecision => "merge_decision",
        Role::Operator => "operator",
        Role::Postmortem => "postmortem",
    }
}

pub(crate) fn run_marker_probe(package_path: &Path) -> Result<(), String> {
    run_marker_probe_with_environment(package_path, None)
}

fn run_marker_probe_with_environment(
    package_path: &Path,
    supplied_environment: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<(), String> {
    let bytes = read_package_wait(package_path)?;
    let package: QualificationRunPackage = crate::protocol::parse_unique(&bytes)
        .map_err(|error| format!("qualification package is invalid: {error}"))?;
    validate_package(&package, package_path)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let executable_size = fs::metadata(&executable)
        .map_err(|error| error.to_string())?
        .len();
    if executable_size > 256 * 1024 * 1024
        || digest(&fs::read(&executable).map_err(|error| error.to_string())?)?
            != package.runtime_binary_digest
    {
        return Err("qualification probe executable does not match the pinned runtime".into());
    }
    let expected = expected_marker_values(&package);
    let tool_shell_marker_hashes = observed_marker_hashes(&expected, supplied_environment)?;
    let (descendant_marker_hashes, descendant_pid) =
        descendant_marker_hashes(supplied_environment, None)?;
    let challenge_digest = digest_bytes(package.marker_probe_challenge.as_bytes())?;
    let report = MarkerProbeReport {
        schema_version: 1,
        request_id: package.request_id,
        request_digest: package.request_digest,
        project_id: package.project_id,
        role: package.role,
        profile_id: package.profile_id,
        run_id: package.descriptor.run_id.as_str().to_owned(),
        profile_digest: package.profile_digest,
        config_revision: package.config_revision,
        config_digest: package.config_digest,
        challenge_digest,
        tool_pid: std::process::id(),
        tool_parent_pid: current_parent_pid(),
        descendant_pid,
        tool_binary_digest: package.runtime_binary_digest,
        tool_shell_marker_hashes,
        descendant_marker_hashes,
    };
    publish_probe_report(&package.marker_probe_path, &report)
}

fn descendant_marker_hashes(
    supplied_environment: Option<&BTreeMap<String, Vec<u8>>>,
    filtered_marker: Option<&str>,
) -> Result<(BTreeMap<String, Digest>, u32), String> {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf '%s\\0' \"$REX_PROJECTS_AGENT\" \"$REX_PROJECTS_CONTEXT\" \"$REX_PROJECTS_PROJECT_ID\" \"$REX_PROJECTS_ROLE\" \"$REX_PROJECTS_RUN_ID\"; /bin/sleep 1"]);
    if let Some(environment) = supplied_environment {
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        for (name, value) in environment {
            if filtered_marker != Some(name.as_str()) {
                command.env(name, String::from_utf8_lossy(value).as_ref());
            }
        }
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start marker descendant: {error}"))?;
    let descendant_pid = child.id();
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or("marker descendant stdout unavailable")?
        .take(4096)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if !child.wait().map_err(|error| error.to_string())?.success() {
        return Err("marker descendant failed".into());
    }
    let descendant_values: Vec<&[u8]> = output.split(|byte| *byte == 0).collect();
    if descendant_values.len() != REQUIRED_AGENT_MARKERS.len() + 1
        || descendant_values.last().copied() != Some(&b""[..])
    {
        return Err("marker descendant returned a malformed probe result".into());
    }
    let hashes = REQUIRED_AGENT_MARKERS
        .iter()
        .zip(descendant_values)
        .map(|(name, value)| {
            Ok::<(String, Digest), String>(((*name).to_owned(), digest_bytes(value)?))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok((hashes, descendant_pid))
}

fn validate_marker_hashes(
    expected_values: &BTreeMap<String, Vec<u8>>,
    observed_hashes: &BTreeMap<String, Digest>,
) -> Result<(), String> {
    let expected_hashes = expected_values
        .iter()
        .map(|(name, value)| Ok::<(String, Digest), String>((name.clone(), digest(value)?)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if observed_hashes != &expected_hashes {
        return Err("qualification probe did not observe all required marker values".into());
    }
    Ok(())
}

fn current_parent_pid() -> u32 {
    #[cfg(unix)]
    {
        // The host later binds this process to the provider's observed process tree.
        unsafe { libc::getppid() as u32 }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn expected_marker_values(package: &QualificationRunPackage) -> BTreeMap<String, Vec<u8>> {
    [
        ("REX_PROJECTS_AGENT", "1".to_owned()),
        ("REX_PROJECTS_CONTEXT", "agent".to_owned()),
        ("REX_PROJECTS_PROJECT_ID", package.project_id.to_string()),
        (
            "REX_PROJECTS_ROLE",
            qualification_role_name(package.role).to_owned(),
        ),
        ("REX_PROJECTS_RUN_ID", package.descriptor.run_id.to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.into_bytes()))
    .collect()
}

#[cfg(test)]
mod marker_probe_tests {
    use super::{
        MarkerProbeBinding, MarkerProbeReport, QualificationRunPackage, REQUIRED_AGENT_MARKERS,
        descendant_marker_hashes, digest, new_marker_probe_challenge,
        run_marker_probe_with_environment, validate_marker_hashes, validate_package,
        verify_marker_probe,
    };
    use crate::adapters::rex::RexQualificationSessionReceipt;
    use crate::config::Profile;
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProfileId, ProjectId, RexBlockId};
    use crate::domain::types::{AgentAdapter, CommitMode, Role};
    use crate::run_step::{ProviderCapabilityEvidence, ProviderQualificationStatus, RunDescriptor};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_values() -> BTreeMap<String, Vec<u8>> {
        REQUIRED_AGENT_MARKERS
            .iter()
            .map(|name| {
                let value = match *name {
                    "REX_PROJECTS_AGENT" => "1",
                    "REX_PROJECTS_CONTEXT" => "agent",
                    "REX_PROJECTS_PROJECT_ID" => "project_1",
                    "REX_PROJECTS_ROLE" => "merge_decision",
                    "REX_PROJECTS_RUN_ID" => "qualification-run",
                    _ => unreachable!(),
                };
                ((*name).to_owned(), value.as_bytes().to_vec())
            })
            .collect()
    }

    #[test]
    fn probe_observes_markers_in_its_shell_descendant_and_rejects_filtered_values() {
        let values = sample_values();
        let (observed, _) = descendant_marker_hashes(Some(&values), None).unwrap();
        validate_marker_hashes(&values, &observed).unwrap();

        let (filtered, _) =
            descendant_marker_hashes(Some(&values), Some("REX_PROJECTS_ROLE")).unwrap();
        assert!(validate_marker_hashes(&values, &filtered).is_err());
    }

    #[test]
    fn report_binding_rejects_a_different_request_or_one_use_challenge() {
        let digest = |letter: &str| Digest::parse(letter.repeat(64)).unwrap();
        let project_id = ProjectId::parse("project_1").unwrap();
        let profile_id = ProfileId::parse("profile_1").unwrap();
        let report = MarkerProbeReport {
            schema_version: 1,
            request_id: "request_1".into(),
            request_digest: digest("a"),
            project_id,
            role: Role::MergeDecision,
            profile_id,
            run_id: "qualification-run".into(),
            profile_digest: digest("b"),
            config_revision: 7,
            config_digest: digest("c"),
            challenge_digest: digest("d"),
            tool_pid: 1,
            tool_parent_pid: 2,
            descendant_pid: 3,
            tool_binary_digest: digest("e"),
            tool_shell_marker_hashes: BTreeMap::new(),
            descendant_marker_hashes: BTreeMap::new(),
        };
        let bound = MarkerProbeBinding::for_report(&report);
        let mut changed_request = report.clone();
        changed_request.request_id.push_str("_other");
        assert_ne!(bound, MarkerProbeBinding::for_report(&changed_request));
        let mut changed_challenge = report.clone();
        changed_challenge.challenge_digest = digest("f");
        assert_ne!(bound, MarkerProbeBinding::for_report(&changed_challenge));
    }

    fn package(root: &std::path::Path) -> QualificationRunPackage {
        let project_id = ProjectId::parse("project_1").unwrap();
        let profile_id = ProfileId::parse("profile_1").unwrap();
        let role = Role::MergeDecision;
        let workspace = root.join("workspace");
        let control_dir = root.join("control");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&control_dir).unwrap();
        let profile = Profile {
            adapter: AgentAdapter::Codex,
            command: vec!["/bin/sh".into()],
            description: None,
            model: None,
            effort: None,
            turn_timeout_seconds: 1800,
            instruction_files: Vec::new(),
            skill_paths: Vec::new(),
            commit_mode: CommitMode::Auto,
            learned_guidance: None,
            options: None,
        };
        let profile_digest = digest(&serde_json::to_vec(&profile).unwrap()).unwrap();
        let deadline_seconds =
            crate::run_step::qualification_deadline_seconds(profile.turn_timeout_seconds, 30)
                .unwrap();
        let project_digest = digest("1".repeat(64).as_bytes()).unwrap();
        let run_id = AgentRunId::parse("qualification-run").unwrap();
        let environment_snapshot_id = digest("2".repeat(64).as_bytes()).unwrap();
        let result_schema = serde_json::json!({"type":"object"});
        let schema_projection = crate::providers::project_result_schema(&result_schema)
            .unwrap()
            .identity;
        let descriptor = RunDescriptor {
            schema_version: 1,
            project_id: project_id.clone(),
            run_id: run_id.clone(),
            operation_id: OperationId::parse("qualification-test-operation").unwrap(),
            role,
            ticket_run_id: None,
            expected_subject_revision: 0,
            attempt: 1,
            run_epoch: 1,
            controller_generation: 1,
            workspace: workspace.clone(),
            control_dir: control_dir.clone(),
            rex_session_id: "session-1".into(),
            rex_block_id: RexBlockId::parse("block-1").unwrap(),
            profile_digest: profile_digest.clone(),
            instruction_digest: project_digest.clone(),
            plan_digest: None,
            environment_snapshot_id: environment_snapshot_id.clone(),
            wake_snapshot_digest: project_digest.clone(),
            provider_capability: ProviderCapabilityEvidence {
                schema_version: 1,
                adapter: AgentAdapter::Codex,
                profile_digest: profile_digest.clone(),
                version: "unobserved".into(),
                executable_path: PathBuf::from("/bin/sh"),
                executable_digest: project_digest.clone(),
                permission_mode: "workspace-write".into(),
                invocation_options_digest: project_digest.clone(),
                commit_mode: CommitMode::Auto,
                schema_projection,
                receipt_digest: project_digest.clone(),
                status: ProviderQualificationStatus::Unknown,
            },
            result_schema,
        };
        let rex_receipt: RexQualificationSessionReceipt =
            serde_json::from_value(serde_json::json!({
                "endpoint":"http://localhost:1", "instance_id":"rex-1",
                "session_id":"session-1", "window_id":"window-1", "block_id":"block-1",
                "operation_id":"qualification-operation", "session_label":"session",
                "window_label":"window"
            }))
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let executable_digest = digest(&std::fs::read(&executable).unwrap()).unwrap();
        QualificationRunPackage {
            schema_version: 1,
            request_id: "request_1".into(),
            request_digest: project_digest.clone(),
            config_revision: 7,
            config_digest: project_digest.clone(),
            project_id,
            role,
            profile_id,
            profile_digest,
            environment_snapshot_id,
            profile,
            descriptor,
            role_contract: "test".into(),
            prompt: "test".into(),
            workspace_root: root.to_path_buf(),
            environment_handoff: root.join("handoff"),
            environment_operation_id: "operation".into(),
            result_path: control_dir.join("result.json"),
            marker_probe_path: workspace.join("marker-probe.json"),
            marker_probe_challenge: new_marker_probe_challenge().unwrap(),
            runtime_binary_path: executable,
            runtime_binary_digest: executable_digest,
            rex_cli_path: PathBuf::from("/usr/bin/env"),
            rex_search_path: Vec::new(),
            rex_receipt,
            deadline_seconds,
            shutdown_grace_seconds: 30,
        }
    }

    #[test]
    fn actual_probe_report_is_written_once_and_host_rejects_unbound_report() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let package = package(&root_path);
        let package_path = root_path.join("package.json");
        package.publish_once(&package_path).unwrap();
        let values = sample_values();
        run_marker_probe_with_environment(&package_path, Some(&values)).unwrap();
        let report_bytes = std::fs::read(&package.marker_probe_path).unwrap();
        let report: MarkerProbeReport = crate::protocol::parse_unique(&report_bytes).unwrap();
        let proof = verify_marker_probe(&package, &report).unwrap();
        assert_eq!(
            proof.tool_shell_markers_present.len(),
            REQUIRED_AGENT_MARKERS.len()
        );
        assert_eq!(
            proof.descendant_markers_present.len(),
            REQUIRED_AGENT_MARKERS.len()
        );
        assert!(run_marker_probe_with_environment(&package_path, Some(&values)).is_err());

        let mut unbound = report;
        unbound.request_digest = Digest::parse("f".repeat(64)).unwrap();
        assert!(verify_marker_probe(&package, &unbound).is_err());
    }

    #[test]
    fn qualification_package_requires_deadline_for_turn_and_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let mut package = package(&root_path);
        assert_eq!(package.deadline_seconds, 1867);
        let path = root_path.join("package.json");
        package.publish_once(&path).unwrap();
        assert!(validate_package(&package, &path).is_ok());

        package.deadline_seconds -= 1;
        assert!(
            validate_package(&package, &path)
                .unwrap_err()
                .contains("deadline does not match")
        );
    }
}

fn observed_marker_hashes(
    expected: &BTreeMap<String, Vec<u8>>,
    supplied_environment: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<BTreeMap<String, Digest>, String> {
    expected
        .iter()
        .map(|(name, expected)| {
            let actual = if let Some(environment) = supplied_environment {
                environment
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("tool process is missing {name}"))?
            } else {
                let actual = std::env::var_os(name)
                    .ok_or_else(|| format!("tool process is missing {name}"))?;
                #[cfg(unix)]
                let actual = {
                    use std::os::unix::ffi::OsStrExt;
                    actual.as_os_str().as_bytes().to_vec()
                };
                #[cfg(not(unix))]
                let actual = actual.to_string_lossy().as_bytes().to_vec();
                actual
            };
            if &actual != expected {
                return Err(format!("tool process has mismatched {name}"));
            }
            Ok((name.clone(), digest_bytes(&actual)?))
        })
        .collect()
}

fn publish_probe_report(path: &Path, report: &MarkerProbeReport) -> Result<(), String> {
    let bytes = serde_json::to_vec(report).map_err(|error| error.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("marker probe report exceeds its size limit".into());
    }
    let parent = path.parent().ok_or("marker probe report has no parent")?;
    let stage = parent.join(format!(".marker-probe-{}.tmp", std::process::id()));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&stage)
            .map_err(|error| error.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stage)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    let result = fs::hard_link(&stage, path).map_err(|error| error.to_string());
    let _ = fs::remove_file(stage);
    result
}

impl QualificationRunPackage {
    pub(crate) fn publish_once(&self, path: &Path) -> Result<(), String> {
        let parent = path.parent().ok_or("qualification package has no parent")?;
        if !parent.is_dir()
            || fs::canonicalize(parent).map_err(|error| error.to_string())? != parent
        {
            return Err("qualification package parent is not a canonical directory".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_PACKAGE_BYTES {
            return Err("qualification package exceeds its size limit".into());
        }
        let stage = parent.join(format!(".qualification-{}.tmp", std::process::id()));
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&stage)
                .map_err(|error| error.to_string())?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stage)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        let publish = fs::hard_link(&stage, path).map_err(|error| error.to_string());
        let _ = fs::remove_file(stage);
        publish
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationRunResult {
    pub schema_version: u32,
    pub request_id: String,
    pub receipt: RunReceipt,
    pub structured_result: Option<serde_json::Value>,
    pub result_digest: Digest,
}

pub(crate) fn new_marker_probe_challenge() -> Result<String, String> {
    let mut challenge = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut challenge))
        .map_err(|error| format!("cannot create qualification probe challenge: {error}"))?;
    Ok(challenge.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn run_wrapper(package_path: &Path) -> Result<Digest, String> {
    if std::env::var("REX_PROJECTS_AGENT").as_deref() != Ok("1")
        || std::env::var("REX_PROJECTS_CONTEXT").as_deref() != Ok("agent")
    {
        return Err("provider qualification wrapper requires a marked Rex Agent block".into());
    }
    let bytes = read_package_wait(package_path)?;
    let package: QualificationRunPackage = crate::protocol::parse_unique(&bytes)
        .map_err(|error| format!("qualification package is invalid: {error}"))?;
    validate_package(&package, package_path)?;
    let mut environment = EnvironmentHandoff::consume_file(
        &package.environment_handoff,
        &package.environment_snapshot_id,
        &package.environment_operation_id,
    )
    .map_err(|error| error.to_string())?;
    set_agent_markers(&mut environment, &package);
    let rex = RexCliTransport::connect(
        &package.rex_cli_path,
        &package.rex_search_path,
        package.rex_receipt.endpoint().to_owned(),
        package.rex_receipt.instance_id().to_owned(),
        package.rex_receipt.session_id().to_owned(),
        environment.clone(),
    )
    .map_err(|error| error.to_string())?;
    let fixture = rex
        .disposable_qualification_fixture(package.rex_receipt.clone())
        .map_err(|error| error.to_string())?;
    let expected_permission_mode = package
        .descriptor
        .provider_capability
        .permission_mode
        .clone();
    let request = TurnRequest {
        descriptor: package.descriptor,
        profile: package.profile,
        role_contract: package.role_contract,
        prompt: package.prompt,
        environment,
        continuation: None,
        shutdown_grace: Duration::from_secs(package.shutdown_grace_seconds),
    };
    let permit = issue_qualification_permit(
        &request,
        DisposableQualificationContext {
            workspace_root: package.workspace_root.clone(),
            rex_fixture: fixture,
            deadline: Duration::from_secs(package.deadline_seconds),
            expected_permission_mode,
            prompts_denied: true,
        },
    )
    .map_err(|error| error.to_string())?;
    let turn = run_qualification_turn(&request, permit, &mut SystemProcessObserver)
        .map_err(|error| error.to_string())?;
    let result_bytes =
        serde_json::to_vec(&turn.structured_result).map_err(|error| error.to_string())?;
    let result = QualificationRunResult {
        schema_version: 1,
        request_id: package.request_id,
        receipt: turn.receipt,
        structured_result: turn.structured_result,
        result_digest: digest(&result_bytes)?,
    };
    publish_result(&package.result_path, &result)?;
    Ok(result.result_digest)
}

fn read_package_wait(path: &Path) -> Result<Vec<u8>, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > MAX_PACKAGE_BYTES
                {
                    return Err("qualification package must be a bounded regular file".into());
                }
                #[cfg(unix)]
                let file = {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                        .open(path)
                        .map_err(|error| error.to_string())?
                };
                #[cfg(not(unix))]
                let mut file = OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                file.take(MAX_PACKAGE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 > MAX_PACKAGE_BYTES {
                    return Err("qualification package exceeds its size limit".into());
                }
                return Ok(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if std::time::Instant::now() >= deadline {
            return Err("qualification package was not published before its deadline".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn validate_package(
    package: &QualificationRunPackage,
    path: &Path,
) -> Result<(), String> {
    let parent = path.parent().ok_or("qualification package has no parent")?;
    if package.schema_version != 1
        || !parent.is_dir()
        || fs::canonicalize(parent).map_err(|error| error.to_string())? != parent
        || package.request_id.is_empty()
        || package.descriptor.project_id != package.project_id
        || package.descriptor.role != package.role
        || package.descriptor.profile_digest != package.profile_digest
        || package.descriptor.environment_snapshot_id != package.environment_snapshot_id
        || package.descriptor.provider_capability.status != ProviderQualificationStatus::Unknown
        || package.descriptor.rex_session_id != package.rex_receipt.session_id()
        || package.descriptor.rex_block_id.as_str() != package.rex_receipt.block_id()
        || package.result_path.parent() != Some(package.descriptor.control_dir.as_path())
        || package.marker_probe_path != package.descriptor.workspace.join("marker-probe.json")
        || package.marker_probe_challenge.len() != 64
        || !package.runtime_binary_path.is_absolute()
        || package.shutdown_grace_seconds == 0
        || package.shutdown_grace_seconds > 300
        || !package.rex_cli_path.is_absolute()
    {
        return Err("qualification package identity or bounds are invalid".into());
    }
    let profile_digest =
        digest(&serde_json::to_vec(&package.profile).map_err(|error| error.to_string())?)?;
    if profile_digest != package.profile_digest {
        return Err("qualification package profile digest mismatch".into());
    }
    let required_deadline = crate::run_step::qualification_deadline_seconds(
        package.profile.turn_timeout_seconds,
        package.shutdown_grace_seconds,
    )?;
    let deadline = std::time::Duration::from_secs(package.deadline_seconds);
    if package.deadline_seconds != required_deadline
        || std::time::Instant::now().checked_add(deadline).is_none()
    {
        return Err(
            "qualification package deadline does not match its representable turn and cleanup"
                .into(),
        );
    }
    Ok(())
}

fn set_agent_markers(
    environment: &mut BTreeMap<OsString, OsString>,
    package: &QualificationRunPackage,
) {
    environment.insert("REX_PROJECTS_CONTEXT".into(), "agent".into());
    environment.insert("REX_PROJECTS_AGENT".into(), "1".into());
    environment.insert(
        "REX_PROJECTS_PROJECT_ID".into(),
        package.project_id.as_str().into(),
    );
    environment.insert(
        "REX_PROJECTS_ROLE".into(),
        qualification_role_name(package.role).into(),
    );
    environment.insert(
        "REX_PROJECTS_RUN_ID".into(),
        package.descriptor.run_id.as_str().into(),
    );
    environment.insert(
        "REX_SESSION".into(),
        package.rex_receipt.session_id().into(),
    );
    environment.insert("REX_BLOCK".into(), package.rex_receipt.block_id().into());
    environment.insert("REX_BLOCK_ID".into(), package.rex_receipt.block_id().into());
}

fn digest(bytes: &[u8]) -> Result<Digest, String> {
    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest, String> {
    digest(bytes)
}

#[allow(dead_code)]
fn publish_result(path: &Path, result: &QualificationRunResult) -> Result<(), String> {
    let bytes = serde_json::to_vec(result).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RESULT_BYTES {
        return Err("qualification result exceeds its size limit".into());
    }
    let parent = path.parent().ok_or("qualification result has no parent")?;
    let temporary = parent.join(format!(".qualification-{}.tmp", std::process::id()));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::hard_link(&temporary, path).map_err(|error| error.to_string())?;
    fs::remove_file(temporary).map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn receipt_outcome_succeeded(receipt: &RunReceipt) -> bool {
    matches!(receipt.outcome, TurnOutcome::Completed)
        && matches!(receipt.cleanup, CleanupState::Confirmed)
        && !receipt.processes.is_empty()
        && receipt.provider_version.is_none()
        && receipt.capability_receipt_digest.is_none()
}
