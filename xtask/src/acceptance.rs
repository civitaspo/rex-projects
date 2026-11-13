use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rex_projects::adapters::rex::{
    CreateDisposition, RexCliTransport, RexProcessObservation, TicketWindow,
    owned_supervisor_window_label, owned_ticket_window_label,
};
use rex_projects::launch::{ObservedProviderStart, ObservedWrapperIdentity};
use rex_projects::process::{
    ProcessIdentity, ProcessIdentityQuality, ProcessOutput, ProcessRequest, ProcessSignal,
    executable_path_for_identity, inspect_process_table, process_identity_for_pid,
    run as run_process, signal_process_if_observed,
};
use rex_projects::run_step_spool::{RunFamilyCoverage, RunStepSpool};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const OUTPUT_LIMIT: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const POLL_LIMIT: Duration = Duration::from_secs(20);
const FULL_FLOW_LIMIT: Duration = Duration::from_secs(30 * 60);
const QUALIFICATION_LIMIT: Duration = Duration::from_secs(180);
const COORDINATOR_STAGE_LIMIT: Duration = Duration::from_secs(180);
const NATIVE_WORKER_READY_LIMIT: Duration = Duration::from_secs(60);
const NATIVE_WORKER_TERMINAL_LIMIT: Duration = Duration::from_secs(360);
const ACCEPTANCE_STAGE_ENV: &str = "REX_PROJECTS_ACCEPTANCE_STAGE";
const COORDINATOR_INBOX_STAGE: &str = "supervisor_coordinator_inbox";
const COORDINATOR_BLOCK_LOSS_STAGE: &str = "supervisor_coordinator_block_loss";
const COORDINATOR_WORKER_INBOX_STAGE: &str = "supervisor_coordinator_worker_inbox";
const HOST_COMMIT_REVIEWER_INBOX_STAGE: &str = "host_commit_reviewer_inbox";
const HOST_COMMIT_WORKER_REWORK_STAGE: &str = "host_commit_worker_rework_inbox";
const HOST_COMMIT_VERIFICATION_REVIEWER_STAGE: &str = "host_commit_verification_reviewer_inbox";
const WORKER_RECOVERY_INBOX_STAGE: &str = "worker_recovery_inbox";
const NATIVE_WORKER_BLOCK_LOSS_STAGE: &str = "native_worker_block_loss";
const NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE: &str = "native_worker_missed_event_block_loss";
const REQUEST_MERGE_STAGE: &str = "request_merge";
const NATIVE_WORKER_CODEX_ENV: &str = "REX_PROJECTS_NATIVE_WORKER_CODEX";
const ACCEPTANCE_FREEZE_MARKER_ENV: &str = "REX_PROJECTS_ACCEPTANCE_FREEZE_MARKER";
const CONTROLLER_WINDOW_LABEL: &str = "rex-projects-controller";
const FIXTURE_PROJECT_ID: &str = "operations_project";
const FIXTURE_TICKET_NAMESPACE: &str = "fixture/acceptance";
const FIXTURE_TICKET_ID: &str = "ticket-1";
const ACCEPTANCE_WORK_TASK: &str = "Create and commit a bounded acceptance fixture artifact in the assigned managed worktree, register the resulting Change manifest through the public Agent CLI, verify the exact signed host commit receipt, and preserve this complete task description in the pull request body.";
const NATIVE_WORKER_LIFECYCLE_TASK: &str = "In the assigned managed worktree, run `/bin/sleep 300` in the foreground and wait for it to return. Do not edit files, run any other command, commit, or make remote changes. This is a bounded process-lifecycle exercise.";
const NATIVE_WORKER_LAUNCH_EVIDENCE_QUERY: &str = "SELECT a.agent_run_id,a.launch_operation_id,a.runtime_binary_digest,a.rex_server_identity,a.rex_session_id,a.rex_window_id,
                    a.rex_block_id,a.control_dir,a.workspace_path,r.state,l.state,
                    l.wrapper_process_identity_json,l.provider_process_tree_json,
                    s.disposition,s.reservation_epoch
             FROM agent_launch_authority a
             JOIN agent_runs r USING(agent_run_id)
             JOIN agent_launch_state l USING(agent_run_id)
             JOIN execution_slots s ON s.owner_kind='agent_run' AND s.owner_id=a.agent_run_id
             WHERE a.role='worker' AND r.state='running' AND l.state='running'
               AND a.rex_server_identity=?1 AND a.rex_session_id=?2
               AND a.qualification_receipt_digest=?3
               AND l.wrapper_process_identity_json IS NOT NULL
               AND l.provider_process_tree_json IS NOT NULL
               AND s.disposition='live'
             ORDER BY a.created_at_unix DESC LIMIT 1";
const PROVIDER_ROLES: [&str; 8] = [
    "supervisor",
    "coordinator",
    "planner",
    "worker",
    "reviewer",
    "merge_decision",
    "operator",
    "postmortem",
];

#[derive(Clone, Debug)]
pub struct Request<'a> {
    pub cli: &'a Path,
    pub rex: &'a Path,
    pub rex_server: &'a str,
    pub rex_session: &'a str,
    pub expected_instance: &'a str,
    pub fixture_root: &'a Path,
}

fn parse_acceptance_stage(value: Option<String>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(stage)
            if stage == COORDINATOR_INBOX_STAGE
                || stage == COORDINATOR_BLOCK_LOSS_STAGE
                || stage == COORDINATOR_WORKER_INBOX_STAGE
                || stage == WORKER_RECOVERY_INBOX_STAGE
                || stage == HOST_COMMIT_REVIEWER_INBOX_STAGE
                || stage == HOST_COMMIT_WORKER_REWORK_STAGE
                || stage == HOST_COMMIT_VERIFICATION_REVIEWER_STAGE
                || stage == NATIVE_WORKER_BLOCK_LOSS_STAGE
                || stage == NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE
                || stage == REQUEST_MERGE_STAGE =>
        {
            Ok(Some(stage))
        }
        Some(_) => Err(format!(
            "unsupported acceptance stage in {ACCEPTANCE_STAGE_ENV}"
        )),
    }
}

fn qualification_roles_for_stage(stage: Option<&str>) -> &'static [&'static str] {
    if stage == Some(REQUEST_MERGE_STAGE) {
        &PROVIDER_ROLES
    } else if matches!(
        stage,
        Some(NATIVE_WORKER_BLOCK_LOSS_STAGE | NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE)
    ) {
        &["planner", "worker", "supervisor", "coordinator"]
    } else if matches!(
        stage,
        Some(HOST_COMMIT_REVIEWER_INBOX_STAGE)
            | Some(HOST_COMMIT_WORKER_REWORK_STAGE)
            | Some(HOST_COMMIT_VERIFICATION_REVIEWER_STAGE)
    ) {
        &["supervisor", "coordinator", "planner", "worker", "reviewer"]
    } else if matches!(
        stage,
        Some(COORDINATOR_WORKER_INBOX_STAGE) | Some(WORKER_RECOVERY_INBOX_STAGE)
    ) {
        &["supervisor", "coordinator", "planner", "worker"]
    } else if stage.is_some() {
        &["supervisor", "coordinator"]
    } else {
        &PROVIDER_ROLES
    }
}

struct QualificationOutcome {
    qualifications: Vec<(String, String, String, String, Value)>,
    terminal_qualifications: BTreeMap<String, String>,
    project_started: bool,
    coordinator_qualification_wait_proof: Option<Value>,
    qualification_failure: bool,
}

fn qualify_profiles(
    request: &Request<'_>,
    provider_roles: &[&str],
    bounded_coordinator_stage: bool,
    trace: &mut Vec<Value>,
    mut run_product: impl FnMut(&[&str]) -> Result<ProcessOutput, String>,
    mut observe_coordinator_wait: impl FnMut() -> Value,
) -> Result<QualificationOutcome, String> {
    let mut qualifications = Vec::new();
    let mut terminal_qualifications = BTreeMap::new();
    let mut project_started = false;
    let mut coordinator_qualification_wait_proof = None;
    let qualification_deadline = Instant::now() + QUALIFICATION_LIMIT;
    let mut qualification_failure = false;
    for role in provider_roles.iter().copied() {
        let phase_start = qualifications.len();
        for project in ["operations_project"] {
            let request_id = format!("acceptance-{project}-{role}");
            let output = run_product(&[
                "provider",
                "qualify",
                "--project",
                project,
                "--role",
                role,
                "--request-id",
                &request_id,
                "--json",
            ])?;
            if !output.status.is_some_and(|status| status.success()) {
                trace.push(json!({"step":"provider_qualification_queue","project":project,"role":role,"status":"rejected","stderr":String::from_utf8_lossy(&output.stderr_tail)}));
                break;
            }
            let response = json_stdout(&output);
            let digest = response["request_digest"]
                .as_str()
                .ok_or("provider qualify response omitted request_digest")?;
            trace.push(json!({"step":"provider_qualification_queue","project":project,"role":role,"status":"queued","request_id":request_id,"request_digest":digest,"emulator":"EMULATED"}));
            qualifications.push((
                project.to_owned(),
                role.to_owned(),
                request_id,
                digest.to_owned(),
                response,
            ));
        }
        loop {
            let mut phase_pending = false;
            for (project, role, request_id, expected_digest, queued) in
                &qualifications[phase_start..]
            {
                if terminal_qualifications.contains_key(request_id) {
                    continue;
                }
                let output =
                    run_product(&["--json", "provider", "status", "--request-id", request_id])?;
                if !output.status.is_some_and(|status| status.success()) {
                    phase_pending = true;
                    continue;
                }
                let status = json_stdout(&output);
                if status["request_digest"].as_str() != Some(expected_digest)
                    || status["project_id"] != queued["project_id"]
                    || status["role"] != queued["role"]
                    || status["profile_id"] != queued["profile_id"]
                    || status["config_revision"] != queued["config_revision"]
                    || status["config_digest"] != queued["config_digest"]
                {
                    phase_pending = true;
                    continue;
                }
                let status_name = status["status"].as_str().unwrap_or("invalid");
                if status_name == "verified" {
                    if status["qualification_receipt_digest"]
                        .as_str()
                        .is_none_or(|digest| {
                            digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                    {
                        trace.push(json!({"step":"provider_qualification_status","project":project,"role":role,"request_id":request_id,"status":"invalid_receipt_digest","evidence":status,"emulator":"EMULATED"}));
                        qualification_failure = true;
                        break;
                    }
                    trace.push(json!({"step":"provider_qualification_status","project":project,"role":role,"request_id":request_id,"status":status_name,"evidence":status,"emulator":"EMULATED"}));
                    terminal_qualifications.insert(request_id.clone(), status_name.to_owned());
                } else if status_name == "failed" || status_name == "unknown" {
                    trace.push(json!({"step":"provider_qualification_status","project":project,"role":role,"request_id":request_id,"status":status_name,"evidence":status,"emulator":"EMULATED"}));
                    let diagnostic = read_probe_diagnostic(request.fixture_root, project, role);
                    if let Some(diagnostic) = diagnostic {
                        trace.push(json!({"step":"emulated_provider_probe_diagnostic","project":project,"role":role,"request_id":request_id,"evidence":diagnostic,"emulator":"EMULATED"}));
                    }
                    terminal_qualifications.insert(request_id.clone(), status_name.to_owned());
                    qualification_failure = true;
                    break;
                } else {
                    phase_pending = true;
                }
            }
            if qualification_failure || !phase_pending {
                break;
            }
            if Instant::now() >= qualification_deadline {
                trace.push(json!({"step":"provider_qualification_poll","status":"timed_out","role":role,"phase_request_count":qualifications.len()-phase_start}));
                qualification_failure = true;
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        if qualification_failure {
            break;
        }
        if bounded_coordinator_stage && role == "supervisor" {
            let project = FIXTURE_PROJECT_ID;
            let output = run_product(&["project", "start", project, "--json"])?;
            if !output.status.is_some_and(|status| status.success()) {
                trace.push(json!({"step":"project_start_after_supervisor_qualification","project":project,"status":"rejected","evidence":json_stdout(&output)}));
                qualification_failure = true;
                break;
            }
            project_started = true;
            trace.push(json!({"step":"project_start_after_supervisor_qualification","project":project,"status":"queued","evidence":json_stdout(&output)}));
            let proof = observe_coordinator_wait();
            trace.push(json!({"step":"coordinator_missing_qualification_wait","status":proof["status"],"evidence":proof}));
            if proof["status"] != "passed" {
                qualification_failure = true;
                coordinator_qualification_wait_proof = Some(proof);
                break;
            }
            coordinator_qualification_wait_proof = Some(proof);
        }
    }
    Ok(QualificationOutcome {
        qualifications,
        terminal_qualifications,
        project_started,
        coordinator_qualification_wait_proof,
        qualification_failure,
    })
}

/// Start from real external boundaries: generate private fixture configuration and a local bare
/// remote, apply it through the product CLI, and run the product controller in an owned Rex
/// window. The report preserves the last actual dashboard/status snapshot when later stages are
/// not yet reachable; fixtures never mint host receipts or claim a completed Project.
pub fn run(request: Request<'_>) -> Result<(), String> {
    if !request.fixture_root.is_absolute() || request.fixture_root.exists() {
        return Err("fixture root must be a new absolute path".into());
    }
    verify_owned_session(&request)?;
    let stage_value = match std::env::var(ACCEPTANCE_STAGE_ENV) {
        Ok(stage) => Some(stage),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(format!("read {ACCEPTANCE_STAGE_ENV}: {error}")),
    };
    let stage = parse_acceptance_stage(stage_value)?;
    let request_merge_stage = stage.as_deref() == Some(REQUEST_MERGE_STAGE);
    let bounded_coordinator_stage = stage.is_some() && !request_merge_stage;
    let coordinator_block_loss_stage = stage.as_deref() == Some(COORDINATOR_BLOCK_LOSS_STAGE);
    let coordinator_worker_inbox_stage = stage.as_deref() == Some(COORDINATOR_WORKER_INBOX_STAGE);
    let worker_verification_stage =
        stage.as_deref() == Some(HOST_COMMIT_VERIFICATION_REVIEWER_STAGE);
    let worker_review_rework_stage =
        stage.as_deref() == Some(HOST_COMMIT_WORKER_REWORK_STAGE) || worker_verification_stage;
    let host_commit_reviewer_inbox_stage =
        stage.as_deref() == Some(HOST_COMMIT_REVIEWER_INBOX_STAGE) || worker_review_rework_stage;
    let worker_recovery_inbox_stage = stage.as_deref() == Some(WORKER_RECOVERY_INBOX_STAGE);
    let native_worker_stage = matches!(
        stage.as_deref(),
        Some(NATIVE_WORKER_BLOCK_LOSS_STAGE | NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE)
    );
    let native_worker_missed_event_stage =
        stage.as_deref() == Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE);
    let native_worker_codex = if native_worker_stage {
        Some(validate_native_worker_codex_path()?)
    } else {
        None
    };
    let worker_connection_stage = coordinator_worker_inbox_stage
        || host_commit_reviewer_inbox_stage
        || worker_recovery_inbox_stage
        || native_worker_stage;
    let provider_roles = qualification_roles_for_stage(stage.as_deref());
    fs::create_dir_all(request.fixture_root).map_err(|error| error.to_string())?;
    let state_root = request.fixture_root.join("state");
    fs::create_dir(&state_root).map_err(|error| error.to_string())?;
    let mut trace = vec![json!({"step":"fixture_root_created","status":"passed"})];
    let version = product(&request, &state_root, &["version", "--json"])?;
    require_success("read product version identity", &version)?;
    let cli_identity = json!({
        "version_json":json_stdout(&version),
        "binary_sha256":format!("{:x}", Sha256::digest(fs::read(request.cli).map_err(|error| error.to_string())?))
    });
    trace.push(json!({"step":"product_cli_identity","status":"observed","evidence":cli_identity}));

    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    prepare_local_repository(&request, &executable)?;
    prepare_profiles(
        &request,
        &executable,
        request.cli,
        ProfilePreparation {
            hold_coordinator_after_inbox: bounded_coordinator_stage && !worker_connection_stage,
            hold_worker_after_inbox: coordinator_worker_inbox_stage,
            hold_reviewer_after_inbox: false,
            host_worker: host_commit_reviewer_inbox_stage
                || coordinator_worker_inbox_stage
                || worker_recovery_inbox_stage
                || request_merge_stage
                || native_worker_stage,
            worker_recovery_stage: worker_recovery_inbox_stage,
            worker_review_rework_stage,
            worker_verification_stage,
            request_merge_stage,
            native_worker_codex: native_worker_codex.as_deref(),
        },
    )?;
    trace.push(json!({"step":"local_bare_repository_and_profiles","status":"passed","provider":"EMULATED"}));

    let config_path = request.fixture_root.join("config.toml");
    fs::write(
        &config_path,
        config_text_for_stage(
            &request,
            &executable,
            native_worker_stage,
            request_merge_stage,
        ),
    )
    .map_err(|error| format!("write fixture config: {error}"))?;
    let seeded_ticket = seed_operations_ticket(&request, &executable)?;
    trace.push(json!({"step":"external_ticket_seeded_through_adapter_protocol","status":"observed","evidence":seeded_ticket}));
    if native_worker_stage {
        write_native_worker_setup_freeze(
            &request,
            &cli_identity,
            &executable,
            &config_path,
            &seeded_ticket,
            native_worker_codex
                .as_deref()
                .expect("native Worker Codex path was validated"),
            stage.as_deref().expect("native Worker stage was selected"),
        )?;
    }
    let validate = product(&request, &state_root, &["config", "validate", "--json"])?;
    require_success("config validate", &validate)?;
    trace.push(
        json!({"step":"config_validate","status":"passed","evidence":json_stdout(&validate)}),
    );

    let apply = product(
        &request,
        &state_root,
        &["config", "apply", "--bootstrap", "--json"],
    )?;
    require_success("config apply", &apply)?;
    trace.push(json!({"step":"config_apply","status":"passed","evidence":json_stdout(&apply)}));

    let mut rex_args = vec![
        OsString::from("--autostart=false"),
        OsString::from("--server"),
        OsString::from(request.rex_server),
        OsString::from("window"),
        OsString::from("new"),
        OsString::from("--session"),
        OsString::from(request.rex_session),
        OsString::from("--cwd"),
        request.fixture_root.as_os_str().to_owned(),
        OsString::from("--shell=none"),
        OsString::from("--keep-open"),
        OsString::from("--json"),
        OsString::from(CONTROLLER_WINDOW_LABEL),
        OsString::from("--"),
    ];
    // `rex window new` receives the absolute executable after `--`; PATH gives the controller
    // its owned local GitHub CLI transport before the user's ordinary tools.
    let fixture_bin = request.fixture_root.join("bin");
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path_parts = vec![fixture_bin.clone()];
    path_parts.extend(std::env::split_paths(&old_path));
    let path = std::env::join_paths(path_parts).map_err(|error| error.to_string())?;
    rex_args.extend([
        OsString::from("/usr/bin/env"),
        OsString::from(format!("PATH={}", path.to_string_lossy())),
        OsString::from(format!(
            "XDG_STATE_HOME={}",
            request.fixture_root.join("xdg-state").display()
        )),
    ]);
    let environment =
        fixture_git_environment(request.fixture_root, &std::env::vars_os().collect())?;
    rex_args.extend(environment.into_iter().map(|(mut key, value)| {
        key.push("=");
        key.push(value);
        key
    }));
    rex_args.extend([
        request.cli.as_os_str().to_owned(),
        OsString::from("--config"),
        config_path.as_os_str().to_owned(),
        OsString::from("--state-root"),
        state_root.as_os_str().to_owned(),
        OsString::from("runtime"),
        OsString::from("run"),
        OsString::from("--rex-server"),
        OsString::from(request.rex_server),
    ]);
    let rex_spawn = invoke(
        request.rex,
        &rex_args,
        None,
        Some((OsString::from("PATH"), path.clone())),
        STEP_TIMEOUT,
    )?;
    require_success("create Rex controller window", &rex_spawn)?;
    let (window, block) = parse_rex_window(&rex_spawn.stdout)?;
    trace.push(json!({"step":"rex_controller_window_created","status":"passed","window_id":window,"session_id":request.rex_session}));

    let owner_status = wait_for_owner(&request, &state_root, &mut trace)?;
    if owner_status["owner"]["active"] != true {
        if let Ok(capture) = rex_capture(&request, &block) {
            trace.push(json!({"step":"controller_startup_failure","status":"captured","evidence":String::from_utf8_lossy(&capture.stdout)}));
        }
        let _ = rex_call(
            &request,
            &["window", "close", "--session", request.rex_session, &window],
        );
        return unsupported(
            request.fixture_root,
            &trace,
            "foreground controller did not publish a live owner receipt",
            true,
        );
    }
    // Qualification is an actual public product workflow. The CLI only queues durable jobs;
    // the foreground controller launches each bounded profile probe in its own Rex session.
    // We qualify roles in pipeline order, polling the public durable status endpoint before
    // moving on. Fixture transport is explicitly EMULATED; it never writes qualification rows
    // or synthesizes host receipts.
    let qualification = qualify_profiles(
        &request,
        provider_roles,
        bounded_coordinator_stage,
        &mut trace,
        |words| product(&request, &state_root, words),
        || {
            observe_coordinator_qualification_wait(
                &request,
                &state_root,
                &block,
                "fixture_coordinator",
            )
        },
    )?;
    let QualificationOutcome {
        qualifications,
        terminal_qualifications,
        project_started,
        coordinator_qualification_wait_proof,
        qualification_failure,
    } = qualification;
    let all_verified = !qualification_failure
        && qualifications.len() == provider_roles.len()
        && qualifications.iter().all(|(_, _, request_id, _, _)| {
            terminal_qualifications
                .get(request_id)
                .is_some_and(|status| status == "verified")
        });
    if !all_verified {
        trace.push(json!({"step":"provider_qualification_poll","status":"incomplete","verified_count":terminal_qualifications.values().filter(|status| status.as_str()=="verified").count(),"requested_count":qualifications.len()}));
        trace.push(json!({"step":"project_start","status":"skipped_unverified_provider_profiles"}));
    }
    let mut last_status = json!({});
    let mut dashboard = json!({});
    let mut external_ticket_status = "unknown".to_owned();
    if all_verified && !project_started {
        let project = "operations_project";
        let output = product(
            &request,
            &state_root,
            &["project", "start", project, "--json"],
        )?;
        if !output.status.is_some_and(|status| status.success()) {
            return unsupported(
                request.fixture_root,
                &trace,
                &format!(
                    "public project start for `{project}` was rejected: {}",
                    String::from_utf8_lossy(&output.stderr_tail)
                ),
                true,
            );
        }
        trace.push(json!({"step":"project_start","project":project,"status":"queued","evidence":json_stdout(&output)}));
    }

    let deadline = Instant::now()
        + if all_verified {
            if bounded_coordinator_stage {
                COORDINATOR_STAGE_LIMIT
            } else {
                FULL_FLOW_LIMIT
            }
        } else {
            Duration::ZERO
        };
    let mut first_dashboard = true;
    let mut lifecycle_traced = false;
    let mut coordinator_boundary_reached = false;
    let mut worker_boundary_reached = false;
    let mut host_commit_reviewer_boundary_reached = false;
    let mut host_commit_connection_evidence = None;
    let mut coordinator_block_loss_proof = None;
    let mut request_merge_evidence = RequestMergeEvidence::default();
    let mut request_merge_stop = None;
    loop {
        let status = product(&request, &state_root, &["status", "--json"])?;
        if !status.status.is_some_and(|status| status.success()) {
            break;
        }
        last_status = serde_json::from_slice(&status.stdout).unwrap_or_else(|_| {
            json!({
                "unparsed_status":String::from_utf8_lossy(&status.stdout).to_string()
            })
        });
        let snapshot = product(&request, &state_root, &["dashboard", "--json"])?;
        if snapshot.status.is_some_and(|status| status.success()) {
            dashboard = json_stdout(&snapshot);
        }
        if first_dashboard {
            trace.push(
                json!({"step":"dashboard_snapshot","status":"observed","evidence":dashboard}),
            );
            first_dashboard = false;
        }
        let external_ticket = observe_seeded_ticket(&request, &executable, &seeded_ticket)?;
        external_ticket_status = external_ticket["status"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        if request_merge_stage {
            match advance_request_merge_acceptance(
                &request,
                &state_root,
                &mut request_merge_evidence,
            ) {
                Ok(progress) => trace.extend(progress),
                Err(error) => {
                    request_merge_stop = Some(error);
                    break;
                }
            }
        }
        if external_ticket["status"]
            .as_str()
            .is_some_and(|status| status.eq_ignore_ascii_case("done"))
        {
            trace.push(json!({"step":"external_ticket_terminal_state","status":"done","evidence":external_ticket}));
            break;
        }
        if external_ticket["status"] != "unknown" {
            trace.push(json!({"step":"external_ticket_observed","status":external_ticket["status"],"evidence":external_ticket}));
        }
        if !lifecycle_traced && projects_running(&last_status) {
            trace.push(json!({"step":"project_lifecycle_observed","status":"running","evidence":last_status}));
            lifecycle_traced = true;
        }
        if native_worker_stage
            && let Some(worker) = observe_running_native_worker(&request, &state_root)?
        {
            let ready = json!({
                "status":"native_worker_running",
                "product":cli_identity,
                "rex_instance":request.expected_instance,
                "worker":worker,
            });
            fs::write(
                request.fixture_root.join("native-worker-ready.json"),
                serde_json::to_vec_pretty(&ready).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("write native Worker ready observation: {error}"))?;
            let proof = observe_native_worker_block_loss(
                &request,
                &state_root,
                &worker,
                if native_worker_missed_event_stage {
                    NativeBlockLossScenario::MissedEvent
                } else {
                    NativeBlockLossScenario::DeliveredEvent
                },
            )?;
            let proof_filename = if native_worker_missed_event_stage {
                "native-worker-missed-event-block-loss.json"
            } else {
                "native-worker-block-loss.json"
            };
            fs::write(
                request.fixture_root.join(proof_filename),
                serde_json::to_vec_pretty(&proof).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("write native Worker block-loss proof: {error}"))?;
            return if proof["status"] == "passed" {
                Ok(())
            } else {
                Err(format!(
                    "native Worker block-loss proof was {}",
                    proof["status"]
                ))
            };
        }
        if bounded_coordinator_stage {
            let observations = read_public_inbox_observations(request.fixture_root)?;
            if coordinator_worker_inbox_stage {
                let mut worker_evidence = None;
                for observation in &observations {
                    if let Some(evidence) =
                        is_prepared_worker_inbox_observation(observation, &state_root)?
                    {
                        worker_evidence = Some(evidence);
                        break;
                    }
                }
                if let Some(worker_evidence) = worker_evidence {
                    trace.push(json!({"step":"prepared_worker_inbox_boundary_observed","status":"passed","evidence":worker_evidence}));
                    worker_boundary_reached = true;
                    let stop = product(&request, &state_root, &["runtime", "stop", "--json"])?;
                    if !stop.status.is_some_and(|status| status.success()) {
                        trace.push(json!({"step":"bounded_stage_stop_request","status":"rejected","evidence":json_stdout(&stop)}));
                    } else {
                        trace.push(json!({"step":"bounded_stage_stop_request","status":"queued","evidence":json_stdout(&stop)}));
                    }
                    break;
                }
            }
            if worker_recovery_inbox_stage {
                for observation in &observations {
                    if let Some(evidence) = worker_recovery_inbox_evidence(observation)? {
                        trace.push(json!({"step":"typed_worker_recovery_wake_materialized","status":"passed","evidence":evidence}));
                        worker_boundary_reached = true;
                        let stop = product(&request, &state_root, &["runtime", "stop", "--json"])?;
                        trace.push(json!({"step":"bounded_stage_stop_request","status":if stop.status.is_some_and(|status| status.success()) {"queued"} else {"rejected"},"evidence":json_stdout(&stop)}));
                        break;
                    }
                }
                if worker_boundary_reached {
                    break;
                }
            }
            if host_commit_reviewer_inbox_stage {
                for observation in &observations {
                    if let Some(evidence) = host_commit_reviewer_connection_evidence(
                        observation,
                        &state_root,
                        if worker_review_rework_stage && !worker_verification_stage {
                            "implementing"
                        } else {
                            "assessing"
                        },
                    )? {
                        let rework = if worker_review_rework_stage {
                            let mut proof = None;
                            for worker in &observations {
                                if let Some(found) =
                                    review_rework_worker_connection_evidence(worker, &state_root)?
                                {
                                    proof = Some(found);
                                    break;
                                }
                            }
                            let Some(proof) = proof else {
                                continue;
                            };
                            Some(proof)
                        } else {
                            None
                        };
                        if let Some(proof) = rework {
                            trace.push(json!({"step":"review_correction_worker_package_materialized","status":"passed","evidence":proof}));
                        }
                        if worker_verification_stage {
                            let Some(proof) = verification_reviewer_connection_evidence(
                                observation,
                                &state_root,
                            )?
                            else {
                                continue;
                            };
                            trace.push(json!({"step":"check_only_worker_to_reviewer","status":"passed","evidence":proof}));
                        }
                        trace.push(json!({
                            "step":"host_worker_commit_to_reviewer_gate",
                            "status":"passed",
                            "evidence":evidence
                        }));
                        host_commit_reviewer_boundary_reached = true;
                        host_commit_connection_evidence = Some(evidence);
                        let stop = product(&request, &state_root, &["runtime", "stop", "--json"])?;
                        if !stop.status.is_some_and(|status| status.success()) {
                            trace.push(json!({"step":"bounded_stage_stop_request","status":"rejected","evidence":json_stdout(&stop)}));
                        } else {
                            trace.push(json!({"step":"bounded_stage_stop_request","status":"queued","evidence":json_stdout(&stop)}));
                        }
                        break;
                    }
                }
                if host_commit_reviewer_boundary_reached {
                    break;
                }
            }
            if let Some(coordinator) = observations
                .iter()
                .find(|observation| is_coordinator_dispatch_observation(observation))
            {
                if !coordinator_boundary_reached {
                    trace.push(json!({"step":"coordinator_inbox_boundary_observed","status":"passed","evidence":coordinator}));
                    coordinator_boundary_reached = true;
                }
                if coordinator_block_loss_stage {
                    let proof = observe_coordinator_block_loss(&request, &state_root, coordinator);
                    let proof = proof.unwrap_or_else(
                        |error| json!({"status":"failed","reason":error,"fault_injected":false}),
                    );
                    trace.push(json!({"step":"coordinator_block_loss_recovery","status":proof["status"],"evidence":proof}));
                    coordinator_block_loss_proof = Some(proof);
                    break;
                }
                if !worker_connection_stage {
                    let stop = product(&request, &state_root, &["runtime", "stop", "--json"])?;
                    if !stop.status.is_some_and(|status| status.success()) {
                        trace.push(json!({"step":"bounded_stage_stop_request","status":"rejected","evidence":json_stdout(&stop)}));
                        break;
                    }
                    trace.push(json!({"step":"bounded_stage_stop_request","status":"queued","evidence":json_stdout(&stop)}));
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            trace.push(
                json!({"step":if bounded_coordinator_stage {"coordinator_inbox_poll"} else {"project_lifecycle_poll"},"status":"timed_out","status_snapshot":last_status,"dashboard_snapshot":dashboard}),
            );
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    let capture = rex_capture(&request, &block);
    if let Ok(capture) = capture {
        trace.push(json!({"step":"rex_controller_output","status":"captured","evidence":String::from_utf8_lossy(&capture.stdout)}));
    }
    let _ = product(&request, &state_root, &["runtime", "stop", "--json"]);
    let stopped = poll_controller_stopped(&request, &state_root);
    trace.push(
        json!({"step":"controller_stop","status":if stopped {"passed"} else {"unconfirmed"}}),
    );
    if !stopped {
        return unsupported(
            request.fixture_root,
            &trace,
            "controller did not confirm stop through the public status snapshot",
            true,
        );
    }
    if !wait_block_exit(&request, &block) {
        return unsupported(
            request.fixture_root,
            &trace,
            "Rex did not observe the owned controller block exit after the durable stop request",
            true,
        );
    }

    let first_closed = rex_call(
        &request,
        &["window", "close", "--session", request.rex_session, &window],
    )
    .is_ok_and(|output| output.status.is_some_and(|status| status.success()));
    let window_absent = !owned_window_present(&request, &window);
    trace.push(json!({"step":"owned_rex_window_cleanup","status":if first_closed && window_absent {"passed"} else {"unconfirmed"},"window_id":window,"absent_after_close":window_absent}));
    let inbox_observations = read_public_inbox_observations(request.fixture_root)?;
    if !inbox_observations.is_empty() {
        trace.push(json!({
            "step":"public_agent_inbox_observed",
            "status":"observed",
            "evidence":inbox_observations
        }));
    }
    let observed_roles = inbox_observations
        .iter()
        .filter_map(|item| item["role"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let furthest_role = PROVIDER_ROLES
        .iter()
        .rev()
        .find(|role| observed_roles.contains(**role))
        .copied();
    let external_done = external_ticket_status.eq_ignore_ascii_case("done");
    request_merge_evidence.external_ticket_done = external_done;
    let coordinator_observation = inbox_observations
        .iter()
        .find(|observation| is_coordinator_dispatch_observation(observation));
    let supervisor_observation = inbox_observations
        .iter()
        .find(|observation| observation["role"] == "supervisor");
    let coordinator_stage_valid = bounded_coordinator_stage
        && coordinator_qualification_wait_proof
            .as_ref()
            .is_some_and(|proof| proof["status"] == "passed")
        && coordinator_boundary_reached
        && (!coordinator_worker_inbox_stage || worker_boundary_reached)
        && (!worker_recovery_inbox_stage || worker_boundary_reached)
        && (!host_commit_reviewer_inbox_stage || host_commit_reviewer_boundary_reached)
        && stopped
        && coordinator_observation.is_some()
        && (!coordinator_block_loss_stage
            || coordinator_block_loss_proof
                .as_ref()
                .is_some_and(|proof| proof["status"] == "passed"))
        && (!host_commit_reviewer_inbox_stage
            || host_commit_connection_evidence
                .as_ref()
                .is_some_and(|proof| proof["status"] == "passed"))
        && supervisor_observation.is_some_and(|observation| {
            observation
                .pointer("/input_files/effective_role_profiles/coordinator")
                .and_then(Value::as_str)
                == Some("fixture_coordinator")
        });
    let stage_valid = if request_merge_stage {
        request_merge_evidence.passed(external_done)
    } else {
        bounded_stage_contract_valid(
            stage.as_deref(),
            coordinator_stage_valid,
            native_worker_ready_marker_is_valid(
                &request.fixture_root.join("native-worker-ready.json"),
            ),
        )
    };
    let current_stop = if request_merge_stage && stage_valid {
        "configured Request-merge acceptance reached host verification and external ticket Done"
            .to_owned()
    } else if request_merge_stage {
        request_merge_stop
            .clone()
            .unwrap_or_else(|| request_merge_evidence.next_missing_milestone(external_done))
    } else if external_done {
        "external ticket is Done, but host evidence for every required role stage has not been established".to_owned()
    } else if let Some(role) = furthest_role {
        format!(
            "external ticket remains {external_ticket_status}; latest public inbox role observed: {role}"
        )
    } else {
        format!(
            "external ticket remains {external_ticket_status}; no public Agent inbox turn was observed"
        )
    };
    if bounded_coordinator_stage {
        let hold_evidence = if coordinator_block_loss_stage {
            json!({
                "coordinator_missing_qualification_wait":coordinator_qualification_wait_proof,
                "coordinator_process_held_until_stop":coordinator_block_loss_proof
                    .as_ref()
                    .and_then(|proof| (proof["agent_state"] == "cancelled").then_some(false)),
                "coordinator_process_held_until_fault":coordinator_block_loss_proof
                    .as_ref()
                    .and_then(|proof| proof["fault_injected"].as_bool()),
                "block_loss_recovery":coordinator_block_loss_proof
            })
        } else {
            json!({
                "coordinator_missing_qualification_wait":coordinator_qualification_wait_proof,
                "coordinator_process_held_until_stop":coordinator_boundary_reached
            })
        };
        trace.push(json!({"step":"supervisor_coordinator_contract","status":if stage_valid {"passed"} else {"failed"},"evidence":{"supervisor_prompt_role_profiles":supervisor_observation.and_then(|observation|observation.pointer("/input_files/effective_role_profiles").cloned()),"coordinator_dispatch_observation":coordinator_observation,"hold_evidence":hold_evidence}}));
    }
    let report = json!({
        "status":if stage_valid {"STAGE_PASSED"} else {"UNSUPPORTED"},
        "stage":stage,
        "product_cli_identity":cli_identity,
        "trace":trace,
        "last_dashboard":dashboard,
        "furthest_stage":furthest_role.unwrap_or("project_started"),
        "external_ticket_status":external_ticket_status,
        "current_stop":current_stop,
        "request_merge_stop":request_merge_stop,
        "request_merge_evidence":request_merge_evidence,
        "missing_capabilities":if request_merge_stage {
            request_merge_evidence.missing_milestones(external_done)
        } else if bounded_coordinator_stage {vec!["This bounded emulated stage does not claim downstream role completion or external Done."]} else {vec!["This emulated lane does not establish host-verified completion of every required role stage and external Done."]},
        "fixture_provider":"EMULATED",
        "resources_created":true,
        "owned_rex_session":request.rex_session,
        "owned_rex_windows":[window],
        "fixture_root":request.fixture_root
    });
    emit_report(request.fixture_root, &report)?;
    if (bounded_coordinator_stage || request_merge_stage) && !stage_valid {
        return Err(if request_merge_stage {
            request_merge_stop.unwrap_or_else(|| "configured Request-merge acceptance did not reach every required durable milestone".into())
        } else {
            "bounded Supervisor-to-Coordinator connection stage did not reach its contract boundary"
                .into()
        });
    }
    Ok(())
}

fn is_coordinator_dispatch_observation(observation: &Value) -> bool {
    observation["role"] == "coordinator"
        && observation["ticket_run_id"]
            .as_str()
            .is_some_and(|ticket_run_id| {
                observation["ticket_run_dispatch_id"].as_str() == Some(ticket_run_id)
            })
        && observation
            .pointer("/input_files/package_path")
            .and_then(Value::as_str)
            .is_some_and(|path| Path::new(path).is_absolute())
        && observation
            .pointer("/input_files/package_sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest.len() == 64)
        && observation
            .pointer("/input_files/snapshot_path")
            .and_then(Value::as_str)
            .is_some_and(|path| Path::new(path).is_absolute())
        && observation
            .pointer("/input_files/snapshot_digest")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest.len() == 64)
}

#[derive(Clone, Debug, Default, serde::Serialize)]
struct RequestMergeEvidence {
    presented_review: bool,
    approval_response_queued: bool,
    human_approval_accepted: bool,
    body_update_recovered: bool,
    request_comment_succeeded: bool,
    verify_pending_while_open: bool,
    separate_merge_observed: bool,
    host_merge_verified: bool,
    external_ticket_done: bool,
    request_id: Option<String>,
    work_id: Option<String>,
    merge_commit_sha: Option<String>,
}

impl RequestMergeEvidence {
    fn missing_milestones(&self, external_ticket_done: bool) -> Vec<&'static str> {
        [
            (
                !self.presented_review,
                "exact TicketReview was not presented through public human list/show",
            ),
            (
                !self.approval_response_queued,
                "exact-digest approval was not queued through public human respond",
            ),
            (
                !self.human_approval_accepted,
                "host controller has not accepted the exact human approval",
            ),
            (
                !self.body_update_recovered,
                "exact approved PR body update has no recovered host receipt",
            ),
            (
                !self.request_comment_succeeded,
                "configured Request comment has no succeeded host receipt",
            ),
            (
                !self.verify_pending_while_open,
                "durable Verify pending observation while the PR is open is missing",
            ),
            (
                !self.separate_merge_observed,
                "separate provider merge operation has not been observed",
            ),
            (
                !self.host_merge_verified,
                "host MergeVerificationReceipt is missing",
            ),
            (
                !external_ticket_done,
                "external ticket has not reached Done",
            ),
        ]
        .into_iter()
        .filter_map(|(missing, description)| missing.then_some(description))
        .collect()
    }

    fn next_missing_milestone(&self, external_ticket_done: bool) -> String {
        self.missing_milestones(external_ticket_done)
            .into_iter()
            .next()
            .unwrap_or("configured Request-merge acceptance is not yet complete")
            .to_owned()
    }

    fn passed(&self, external_ticket_done: bool) -> bool {
        self.presented_review
            && self.approval_response_queued
            && self.human_approval_accepted
            && self.body_update_recovered
            && self.request_comment_succeeded
            && self.verify_pending_while_open
            && self.separate_merge_observed
            && self.host_merge_verified
            && external_ticket_done
    }
}

fn advance_request_merge_acceptance(
    request: &Request<'_>,
    state_root: &Path,
    evidence: &mut RequestMergeEvidence,
) -> Result<Vec<Value>, String> {
    let mut trace = Vec::new();
    let listed = product_as_human(
        request,
        state_root,
        &["human", "list", "--project", FIXTURE_PROJECT_ID, "--json"],
    )?;
    require_success("list public human requests", &listed)?;
    let requests = json_stdout(&listed)["requests"]
        .as_array()
        .cloned()
        .ok_or("public human list omitted requests array")?;
    let Some(ticket_run_id) = acceptance_ticket_run_id(state_root)? else {
        return Ok(trace);
    };
    let mut candidate = None;
    for raw in requests {
        let summary: rex_projects::human_runtime::HumanRequestSummary = serde_json::from_value(raw)
            .map_err(|error| format!("parse public human request: {error}"))?;
        if summary.request.purpose != rex_projects::human_runtime::HumanPurpose::TicketReview
            || summary.request.subject.kind
                != rex_projects::human_runtime::HumanSubjectKind::TicketRun
            || summary.request.subject.project_id.as_str() != FIXTURE_PROJECT_ID
            || summary.request.subject.subject_id != ticket_run_id
            || summary
                .request
                .subject
                .ticket_run_id
                .as_ref()
                .map(|id| id.as_str())
                != Some(ticket_run_id.as_str())
        {
            continue;
        }
        let Some(work) = read_review_merge_work_item(state_root, &summary.request.subject)? else {
            continue;
        };
        let canonical_request_id = format!("merge-review-{}", work.document.intent_evidence_id);
        if summary.request.request_id.as_str() != canonical_request_id {
            return Err(
                "public human request ID is not the canonical MergeWork review request ID".into(),
            );
        }
        let expected =
            rex_projects::human_runtime::HumanAuthorityMaterial::merge_work_review_request(
                summary.request.request_id.clone(),
                work.clone(),
                summary.request.expires_at_unix,
            )?;
        if expected != summary.request {
            continue;
        }
        candidate = Some((summary, work));
        break;
    }
    let Some((listed_summary, work)) = candidate else {
        return Ok(trace);
    };
    let request_id = listed_summary.request.request_id.as_str().to_owned();
    let shown = product_as_human(
        request,
        state_root,
        &["human", "show", &request_id, "--json"],
    )?;
    require_success("show exact public human review", &shown)?;
    let summary: rex_projects::human_runtime::HumanRequestSummary =
        serde_json::from_slice(&shown.stdout)
            .map_err(|error| format!("parse public human show response: {error}"))?;
    if summary != listed_summary {
        return Err("public human request changed between list and show".into());
    }
    validate_request_merge_work(&work)?;
    evidence.request_id = Some(request_id.clone());
    evidence.work_id = Some(work.work_id.as_str().to_owned());
    if !evidence.presented_review {
        evidence.presented_review = true;
        trace.push(json!({"step":"exact_merge_review_presented","status":"observed","request_id":request_id,"work_id":work.work_id.as_str(),"project_id":FIXTURE_PROJECT_ID,"ticket_run_id":ticket_run_id}));
    }

    if summary.lifecycle == rex_projects::human_runtime::HumanRequestLifecycle::Presented {
        let subject_digest = summary
            .request
            .subject
            .digest()
            .map_err(|error| format!("digest exact presented review subject: {error}"))?;
        let response = product_as_human(
            request,
            state_root,
            &[
                "human",
                "respond",
                &request_id,
                "--subject-digest",
                subject_digest.as_str(),
                "--choice",
                "approve",
                "--explanation",
                "Acceptance fixture approves this exact immutable merge work review.",
                "--json",
            ],
        )?;
        require_success("queue exact public human approval", &response)?;
        let queued = json_stdout(&response);
        if queued["state"] != "queued_for_validation" || queued["accepted_for_validation"] != true {
            return Err("human respond did not queue the exact review for host validation".into());
        }
        if !evidence.approval_response_queued {
            evidence.approval_response_queued = true;
            trace.push(json!({"step":"exact_human_approval_response","status":"queued_for_validation","request_id":request_id,"subject_digest":subject_digest.as_str(),"evidence":queued}));
        }
    } else if matches!(
        summary.lifecycle,
        rex_projects::human_runtime::HumanRequestLifecycle::ResponseQueued
            | rex_projects::human_runtime::HumanRequestLifecycle::Decided
    ) && !evidence.approval_response_queued
    {
        evidence.approval_response_queued = true;
        trace.push(json!({"step":"exact_human_approval_response","status":"observed_queued","request_id":request_id}));
    }

    let Some(accepted_response) = accepted_merge_review_response(state_root, &summary)? else {
        return Ok(trace);
    };
    if !evidence.human_approval_accepted {
        evidence.human_approval_accepted = true;
        trace.push(json!({"step":"exact_human_approval_accepted","status":"passed","request_id":request_id,"response_id":accepted_response,"subject_digest":summary.request.subject.digest()?.as_str()}));
    }

    let effects = read_request_merge_effects(state_root, &work, &summary)?;
    if let Some(update) = effects.body_update {
        if !evidence.body_update_recovered {
            evidence.body_update_recovered = true;
            trace.push(json!({"step":"approved_body_update_recovered_noop","status":"passed","operation_id":update.operation_id,"receipt":update.receipt}));
        }
    } else {
        return Ok(trace);
    }
    let Some(request_effect) = effects.request.as_ref() else {
        return Ok(trace);
    };
    if !evidence.request_comment_succeeded {
        evidence.request_comment_succeeded = true;
        trace.push(json!({"step":"request_merge_effect_succeeded","status":"passed","operation_id":request_effect.operation_id,"receipt":request_effect.receipt}));
    }
    let verify_effect = effects.verify_pending.as_ref();
    let pull = work_pull_ref(&work)?;
    let pull_observation = fixture_gh_api(
        request,
        "GET",
        &format!(
            "repos/{}/{}/pulls/{}",
            pull.repository.owner, pull.repository.name, pull.number
        ),
        None,
    )?;
    let request_receipt = request_effect
        .receipt
        .as_ref()
        .ok_or("succeeded Request effect has no parsed receipt")?;
    let comment_intent = match &request_receipt.effect_intent.operation {
        rex_projects::forge::MergeEffectOperation::RequestComment(intent) => intent,
        _ => return Err("succeeded Request receipt is not a RequestComment effect".into()),
    };
    if pull_observation["state"] == "open"
        && (pull_observation["merged"] != false
            || pull_observation
                .pointer("/head/sha")
                .and_then(Value::as_str)
                != Some(work.document.evidence.subject.head_sha.as_str())
            || pull_observation["body"].as_str() != work.document.prepared_body.as_deref())
    {
        return Err(
            "open PR observation does not match the approved Request work and exact prepared body"
                .into(),
        );
    }
    let comments = fixture_gh_api(
        request,
        "GET",
        &format!(
            "repos/{}/{}/issues/{}/comments",
            pull.repository.owner, pull.repository.name, pull.number
        ),
        None,
    )?;
    let comments = comments
        .as_array()
        .ok_or("request comment observation is not a complete array")?;
    let external_id = request_receipt
        .acknowledgement
        .external_id
        .as_deref()
        .ok_or("Request receipt omitted the exact external comment ID")?;
    let observed_comment = comments
        .iter()
        .find(|comment| {
            comment["id"]
                .as_u64()
                .is_some_and(|id| id.to_string() == external_id)
                && comment["body"].as_str() == Some(comment_intent.exact_body.as_str())
                && comment.pointer("/user/login").and_then(Value::as_str)
                    == Some(comment_intent.authenticated_actor.as_str())
        })
        .ok_or("provider does not expose the exact acknowledged Request comment")?;
    let created_at = observed_comment["created_at"]
        .as_str()
        .ok_or("Request comment lacks a provider timestamp")?;
    if comment_timestamp_unix(created_at)
        .is_none_or(|created| created < comment_intent.attempt_started_unix)
    {
        return Err(
            "Request comment timestamp is missing, malformed, or predates its durable attempt"
                .into(),
        );
    }
    if pull_observation["state"] == "open" {
        let Some(verify_effect) = verify_effect else {
            return Ok(trace);
        };
        if !evidence.verify_pending_while_open {
            evidence.verify_pending_while_open = true;
            trace.push(json!({"step":"verify_pending_while_provider_pr_open","status":"passed","operation_id":verify_effect.operation_id,"status_in_sqlite":"uncertain","receipt_json":"pull request has not merged yet","next_attempt_at_unix":verify_effect.next_attempt_at_unix,"provider_pull_request":pull_observation,"request_comment":observed_comment}));
        }
    } else if pull_observation["state"] != "closed" || pull_observation["merged"] != true {
        return Err("provider PR is neither the expected open state nor a completed merge".into());
    } else if !evidence.verify_pending_while_open {
        return Err(
            "provider PR merged before the acceptance observed the durable pending Verify effect"
                .into(),
        );
    }

    if pull_observation["state"] == "open" {
        let reviews = fixture_gh_api(
            request,
            "GET",
            &format!(
                "repos/{}/{}/pulls/{}/reviews",
                pull.repository.owner, pull.repository.name, pull.number
            ),
            None,
        )?;
        let has_current_approval = reviews.as_array().is_some_and(|reviews| {
            reviews.iter().any(|review| {
                review["state"] == "APPROVED"
                    && review["commit_id"].as_str()
                        == Some(comment_intent.expected_head_sha.as_str())
            })
        });
        if !has_current_approval {
            let review = fixture_gh_api(
                request,
                "POST",
                &format!(
                    "repos/{}/{}/pulls/{}/reviews",
                    pull.repository.owner, pull.repository.name, pull.number
                ),
                Some(json!({"event":"APPROVE"})),
            )?;
            if review["state"] != "APPROVED"
                || review["commit_id"].as_str() != Some(comment_intent.expected_head_sha.as_str())
            {
                return Err(
                    "fixture provider did not accept approval for the reviewed head".into(),
                );
            }
            trace.push(json!({"step":"fixture_human_provider_review","status":"passed","head_sha":comment_intent.expected_head_sha}));
        }
        let merge_method = serde_json::to_value(work.document.procedure.method)
            .map_err(|error| error.to_string())?;
        let merge_method = merge_method
            .as_str()
            .ok_or("configured merge method is not a string")?;
        if merge_method != "squash" {
            return Err("configured Request acceptance fixture expects its repository's squash merge method".into());
        }
        let merge = fixture_gh_api(
            request,
            "PUT",
            &format!(
                "repos/{}/{}/pulls/{}/merge",
                pull.repository.owner, pull.repository.name, pull.number
            ),
            Some(
                json!({"sha":comment_intent.expected_head_sha,"merge_method":merge_method,"commit_message":work.document.prepared_body}),
            ),
        )?;
        if merge["merged"] != true {
            return Err(format!(
                "fixture provider refused the separate merge operation: {merge}"
            ));
        }
        trace.push(json!({"step":"separate_provider_merge","status":"applied","response":merge}));
    }
    let merged = fixture_gh_api(
        request,
        "GET",
        &format!(
            "repos/{}/{}/pulls/{}",
            pull.repository.owner, pull.repository.name, pull.number
        ),
        None,
    )?;
    if merged["state"] != "closed" || merged["merged"] != true {
        return Ok(trace);
    }
    let merge_sha = merged["merge_commit_sha"]
        .as_str()
        .ok_or("provider merge observation omitted merge_commit_sha")?
        .to_owned();
    if !evidence.separate_merge_observed {
        evidence.separate_merge_observed = true;
        evidence.merge_commit_sha = Some(merge_sha.clone());
        trace.push(json!({"step":"separate_provider_merge_observed","status":"passed","merge_commit_sha":merge_sha,"pull_request":merged}));
    }
    if let Some(verified) = effects.verify_verified.as_ref() {
        if verified.merge_commit_sha != merge_sha
            || verified.included_head_sha != comment_intent.expected_head_sha
            || verified.merge_method != work.document.procedure.method
        {
            return Err("host MergeVerificationReceipt does not match the separately observed provider merge".into());
        }
        if !evidence.host_merge_verified {
            evidence.host_merge_verified = true;
            trace.push(json!({"step":"host_merge_verification_receipt","status":"passed","receipt":verified}));
        }
    }
    Ok(trace)
}

fn acceptance_ticket_run_id(state_root: &Path) -> Result<Option<String>, String> {
    let database = open_acceptance_state_read_only(state_root)?;
    database
        .query_row(
            "SELECT ticket_run_id FROM ticket_runs WHERE project_id=?1 AND namespace=?2 AND ticket_id=?3 ORDER BY generation DESC LIMIT 1",
            params![FIXTURE_PROJECT_ID, FIXTURE_TICKET_NAMESPACE, FIXTURE_TICKET_ID],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("read acceptance TicketRun identity: {error}"))
}

fn open_acceptance_state_read_only(state_root: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open acceptance state read-only: {error}"))
}

fn read_review_merge_work_item(
    state_root: &Path,
    subject: &rex_projects::human_runtime::HumanSubjectBinding,
) -> Result<Option<rex_projects::store::merge_work::MergeWorkItem>, String> {
    if subject.kind != rex_projects::human_runtime::HumanSubjectKind::TicketRun
        || subject.ticket_run_id.as_ref().map(|id| id.as_str()) != Some(subject.subject_id.as_str())
    {
        return Ok(None);
    }
    let database = open_acceptance_state_read_only(state_root)?;
    let row: Option<(String, String)> = database
        .query_row(
            "SELECT work_id,work_json FROM merge_work_items WHERE project_id=?1 AND ticket_run_id=?2 AND awaiting_merge_revision=?3",
            params![subject.project_id.as_str(), subject.subject_id, subject.revision.0],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read immutable merge work for public review: {error}"))?;
    let Some((stored_work_id, work_json)) = row else {
        return Ok(None);
    };
    let work: rex_projects::store::merge_work::MergeWorkItem = serde_json::from_str(&work_json)
        .map_err(|error| format!("parse stored immutable merge work: {error}"))?;
    let rebuilt = rex_projects::store::merge_work::MergeWorkItem::new(
        work.project_id.clone(),
        work.ticket_run_id.clone(),
        work.assessed_revision,
        work.awaiting_merge_revision,
        work.configuration_digest.clone(),
        work.accepted_plan_digest.clone(),
        work.prepared_receipt_digest.clone(),
        work.publication_set_digest.clone(),
        work.document.clone(),
    )?;
    if work.work_id.as_str() != stored_work_id
        || rebuilt != work
        || work.project_id.as_str() != subject.project_id.as_str()
        || work.ticket_run_id.as_str() != subject.subject_id
        || work.awaiting_merge_revision != subject.revision
    {
        return Err(
            "stored immutable merge work does not match its canonical identity and review subject"
                .into(),
        );
    }
    work.document
        .validate_for(&work.configuration_digest, &work.document.assessment_id)?;
    Ok(Some(work))
}

fn validate_request_merge_work(
    work: &rex_projects::store::merge_work::MergeWorkItem,
) -> Result<(), String> {
    use rex_projects::merge_policy::MergeProcedureOperation as Operation;
    if work.project_id.as_str() != FIXTURE_PROJECT_ID
        || work.document.policy.executor != rex_projects::domain::types::MergeExecutor::Request
        || work.document.procedure.executor != rex_projects::domain::types::MergeExecutor::Request
        || work.document.procedure.method != rex_projects::domain::types::MergeMethod::Squash
        || work.document.procedure.steps.len() != 3
    {
        return Err(
            "presented MergeWork is not the configured Request/squash fixture procedure".into(),
        );
    }
    let operations = work
        .document
        .procedure
        .steps
        .iter()
        .map(|step| &step.operation)
        .collect::<Vec<_>>();
    if !matches!(operations[0], Operation::UpdatePullRequestBody { .. })
        || !matches!(operations[1], Operation::RequestMerge { exact_comment } if exact_comment == "/merge")
        || !matches!(operations[2], Operation::VerifyMergeCommit { .. })
        || work
            .document
            .prepared_body
            .as_deref()
            .is_none_or(str::is_empty)
        || work.document.evidence.subject.repository_id != "fixture"
        || work.document.evidence.subject.forge != "github"
        || work
            .document
            .evidence
            .subject
            .pull_request_id
            .parse::<u64>()
            .is_err()
    {
        return Err(
            "MergeWork procedure is not the expected typed body-recovery, /merge, verify sequence"
                .into(),
        );
    }
    Ok(())
}

fn accepted_merge_review_response(
    state_root: &Path,
    summary: &rex_projects::human_runtime::HumanRequestSummary,
) -> Result<Option<String>, String> {
    type AcceptedMergeReviewRow = (
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    let database = open_acceptance_state_read_only(state_root)?;
    let row: Option<AcceptedMergeReviewRow> = database
        .query_row(
            "SELECT hr.lifecycle,hd.response_id,hd.choice,hd.approved,hd.subject_digest,hd.configuration_digest,hd.policy_digest FROM human_requests hr LEFT JOIN human_decisions hd ON hd.request_id=hr.request_id WHERE hr.request_id=?1",
            [summary.request.request_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        )
        .optional()
        .map_err(|error| format!("read exact accepted human review receipt: {error}"))?;
    let Some((
        lifecycle,
        response_id,
        choice,
        approved,
        subject_digest,
        configuration_digest,
        policy_digest,
    )) = row
    else {
        return Ok(None);
    };
    let expected_subject = summary.request.subject.digest()?;
    match (
        lifecycle.as_str(),
        response_id,
        choice,
        approved,
        subject_digest,
        configuration_digest,
        policy_digest,
    ) {
        (
            "decided",
            Some(response_id),
            Some(choice),
            Some(1),
            Some(subject),
            Some(configuration),
            Some(policy),
        ) if choice == "approve"
            && subject == expected_subject.as_str()
            && configuration == summary.request.subject.configuration_digest.as_str()
            && policy == summary.request.subject.policy_digest.as_str() =>
        {
            Ok(Some(response_id))
        }
        ("decided", ..) => {
            Err("the exact MergeWork review was decided without an accepted approval".into())
        }
        _ => Ok(None),
    }
}

#[derive(Debug)]
struct StoredMergeStep {
    operation_id: String,
    receipt: Option<rex_projects::merge_executor::MergeStepReceipt>,
    next_attempt_at_unix: i64,
}

#[derive(Debug)]
struct RequestMergeEffects {
    body_update: Option<StoredMergeStep>,
    request: Option<StoredMergeStep>,
    verify_pending: Option<StoredMergeStep>,
    verify_verified: Option<rex_projects::merge_executor::MergeVerificationReceipt>,
}

fn validate_recovered_body_update_receipt(
    receipt: &rex_projects::merge_executor::MergeStepReceipt,
    step_key: &str,
    operation_id: &str,
    exact_body: &str,
    expected_head_sha: &str,
) -> Result<(), String> {
    let operation_key = format!("{operation_id}:{step_key}");
    let rex_projects::forge::MergeEffectOperation::UpdateBody(body) =
        &receipt.effect_intent.operation
    else {
        return Err("body update receipt contains a different Forge operation".into());
    };
    let approved_bytes_digest = rex_projects::domain::ids::Digest::parse(format!(
        "{:x}",
        Sha256::digest(exact_body.as_bytes())
    ))?;
    let canonical_request_digest = serialized_sha256_digest(body)?;
    if receipt.step_key != step_key
        || receipt.operation_key != operation_key
        || receipt.effect_intent.operation_key != operation_key
        || receipt.certainty != rex_projects::forge::EffectCertainty::Recovered
        || receipt.acknowledgement.certainty != rex_projects::forge::EffectCertainty::Recovered
        || receipt.effect_intent.request_digest != canonical_request_digest
        || receipt.request_digest != canonical_request_digest
        || receipt.acknowledgement.request_digest != canonical_request_digest
        || receipt.acknowledgement.operation_key != operation_key
        || body.exact_body != exact_body
        || body.expected_head_sha != expected_head_sha
        || body.approved_body_digest != approved_bytes_digest
    {
        return Err(
            "body update receipt does not prove exact recovered no-op for approved body".into(),
        );
    }
    Ok(())
}

fn validate_request_comment_receipt(
    receipt: &rex_projects::merge_executor::MergeStepReceipt,
    effect: &rex_projects::merge_executor::MergeStepEffectRequest,
    step_key: &str,
    operation_id: &str,
    exact_comment: &str,
    body_receipt: &rex_projects::merge_executor::MergeStepReceipt,
) -> Result<(), String> {
    let operation_key = format!("{operation_id}:{step_key}");
    let rex_projects::forge::MergeEffectOperation::RequestComment(comment) =
        &receipt.effect_intent.operation
    else {
        return Err("Request receipt contains a different Forge operation".into());
    };
    let canonical_request_digest = serialized_sha256_digest(comment)?;
    if receipt.step_key != step_key
        || receipt.operation_key != operation_key
        || receipt.effect_intent.operation_key != operation_key
        || !matches!(
            receipt.certainty,
            rex_projects::forge::EffectCertainty::Applied
                | rex_projects::forge::EffectCertainty::Recovered
        )
        || receipt.effect_intent.request_digest != canonical_request_digest
        || receipt.request_digest != canonical_request_digest
        || receipt.acknowledgement.request_digest != canonical_request_digest
        || receipt.acknowledgement.operation_key != operation_key
        || comment.exact_body != exact_comment
        || comment.authenticated_actor.trim().is_empty()
        || comment.attempt_started_unix == 0
        || effect.prior_receipts.len() != 1
        || effect.prior_receipts.first() != Some(body_receipt)
        || receipt.acknowledgement.external_id.is_none()
    {
        return Err("Request receipt is not the exact approved comment operation after recovered body preparation".into());
    }
    Ok(())
}

fn validate_pending_verify_effect(
    effect: &rex_projects::merge_executor::MergeStepEffectRequest,
    receipt_json: Option<&str>,
    next_attempt_at_unix: i64,
    body_receipt: &rex_projects::merge_executor::MergeStepReceipt,
    request_receipt: &rex_projects::merge_executor::MergeStepReceipt,
) -> Result<(), String> {
    if effect.prior_receipts.len() != 2
        || effect.prior_receipts.first() != Some(body_receipt)
        || effect.prior_receipts.get(1) != Some(request_receipt)
        || receipt_json != Some("pull request has not merged yet")
        || next_attempt_at_unix <= 0
    {
        return Err(
            "Verify effect is not the durable scheduled pending observation for the open PR".into(),
        );
    }
    Ok(())
}

fn serialized_sha256_digest<T: serde::Serialize>(
    value: &T,
) -> Result<rex_projects::domain::ids::Digest, String> {
    let encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    rex_projects::domain::ids::Digest::parse(format!("{:x}", Sha256::digest(encoded)))
}

fn read_request_merge_effects(
    state_root: &Path,
    work: &rex_projects::store::merge_work::MergeWorkItem,
    summary: &rex_projects::human_runtime::HumanRequestSummary,
) -> Result<RequestMergeEffects, String> {
    use rex_projects::merge_policy::MergeProcedureOperation as Operation;
    let database = open_acceptance_state_read_only(state_root)?;
    let mut statement = database
        .prepare("SELECT operation_id,expected_revision,request_json,status,receipt_json,next_attempt_at_unix FROM effects WHERE project_id=?1 AND subject_type='ticket_run' AND subject_id=?2 AND kind='merge' ORDER BY created_at_unix,operation_id")
        .map_err(|error| format!("prepare read-only merge outbox evidence query: {error}"))?;
    let rows = statement
        .query_map(
            params![work.project_id.as_str(), work.ticket_run_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|error| format!("query read-only merge outbox evidence: {error}"))?;
    let mut effects = RequestMergeEffects {
        body_update: None,
        request: None,
        verify_pending: None,
        verify_verified: None,
    };
    for row in rows {
        let (
            operation_id,
            expected_revision,
            request_json,
            status,
            receipt_json,
            next_attempt_at_unix,
        ) = row.map_err(|error| format!("read merge outbox evidence row: {error}"))?;
        let effect: rex_projects::merge_executor::MergeStepEffectRequest =
            serde_json::from_str(&request_json)
                .map_err(|error| format!("parse durable merge effect request: {error}"))?;
        if effect.work_id != work.work_id
            || effect.request_id != summary.request.request_id
            || effect.assessed_revision != work.assessed_revision
            || effect.awaiting_merge_revision != work.awaiting_merge_revision
            || expected_revision != Some(work.awaiting_merge_revision.0 as i64)
        {
            continue;
        }
        let (index, step) = work
            .document
            .procedure
            .steps
            .iter()
            .enumerate()
            .find(|(_, step)| step.key == effect.step_key)
            .ok_or("durable merge effect references a step outside the approved procedure")?;
        let raw = receipt_json.clone();
        match (&step.operation, status.as_str()) {
            (Operation::UpdatePullRequestBody { .. }, "succeeded") => {
                let receipt: rex_projects::merge_executor::MergeStepReceipt = serde_json::from_str(
                    raw.as_deref()
                        .ok_or("succeeded body update omitted its durable receipt")?,
                )
                .map_err(|error| format!("parse body update receipt: {error}"))?;
                let exact_body = work
                    .document
                    .prepared_body
                    .as_deref()
                    .ok_or("MergeWork omitted its exact prepared body")?;
                validate_recovered_body_update_receipt(
                    &receipt,
                    &step.key,
                    &operation_id,
                    exact_body,
                    &work.document.evidence.subject.head_sha,
                )?;
                effects.body_update = Some(StoredMergeStep {
                    operation_id,
                    receipt: Some(receipt),
                    next_attempt_at_unix,
                });
            }
            (Operation::RequestMerge { exact_comment }, "succeeded") if index == 1 => {
                let receipt: rex_projects::merge_executor::MergeStepReceipt = serde_json::from_str(
                    raw.as_deref()
                        .ok_or("succeeded Request step omitted its durable receipt")?,
                )
                .map_err(|error| format!("parse Request step receipt: {error}"))?;
                let body_receipt = effects
                    .body_update
                    .as_ref()
                    .and_then(|row| row.receipt.as_ref())
                    .ok_or("Request receipt preceded the recovered body update receipt")?;
                validate_request_comment_receipt(
                    &receipt,
                    &effect,
                    &step.key,
                    &operation_id,
                    exact_comment,
                    body_receipt,
                )?;
                effects.request = Some(StoredMergeStep {
                    operation_id,
                    receipt: Some(receipt),
                    next_attempt_at_unix,
                });
            }
            (Operation::VerifyMergeCommit { .. }, "uncertain") => {
                let request_receipt = effects
                    .request
                    .as_ref()
                    .and_then(|row| row.receipt.as_ref())
                    .ok_or("Verify pending observation preceded the succeeded Request receipt")?;
                let body_receipt = effects
                    .body_update
                    .as_ref()
                    .and_then(|row| row.receipt.as_ref())
                    .ok_or("Verify has no body update prerequisite")?;
                validate_pending_verify_effect(
                    &effect,
                    raw.as_deref(),
                    next_attempt_at_unix,
                    body_receipt,
                    request_receipt,
                )?;
                effects.verify_pending = Some(StoredMergeStep {
                    operation_id,
                    receipt: None,
                    next_attempt_at_unix,
                });
            }
            (Operation::VerifyMergeCommit { .. }, "succeeded") => {
                let request_receipt = effects
                    .request
                    .as_ref()
                    .and_then(|row| row.receipt.as_ref())
                    .ok_or("verified Merge effect has no prior Request receipt")?;
                if effect.prior_receipts.len() != 2 || effect.prior_receipts[1] != *request_receipt
                {
                    return Err(
                        "verified Merge effect is not bound to the exact Request receipt".into(),
                    );
                }
                let verification: rex_projects::merge_executor::MergeVerificationReceipt =
                    serde_json::from_str(
                        raw.as_deref()
                            .ok_or("verified Merge effect omitted typed verification receipt")?,
                    )
                    .map_err(|error| format!("parse host MergeVerificationReceipt: {error}"))?;
                effects.verify_verified = Some(verification);
            }
            _ => {}
        }
    }
    Ok(effects)
}

fn work_pull_ref(
    work: &rex_projects::store::merge_work::MergeWorkItem,
) -> Result<rex_projects::forge::PullRequestRef, String> {
    let subject = &work.document.evidence.subject;
    if subject.repository_id != "fixture"
        || subject.forge != "github"
        || subject.forge_host != "github.com"
    {
        return Err("MergeWork does not identify the configured local GitHub fixture".into());
    }
    Ok(rex_projects::forge::PullRequestRef {
        repository: rex_projects::forge::RepositoryRef {
            host: subject.forge_host.clone(),
            owner: "fixture".into(),
            name: "repository".into(),
            expected_id: Some(subject.forge_repository_id),
        },
        number: subject
            .pull_request_id
            .parse()
            .map_err(|_| "MergeWork pull request ID is invalid")?,
        expected_node_id: Some(subject.pull_request_node_id.clone()),
    })
}

fn product_as_human(
    request: &Request<'_>,
    state_root: &Path,
    words: &[&str],
) -> Result<ProcessOutput, String> {
    let mut args = vec![
        OsString::from("--config"),
        request.fixture_root.join("config.toml").into_os_string(),
        OsString::from("--state-root"),
        state_root.as_os_str().to_owned(),
    ];
    args.extend(words.iter().map(OsString::from));
    let mut environment = std::env::vars_os()
        .filter(|(key, _)| {
            key != std::ffi::OsStr::new("REX_PROJECTS_AGENT")
                && key != std::ffi::OsStr::new("REX_PROJECTS_CONTEXT")
        })
        .collect::<BTreeMap<_, _>>();
    environment.insert(
        "XDG_STATE_HOME".into(),
        request.fixture_root.join("xdg-state").into_os_string(),
    );
    run_process(ProcessRequest {
        executable: request.cli.to_path_buf(),
        args,
        stdin: Vec::new(),
        cwd: Some(request.fixture_root.to_path_buf()),
        clear_environment: true,
        environment,
        timeout: STEP_TIMEOUT,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| format!("run public human command outside Agent context: {error}"))
}

fn fixture_gh_api(
    request: &Request<'_>,
    method: &str,
    endpoint: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut args = vec![
        OsString::from("api"),
        OsString::from(endpoint),
        OsString::from("--method"),
        OsString::from(method),
    ];
    let stdin = if let Some(body) = body {
        args.extend([OsString::from("--input"), OsString::from("-")]);
        serde_json::to_vec(&body).map_err(|error| error.to_string())?
    } else {
        Vec::new()
    };
    let output = run_process(ProcessRequest {
        executable: request.fixture_root.join("bin/gh"),
        args,
        stdin,
        cwd: Some(request.fixture_root.to_path_buf()),
        clear_environment: false,
        environment: std::env::vars_os().collect(),
        timeout: STEP_TIMEOUT,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| format!("run fixture provider API process: {error}"))?;
    require_success("fixture provider API request", &output)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse fixture provider response JSON: {error}"))
}

fn comment_timestamp_unix(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date = date.split('-');
    let year = date.next()?.parse::<i64>().ok()?;
    let month = date.next()?.parse::<i64>().ok()?;
    let day = date.next()?.parse::<i64>().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (clock, _) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.split(':');
    let hour = clock.next()?.parse::<u64>().ok()?;
    let minute = clock.next()?.parse::<u64>().ok()?;
    let second = clock.next()?.parse::<u64>().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;
    let seconds =
        days_since_epoch * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    u64::try_from(seconds).ok()
}

fn bounded_stage_contract_valid(
    stage: Option<&str>,
    coordinator_stage_valid: bool,
    native_worker_ready: bool,
) -> bool {
    coordinator_stage_valid
        && (!matches!(
            stage,
            Some(NATIVE_WORKER_BLOCK_LOSS_STAGE | NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE)
        ) || native_worker_ready)
}

fn native_worker_ready_marker_is_valid(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(marker) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let worker = &marker["worker"];
    let anchor = &worker["wrapper_process_identity"]["rex_launch_anchor"];
    let anchor_pid = anchor["pid"].as_u64();
    let anchor_birth = anchor["start_identity"].as_str();
    let child_pid = worker["rex_process_observation"]["child"]["pid"].as_u64();
    let supervisor_birth = worker["wrapper_process_identity"]["start_identity"].as_str();
    let live = worker["live_process_identities"].as_array();
    let exact_live = anchor_pid.zip(anchor_birth).is_some_and(|(pid, birth)| {
        live.is_some_and(|processes| {
            processes.iter().any(|process| {
                process["pid"].as_u64() == Some(pid)
                    && process["start_identity"].as_str() == Some(birth)
            }) && supervisor_birth.is_some_and(|supervisor_birth| {
                processes.iter().any(|process| {
                    process["pid"].as_u64() == worker["wrapper_process_identity"]["pid"].as_u64()
                        && process["start_identity"].as_str() == Some(supervisor_birth)
                        && process["parent_pid"].as_u64() == Some(pid)
                })
            })
        })
    });
    marker["status"] == "native_worker_running"
        && marker
            .pointer("/worker/agent_state")
            .and_then(Value::as_str)
            == Some("running")
        && marker
            .pointer("/worker/launch_state")
            .and_then(Value::as_str)
            == Some("running")
        && marker
            .pointer("/worker/slot_disposition")
            .and_then(Value::as_str)
            == Some("live")
        && marker
            .pointer("/worker/live_process_identities")
            .and_then(Value::as_array)
            .is_some_and(|processes| processes.len() >= 2)
        && worker["anchored_topology_verified"] == true
        && child_pid == anchor_pid
        && exact_live
}

fn is_prepared_worker_inbox_observation(
    observation: &Value,
    state_root: &Path,
) -> Result<Option<Value>, String> {
    if observation["role"] != "worker"
        || observation["ticket_run_id"]
            .as_str()
            .is_none_or(str::is_empty)
        || observation
            .pointer("/input_files/package_path")
            .and_then(Value::as_str)
            .is_none_or(|path| !Path::new(path).is_absolute())
        || observation
            .pointer("/input_files/package_sha256")
            .and_then(Value::as_str)
            .is_none_or(|digest| digest.len() != 64)
        || observation
            .pointer("/input_files/snapshot_path")
            .and_then(Value::as_str)
            .is_none_or(|path| !Path::new(path).is_absolute())
        || observation
            .pointer("/input_files/snapshot_digest")
            .and_then(Value::as_str)
            .is_none_or(|digest| digest.len() != 64)
    {
        return Ok(None);
    }
    let assignment = &observation["worker_assignment"];
    let (Some(node_id), Some(plan_digest), Some(worktree_path)) = (
        assignment["node_id"].as_str(),
        assignment["accepted_plan_digest"].as_str(),
        assignment["worktree_path"].as_str(),
    ) else {
        return Ok(None);
    };
    let ticket_run_id = observation["ticket_run_id"].as_str().unwrap_or_default();
    let inputs = observation["inbox_inputs"].as_array();
    let Some(input) = inputs.and_then(|inputs| {
        inputs.iter().find(|input| {
            input["source_type"] == "work_node_ready"
                && input.pointer("/payload_json/kind").and_then(Value::as_str)
                    == Some("work_node_ready")
                && input
                    .pointer("/payload_json/ticket_run_id")
                    .and_then(Value::as_str)
                    == Some(ticket_run_id)
                && input
                    .pointer("/payload_json/work_node_id")
                    .and_then(Value::as_str)
                    == Some(node_id)
                && input
                    .pointer("/payload_json/accepted_plan_digest")
                    .and_then(Value::as_str)
                    == Some(plan_digest)
                && input
                    .pointer("/payload_json/source_message_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.starts_with("prepare-worktrees:"))
                && input
                    .pointer("/payload_json/revision")
                    .and_then(Value::as_u64)
                    .is_some()
        })
    }) else {
        return Ok(None);
    };
    let run_id = observation["run_id"]
        .as_str()
        .ok_or("Worker inbox observation omitted its run ID")?;
    let database = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open acceptance state read-only for Worker authority: {error}"))?;
    let authority_row: Option<(String, String)> = database
        .query_row(
            "SELECT a.authority_json,r.reservation_json FROM agent_launch_authority a JOIN agent_launch_reservations r USING(agent_run_id) WHERE a.agent_run_id=?1 AND a.role='worker'",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read registered Worker launch authority: {error}"))?;
    let Some((authority_json, reservation_json)) = authority_row else {
        return Ok(None);
    };
    let authority: rex_projects::launch::AgentLaunchAuthority =
        serde_json::from_str(&authority_json)
            .map_err(|error| format!("parse registered Worker launch authority: {error}"))?;
    let reservation: rex_projects::launch::AgentLaunchReservation =
        serde_json::from_str(&reservation_json)
            .map_err(|error| format!("parse registered Worker launch reservation: {error}"))?;
    let Some(binding) = reservation.worker_assignment.as_ref() else {
        return Ok(None);
    };
    let expected_source_message = format!("prepare-worktrees:{}", binding.prepare_operation_id);
    let source_message_id = input
        .pointer("/payload_json/source_message_id")
        .and_then(Value::as_str);
    let coordinator_row: (String, String) = database
        .query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            params![binding.coordinator_agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read registered Coordinator parent authority: {error}"))?
        .ok_or("Worker binding references an unregistered Coordinator authority")?;
    let (coordinator_json, coordinator_digest) = coordinator_row;
    let coordinator: rex_projects::launch::AgentLaunchAuthority =
        serde_json::from_str(&coordinator_json)
            .map_err(|error| format!("parse registered Coordinator authority: {error}"))?;
    let worker_run_id = observation["run_id"].as_str().unwrap_or_default();
    let ticket_revision = input
        .pointer("/payload_json/revision")
        .and_then(Value::as_u64);
    let authority_matches = authority.agent_run_id.as_str() == worker_run_id
        && authority.role == rex_projects::domain::types::Role::Worker
        && authority.parent_role == Some(rex_projects::domain::types::Role::Coordinator)
        && authority.parent_run_id.as_ref().map(|id| id.as_str())
            == Some(binding.coordinator_agent_run_id.as_str())
        && authority.ticket_run_id.as_ref().map(|id| id.as_str()) == Some(ticket_run_id)
        && reservation.role == rex_projects::domain::types::Role::Worker
        && reservation.ticket_run_id.as_ref().map(|id| id.as_str()) == Some(ticket_run_id)
        && coordinator.role == rex_projects::domain::types::Role::Coordinator
        && coordinator.parent_role == Some(rex_projects::domain::types::Role::Supervisor)
        && coordinator.ticket_run_id.as_ref().map(|id| id.as_str()) == Some(ticket_run_id)
        && binding.coordinator_authority_digest.as_str() == coordinator_digest
        && binding.node_id.as_str() == node_id
        && binding.plan_digest.as_str() == plan_digest
        && binding.repository_id.as_str()
            == assignment["repository_id"].as_str().unwrap_or_default()
        && binding.base_sha == assignment["base_sha"].as_str().unwrap_or_default()
        && binding.worktree_path.as_path() == Path::new(worktree_path)
        && Path::new(worktree_path).is_absolute()
        && binding.ticket_revision == ticket_revision.unwrap_or_default()
        && source_message_id == Some(expected_source_message.as_str());
    if !authority_matches {
        return Ok(None);
    }
    Ok(Some(json!({
        "run_id":worker_run_id,
        "parent_run_id":authority.parent_run_id.as_ref().map(|id| id.as_str()),
        "parent_role":authority.parent_role,
        "ticket_run_id":ticket_run_id,
        "source_message_id":source_message_id,
        "plan_ready_source_message_id":binding.source_message_id,
        "plan_ready_source_agent_run_id":binding.source_agent_run_id.as_str(),
        "accepted_plan_digest":plan_digest,
        "accepted_revision":binding.accepted_revision,
        "work_node_id":node_id,
        "repository_id":binding.repository_id.as_str(),
        "worktree_path":worktree_path,
        "base_sha":binding.base_sha,
        "prepare_operation_id":binding.prepare_operation_id,
        "prepare_receipt_digest":binding.prepare_receipt_digest.as_str()
    })))
}

/// Proves the recovery wake reached the next actual production-generated Worker package and
/// immutable snapshot. The native provider is deliberately not required for this connection gate.
fn worker_recovery_inbox_evidence(observation: &Value) -> Result<Option<Value>, String> {
    if observation["role"] != "worker" {
        return Ok(None);
    }
    let Some(inputs) = observation["inbox_inputs"].as_array() else {
        return Ok(None);
    };
    let Some(input) = inputs.iter().find(|input| {
        input["source_type"] == "worker_recovery_authorization"
            && input
                .pointer("/payload_json/authorization/prior_worker_agent_run_id")
                .is_some()
    }) else {
        return Ok(None);
    };
    let package_path = observation
        .pointer("/input_files/package_path")
        .and_then(Value::as_str)
        .ok_or("recovery Worker observation has no package path")?;
    let snapshot_path = observation
        .pointer("/input_files/snapshot_path")
        .and_then(Value::as_str)
        .ok_or("recovery Worker observation has no wake snapshot path")?;
    let package: Value = serde_json::from_slice(
        &fs::read(package_path)
            .map_err(|error| format!("read recovery Worker package: {error}"))?,
    )
    .map_err(|error| format!("parse recovery Worker package: {error}"))?;
    let snapshot_bytes =
        fs::read(snapshot_path).map_err(|error| format!("read recovery wake snapshot: {error}"))?;
    let snapshot = parse_recovery_wake_snapshot(&snapshot_bytes)?;
    let package_bytes = fs::read(package_path)
        .map_err(|error| format!("read recovery Worker package for digest check: {error}"))?;
    let package_digest = format!("{:x}", Sha256::digest(&package_bytes));
    let snapshot_digest = snapshot.digest.as_str().to_owned();
    let authorization = &input["payload_json"]["authorization"];
    let Some(prior_run_id) = authorization["prior_worker_agent_run_id"].as_str() else {
        return Ok(None);
    };
    let snapshot_authorization = snapshot
        .worker_recovery_authorization()
        .map_err(|error| format!("read typed recovery authorization from snapshot: {error}"))?;
    let snapshot_has_authorization = snapshot_authorization
        .map(|authorization| serde_json::to_value(authorization).map_err(|e| e.to_string()))
        .transpose()?
        .is_some_and(|snapshot_authorization| snapshot_authorization == *authorization);
    let prompt = package["prompt"].as_str().unwrap_or_default();
    let assignment = &observation["worker_assignment"];
    let matching_input = snapshot_has_authorization
        && observation
            .pointer("/input_files/package_sha256")
            .and_then(Value::as_str)
            == Some(package_digest.as_str())
        && observation
            .pointer("/input_files/snapshot_digest")
            .and_then(Value::as_str)
            == Some(snapshot_digest.as_str())
        && snapshot.agent_run_id == observation["run_id"]
        && package["descriptor"]["role"] == "worker"
        && package["descriptor"]["ticket_run_id"] == observation["ticket_run_id"]
        && prompt.contains("Prior uncommitted changes may remain")
        && prompt.contains(prior_run_id)
        && authorization["ticket_run_id"] == observation["ticket_run_id"]
        && authorization["ticket_revision"] == input["source_revision"]
        && authorization["work_node_id"] == assignment["node_id"]
        && authorization["accepted_plan_digest"] == assignment["accepted_plan_digest"]
        && authorization["expected_head"]
            .as_str()
            .is_some_and(|head| prompt.contains(head));
    if !matching_input {
        return Ok(None);
    }
    Ok(Some(json!({
        "run_id":observation["run_id"],
        "ticket_run_id":observation["ticket_run_id"],
        "prior_worker_agent_run_id":prior_run_id,
        "work_node_id":assignment["node_id"],
        "accepted_plan_digest":assignment["accepted_plan_digest"],
        "expected_head":authorization["expected_head"],
        "package_path":package_path,
        "snapshot_path":snapshot_path,
        "snapshot_contains_exact_authorization":snapshot_has_authorization
    })))
}

fn parse_recovery_wake_snapshot(
    bytes: &[u8],
) -> Result<rex_projects::agent_api::AgentWakeSnapshot, String> {
    let snapshot: rex_projects::agent_api::AgentWakeSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse recovery wake snapshot: {error}"))?;
    snapshot
        .validate()
        .map_err(|error| format!("validate recovery wake snapshot: {error}"))?;
    Ok(snapshot)
}

/// Inspect the actual package and public inbox of a second Worker after a committed review correction.
fn review_rework_worker_connection_evidence(
    observation: &Value,
    state_root: &Path,
) -> Result<Option<Value>, String> {
    if observation["role"] != "worker" {
        return Ok(None);
    }
    let assignment = &observation["worker_assignment"];
    let (Some(run_id), Some(ticket_run_id), Some(expected_head), Some(base_sha)) = (
        observation["run_id"].as_str(),
        observation["ticket_run_id"].as_str(),
        assignment["expected_head"].as_str(),
        assignment["base_sha"].as_str(),
    ) else {
        return Ok(None);
    };
    if expected_head == base_sha {
        return Ok(None);
    }
    let db = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open rework proof state: {error}"))?;
    let row: Option<(String, String, String)> = db.query_row(
        "SELECT a.authority_json,r.reservation_json,t.evidence_json FROM agent_launch_authority a JOIN agent_launch_reservations r USING(agent_run_id) JOIN transitions t ON t.entity_type='ticket_run' AND t.entity_id=a.ticket_run_id AND t.project_id=a.project_id AND t.new_revision=a.ticket_revision WHERE a.agent_run_id=?1 AND a.role='worker'",
        [run_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(|error| format!("read correction Worker authority: {error}"))?;
    let Some((authority_json, reservation_json, transition_json)) = row else {
        return Ok(None);
    };
    let authority: rex_projects::launch::AgentLaunchAuthority =
        serde_json::from_str(&authority_json).map_err(|error| error.to_string())?;
    let reservation: rex_projects::launch::AgentLaunchReservation =
        serde_json::from_str(&reservation_json).map_err(|error| error.to_string())?;
    let transition: Value =
        serde_json::from_str(&transition_json).map_err(|error| error.to_string())?;
    if transition["kind"] != "review_assessment" || transition["transition"] != "corrections_remain"
    {
        return Err("rework Worker is not bound to a committed review correction".into());
    }
    let binding = reservation
        .worker_assignment
        .as_ref()
        .ok_or("rework Worker has no assignment binding")?;
    let package_path = observation
        .pointer("/input_files/package_path")
        .and_then(Value::as_str)
        .ok_or("rework Worker has no generated package path")?;
    let package_bytes = fs::read(package_path)
        .map_err(|error| format!("read generated correction Worker package: {error}"))?;
    let package: rex_projects::run_step_package::RunStepPackage =
        serde_json::from_slice(&package_bytes).map_err(|error| error.to_string())?;
    package.validate()?;
    let mut publications = db.prepare("SELECT receipt_json FROM effects WHERE subject_type='ticket_run' AND subject_id=?1 AND project_id=?2 AND kind='publish_implementation' AND status='succeeded'").map_err(|error| error.to_string())?;
    let publication_rows = publications
        .query_map(
            params![ticket_run_id, authority.project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| error.to_string())?;
    let mut matching = 0;
    for row in publication_rows {
        let publication: rex_projects::delivery_runtime::ImplementationPublicationReceipt =
            serde_json::from_str(&row.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if publication.work_node_id == binding.node_id
            && publication.repository_id == binding.repository_id
            && publication.commit.head() == expected_head
        {
            matching += 1;
        }
    }
    let snapshot_path = observation
        .pointer("/input_files/snapshot_path")
        .and_then(Value::as_str)
        .ok_or("rework Worker has no generated inbox path")?;
    let snapshot_bytes = fs::read(snapshot_path)
        .map_err(|error| format!("read generated correction Worker inbox: {error}"))?;
    let snapshot: rex_projects::agent_api::AgentWakeSnapshot =
        serde_json::from_slice(&snapshot_bytes).map_err(|error| error.to_string())?;
    snapshot.validate()?;
    let actual_head = git_output(&binding.worktree_path, &["rev-parse", "HEAD"])?;
    if authority.project_id.as_str() != observation["project_id"].as_str().unwrap_or_default()
        || authority.ticket_run_id.as_ref().map(|id| id.as_str()) != Some(ticket_run_id)
        || authority.ticket_revision.map(|revision| revision.0) != Some(binding.ticket_revision)
        || package.project_id != authority.project_id
        || package.descriptor.project_id != authority.project_id
        || package
            .descriptor
            .ticket_run_id
            .as_ref()
            .map(|id| id.as_str())
            != Some(ticket_run_id)
        || matching != 1
        || binding.expected_head() != expected_head
        || binding.base_sha != base_sha
        || authority.descriptor_path != Path::new(package_path)
        || authority.descriptor_digest.as_str() != format!("{:x}", Sha256::digest(&package_bytes))
        || observation
            .pointer("/input_files/package_sha256")
            .and_then(Value::as_str)
            != Some(authority.descriptor_digest.as_str())
        || package.descriptor.worker_assignment.as_ref() != Some(binding)
        || package.descriptor.run_id.as_str() != run_id
        || package.descriptor.expected_subject_revision != binding.ticket_revision
        || snapshot.agent_run_id.as_str() != run_id
        || snapshot.digest != authority.wake_snapshot_digest
        || package.descriptor.wake_snapshot_digest != snapshot.digest
        || snapshot.project_id != authority.project_id
        || snapshot.role_session_id != authority.role_session_id
        || observation
            .pointer("/input_files/snapshot_digest")
            .and_then(Value::as_str)
            != Some(snapshot.digest.as_str())
        || serde_json::to_value(&snapshot.inputs).map_err(|error| error.to_string())?
            != observation["inbox_inputs"]
        || actual_head.trim() != expected_head
    {
        return Err("correction Worker package, public inbox, original base, and published head do not match".into());
    }
    Ok(Some(
        json!({"run_id":run_id,"ticket_run_id":ticket_run_id,"ticket_revision":binding.ticket_revision,"work_node_id":binding.node_id,"accepted_plan_digest":binding.plan_digest,"base_sha":base_sha,"expected_head":expected_head,"actual_head":actual_head.trim(),"package_path":package_path,"package_digest":authority.descriptor_digest,"snapshot_path":snapshot_path,"source":"public_agent_inbox_and_host_generated_package"}),
    ))
}

fn verification_reviewer_connection_evidence(
    observation: &Value,
    state_root: &Path,
) -> Result<Option<Value>, String> {
    if observation["role"] != "reviewer" {
        return Ok(None);
    }
    let Some(run_id) = observation["run_id"].as_str() else {
        return Ok(None);
    };
    let db = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open check-only Reviewer proof state: {error}"))?;
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT a.authority_json,t.evidence_json FROM agent_launch_authority a
         JOIN transitions t ON t.entity_type='ticket_run' AND t.project_id=a.project_id
         AND t.entity_id=a.ticket_run_id AND t.new_revision=a.ticket_revision
         WHERE a.agent_run_id=?1 AND a.role='reviewer'
         AND json_extract(t.evidence_json,'$.kind')='worker_verification_completed'",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read check-only Reviewer authority: {error}"))?;
    let Some((authority_json, transition_json)) = row else {
        return Ok(None);
    };
    let authority: rex_projects::launch::AgentLaunchAuthority =
        serde_json::from_str(&authority_json).map_err(|error| error.to_string())?;
    let transition: Value =
        serde_json::from_str(&transition_json).map_err(|error| error.to_string())?;
    let verification: rex_projects::store::accepted_plans::AcceptedWorkerVerification =
        serde_json::from_value(transition["verification"].clone())
            .map_err(|error| format!("parse accepted Worker verification: {error}"))?;
    if authority.ticket_revision.map(|value| value.0) != Some(verification.review_revision)
        || verification.source_revision.checked_add(1) != Some(verification.review_revision)
        || verification.publication_revision.checked_add(2) != Some(verification.review_revision)
        || transition["evidence_id"] != verification.source_evidence_id
        || transition["result_digest"] != verification.source_result_digest.as_str()
    {
        return Err(
            "check-only Reviewer authority differs from the accepted verification transition"
                .into(),
        );
    }
    let result_json: String = db.query_row(
        "SELECT result_json FROM agent_result_evidence WHERE evidence_id=?1 AND agent_run_id=?2 AND project_id=?3 AND role='worker' AND outcome='completed'",
        params![verification.source_evidence_id,verification.source_agent_run_id.as_str(),authority.project_id.as_str()],
        |row| row.get(0),
    ).map_err(|error| format!("read check-only Worker terminal evidence: {error}"))?;
    let result: Value = serde_json::from_str(&result_json).map_err(|error| error.to_string())?;
    if result["kind"] != "verification_ready"
        || result["result_digest"] != verification.source_result_digest.as_str()
        || result["structured_result"]["publication_operation_id"]
            != verification.publication_operation_id.as_str()
        || result["structured_result"]["published_head"] != verification.published_head.as_str()
    {
        return Err(
            "check-only Worker result differs from its host-accepted publication binding".into(),
        );
    }
    let publication_json: String = db.query_row(
        "SELECT receipt_json FROM effects WHERE operation_id=?1 AND kind='publish_implementation' AND status='succeeded' AND project_id=?2 AND subject_id=?3",
        params![verification.publication_operation_id.as_str(),authority.project_id.as_str(),authority.ticket_run_id.as_ref().ok_or("Reviewer has no TicketRun")?.as_str()],
        |row| row.get(0),
    ).map_err(|error| format!("read preserved implementation publication: {error}"))?;
    let publication: rex_projects::delivery_runtime::ImplementationPublicationReceipt =
        serde_json::from_str(&publication_json).map_err(|error| error.to_string())?;
    if publication.commit.head() != verification.published_head.as_str() {
        return Err("check-only verification changed the accepted publication head".into());
    }
    let package_bytes = fs::read(&authority.descriptor_path)
        .map_err(|error| format!("read check-only Reviewer package: {error}"))?;
    let package: rex_projects::run_step_package::RunStepPackage =
        serde_json::from_slice(&package_bytes).map_err(|error| error.to_string())?;
    package.validate()?;
    if format!("{:x}", Sha256::digest(&package_bytes)) != authority.descriptor_digest.as_str()
        || package.descriptor.run_id != authority.agent_run_id
    {
        return Err("check-only Reviewer package differs from its launch authority".into());
    }
    let binding_json = package
        .prompt
        .split_once("Host-validated implementation publication subject ")
        .and_then(|(_, tail)| tail.split_once("```json\n"))
        .and_then(|(_, tail)| tail.split_once("\n```"))
        .map(|(binding, _)| binding)
        .ok_or("check-only Reviewer prompt has no publication subject JSON")?;
    let binding: Value = serde_json::from_str(binding_json).map_err(|error| error.to_string())?;
    let subject = rex_projects::delivery_runtime::ImplementationPublicationSetSubject {
        ticket_run_id: authority
            .ticket_run_id
            .clone()
            .ok_or("Reviewer has no TicketRun")?,
        accepted_plan_digest: serde_json::from_value(binding["accepted_plan_digest"].clone())
            .map_err(|error| error.to_string())?,
        publications: serde_json::from_value(binding["publications"].clone())
            .map_err(|error| error.to_string())?,
        coverage: serde_json::from_value(binding["evidence_coverage"].clone())
            .map_err(|error| error.to_string())?,
        publication_revision: binding["publication_revision"]
            .as_u64()
            .ok_or("Reviewer subject has no publication revision")?,
        verification: Some(
            serde_json::from_value(binding["verification"].clone()).map_err(|error| {
                format!("Reviewer prompt has invalid verification provenance: {error}")
            })?,
        ),
    };
    let expected_verification = serde_json::json!({
        "review_revision":verification.review_revision,
        "source_evidence_id":verification.source_evidence_id,
        "source_agent_run_id":verification.source_agent_run_id,
        "source_result_digest":verification.source_result_digest,
        "publication_revision":verification.publication_revision,
        "publication_operation_id":verification.publication_operation_id,
        "published_head":verification.published_head,
        "work_node_id":verification.work_node_id,
        "repository_id":verification.repository_id,
        "test_receipt_artifacts":verification.test_receipt_artifacts
    });
    let (plan_digest, plan_json): (String, String) = db.query_row(
        "SELECT plan_digest,plan_json FROM accepted_work_plans WHERE project_id=?1 AND ticket_run_id=?2 AND configuration_digest=?3 ORDER BY accepted_revision DESC LIMIT 1",
        params![authority.project_id.as_str(),publication.ticket_run_id.as_str(),authority.config_digest.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|error| format!("read exact accepted Reviewer plan: {error}"))?;
    let stored_plan: Value = serde_json::from_str(&plan_json).map_err(|error| error.to_string())?;
    let work_plan: rex_projects::engine::orchestration::WorkPlan =
        serde_json::from_value(stored_plan["proposal"].clone())
            .map_err(|error| error.to_string())?;
    let expected_coverage = work_plan
        .nodes
        .iter()
        .filter(|node| !node.investigation)
        .map(|node| node.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let expected_subject = rex_projects::delivery_runtime::ImplementationPublicationSetSubject {
        ticket_run_id: publication.ticket_run_id.clone(),
        accepted_plan_digest: serde_json::from_value(json!(plan_digest))
            .map_err(|error| error.to_string())?,
        publications: vec![
            rex_projects::delivery_runtime::ImplementationPublicationSubjectFact {
                work_node_id: publication.work_node_id.clone(),
                repository_id: publication.repository_id.clone(),
                pull_request_number: publication.pull_request.number,
                pull_request_node_id: publication.pull_request.node_id.clone(),
                pull_request_head: publication.pull_request.source_head.clone(),
                published_head: publication.push.pushed_head.clone(),
                receipt_digest: format!("{:x}", Sha256::digest(publication_json.as_bytes())),
            },
        ],
        coverage: expected_coverage,
        publication_revision: verification.publication_revision,
        verification: Some(
            serde_json::from_value(expected_verification.clone())
                .map_err(|error| error.to_string())?,
        ),
    };
    if subject != expected_subject {
        return Err("generated Reviewer subject differs from the exact accepted plan and persisted publication".into());
    }
    if binding["verification"] != expected_verification
        || binding["subject_digest"] != subject.digest()?.as_str()
        || verification.test_receipt_artifacts.is_empty()
    {
        return Err(
            "generated Reviewer subject omits or alters the exact accepted verification provenance"
                .into(),
        );
    }
    let deliveries: (u64,u64) = db.query_row(
        "SELECT SUM(kind='commit_worker_manifest'),SUM(kind='publish_implementation') FROM effects WHERE project_id=?1 AND subject_id=?2 AND status='succeeded'",
        params![authority.project_id.as_str(),authority.ticket_run_id.as_ref().ok_or("Reviewer has no TicketRun")?.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|error| format!("count delivery side effects: {error}"))?;
    if deliveries != (1, 1) {
        return Err("check-only completion created another commit or publication".into());
    }
    let workspace = observation["workspace_path"]
        .as_str()
        .ok_or("check-only Reviewer observation has no workspace")?;
    for reference in &verification.test_receipt_artifacts {
        let staged = observation["inbox_inputs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|input| input["host_artifacts"].as_array().into_iter().flatten())
            .find(|artifact| {
                artifact["artifact_id"] == reference.artifact_id.as_str()
                    && artifact["source_run_id"] == verification.source_agent_run_id.as_str()
                    && artifact["source_evidence_id"] == verification.source_evidence_id
            })
            .ok_or("Reviewer did not receive the exact check-only Worker's registered receipt")?;
        let locator: rex_projects::agent_api::HostArtifactLocator =
            serde_json::from_value(staged.clone()).map_err(|error| error.to_string())?;
        locator.validate()?;
        let bytes = fs::read(Path::new(workspace).join(&locator.path))
            .map_err(|error| format!("read staged check-only Worker receipt: {error}"))?;
        if locator.kind != reference.kind
            || locator.digest != reference.digest
            || locator.bytes != reference.bytes
            || locator.schema_version != reference.schema_version
            || bytes.len() as u64 != reference.bytes
            || format!("{:x}", Sha256::digest(&bytes)) != reference.digest.as_str()
            || bytes != b"Emulated check-only Worker evidence for the unchanged published head.\n"
        {
            return Err(
                "staged check-only evidence differs from its exact registered source".into(),
            );
        }
    }
    Ok(Some(json!({
        "status":"passed","provider":"EMULATED","reviewer_run_id":run_id,
        "verification_worker_run_id":verification.source_agent_run_id,
        "verification_evidence_id":verification.source_evidence_id,
        "review_revision":verification.review_revision,
        "publication_revision":verification.publication_revision,
        "publication_operation_id":verification.publication_operation_id,
        "published_head":verification.published_head,
        "commit_count":deliveries.0,"publication_count":deliveries.1,
        "test_receipt_artifacts":verification.test_receipt_artifacts
    })))
}

fn accepted_reviewer_result(
    db: &Connection,
    ticket_run_id: &str,
    reviewer_run_id: &str,
    expected_phase: &str,
) -> Result<Option<Value>, String> {
    let row: Option<(String, u64)> = db
        .query_row(
            "SELECT e.result_json,k.reducer_revision FROM ticket_runs t
             JOIN agent_runs a ON a.agent_run_id=?2 AND a.project_id=t.project_id AND a.role='reviewer' AND a.state='completed'
             JOIN agent_result_evidence e ON e.agent_run_id=a.agent_run_id AND e.project_id=t.project_id AND e.ticket_run_id=t.ticket_run_id AND e.role='reviewer' AND e.outcome='completed'
             JOIN agent_result_reducer_ack k ON k.evidence_id=e.evidence_id AND k.disposition='applied' AND k.reducer_revision=t.revision
             WHERE t.ticket_run_id=?1 AND t.internal_phase=?3 AND json_extract(e.result_json,'$.kind')='review_ready'",
            params![ticket_run_id, reviewer_run_id, expected_phase],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read applied Reviewer result: {error}"))?;
    row.map(|(encoded, revision)| {
        let result: Value = serde_json::from_str(&encoded)
            .map_err(|error| format!("parse applied Reviewer result: {error}"))?;
        Ok(json!({"result":result,"reducer_revision":revision}))
    })
    .transpose()
}

/// Require an applied Reviewer result and the durable Worker commit/publication chain.
fn host_commit_reviewer_connection_evidence(
    observation: &Value,
    state_root: &Path,
    expected_phase: &str,
) -> Result<Option<Value>, String> {
    if observation["role"] != "reviewer"
        || observation["ticket_run_id"]
            .as_str()
            .is_none_or(str::is_empty)
        || observation["run_id"].as_str().is_none_or(str::is_empty)
        || observation["inbox_inputs"]
            .as_array()
            .is_none_or(Vec::is_empty)
    {
        return Ok(None);
    }
    let ticket_run_id = observation["ticket_run_id"].as_str().unwrap_or_default();
    let reviewer_run_id = observation["run_id"].as_str().unwrap_or_default();
    let db = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open acceptance database read-only for Reviewer handoff: {error}"))?;
    let Some(reviewer_result) =
        accepted_reviewer_result(&db, ticket_run_id, reviewer_run_id, expected_phase)?
    else {
        return Ok(None);
    };
    let mut statement = db
        .prepare("SELECT operation_id,kind,request_json,receipt_json FROM effects WHERE project_id=?1 AND subject_type='ticket_run' AND subject_id=?2 AND status='succeeded' AND kind IN ('commit_worker_manifest','publish_implementation') ORDER BY created_at_unix,operation_id")
        .map_err(|error| format!("prepare host publication evidence query: {error}"))?;
    let rows = statement
        .query_map(
            params![
                observation["project_id"]
                    .as_str()
                    .unwrap_or("operations_project"),
                ticket_run_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|error| format!("query host publication evidence: {error}"))?;
    let mut commit_receipts = std::collections::BTreeMap::new();
    let mut publications = Vec::new();
    for row in rows {
        let (operation_id, kind, request_json, receipt_json) =
            row.map_err(|error| format!("read host publication evidence: {error}"))?;
        if kind == "commit_worker_manifest" {
            let receipt: rex_projects::delivery_runtime::CommitWorkerManifestEffectReceipt =
                serde_json::from_str(&receipt_json)
                    .map_err(|error| format!("parse host commit receipt: {error}"))?;
            commit_receipts.insert(operation_id, receipt);
        } else {
            let payload: rex_projects::delivery_runtime::PublishImplementationEffectPayload =
                serde_json::from_str(&request_json).map_err(|error| {
                    format!("parse implementation publication request: {error}")
                })?;
            let receipt: rex_projects::delivery_runtime::ImplementationPublicationReceipt =
                serde_json::from_str(&receipt_json).map_err(|error| {
                    format!("parse implementation publication receipt: {error}")
                })?;
            publications.push((payload, receipt));
        }
    }
    let Some((publish_request, publication)) = publications.into_iter().find(|(request, _)| {
        request.ticket_run_id.as_str() == ticket_run_id
            && request.commit_mode == rex_projects::domain::types::CommitMode::Host
            && request.work_node_id.as_str() == "acceptance-node"
    }) else {
        return Ok(None);
    };
    let rex_projects::delivery_runtime::WorkerDeliveryCommit::HostReceipt {
        operation_id,
        expected_head,
        worker_reported_head,
        receipt: result_commit_receipt,
    } = &publish_request.commit
    else {
        return Err(
            "accepted host publication request does not carry a Worker commit receipt".into(),
        );
    };
    let Some(durable_commit_receipt) = commit_receipts.get(operation_id.as_str()) else {
        return Err("implementation publication has no succeeded repository.commit receipt".into());
    };
    let result_row: Option<(String, String)> = db
        .query_row(
            "SELECT evidence_id,result_json FROM agent_result_evidence WHERE agent_run_id=?1 AND role='worker' AND outcome='completed' ORDER BY received_at_unix DESC LIMIT 1",
            [durable_commit_receipt.agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("read accepted Worker result evidence: {error}"))?;
    let Some((worker_evidence_id, result_json)) = result_row else {
        return Ok(None);
    };
    let worker_result: Value = serde_json::from_str(&result_json)
        .map_err(|error| format!("parse accepted Worker result evidence: {error}"))?;
    let change = &worker_result["structured_result"]["change_references"][0];
    let reservation_json: String = db
        .query_row(
            "SELECT reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
            [durable_commit_receipt.agent_run_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| format!("read immutable Worker assignment: {error}"))?;
    let reservation: rex_projects::launch::AgentLaunchReservation =
        serde_json::from_str(&reservation_json)
            .map_err(|error| format!("parse immutable Worker assignment: {error}"))?;
    reservation.validate()?;
    let assignment = reservation
        .worker_assignment
        .as_ref()
        .ok_or("published Worker reservation has no prepared assignment")?;
    let expected_worktree_id = assignment
        .worktree_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("prepared Worker worktree has no directory ID")?;
    let workspace = observation["workspace_path"]
        .as_str()
        .map(PathBuf::from)
        .ok_or("Reviewer inbox observation has no workspace path")?;
    let staged_checks = observation["inbox_inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|item| item["host_artifacts"].as_array().into_iter().flatten())
        .find(|artifact| {
            artifact["kind"] == "test_receipt"
                && artifact["source_run_id"].as_str()
                    == Some(durable_commit_receipt.agent_run_id.as_str())
                && artifact["source_evidence_id"].as_str() == Some(worker_evidence_id.as_str())
        })
        .ok_or("Reviewer public inbox is missing the published Worker's check artifact")?;
    let staged: rex_projects::agent_api::HostArtifactLocator =
        serde_json::from_value(staged_checks.clone())
            .map_err(|error| format!("parse Reviewer check artifact locator: {error}"))?;
    staged.validate()?;
    let registered = worker_result["artifact_refs"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|reference| reference["artifact_id"].as_str() == Some(staged.artifact_id.as_str()))
        .ok_or("Reviewer check artifact is absent from the exact accepted Worker result")?;
    let staged_bytes = fs::read(workspace.join(&staged.path))
        .map_err(|error| format!("read Reviewer staged Worker check artifact: {error}"))?;
    if registered["kind"] != "test_receipt"
        || registered["digest"].as_str() != Some(staged.digest.as_str())
        || registered["bytes"].as_u64() != Some(staged.bytes)
        || registered["schema_version"].as_u64() != Some(u64::from(staged.schema_version))
        || staged_bytes.len() as u64 != staged.bytes
        || format!("{:x}", Sha256::digest(&staged_bytes)) != staged.digest.as_str()
        || String::from_utf8_lossy(&staged_bytes)
            != "Emulated Worker check evidence for the exact published source revision.\n"
    {
        return Err("Reviewer staged check bytes or Worker evidence provenance differ from the accepted source".into());
    }
    if publish_request.pull_request.title != "test: record acceptance fixture change"
        || publication.pull_request.title != publish_request.pull_request.title
        || !publish_request
            .pull_request
            .body
            .contains(ACCEPTANCE_WORK_TASK)
        || worker_result["kind"] != "implementation_ready"
        || worker_result["structured_result"]["change_references"]
            .as_array()
            .map(Vec::len)
            != Some(1)
        || reservation.agent_run_id != durable_commit_receipt.agent_run_id
        || reservation.project_id.as_str()
            != observation["project_id"]
                .as_str()
                .unwrap_or("operations_project")
        || reservation.role != rex_projects::domain::types::Role::Worker
        || reservation
            .ticket_run_id
            .as_ref()
            .is_none_or(|run| run.as_str() != ticket_run_id)
        || reservation.config_digest != publish_request.configuration_digest
        || assignment.configuration_digest != publish_request.configuration_digest
        || assignment.node_id != publish_request.work_node_id
        || assignment.repository_id != publish_request.repository_id
        || change["worktree_id"].as_str() != Some(expected_worktree_id)
        || change["host_commit_operation_id"].as_str() != Some(operation_id.as_str())
        || change["base_commit"].as_str() != Some(durable_commit_receipt.base_sha.as_str())
        || change["previous_head"].as_str() != Some(expected_head.as_str())
        || change["branch_head"].as_str() != Some(worker_reported_head.as_str())
        || change["commit_shas"].as_array().map(Vec::len) != Some(1)
        || change["commit_shas"][0].as_str() != Some(worker_reported_head.as_str())
        || *durable_commit_receipt != **result_commit_receipt
        || publication.commit.head() != worker_reported_head
    {
        return Err(
            "Worker result, durable host commit, and accepted publication receipts do not match"
                .into(),
        );
    }
    Ok(Some(json!({
        "status":"passed",
        "ticket_run_id":ticket_run_id,
        "phase":expected_phase,
        "reviewer_run_id":reviewer_run_id,
        "reviewer_state":"completed",
        "reviewer_result":reviewer_result,
        "reviewer_inbox_observation":observation,
        "worker_run_id":durable_commit_receipt.agent_run_id.as_str(),
        "worker_result":worker_result,
        "repository_commit_operation_id":operation_id.as_str(),
        "repository_commit_receipt":durable_commit_receipt,
        "publication_effect_operation_id":publication.effect_operation_id,
        "publication_receipt":publication,
        "reviewer_input_count":observation["inbox_inputs"].as_array().map(Vec::len),
        "reviewer_staged_worker_check":staged_checks
    })))
}

fn read_public_inbox_observations(fixture_root: &Path) -> Result<Vec<Value>, String> {
    let directory = fixture_root.join("agent-state").join("inbox-observations");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("read public Agent inbox observations: {error}")),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 16 * 1024 {
            paths.push(path);
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                .map_err(|error| format!("parse public Agent inbox observation: {error}"))
        })
        .collect()
}

fn read_probe_diagnostic(fixture_root: &Path, project: &str, role: &str) -> Option<Value> {
    let directory = fixture_root.join("agent-state").join("probe-diagnostics");
    for entry in fs::read_dir(directory).ok()? {
        let path = entry.ok()?.path();
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8 * 1024 {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        if value["schema_version"] == 1 && value["project_id"] == project && value["role"] == role {
            return Some(value);
        }
    }
    None
}

fn fixture_git_environment(
    root: &Path,
    snapshot: &BTreeMap<OsString, OsString>,
) -> Result<BTreeMap<OsString, OsString>, String> {
    let mut environment = snapshot
        .iter()
        .filter(|(key, _)| key.to_string_lossy().starts_with("GIT_CONFIG_"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let count = environment
        .get(std::ffi::OsStr::new("GIT_CONFIG_COUNT"))
        .map(|value| {
            value
                .to_str()
                .ok_or("Git config count is not UTF-8")?
                .parse::<usize>()
                .map_err(|_| "Git config count is not an unsigned integer")
        })
        .transpose()?
        .unwrap_or(0);
    let next = count.checked_add(1).ok_or("Git config count overflow")?;
    environment.insert("GIT_CONFIG_COUNT".into(), next.to_string().into());
    environment.insert(
        format!("GIT_CONFIG_KEY_{count}").into(),
        format!(
            "url.file://{}.insteadOf",
            root.join("git/fixture/repository.git").display()
        )
        .into(),
    );
    environment.insert(
        format!("GIT_CONFIG_VALUE_{count}").into(),
        "https://github.com/fixture/repository.git".into(),
    );
    Ok(environment)
}

fn prepare_local_repository(request: &Request<'_>, executable: &Path) -> Result<(), String> {
    let bare = request.fixture_root.join("git/fixture/repository.git");
    fs::create_dir_all(
        bare.parent()
            .ok_or("fixture bare repository has no parent directory")?,
    )
    .map_err(|error| error.to_string())?;
    fs::create_dir_all(request.fixture_root.join("bin")).map_err(|error| error.to_string())?;
    fs::copy(executable, request.fixture_root.join("bin/gh"))
        .map_err(|error| format!("copy owned fake gh transport: {error}"))?;
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask is not directly under the repository root")?
        .to_path_buf();
    git(
        request.fixture_root,
        &[
            "clone",
            "--bare",
            source
                .to_str()
                .ok_or("source repository path is not UTF-8")?,
            bare.to_str()
                .ok_or("fixture bare repository path is not UTF-8")?,
        ],
    )?;
    let bare_text = bare
        .to_str()
        .ok_or("fixture bare repository path is not UTF-8")?;
    git(
        request.fixture_root,
        &[
            "--git-dir",
            bare_text,
            "update-ref",
            "refs/heads/main",
            "HEAD",
        ],
    )?;
    git(
        request.fixture_root,
        &[
            "--git-dir",
            bare_text,
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    )?;
    let head = git_output(
        request.fixture_root,
        &["--git-dir", bare_text, "rev-parse", "HEAD"],
    )?;
    fs::write(
        request.fixture_root.join("repository-head.txt"),
        head.trim(),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct ProfilePreparation<'a> {
    hold_coordinator_after_inbox: bool,
    hold_worker_after_inbox: bool,
    hold_reviewer_after_inbox: bool,
    host_worker: bool,
    worker_recovery_stage: bool,
    worker_review_rework_stage: bool,
    worker_verification_stage: bool,
    request_merge_stage: bool,
    native_worker_codex: Option<&'a Path>,
}

fn prepare_profiles(
    request: &Request<'_>,
    executable: &Path,
    runtime_binary: &Path,
    preparation: ProfilePreparation<'_>,
) -> Result<(), String> {
    let profiles = request.fixture_root.join("profiles");
    let contexts = request.fixture_root.join("contexts");
    fs::create_dir_all(&profiles).map_err(|error| error.to_string())?;
    fs::create_dir_all(&contexts).map_err(|error| error.to_string())?;
    let roles = [
        "supervisor",
        "coordinator",
        "planner",
        "worker",
        "reviewer",
        "merge_decision",
        "operator",
        "postmortem",
    ];
    for role in roles {
        let profile = profiles.join(format!("fixture_{role}"));
        fs::create_dir_all(&profile).map_err(|error| error.to_string())?;
        let scenario = format!("acceptance_{role}");
        let context = contexts.join(format!("{role}.json"));
        let messages = if preparation.worker_recovery_stage {
            profile_messages_with_worker_recovery(role, preparation.host_worker)?
        } else if preparation.worker_verification_stage {
            profile_messages_with_worker_verification(role)?
        } else if preparation.worker_review_rework_stage {
            profile_messages_with_review_rework(role)?
        } else {
            profile_messages_for_native_worker(
                role,
                preparation.host_worker,
                preparation.native_worker_codex.is_some(),
            )?
        };
        let messages = if preparation.request_merge_stage && role == "merge_decision" {
            request_merge_messages(messages)
        } else {
            messages
        };
        let hold = (preparation.hold_coordinator_after_inbox && role == "coordinator")
            || (preparation.hold_worker_after_inbox && role == "worker")
            || (preparation.hold_reviewer_after_inbox && role == "reviewer");
        fs::write(
            &context,
            serde_json::to_vec(
                &json!({"schema_version":1,"scenario":scenario,"hold_after_inbox":hold,"messages":messages}),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let native_codex = (role == "worker")
            .then_some(preparation.native_worker_codex)
            .flatten();
        let command = if let Some(codex) = native_codex {
            format!("[{:?}]", codex.display().to_string())
        } else {
            format!(
                "[{:?}, \"fixture\", \"agent\", \"--provider\", \"codex\", \"--role\", {:?}, \"--scenario\", {:?}, \"--context\", {:?}, \"--state-dir\", {:?}, \"--runtime-binary\", {:?}, \"--\"]",
                executable.display().to_string(),
                role,
                scenario,
                context.display().to_string(),
                request
                    .fixture_root
                    .join("agent-state")
                    .display()
                    .to_string(),
                runtime_binary.display().to_string()
            )
        };
        let commit_mode = if role == "worker" && preparation.host_worker {
            "host"
        } else {
            "native"
        };
        let model = if native_codex.is_some() {
            String::new()
        } else {
            "model = \"fixture-emulator\"\n".to_owned()
        };
        let config = format!(
            "adapter = \"codex\"\ncommand = {command}\n{model}commit_mode = {commit_mode:?}\n\n[options]\nsandbox = \"workspace_write\"\napproval = \"never\"\n"
        );
        fs::write(profile.join("config.toml"), config).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn profile_messages_with_review_rework(role: &str) -> Result<Vec<Value>, String> {
    let mut messages = profile_messages(role, true)?;
    match role {
        "reviewer" => {
            for message in messages.iter_mut().filter(|item| item["lane"] == "workflow") {
                message["structured_result"]["disposition"] = json!("changes_requested");
                message["structured_result"]["unknowns"] = json!(["Repeat the bounded check against the unchanged published head."]);
            }
        }
        "worker" => messages.push(message("worker", "progress", json!({
            "summary":"The correction Worker read its host-generated assignment through the public inbox CLI.",
            "completed_node_keys":[],"pending_node_keys":["acceptance-node"],
            "evidence":[],"next_observation_at":null
        })).with_lane("workflow")),
        "coordinator" => {
            let fourth = messages.iter().enumerate().filter(|(_, item)| item["lane"] == "workflow").nth(3).map(|(index, _)| index)
                .ok_or("Coordinator fixture has no post-review message")?;
            messages[fourth] = message("coordinator", "progress", json!({
                "summary":"The host retains the same accepted node while review corrections are checked.",
                "completed_node_keys":[],"pending_node_keys":["acceptance-node"],
                "evidence":[],"next_observation_at":null
            })).with_lane("workflow");
            messages.truncate(fourth + 1);
        }
        _ => {}
    }
    Ok(messages)
}

pub(crate) fn profile_messages_with_worker_verification(role: &str) -> Result<Vec<Value>, String> {
    let mut messages = profile_messages_with_review_rework(role)?;
    match role {
        "worker" => {
            let last = messages
                .last_mut()
                .ok_or("Worker fixture has no correction turn")?;
            *last = message("worker", "verification_ready", json!({
                "work_node_id":{"$fixture_ref":"worker_node_id"},
                "repository":{"$fixture_ref":"worker.repository_id"},
                "publication_operation_id":{"$fixture_ref":"prompt.publication_operation_id"},
                "published_head":{"$fixture_ref":"prompt.published_head"},
                "test_receipt_artifact_ids":[{"$fixture_ref":"artifact.test_receipt.artifact_id"}]
            })).with_lane("workflow").with_actions(vec![
                json!({"action":"write_file","path":"verification-checks.txt","contents":"Emulated check-only Worker evidence for the unchanged published head.\n"}),
                json!({"action":"register_artifact","action_id":"test_receipt","path":"verification-checks.txt","kind":"test_receipt","schema_version":1,"message_id":"verification-checks","remove_after_registration":true})
            ]).with_artifact_ref(json!({"$fixture_ref":"artifact.test_receipt"}));
        }
        "reviewer" => {
            messages.extend(
                profile_messages("reviewer", true)?
                    .into_iter()
                    .filter(|message| message["lane"] == "workflow"),
            );
        }
        "coordinator" => {
            let reviewer = messages
                .iter()
                .find(|message| {
                    message["lane"] == "workflow"
                        && message["kind"] == "spawn_request"
                        && message["structured_result"]["role"] == "reviewer"
                })
                .cloned()
                .ok_or("Coordinator fixture has no Reviewer spawn request")?;
            let correction_result = messages
                .iter()
                .enumerate()
                .filter(|(_, message)| message["lane"] == "workflow")
                .nth(3)
                .map(|(index, _)| index)
                .ok_or("Coordinator fixture has no correction-result response")?;
            messages[correction_result] = reviewer;
            messages.push(
                message(
                    "coordinator",
                    "progress",
                    json!({
                        "summary":"The bounded check-only Reviewer connection is complete.",
                        "completed_node_keys":[],"pending_node_keys":["acceptance-node"],
                        "evidence":[],"next_observation_at":null
                    }),
                )
                .with_lane("workflow"),
            );
        }
        _ => {}
    }
    Ok(messages)
}

fn profile_messages_with_worker_recovery(
    role: &str,
    host_worker: bool,
) -> Result<Vec<Value>, String> {
    let mut messages = profile_messages(role, host_worker)?;
    match role {
        "coordinator" => {
            let workflow_indices = messages
                .iter()
                .enumerate()
                .filter(|(_, message)| message["lane"] == "workflow")
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if workflow_indices.len() < 3 {
                return Err("Coordinator fixture has fewer than three workflow actions".into());
            }
            let indices = &workflow_indices;
            messages[indices[2]] = message(
                "coordinator",
                "spawn_request",
                json!({
                    "work_node":"acceptance-node","role":"worker","profile_id":"fixture_worker",
                    "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                    "worker_recovery":{"$fixture_ref":"prompt.recovery_candidate"},
                    "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
                }),
            )
            .with_lane("workflow");
            messages.truncate(indices[2] + 1);
        }
        "worker" => {
            let position = messages
                .iter()
                .position(|message| message["lane"] == "workflow")
                .ok_or("Worker fixture has no workflow message")?;
            let retry = messages[position].clone();
            messages[position] = json!({
                "role":"worker","lane":"workflow","kind":"progress",
                "assertion":{"assertion":"blocked","reason":"fixture blocker before any commit"},
                "structured_result":{
                    "summary":"Blocked before making changes; retry this accepted node after the blocker is resolved.",
                    "completed_node_keys":[],"pending_node_keys":["acceptance-node"],
                    "evidence":[],"next_observation_at":null
                }
            });
            messages.push(retry);
        }
        _ => {}
    }
    Ok(messages)
}

pub(crate) fn profile_messages(role: &str, host_worker: bool) -> Result<Vec<Value>, String> {
    profile_messages_for_native_worker(role, host_worker, false)
}

fn profile_messages_for_native_worker(
    role: &str,
    host_worker: bool,
    native_worker_lifecycle: bool,
) -> Result<Vec<Value>, String> {
    let mut messages = vec![json!({
        "role": role,
        "lane": "qualification",
        "kind": "progress",
        "assertion": {"assertion":"succeeded"},
        "structured_result": {
            "summary":"Qualification transport completed its real host-owned probe.",
            "completed_node_keys":[],"pending_node_keys":[],"evidence":[],"next_observation_at":null
        }
    })];
    let workflow = match role {
        "supervisor" => vec![message("supervisor", "dispatch_request", json!({
            "ticket_reference":{"$fixture_ref":"inbox.ticket_id"},
            "expected_ticket_revision":{"$fixture_ref":"inbox.external_revision"},
            "coordinator_profile":{"$fixture_ref":"inbox.coordinator_profile"},"priority":1,
            "rationale":"The actual normalized ticket observation is eligible for this configured Operations Project."
        }))],
        "coordinator" => vec![
            message("coordinator", "spawn_request", json!({
                "work_node":"acceptance-node","role":"planner","profile_id":"fixture_planner",
                "plan_digest":null,
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            })),
            message("coordinator", "plan_ready", json!({"$fixture_ref":"inbox.planner_result"})),
            message("coordinator", "spawn_request", json!({
                "work_node":"acceptance-node","role":"reviewer","profile_id":"fixture_reviewer",
                "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            })),
            message("coordinator", "spawn_request", json!({
                "work_node":"acceptance-node","role":"merge_decision","profile_id":"fixture_merge_decision",
                "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            })),
            message("coordinator", "spawn_request", json!({
                "work_node":"acceptance-node","role":"operator","profile_id":"fixture_operator",
                "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            })),
            message("coordinator", "spawn_request", json!({
                "work_node":"acceptance-node","role":"postmortem","profile_id":"fixture_postmortem",
                "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            }))
        ],
        "planner" => vec![message("planner", "plan_ready", json!({
            "plan":{"nodes":[{"id":"acceptance-node","repository":"fixture","task":if native_worker_lifecycle {NATIVE_WORKER_LIFECYCLE_TASK} else {ACCEPTANCE_WORK_TASK},"depends_on":[],"required_evidence":[if native_worker_lifecycle {"The bounded foreground process remains active until the host closes the Worker Rex block."} else {"The exact committed source change is visible in the prepared worktree."}],"investigation":false}],"requested_investigation_children":0},
            "unresolved_questions":[]
        }))],
        "worker" => {
            let mut change = json!({
                "repository":{"$fixture_ref":"worker.repository_id"},
                "worktree_id":{"$fixture_ref":"worker_node_id"},
                "commit_mode":{"$fixture_ref":"worker.commit_mode"},
                "base_commit":{"$fixture_ref":"worker.base_sha"},
                "previous_head":{"$fixture_ref":"worker.previous_head"},
                "branch_head":{"$fixture_ref":"worker.branch_head"},
                "commit_shas":{"$fixture_ref":"worker.commit_shas"}
            });
            if host_worker {
                change["worktree_id"] = json!({"$fixture_ref":"worker_worktree_id"});
                change.as_object_mut().expect("change reference is an object").insert(
                    "host_commit_operation_id".into(),
                    json!({"$fixture_ref":"worker.host_commit_operation_id"}),
                );
                let mut worker_result = message("worker", "implementation_ready", json!({
                    "change_references":[change],
                    "completed_acceptance_items":["The production CLI registered a Change manifest and returned the exact host commit receipt."],
                    "unresolved_items":[],"irregularity_references":[]
                })).with_actions(vec![
                    json!({"action":"write_file","path":"fixture-change.md","contents":"# Acceptance fixture change\n\nCreated by the bounded emulated Worker action.\n"}),
                    json!({"action":"repository_commit","action_id":"worker-change","message":"test: record acceptance fixture change"}),
                    json!({"action":"write_file","path":"worker-checks.txt","contents":"Emulated Worker check evidence for the exact published source revision.\n"}),
                    json!({"action":"register_artifact","action_id":"test_receipt","path":"worker-checks.txt","kind":"test_receipt","schema_version":1,"message_id":"worker-checks","remove_after_registration":true})
                ]).with_artifact_ref(json!({"$fixture_ref":"artifact.change"}));
                worker_result["artifact_refs"] = json!([
                    {"$fixture_ref":"artifact.change"},
                    {"$fixture_ref":"artifact.test_receipt"}
                ]);
                vec![worker_result]
            } else {
                vec![message("worker", "implementation_ready", json!({
                    "change_references":[change],
                    "completed_acceptance_items":["The fixture artifact was committed in the assigned managed worktree."],
                    "unresolved_items":[],"irregularity_references":[]
                })).with_actions(vec![
                    json!({"action":"write_file","path":"fixture-change.md","contents":"# Acceptance fixture change\n\nCreated by the bounded emulated Worker action.\n"}),
                    json!({"action":"git_commit","action_id":"worker-change","message":"test: record acceptance fixture change"}),
                    json!({"action":"register_artifact","action_id":"change","path":"fixture-change.md","kind":"change","schema_version":1,"message_id":"fixture-change-artifact"})
                ]).with_artifact_ref(json!({"$fixture_ref":"artifact.change"}))]
            }
        },
        "reviewer" => vec![message("reviewer", "review_ready", json!({
            "subject_kind":"implementation_publication_set","subject_digest":{"$fixture_ref":"prompt.subject_digest"},
            "findings":[],"evidence_coverage":{"$fixture_ref":"prompt.evidence_coverage"},
            "disposition":"approved","unknowns":[]
        })).with_actions(vec![
            json!({"action":"write_file","path":"fixture-review.md","contents":"# Review evidence\n\nThe bounded fixture change meets the acceptance criterion.\n"}),
            json!({"action":"register_artifact","action_id":"review","path":"fixture-review.md","kind":"review","schema_version":1,"message_id":"fixture-review-artifact"})
        ]).with_artifact_ref(json!({"$fixture_ref":"artifact.review"}))],
        "merge_decision" => vec![
            message("merge_decision", "merge_assessment", json!({
                "pr_references":[{"$fixture_ref":"prompt.pr_reference"}],
                "subject_digest":{"$fixture_ref":"prompt.subject_digest"},
                "deterministic_gate_evidence":[{"gate_id":"required-checks","outcome":"pass","evidence_references":[]}],
                "ratings":{"change_impact":{"rating":1,"source":"emulated fixture diff","rationale":"One bounded documentation file.","evidence_references":[],"uncertainty":null},"complexity":{"rating":1,"source":"emulated fixture diff","rationale":"One-file change.","evidence_references":[],"uncertainty":null},"verification_gaps":{"rating":1,"source":"fixture checks","rationale":"The fixture CLI reports deterministic checks.","evidence_references":[],"uncertainty":null},"review_uncertainty":{"rating":0,"source":"fixture review artifact","rationale":"No findings were reported.","evidence_references":[],"uncertainty":null},"operational_exposure":{"rating":0,"source":"repository fixture policy","rationale":"No production target is selected.","evidence_references":[],"uncertainty":null}},
                "confidence":"high","rationale":"The emulated fixture exposes exact host and forge observations.","disposition":"merge"
            })).with_artifact("merge_assessment", "fixture-merge-assessment.md", "merge_assessment"),
            message(
                "merge_decision",
                "merge_intent",
                default_merge_intent_template("fixture"),
            )
        ],
        "operator" => vec![message("operator", "operation_action", json!({
            "operation_plan_digest":{"$fixture_ref":"prompt.operation_plan_digest"},
            "node_key":{"$fixture_ref":"prompt.node_key"},"action_id":"fixture_echo",
            "parameters":{"acceptance":"one-ticket-vertical"},"preconditions":["The source merge is host-observed."],
            "approval_receipt":{"$fixture_ref":"prompt.approval_receipt"}
        })), message("operator", "operation_result", json!({
            "node_key":{"$fixture_ref":"prompt.node_key"},"outcome":"succeeded","remote_receipt":{},
            "source_commit":{"$fixture_ref":"prompt.source_commit"},"environment":{"$fixture_ref":"prompt.environment"},"evidence_references":[]
        })).with_actions(vec![
            json!({"action":"write_file","path":"fixture-operation.md","contents":"# Operation receipt\n\nThe configured deterministic fixture operation was observed.\n"}),
            json!({"action":"register_artifact","action_id":"operation","path":"fixture-operation.md","kind":"operation_receipt","schema_version":1,"message_id":"fixture-operation-artifact"})
        ]).with_artifact_ref(json!({"$fixture_ref":"artifact.operation"}))],
        "postmortem" => vec![message("postmortem", "postmortem_ready", json!({
            "candidate_publication_manifest":{"title":"Acceptance fixture delivery","summary":"Observed one-ticket emulated delivery through the configured Operations adapter."},
            "findings":["The fixture exercises a real host-managed ticket lifecycle with deterministic external boundaries."],
            "source_references":[{"$fixture_ref":"artifact.postmortem"}],"unresolved_provenance":[]
        })).with_actions(vec![
            json!({"action":"write_file","path":"fixture-postmortem.md","contents":"---\nformat: okf-0.2\n---\n\n# Acceptance fixture delivery\n\nObserved facts: the emulated ticket passed the fixture delivery flow.\n"}),
            json!({"action":"register_artifact","action_id":"postmortem","path":"fixture-postmortem.md","kind":"postmortem","schema_version":1,"message_id":"fixture-postmortem-artifact"})
        ])],
        _ => return Err(format!("unknown acceptance role `{role}`")),
    };
    messages.extend(
        workflow
            .into_iter()
            .map(|message| message.with_lane("workflow")),
    );
    Ok(messages)
}

fn seed_operations_ticket(request: &Request<'_>, executable: &Path) -> Result<Value, String> {
    let envelope = json!({
        "schema_version":1,
        "request_id":"acceptance-seed-request",
        "operation_id":"acceptance-seed-operation",
        "method":"ticket.create",
        "params":{
            "scope":{"project":"operations"},
            "creation_key":"acceptance-seed-ticket",
            "title":"Acceptance fixture vertical",
            "body":"Exercise the configured Operations Project through implementation, review, merge, operation, and postmortem.",
            "status":"ready"
        }
    });
    let response = ticket_adapter_call(request, executable, &envelope)?;
    let ticket = response
        .get("result")
        .and_then(|result| result.get("ticket"))
        .cloned()
        .ok_or("fixture ticket adapter create response omitted normalized result.ticket")?;
    if ticket["scope"] != json!({"project":"operations"})
        || ticket["status"]["value"] != "ready"
        || ticket["id"].as_str().is_none_or(str::is_empty)
    {
        return Err(
            "fixture ticket adapter returned a ticket outside the requested scope or status".into(),
        );
    }
    Ok(ticket)
}

fn observe_seeded_ticket(
    request: &Request<'_>,
    executable: &Path,
    seeded_ticket: &Value,
) -> Result<Value, String> {
    let ticket_id = seeded_ticket["id"]
        .as_str()
        .ok_or("seeded normalized ticket has no id")?;
    let response = ticket_adapter_call(
        request,
        executable,
        &json!({
            "schema_version":1,
            "request_id":"acceptance-observe-request",
            "method":"ticket.get",
            "params":{"scope":{"project":"operations"},"ticket_id":ticket_id}
        }),
    )?;
    let ticket = response
        .get("result")
        .and_then(|result| result.get("ticket"))
        .ok_or("fixture ticket adapter get response omitted result.ticket")?;
    Ok(
        json!({"id":ticket["id"],"status":ticket["status"]["value"],"revision":ticket["revision"],"title":ticket["title"]}),
    )
}

fn ticket_adapter_call(
    request: &Request<'_>,
    executable: &Path,
    envelope: &Value,
) -> Result<Value, String> {
    let input = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
    let args = [
        OsString::from("fixture"),
        OsString::from("ticket"),
        OsString::from("--database"),
        request.fixture_root.join("tickets.sqlite").into_os_string(),
        OsString::from("--namespace"),
        OsString::from("fixture/acceptance"),
    ];
    let output = run_process(ProcessRequest {
        executable: executable.to_path_buf(),
        args: args.to_vec(),
        stdin: input,
        cwd: Some(request.fixture_root.to_path_buf()),
        clear_environment: false,
        environment: std::env::vars_os().collect(),
        timeout: STEP_TIMEOUT,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| format!("run normalized fixture ticket adapter CLI: {error}"))?;
    require_success("normalized fixture ticket adapter CLI", &output)?;
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!("normalized fixture ticket adapter returned invalid JSON: {error}")
    })
}

fn message(role: &str, kind: &str, structured_result: Value) -> Value {
    json!({"role":role,"kind":kind,"assertion":{"assertion":"succeeded"},"structured_result":structured_result})
}

fn default_merge_intent_template(repository_id: &str) -> Value {
    let template =
        include_str!("fixtures/merge_intent.json").replace("{repository_id}", repository_id);
    serde_json::from_str(&template).expect("shared MergeIntent fixture is valid JSON")
}

fn request_merge_messages(mut messages: Vec<Value>) -> Vec<Value> {
    let intent = messages
        .iter_mut()
        .find(|message| message["kind"] == "merge_intent")
        .expect("MergeDecision fixture has an intent message");
    intent["structured_result"] = json!({
        "assessment_id":{"$fixture_ref":"prompt.assessment_id"},
        "pr_identities":[{"$fixture_ref":"prompt.pr_reference"}],
        "policy_digest":{"$fixture_ref":"prompt.policy_digest"},
        "prepared_body_digest":{"$fixture_ref":"prompt.prepared_body_digest"},
        "steps":[
            {"kind":"update_pull_request_body","instruction_reference":"repository:fixture:merge#prepare-body","rationale":"Recover the exact host-prepared authorship-trailer body already published by the Worker."},
            {"kind":"request_merge","instruction_reference":"repository:fixture:merge#request-merge","rationale":"Request the repository-configured merge through its exact public procedure."},
            {"kind":"verify_merge_commit","instruction_reference":"repository:fixture:merge#verify-merge","rationale":"Verify the provider's recorded merge commit and required authorship trailers."}
        ],
        "post_merge_verification":[
            {"kind":"merge_commit_recorded","instruction_reference":"repository:fixture:merge#verify-merge","rationale":"Confirm the provider records the verified merge commit."}
        ]
    });
    messages
}

trait FixtureMessageExt {
    fn with_lane(self, lane: &str) -> Self;
    fn with_actions(self, actions: Vec<Value>) -> Self;
    fn with_artifact(self, path: &str, content: &str, kind: &str) -> Self;
    fn with_artifact_ref(self, reference: Value) -> Self;
}

impl FixtureMessageExt for Value {
    fn with_lane(mut self, lane: &str) -> Self {
        self["lane"] = json!(lane);
        self
    }
    fn with_actions(mut self, actions: Vec<Value>) -> Self {
        self["actions"] = json!(actions);
        self
    }
    fn with_artifact(self, path: &str, content: &str, kind: &str) -> Self {
        self.with_actions(vec![json!({"action":"write_file","path":path,"contents":content}),json!({"action":"register_artifact","action_id":"plan","path":path,"kind":kind,"schema_version":1,"message_id":"fixture-plan-artifact"})]).with_artifact_ref(json!({"$fixture_ref":"artifact.plan"}))
    }
    fn with_artifact_ref(mut self, reference: Value) -> Self {
        self["artifact_refs"] = json!([reference]);
        self
    }
}

#[cfg(test)]
fn config_text(request: &Request<'_>, executable: &Path, native_stage: bool) -> String {
    config_text_for_stage(request, executable, native_stage, false)
}

fn config_text_for_stage(
    request: &Request<'_>,
    executable: &Path,
    native_stage: bool,
    request_merge_stage: bool,
) -> String {
    let db = request.fixture_root.join("tickets.sqlite");
    let native_runtime_limits = if native_stage {
        "max_agent_runs = 1\nmax_blocks_per_tab = 2\ncompleted_blocks_to_keep = 0\n"
    } else {
        ""
    };
    format!(
        r#"schema_version = 1
state_root = {:?}

[runtime]
rex_binary = {:?}
{}
external_poll_seconds = 1
[runtime.environment]
source = "inherit"
interactive = false

[adapters.tickets]
kind = "command"
command = [{:?}, "fixture", "ticket", "--database", {:?}, "--namespace", "fixture/acceptance"]

[repositories.fixture]
clone_url = "https://github.com/fixture/repository.git"
base_branch = "main"
forge = "github"
[repositories.fixture.merge]
auto_merge = true
required_checks = ["required-tests"]
method = "squash"
executor = {:?}
instructions = {:?}
[repositories.fixture.operations]
recipe = "docs_fixture"
allowed_actions = ["fixture_echo"]

[projects.operations_project]
mode = "operations"
ticket_adapter = "tickets"
ticket_scope = {{ project = "operations" }}
repositories = ["fixture"]
auto_merge = true
[[projects.operations_project.operation_matches]]
labels_all = []
recipe = "docs_fixture"
[projects.operations_project.roles]
supervisor = "fixture_supervisor"
coordinator = "fixture_coordinator"
planner = "fixture_planner"
worker = "fixture_worker"
reviewer = "fixture_reviewer"
merge_decision = "fixture_merge_decision"
operator = "fixture_operator"
postmortem = "fixture_postmortem"

[operation_recipes.docs_fixture]
required_stages = ["planning", "implementation", "review", "merge", "postmortem"]
required_evidence = ["plan", "review", "merge_assessment", "postmortem_publication"]
[[operation_recipes.docs_fixture.targets]]
id = "fixture-operation"
repository = "fixture"
environment = "test"
action = "fixture_echo"
depends_on = []
source = "merge_commit"
selector = {{}}
success_predicate = {{ kind = "target_succeeded" }}
timeout_seconds = 30
approval = "repository_policy"

[operation_actions.fixture_echo]
kind = "command"
command = [{:?}, "fixture", "operations", "--state-dir", {:?}, "--observe-status", "succeeded"]
"#,
        request.fixture_root.join("state").display().to_string(),
        request.rex.display().to_string(),
        native_runtime_limits,
        executable.display().to_string(),
        db.display().to_string(),
        if request_merge_stage {
            "request"
        } else {
            "direct"
        },
        if request_merge_stage {
            "Request merge by posting the configured command.\n/merge\nVerify the provider records the squash merge commit and required Co-authored-by trailers."
        } else {
            "Use the repository's configured merge procedure."
        },
        executable.display().to_string(),
        request
            .fixture_root
            .join("operations")
            .display()
            .to_string(),
    )
}

fn validate_native_worker_codex_path() -> Result<PathBuf, String> {
    let path = std::env::var_os(NATIVE_WORKER_CODEX_ENV)
        .map(PathBuf::from)
        .ok_or("native Worker Codex path was not frozen")?;
    if !path.is_absolute() || !path.is_file() {
        return Err("native Worker Codex path must be an absolute executable file".into());
    }
    #[cfg(unix)]
    if fs::metadata(&path)
        .map_err(|error| format!("inspect native Worker Codex executable: {error}"))?
        .permissions()
        .mode()
        & 0o111
        == 0
    {
        return Err("native Worker Codex path is not executable".into());
    }
    let version = run_process(ProcessRequest {
        executable: path.clone(),
        args: vec![OsString::from("--version")],
        stdin: Vec::new(),
        cwd: None,
        clear_environment: false,
        environment: BTreeMap::new(),
        timeout: STEP_TIMEOUT,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| format!("run native Worker Codex version probe: {error}"))?;
    let version_text = String::from_utf8_lossy(&version.stdout);
    if version.timed_out
        || !version.cleanup_confirmed
        || !version.status.is_some_and(|status| status.success())
        || version_text.lines().last().map(str::trim) != Some("codex-cli 0.166.0")
    {
        return Err("native Worker Codex must be the verified 0.166.0 executable".into());
    }
    Ok(path)
}

fn observe_running_native_worker(
    request: &Request<'_>,
    state_root: &Path,
) -> Result<Option<Value>, String> {
    let database = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open state read-only for native Worker observation: {error}"))?;
    let qualification: Option<(String, String, String, String, String)> = database
        .query_row(
            "SELECT executable_path,executable_digest,provider_version,profile_digest,receipt_digest
             FROM provider_qualifications
             WHERE project_id=?1 AND profile_id='fixture_worker' AND adapter='codex' AND status='verified'
             AND receipt_digest=(SELECT qualification_receipt_digest FROM agent_launch_authority WHERE role='worker' AND rex_server_identity=?2 AND rex_session_id=?3 ORDER BY created_at_unix DESC LIMIT 1)
             ORDER BY created_at_unix DESC LIMIT 1",
            [FIXTURE_PROJECT_ID, request.expected_instance, request.rex_session],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(|error| format!("read native Worker provider qualification: {error}"))?;
    let Some((codex_path, codex_digest, codex_version, profile_digest, receipt_digest)) =
        qualification
    else {
        return Ok(None);
    };
    let expected_codex_path = std::env::var_os(NATIVE_WORKER_CODEX_ENV)
        .map(PathBuf::from)
        .ok_or("native Worker Codex path was not frozen")?;
    if codex_path != expected_codex_path.to_string_lossy().as_ref()
        || !codex_version.contains("0.166.0")
        || codex_digest
            != format!(
                "{:x}",
                Sha256::digest(
                    fs::read(&expected_codex_path)
                        .map_err(|error| format!("read native Worker Codex binary: {error}"))?
                )
            )
    {
        return Ok(None);
    }
    type NativeWorkerLaunchRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        i64,
    );
    let row: Option<NativeWorkerLaunchRow> = database
        .query_row(
            NATIVE_WORKER_LAUNCH_EVIDENCE_QUERY,
            params![
                request.expected_instance,
                request.rex_session,
                receipt_digest
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("read native Worker launch evidence: {error}"))?;
    let Some((
        run_id,
        operation_id,
        runtime_binary_digest,
        server_identity,
        session_id,
        window_id,
        block_id,
        control_dir,
        workspace_path,
        agent_state,
        launch_state,
        wrapper_identity_json,
        provider_tree_json,
        slot_disposition,
        reservation_epoch,
    )) = row
    else {
        return Ok(None);
    };
    let wrapper: ObservedWrapperIdentity = serde_json::from_str(
        wrapper_identity_json
            .as_deref()
            .ok_or("native Worker wrapper identity was not saved")?,
    )
    .map_err(|error| format!("parse saved native Worker wrapper identity: {error}"))?;
    let provider_start = parse_native_worker_provider_start(
        &provider_tree_json,
        &run_id,
        &operation_id,
        &codex_digest,
        &runtime_binary_digest,
        &wrapper,
    )?;
    let provider_tree = &provider_start.process_tree;
    if wrapper.rex_session_id != session_id || wrapper.rex_block_id != block_id {
        return Err(
            "native Worker wrapper identity differs from its exact Rex block authority".into(),
        );
    }
    let rex = match RexCliTransport::connect(
        request.rex,
        &[],
        request.rex_server.to_owned(),
        request.expected_instance.to_owned(),
        session_id.clone(),
        BTreeMap::new(),
    ) {
        Ok(rex) => rex,
        Err(_) => return Ok(None),
    };
    let window = TicketWindow {
        server_instance_id: server_identity.clone(),
        session_id: session_id.clone(),
        window_id: window_id.clone(),
        label: String::new(),
        initial_block_id: Some(block_id.clone()),
        disposition: CreateDisposition::Existing,
    };
    if !rex
        .agent_block_is_present(&window, &run_id, &block_id)
        .map_err(|error| format!("verify exact native Worker Rex block: {error}"))?
    {
        return Ok(None);
    }
    let rex_process_observation = match rex.observe_process(&window, &run_id, &block_id) {
        Ok(observation) => observation,
        Err(_) => return Ok(None),
    };
    let current_processes = inspect_process_table()
        .map_err(|error| format!("inspect live process identities for native Worker: {error}"))?;
    if !native_worker_launch_is_live(
        &wrapper,
        &provider_start,
        &rex_process_observation,
        &runtime_binary_digest,
        &current_processes,
    ) {
        return Ok(None);
    }
    let mut live_processes = Vec::with_capacity(provider_tree.len() + 2);
    let mut expected_live = provider_tree
        .iter()
        .map(|identity| (identity.pid, identity.start_identity.as_str()))
        .collect::<Vec<_>>();
    if let Some(anchor) = &wrapper.rex_launch_anchor {
        expected_live.push((anchor.pid, &anchor.start_identity));
    }
    for (pid, start_identity) in expected_live {
        if let Some(process) = current_processes.iter().find(|process| {
            process.pid == pid
                && process.start_identity == start_identity
                && process.quality == ProcessIdentityQuality::KernelBirthToken
        }) {
            live_processes.push(process);
        }
    }
    Ok(Some(json!({
        "run_id":run_id,
        "server_instance_id":server_identity,
        "session_id":session_id,
        "window_id":window_id,
        "block_id":block_id,
        "control_dir":control_dir,
        "managed_worktree":workspace_path,
        "agent_state":agent_state,
        "launch_state":launch_state,
        "wrapper_process_identity":wrapper,
        "provider_process_tree":provider_tree,
        "provider_start_observation":provider_start,
        "rex_process_observation":rex_process_observation_json(&rex_process_observation),
        "anchored_topology_verified":wrapper.rex_launch_anchor.is_some(),
        "live_process_identities":live_processes,
        "slot_disposition":slot_disposition,
        "reservation_epoch":reservation_epoch,
        "worker_provider_qualification":{
            "executable_path":codex_path,
            "executable_sha256":codex_digest,
            "provider_version":codex_version,
            "profile_digest":profile_digest,
            "receipt_digest":receipt_digest
        }
    })))
}

fn rex_process_observation_json(
    observation: &rex_projects::adapters::rex::RexProcessObservation,
) -> Value {
    use rex_projects::adapters::rex::{RexLastExit, RexProcessInfo};

    fn process_json(process: &RexProcessInfo) -> Value {
        json!({
            "pid": process.pid,
            "user_id": process.user_id,
            "name": process.name,
            "argv0": process.argv0,
            "path": process.path,
            "invoked_path": process.invoked_path,
            "script": process.script,
            "cwd": process.cwd,
            "user": process.user,
        })
    }

    let last_exit = observation
        .last_exit
        .as_ref()
        .map(|exit: &RexLastExit| json!({"exit_code": exit.exit_code, "error": exit.error}));
    json!({
        "last_exit": last_exit,
        "child": observation.child.as_ref().map(process_json),
        "foreground": observation.foreground.as_ref().map(process_json),
        "ancestors": observation.ancestors.as_ref().map(|ancestors| {
            ancestors.iter().map(process_json).collect::<Vec<_>>()
        }),
    })
}

fn parse_native_worker_provider_start(
    serialized: &str,
    expected_run_id: &str,
    expected_operation_id: &str,
    expected_executable_digest: &str,
    expected_runtime_digest: &str,
    wrapper: &ObservedWrapperIdentity,
) -> Result<ObservedProviderStart, String> {
    let observation: ObservedProviderStart = serde_json::from_str(serialized)
        .map_err(|error| format!("parse saved native Worker provider observation: {error}"))?;
    let tree_bytes = serde_json::to_vec(&observation.process_tree)
        .map_err(|error| format!("encode saved native Worker process tree: {error}"))?;
    let tree_digest = format!("{:x}", Sha256::digest(tree_bytes));
    let wrapper_matches = observation
        .process_tree
        .iter()
        .filter(|identity| {
            identity.pid == wrapper.pid && identity.start_identity == wrapper.start_identity
        })
        .count()
        == 1;
    let provider_matches = observation.process_tree.iter().any(|identity| {
        identity.pid == observation.provider_pid
            && identity.start_identity == observation.provider_start_identity
    });
    let unique_kernel_identities = observation.process_tree.iter().all(|identity| {
        identity.pid != 0
            && !identity.start_identity.trim().is_empty()
            && identity.identity_quality == ProcessIdentityQuality::KernelBirthToken
            && identity.process_group_id != 0
    }) && observation
        .process_tree
        .iter()
        .map(|identity| identity.pid)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == observation.process_tree.len();
    if observation.agent_run_id.to_string() != expected_run_id
        || observation.operation_id.to_string() != expected_operation_id
        || observation.executable_digest.to_string() != expected_executable_digest
        || wrapper.runtime_binary_digest.to_string() != expected_runtime_digest
        || !observation.process_tree_confirmed
        || observation.process_tree_digest.to_string() != tree_digest
        || observation.provider_pid == wrapper.pid
        || observation.provider_start_identity.trim().is_empty()
        || observation
            .provider_start_identity
            .chars()
            .any(char::is_control)
        || !wrapper_matches
        || !provider_matches
        || !unique_kernel_identities
    {
        return Err("saved native Worker provider observation does not match launch authority or complete process evidence".into());
    }
    Ok(observation)
}

fn native_worker_processes_are_live(
    wrapper: &ObservedWrapperIdentity,
    provider: &ObservedProviderStart,
    current: &[ProcessIdentity],
) -> bool {
    let is_live = |pid: u32, start_identity: &str| {
        current.iter().any(|process| {
            process.pid == pid
                && process.start_identity == start_identity
                && process.quality == ProcessIdentityQuality::KernelBirthToken
        })
    };
    if provider.process_tree.is_empty()
        || wrapper.pid == 0
        || wrapper.start_identity.trim().is_empty()
        || !is_live(wrapper.pid, &wrapper.start_identity)
        || provider.provider_pid == wrapper.pid
        || !is_live(provider.provider_pid, &provider.provider_start_identity)
    {
        return false;
    }
    let mut pids = std::collections::BTreeSet::new();
    let wrapper_count = provider
        .process_tree
        .iter()
        .filter(|identity| {
            identity.pid == wrapper.pid && identity.start_identity == wrapper.start_identity
        })
        .count();
    // Start snapshots retain completed hook children; supervisor/provider liveness is checked above.
    wrapper_count == 1
        && provider.process_tree.iter().all(|identity| {
            identity.pid != 0
                && !identity.start_identity.trim().is_empty()
                && identity.identity_quality == ProcessIdentityQuality::KernelBirthToken
                && pids.insert(identity.pid)
        })
        && provider.process_tree.iter().any(|identity| {
            identity.pid == provider.provider_pid
                && identity.start_identity == provider.provider_start_identity
        })
}

fn native_worker_launch_is_live(
    wrapper: &ObservedWrapperIdentity,
    provider: &ObservedProviderStart,
    rex: &RexProcessObservation,
    runtime_binary_digest: &str,
    current: &[ProcessIdentity],
) -> bool {
    if !native_worker_processes_are_live(wrapper, provider, current)
        || !native_worker_anchor_topology_is_live(wrapper, provider.provider_pid, rex, current)
    {
        return false;
    }
    let runtime_digest_matches = |process: &ProcessIdentity| {
        let Ok(Some(path)) = rex_projects::process::executable_path_for_identity(process) else {
            return false;
        };
        let Ok(bytes) = fs::read(path) else {
            return false;
        };
        format!("{:x}", Sha256::digest(bytes)) == runtime_binary_digest
    };
    let Some(supervisor) = current.iter().find(|process| {
        process.pid == wrapper.pid && process.start_identity == wrapper.start_identity
    }) else {
        return false;
    };
    if !runtime_digest_matches(supervisor) {
        return false;
    }
    if let Some(anchor) = &wrapper.rex_launch_anchor {
        let Some(anchor_process) = current.iter().find(|process| {
            process.pid == anchor.pid && process.start_identity == anchor.start_identity
        }) else {
            return false;
        };
        if !runtime_digest_matches(anchor_process)
            || !rex
                .child
                .as_ref()
                .and_then(|child| child.path.as_deref())
                .and_then(|path| fs::read(path).ok())
                .is_some_and(|bytes| {
                    format!("{:x}", Sha256::digest(bytes)) == runtime_binary_digest
                })
        {
            return false;
        }
    } else if !rex
        .child
        .as_ref()
        .and_then(|child| child.path.as_deref())
        .and_then(|path| fs::read(path).ok())
        .is_some_and(|bytes| format!("{:x}", Sha256::digest(bytes)) == runtime_binary_digest)
    {
        return false;
    }
    true
}

fn native_worker_anchor_topology_is_live(
    wrapper: &ObservedWrapperIdentity,
    provider_pid: u32,
    rex: &RexProcessObservation,
    current: &[ProcessIdentity],
) -> bool {
    let expected_rex_pid = wrapper
        .rex_launch_anchor
        .as_ref()
        .map_or(wrapper.pid, |anchor| anchor.pid);
    if rex.last_exit.is_some()
        || rex
            .child
            .as_ref()
            .is_none_or(|child| child.pid != expected_rex_pid)
        || rex.foreground.as_ref().is_none_or(|foreground| {
            foreground.pid != wrapper.pid
                && foreground.pid != provider_pid
                && wrapper
                    .rex_launch_anchor
                    .as_ref()
                    .is_none_or(|anchor| foreground.pid != anchor.pid)
        })
    {
        return false;
    }
    let Some(supervisor) = current.iter().find(|process| {
        process.pid == wrapper.pid
            && process.start_identity == wrapper.start_identity
            && process.quality == ProcessIdentityQuality::KernelBirthToken
    }) else {
        return false;
    };
    wrapper.rex_launch_anchor.as_ref().is_none_or(|anchor| {
        current.iter().any(|process| {
            process.pid == anchor.pid
                && process.start_identity == anchor.start_identity
                && process.quality == ProcessIdentityQuality::KernelBirthToken
        }) && supervisor.parent_pid == anchor.pid
    })
}
fn write_native_worker_setup_freeze(
    request: &Request<'_>,
    cli_identity: &Value,
    driver_executable: &Path,
    config_path: &Path,
    seeded_ticket: &Value,
    codex_path: &Path,
    stage: &str,
) -> Result<(), String> {
    let marker = std::env::var_os(ACCEPTANCE_FREEZE_MARKER_ENV)
        .map(PathBuf::from)
        .ok_or("native Worker setup freeze marker path is required")?;
    if !marker.is_absolute() || !marker.starts_with(request.fixture_root) || marker.exists() {
        return Err(
            "native Worker setup freeze marker must be a new absolute path inside the fixture root"
                .into(),
        );
    }
    let continuation = marker.with_extension("continue");
    if continuation.exists() {
        return Err("native Worker setup freeze continuation marker already exists".into());
    }
    let worker_profile_path = request
        .fixture_root
        .join("profiles/fixture_worker/config.toml");
    let frozen = json!({
        "product":cli_identity,
        "product_cli_path":request.cli,
        "product_cli_sha256":format!("{:x}", Sha256::digest(fs::read(request.cli).map_err(|error| error.to_string())?)),
        "driver_path":driver_executable,
        "driver_sha256":format!("{:x}", Sha256::digest(fs::read(driver_executable).map_err(|error| error.to_string())?)),
        "driver_version":env!("CARGO_PKG_VERSION"),
        "driver_source_revision":rex_projects::BUILD_SOURCE_REVISION,
        "driver_source_sha256":format!("{:x}", Sha256::digest(include_bytes!("acceptance.rs"))),
        "rex_instance_id":request.expected_instance,
        "rex_endpoint":request.rex_server,
        "rex_session_id":request.rex_session,
        "fixture_root":request.fixture_root,
        "stage":stage,
        "config_path":config_path,
        "config_sha256":format!("{:x}", Sha256::digest(fs::read(config_path).map_err(|error| error.to_string())?)),
        "controller_xdg_state_home":request.fixture_root.join("xdg-state"),
        "seeded_ticket":seeded_ticket,
        "worker_profile_path":worker_profile_path,
        "worker_profile_sha256":format!("{:x}", Sha256::digest(fs::read(&worker_profile_path).map_err(|error| error.to_string())?)),
        "emulated_roles":["supervisor","coordinator","planner"],
        "worker_provider":"native Codex 0.166.0",
        "worker_codex_path":codex_path,
        "worker_codex_sha256":format!("{:x}", Sha256::digest(fs::read(codex_path).map_err(|error| error.to_string())?)),
        "native_worker_task":NATIVE_WORKER_LIFECYCLE_TASK
    });
    fs::write(
        &marker,
        serde_json::to_vec_pretty(&frozen).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write setup freeze marker: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(300);
    while !continuation.exists() {
        if Instant::now() >= deadline {
            return Err("timed out waiting for native Worker setup freeze continuation".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn verify_owned_session(request: &Request<'_>) -> Result<(), String> {
    let identity = rex_call(request, &["whoami", "--json"])?;
    require_success("verify Rex instance", &identity)?;
    let identity: Value = serde_json::from_slice(&identity.stdout)
        .map_err(|error| format!("Rex whoami returned invalid JSON: {error}"))?;
    if identity["instance_id"].as_str() != Some(request.expected_instance) {
        return Err("Rex endpoint instance changed after preflight".into());
    }
    let output = rex_call(
        request,
        &["session", "inspect", request.rex_session, "--json"],
    )?;
    require_success("inspect owned Rex session", &output)?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Rex session inspect returned invalid JSON: {error}"))?;
    if value["session_id"].as_str() != Some(request.rex_session) {
        return Err("Rex session ID does not match the explicitly selected owned session".into());
    }
    verify_fixture_session_is_fresh(&value)?;
    Ok(())
}

fn verify_fixture_session_is_fresh(session: &Value) -> Result<(), String> {
    let owned_labels = [
        CONTROLLER_WINDOW_LABEL.to_owned(),
        owned_supervisor_window_label(FIXTURE_PROJECT_ID),
        owned_ticket_window_label(FIXTURE_TICKET_NAMESPACE, FIXTURE_TICKET_ID)
            .map_err(|error| error.to_string())?,
    ];
    let windows: &[Value] = match session.get("windows") {
        None => &[],
        Some(Value::Array(windows)) => windows,
        Some(_) => return Err("Rex session inspect returned an invalid windows field".into()),
    };
    let has_existing_fixture_window = windows.iter().any(|window| {
        window
            .get("label")
            .and_then(Value::as_str)
            .is_some_and(|label| owned_labels.iter().any(|owned| owned == label))
    });
    if has_existing_fixture_window {
        return Err(
            "Rex session already contains resources from this acceptance fixture; select a fresh session".into(),
        );
    }
    Ok(())
}

fn wait_for_owner(
    request: &Request<'_>,
    state_root: &Path,
    trace: &mut Vec<Value>,
) -> Result<Value, String> {
    let deadline = Instant::now() + POLL_LIMIT;
    loop {
        let output = product(request, state_root, &["status", "--json"])?;
        if output.status.is_some_and(|status| status.success())
            && let Ok(value) = serde_json::from_slice::<Value>(&output.stdout)
            && value["owner"]["active"] == true
        {
            trace.push(
                json!({"step":"controller_owner_observed","status":"passed","evidence":value}),
            );
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Ok(
                json!({"owner":{"active":false},"last_output":String::from_utf8_lossy(&output.stdout)}),
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn projects_running(status: &Value) -> bool {
    status["projects"].as_array().is_some_and(|projects| {
        projects.iter().any(|project| {
            project["id"] == "operations_project"
                && project["desired_lifecycle"] == "running"
                && project["observed_lifecycle"] == "running"
        })
    })
}

fn poll_controller_stopped(request: &Request<'_>, state_root: &Path) -> bool {
    let deadline = Instant::now() + POLL_LIMIT;
    loop {
        if let Ok(output) = product(request, state_root, &["status", "--json"])
            && let Ok(value) = serde_json::from_slice::<Value>(&output.stdout)
            && value["owner"]["active"] == false
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn rex_capture(request: &Request<'_>, block: &str) -> Result<ProcessOutput, String> {
    rex_call(
        request,
        &[
            "capture",
            "--session",
            request.rex_session,
            "--block",
            block,
            "--trim",
            "--unwrap",
        ],
    )
}

fn wait_block_exit(request: &Request<'_>, block: &str) -> bool {
    rex_call(
        request,
        &[
            "wait",
            block,
            "--session",
            request.rex_session,
            "--for",
            "20s",
            "--json",
        ],
    )
    .is_ok_and(|output| {
        !output.timed_out
            && output.cleanup_confirmed
            && serde_json::from_slice::<Value>(&output.stdout)
                .is_ok_and(|value| value.get("exit_code").and_then(Value::as_i64).is_some())
    })
}

fn owned_window_present(request: &Request<'_>, window_id: &str) -> bool {
    let Ok(output) = rex_call(
        request,
        &["window", "ls", "--session", request.rex_session, "--json"],
    ) else {
        return true;
    };
    if !output.status.is_some_and(|status| status.success()) {
        return true;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return true;
    };
    value
        .get("windows")
        .and_then(Value::as_array)
        .is_none_or(|windows| {
            windows
                .iter()
                .any(|window| window.get("window_id").and_then(Value::as_str) == Some(window_id))
        })
}

fn rex_call(request: &Request<'_>, words: &[&str]) -> Result<ProcessOutput, String> {
    let mut args = vec![
        OsString::from("--autostart=false"),
        OsString::from("--server"),
        OsString::from(request.rex_server),
    ];
    args.extend(words.iter().map(OsString::from));
    invoke(request.rex, &args, None, None, STEP_TIMEOUT)
}

fn git(cwd: &Path, args: &[&str]) -> Result<(), String> {
    let output = invoke(
        Path::new("/usr/bin/git"),
        &args.iter().map(OsString::from).collect::<Vec<_>>(),
        Some(cwd),
        None,
        STEP_TIMEOUT,
    )?;
    require_success("local fixture git operation", &output)
}

fn git_output(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let output = invoke(
        Path::new("/usr/bin/git"),
        &args.iter().map(OsString::from).collect::<Vec<_>>(),
        Some(cwd),
        None,
        STEP_TIMEOUT,
    )?;
    require_success("local fixture git query", &output)?;
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn product(
    request: &Request<'_>,
    state_root: &Path,
    words: &[&str],
) -> Result<ProcessOutput, String> {
    let mut args = vec![
        OsString::from("--config"),
        request.fixture_root.join("config.toml").into_os_string(),
        OsString::from("--state-root"),
        state_root.as_os_str().to_owned(),
    ];
    args.extend(words.iter().map(OsString::from));
    let xdg_state = OsString::from("XDG_STATE_HOME");
    let xdg_state_value = request.fixture_root.join("xdg-state").into_os_string();
    let output = invoke(
        request.cli,
        &args,
        Some(request.fixture_root),
        Some((xdg_state, xdg_state_value)),
        STEP_TIMEOUT,
    )?;
    Ok(output)
}

fn invoke(
    executable: &Path,
    args: &[OsString],
    cwd: Option<&Path>,
    path_override: Option<(OsString, OsString)>,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    if let Some((key, value)) = path_override {
        environment.insert(key, value);
    }
    run_process(ProcessRequest {
        executable: executable.to_path_buf(),
        args: args.to_vec(),
        stdin: Vec::new(),
        cwd: cwd.map(PathBuf::from),
        clear_environment: false,
        environment,
        timeout,
        shutdown_grace: SHUTDOWN_GRACE,
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: OUTPUT_LIMIT,
    })
    .map_err(|error| format!("start {}: {error}", executable.display()))
}

fn require_success(label: &str, output: &ProcessOutput) -> Result<(), String> {
    if output.timed_out
        || !output.cleanup_confirmed
        || !output.status.is_some_and(|status| status.success())
    {
        return Err(format!(
            "{label} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr_tail)
        ));
    }
    Ok(())
}

struct CoordinatorQualificationWaitState {
    generation: u64,
    heartbeat_at_unix: i64,
    owner_active: bool,
    ticket_run_id: Option<String>,
    pending_wake_count: u64,
    verified_qualification_count: u64,
    agent_run_count: u64,
    active_slot_count: u64,
}

fn coordinator_qualification_wait_state(
    database: &Connection,
    project: &str,
    namespace: &str,
    ticket: &str,
    profile: &str,
) -> Result<CoordinatorQualificationWaitState, String> {
    let (generation, heartbeat_at_unix, stopped_at_unix): (u64, i64, Option<i64>) = database
        .query_row(
            "SELECT generation,heartbeat_at_unix,stopped_at_unix FROM controller_owners WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| format!("read acceptance controller owner: {error}"))?;
    let ticket_run_id: Option<String> = database
        .query_row(
            "SELECT ticket_run_id FROM ticket_runs WHERE project_id=?1 AND namespace=?2 AND ticket_id=?3 AND internal_phase NOT IN ('done','canceled') ORDER BY generation DESC LIMIT 1",
            params![project, namespace, ticket],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("read acceptance TicketRun: {error}"))?;
    let (pending_wake_count, verified_qualification_count, agent_run_count, active_slot_count) =
        if let Some(ticket_run_id) = ticket_run_id.as_deref() {
            (
                database
                    .query_row(
                        "SELECT COUNT(*) FROM role_wake_inputs WHERE project_id=?1 AND role_session_id=?2 AND source_type='ticket_run_dispatch' AND source_id=?3 AND lifecycle='pending'",
                        params![project, format!("ticket_run:{ticket_run_id}:coordinator"), ticket_run_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("read pending Coordinator dispatch wake: {error}"))?,
                database
                    .query_row(
                        "SELECT COUNT(*) FROM provider_qualifications WHERE project_id=?1 AND profile_id=?2 AND status='verified'",
                        params![project, profile],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("read Coordinator qualification: {error}"))?,
                database
                    .query_row(
                        "SELECT COUNT(*) FROM agent_launch_authority WHERE project_id=?1 AND ticket_run_id=?2 AND role='coordinator'",
                        params![project, ticket_run_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("read Coordinator AgentRun authority: {error}"))?,
                database
                    .query_row(
                        "SELECT COUNT(*) FROM execution_slots s JOIN agent_launch_authority a ON s.owner_kind='agent_run' AND s.owner_id=a.agent_run_id WHERE a.project_id=?1 AND a.ticket_run_id=?2 AND a.role='coordinator' AND s.disposition!='released'",
                        params![project, ticket_run_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("read Coordinator execution slot: {error}"))?,
            )
        } else {
            (0, 0, 0, 0)
        };
    Ok(CoordinatorQualificationWaitState {
        generation,
        heartbeat_at_unix,
        owner_active: stopped_at_unix.is_none(),
        ticket_run_id,
        pending_wake_count,
        verified_qualification_count,
        agent_run_count,
        active_slot_count,
    })
}

fn observe_coordinator_qualification_wait(
    request: &Request<'_>,
    state_root: &Path,
    block: &str,
    profile: &str,
) -> Value {
    let database = match Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(database) => database,
        Err(error) => {
            return json!({"status":"inconclusive","reason":format!("open acceptance state read-only: {error}")});
        }
    };
    if let Err(error) = database.busy_timeout(Duration::from_secs(2)) {
        return json!({"status":"inconclusive","reason":format!("set acceptance SQLite timeout: {error}")});
    }
    let deadline = Instant::now() + COORDINATOR_STAGE_LIMIT;
    let mut heartbeat_baseline = None;
    let mut last_heartbeat = None;
    let mut heartbeat_advances = Vec::new();
    let diagnostic = format!(
        "parked ticket role launch for Project {FIXTURE_PROJECT_ID}: role coordinator profile {profile} has no exact verified provider qualification"
    );
    loop {
        let status = match product(request, state_root, &["status", "--json"]) {
            Ok(output) if output.status.is_some_and(|status| status.success()) => {
                json_stdout(&output)
            }
            Ok(output) => {
                return json!({"status":"inconclusive","reason":"product status failed while observing Coordinator qualification wait","stdout":String::from_utf8_lossy(&output.stdout)});
            }
            Err(error) => return json!({"status":"inconclusive","reason":error}),
        };
        let state = match coordinator_qualification_wait_state(
            &database,
            FIXTURE_PROJECT_ID,
            FIXTURE_TICKET_NAMESPACE,
            FIXTURE_TICKET_ID,
            profile,
        ) {
            Ok(state) => state,
            Err(error) => return json!({"status":"inconclusive","reason":error}),
        };
        let owner_active =
            state.owner_active && status.pointer("/owner/active") == Some(&Value::Bool(true));
        if !owner_active {
            let capture = rex_capture(request, block).ok();
            let controller_output = capture
                .as_ref()
                .map(|output| String::from_utf8_lossy(&output.stdout).to_string());
            return json!({
                "status":"failed",
                "reason":"controller stopped while Coordinator was waiting for an unqualified profile",
                "owner_generation":state.generation,
                "ticket_run_id":state.ticket_run_id,
                "pending_coordinator_dispatch_wakes":state.pending_wake_count,
                "coordinator_qualifications":state.verified_qualification_count,
                "coordinator_agent_runs":state.agent_run_count,
                "coordinator_active_slots":state.active_slot_count,
                "controller_output":controller_output
            });
        }
        let at_boundary = state.ticket_run_id.is_some()
            && state.pending_wake_count == 1
            && state.verified_qualification_count == 0
            && state.agent_run_count == 0
            && state.active_slot_count == 0;
        let mut diagnostic_observed = false;
        if at_boundary {
            let baseline = *heartbeat_baseline.get_or_insert(state.heartbeat_at_unix);
            if last_heartbeat.is_none_or(|last| state.heartbeat_at_unix > last) {
                last_heartbeat = Some(state.heartbeat_at_unix);
                if state.heartbeat_at_unix > baseline
                    && !heartbeat_advances.contains(&state.heartbeat_at_unix)
                {
                    heartbeat_advances.push(state.heartbeat_at_unix);
                }
            }
            let capture = rex_capture(request, block).ok();
            diagnostic_observed = capture.as_ref().is_some_and(|output| {
                output.status.is_some_and(|status| status.success())
                    && String::from_utf8_lossy(&output.stdout).contains(&diagnostic)
            });
            if diagnostic_observed && heartbeat_advances.len() >= 2 && projects_running(&status) {
                return json!({
                    "status":"passed",
                    "owner_generation":state.generation,
                    "owner_active":true,
                    "ticket_run_id":state.ticket_run_id,
                    "pending_coordinator_dispatch_wakes":state.pending_wake_count,
                    "coordinator_profile":profile,
                    "coordinator_qualifications":state.verified_qualification_count,
                    "coordinator_agent_runs":state.agent_run_count,
                    "coordinator_active_slots":state.active_slot_count,
                    "heartbeat_baseline":baseline,
                    "distinct_heartbeat_advances":heartbeat_advances,
                    "parked_diagnostic":diagnostic
                });
            }
        } else if state.ticket_run_id.is_some() {
            return json!({
                "status":"failed",
                "reason":"Coordinator dispatch wake was not left pending without qualification or launch state",
                "owner_generation":state.generation,
                "owner_active":true,
                "ticket_run_id":state.ticket_run_id,
                "pending_coordinator_dispatch_wakes":state.pending_wake_count,
                "coordinator_qualifications":state.verified_qualification_count,
                "coordinator_agent_runs":state.agent_run_count,
                "coordinator_active_slots":state.active_slot_count
            });
        }
        if Instant::now() >= deadline {
            return json!({
                "status":"timed_out",
                "reason":"Coordinator qualification wait was not proven",
                "owner_generation":state.generation,
                "owner_active":true,
                "ticket_run_id":state.ticket_run_id,
                "pending_coordinator_dispatch_wakes":state.pending_wake_count,
                "coordinator_qualifications":state.verified_qualification_count,
                "coordinator_agent_runs":state.agent_run_count,
                "coordinator_active_slots":state.active_slot_count,
                "parked_diagnostic_observed":diagnostic_observed,
                "project_running":projects_running(&status),
                "heartbeat_baseline":heartbeat_baseline,
                "distinct_heartbeat_advances":heartbeat_advances
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn observe_coordinator_block_loss(
    request: &Request<'_>,
    state_root: &Path,
    inbox_observation: &Value,
) -> Result<Value, String> {
    let run_id = inbox_observation
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or("Coordinator inbox observation omitted its AgentRun ID")?;
    let deadline = Instant::now() + COORDINATOR_STAGE_LIMIT;
    let (status, agent) = loop {
        let status = product(request, state_root, &["status", "--json"])?;
        let dashboard = product(request, state_root, &["dashboard", "--json"])?;
        require_success("read controller before block-loss fault", &status)?;
        require_success("read Coordinator before block-loss fault", &dashboard)?;
        let status = json_stdout(&status);
        let dashboard = json_stdout(&dashboard);
        if status.pointer("/owner/active") != Some(&Value::Bool(true)) {
            return Err("controller stopped before the block-loss fault".into());
        }
        if let Some(agent) = dashboard_agent(&dashboard, run_id) {
            match agent["state"].as_str() {
                Some("running")
                    if agent["rex_session_id"].as_str() == Some(request.rex_session)
                        && agent["rex_window_id"].as_str().is_some()
                        && agent["rex_block_id"].as_str().is_some() =>
                {
                    break (status, agent.clone());
                }
                Some("launch_pending" | "running") => {}
                _ => return Err("Coordinator stopped before the block-loss fault".into()),
            }
        }
        if Instant::now() >= deadline {
            return Err("Coordinator did not publish a running Rex block before the fault".into());
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    let window_id = agent["rex_window_id"]
        .as_str()
        .ok_or("Coordinator dashboard row omitted its Rex window")?;
    let block_id = agent["rex_block_id"]
        .as_str()
        .ok_or("Coordinator dashboard row omitted its Rex block")?;
    if agent["state"] != "running"
        || agent["rex_session_id"].as_str() != Some(request.rex_session)
        || status.pointer("/owner/active") != Some(&Value::Bool(true))
    {
        return Err("Coordinator block-loss stage did not start from a live owned AgentRun".into());
    }
    let generation = status
        .pointer("/owner/generation")
        .and_then(Value::as_u64)
        .ok_or("controller status omitted owner generation")?;
    let rex = RexCliTransport::connect(
        request.rex,
        &[],
        request.rex_server.to_owned(),
        request.expected_instance.to_owned(),
        request.rex_session.to_owned(),
        BTreeMap::new(),
    )
    .map_err(|error| format!("connect to pinned Rex identity: {error}"))?;
    let window = TicketWindow {
        server_instance_id: request.expected_instance.to_owned(),
        session_id: request.rex_session.to_owned(),
        window_id: window_id.to_owned(),
        label: String::new(),
        initial_block_id: Some(block_id.to_owned()),
        disposition: CreateDisposition::Existing,
    };
    if !rex
        .agent_block_is_present(&window, run_id, block_id)
        .map_err(|error| format!("verify exact Coordinator block before close: {error}"))?
    {
        return Err("exact Coordinator block was absent before the fault".into());
    }

    let database = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open acceptance state read-only: {error}"))?;
    let baseline = recovery_state(&database, run_id, block_id)?;
    if baseline.generation != generation
        || baseline.disposition == "released"
        || baseline.state != "running"
    {
        return Err("Coordinator has no active recovery cursor at the block-loss boundary".into());
    }
    let deadline = Instant::now() + COORDINATOR_STAGE_LIMIT;
    let mut last_order = baseline.observation_order;
    let mut observed_advances = 0;
    while observed_advances < 2 {
        if Instant::now() >= deadline {
            return Err(
                "two regular live Coordinator recovery observations did not complete".into(),
            );
        }
        let status = product(request, state_root, &["status", "--json"])?;
        let snapshot = product(request, state_root, &["dashboard", "--json"])?;
        if !status.status.is_some_and(|status| status.success())
            || !snapshot.status.is_some_and(|status| status.success())
        {
            return Err(
                "controller status became unavailable before Coordinator block close".into(),
            );
        }
        let status = json_stdout(&status);
        let snapshot = json_stdout(&snapshot);
        let live_agent = dashboard_agent(&snapshot, run_id);
        if status.pointer("/owner/active") != Some(&Value::Bool(true))
            || !live_agent.is_some_and(|agent| agent["state"] == "running")
        {
            return Err("Coordinator or controller stopped before the block-loss fault".into());
        }
        let cursor = recovery_state(&database, run_id, block_id)?;
        if cursor.generation != generation || cursor.reservation_epoch != baseline.reservation_epoch
        {
            return Err(
                "Coordinator recovery cursor changed generation or reservation epoch".into(),
            );
        }
        if observe_cursor_advance(&mut last_order, cursor.observation_order)? {
            observed_advances += 1;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    if !rex
        .agent_block_is_present(&window, run_id, block_id)
        .map_err(|error| format!("recheck exact Coordinator block before close: {error}"))?
    {
        return Err("Coordinator block disappeared before the requested block-loss fault".into());
    }
    if let Err(error) = rex.close_agent_block(&window, run_id, block_id) {
        return Ok(json!({
            "status":"inconclusive",
            "reason":format!("close exact Coordinator block: {error}"),
            "fault_injected":null,
            "run_id":run_id,
            "reservation_epoch":baseline.reservation_epoch
        }));
    }

    let deadline = Instant::now() + COORDINATOR_STAGE_LIMIT;
    loop {
        let status = match product(request, state_root, &["status", "--json"]) {
            Ok(status) => status,
            Err(error) => {
                return Ok(
                    json!({"status":"inconclusive","reason":error,"fault_injected":true,"run_id":run_id,"reservation_epoch":baseline.reservation_epoch}),
                );
            }
        };
        let snapshot = match product(request, state_root, &["dashboard", "--json"]) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(
                    json!({"status":"inconclusive","reason":error,"fault_injected":true,"run_id":run_id,"reservation_epoch":baseline.reservation_epoch}),
                );
            }
        };
        if !status.status.is_some_and(|status| status.success())
            || !snapshot.status.is_some_and(|status| status.success())
        {
            return Ok(
                json!({"status":"inconclusive","reason":"controller status became unavailable after block close","fault_injected":true,"run_id":run_id,"reservation_epoch":baseline.reservation_epoch}),
            );
        }
        let status = json_stdout(&status);
        let snapshot = json_stdout(&snapshot);
        let evidence = match recovery_state(&database, run_id, block_id) {
            Ok(evidence) => evidence,
            Err(error) => {
                return Ok(
                    json!({"status":"inconclusive","reason":error,"fault_injected":true,"run_id":run_id,"reservation_epoch":baseline.reservation_epoch}),
                );
            }
        };
        let agent_cancelled =
            dashboard_agent(&snapshot, run_id).is_some_and(|agent| agent["state"] == "cancelled");
        let proof_complete = status.pointer("/owner/active") == Some(&Value::Bool(true))
            && evidence.generation == generation
            && evidence.reservation_epoch == baseline.reservation_epoch
            && observed_advances == 2
            && agent_cancelled
            && evidence.disposition == "released"
            && evidence.event_received
            && evidence.exit_confirmed
            && evidence.slot_released;
        if proof_complete {
            return Ok(json!({
                "status":"passed",
                "run_id":run_id,
                "reservation_epoch":evidence.reservation_epoch,
                "recovery_observation_order":evidence.observation_order,
                "observed_live_recovery_advances":observed_advances,
                "agent_state":"cancelled",
                "slot_disposition":evidence.disposition,
                "process_survived":evidence.process_survived,
                "lifecycle_facts":{"event_received":true,"exit_confirmed":true,"slot_released":true},
                "fault_injected":true,
                "owner_active":true
            }));
        }
        if Instant::now() >= deadline {
            return Ok(json!({
                "status":"timed_out",
                "run_id":run_id,
                "reservation_epoch":evidence.reservation_epoch,
                "recovery_observation_order":evidence.observation_order,
                "observed_live_recovery_advances":observed_advances,
                "agent_state":dashboard_agent(&snapshot, run_id).and_then(|agent| agent["state"].as_str()),
                "slot_disposition":evidence.disposition,
                "lifecycle_facts":{"event_received":evidence.event_received,"exit_confirmed":evidence.exit_confirmed,"slot_released":evidence.slot_released},
                "process_survived":evidence.process_survived,
                "fault_injected":true,
                "owner_active":status.pointer("/owner/active") == Some(&Value::Bool(true))
            }));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn observe_cursor_advance(last: &mut Option<u64>, current: Option<u64>) -> Result<bool, String> {
    let Some(current) = current else {
        return Ok(false);
    };
    match *last {
        None => {
            *last = Some(current);
            Ok(false)
        }
        Some(previous) if current > previous => {
            *last = Some(current);
            Ok(true)
        }
        Some(previous) if current == previous => Ok(false),
        Some(_) => Err("Coordinator recovery observation order moved backwards".into()),
    }
}

struct RecoveryState {
    generation: u64,
    reservation_epoch: u64,
    observation_order: Option<u64>,
    disposition: String,
    state: String,
    event_received: bool,
    exit_confirmed: bool,
    slot_released: bool,
    process_survived: Option<Value>,
}

fn recovery_state(
    database: &Connection,
    run_id: &str,
    block_id: &str,
) -> Result<RecoveryState, String> {
    struct RecoveryStateRow {
        generation: u64,
        reservation_epoch: u64,
        disposition: String,
        state: String,
        observed_generation: Option<u64>,
        observed_epoch: Option<u64>,
        order: Option<u64>,
        event_received: bool,
        exit_confirmed: bool,
        slot_released: bool,
        survived: Option<String>,
    }

    let row: Option<RecoveryStateRow> = database
        .query_row(
            "SELECT r.controller_generation,s.reservation_epoch,s.disposition,r.state,
                    o.controller_generation,o.reservation_epoch,o.observation_order,
                    EXISTS(SELECT 1 FROM agent_block_lifecycle_facts f WHERE f.agent_run_id=r.agent_run_id AND f.reservation_epoch=s.reservation_epoch AND f.rex_block_id=?2 AND f.fact_type='event_received'),
                    EXISTS(SELECT 1 FROM agent_block_lifecycle_facts f WHERE f.agent_run_id=r.agent_run_id AND f.reservation_epoch=s.reservation_epoch AND f.rex_block_id=?2 AND f.fact_type='exit_confirmed'),
                    EXISTS(SELECT 1 FROM agent_block_lifecycle_facts f WHERE f.agent_run_id=r.agent_run_id AND f.reservation_epoch=s.reservation_epoch AND f.rex_block_id=?2 AND f.fact_type='slot_released'),
                    (SELECT f.detail_json FROM agent_block_lifecycle_facts f WHERE f.agent_run_id=r.agent_run_id AND f.reservation_epoch=s.reservation_epoch AND f.rex_block_id=?2 AND f.fact_type='process_survived')
             FROM agent_runs r JOIN execution_slots s
               ON s.owner_kind='agent_run' AND s.owner_id=r.agent_run_id
             LEFT JOIN agent_run_recovery_observations o USING(agent_run_id)
             WHERE r.agent_run_id=?1",
            params![run_id, block_id],
            |row| {
                Ok(RecoveryStateRow {
                    generation: row.get(0)?,
                    reservation_epoch: row.get(1)?,
                    disposition: row.get(2)?,
                    state: row.get(3)?,
                    observed_generation: row.get(4)?,
                    observed_epoch: row.get(5)?,
                    order: row.get(6)?,
                    event_received: row.get(7)?,
                    exit_confirmed: row.get(8)?,
                    slot_released: row.get(9)?,
                    survived: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|error| format!("read Coordinator recovery cursor: {error}"))?;
    let RecoveryStateRow {
        generation,
        reservation_epoch,
        disposition,
        state,
        observed_generation,
        observed_epoch,
        order,
        event_received,
        exit_confirmed,
        slot_released,
        survived,
    } = row.ok_or("Coordinator AgentRun slot was absent from fixture state")?;
    match (observed_generation, observed_epoch, order) {
        (None, None, None) => {}
        (Some(observed_generation), Some(observed_epoch), Some(_))
            if observed_generation == generation && observed_epoch == reservation_epoch => {}
        _ => return Err("Coordinator recovery cursor is not bound to its active slot".into()),
    }
    Ok(RecoveryState {
        generation,
        reservation_epoch,
        observation_order: order,
        disposition,
        state,
        event_received,
        exit_confirmed,
        slot_released,
        process_survived: survived.and_then(|detail| serde_json::from_str(&detail).ok()),
    })
}

fn dashboard_agent<'a>(dashboard: &'a Value, run_id: &str) -> Option<&'a Value> {
    dashboard
        .get("agents")?
        .as_array()?
        .iter()
        .find(|agent| agent["agent_run_id"] == run_id && agent["role"] == "coordinator")
}

fn dashboard_worker<'a>(dashboard: &'a Value, run_id: &str) -> Option<&'a Value> {
    dashboard
        .get("agents")?
        .as_array()?
        .iter()
        .find(|agent| agent["agent_run_id"] == run_id && agent["role"] == "worker")
}

fn observe_native_worker_block_loss(
    request: &Request<'_>,
    state_root: &Path,
    worker: &Value,
    scenario: NativeBlockLossScenario,
) -> Result<Value, String> {
    let ready_at = Instant::now();
    let string = |key: &str| {
        worker
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("native Worker ready evidence omitted {key}"))
    };
    let run_id = string("run_id")?;
    let session_id = string("session_id")?;
    let window_id = string("window_id")?;
    let block_id = string("block_id")?;
    let control_dir = PathBuf::from(string("control_dir")?);
    let epoch = worker["reservation_epoch"]
        .as_u64()
        .ok_or("native Worker ready evidence omitted reservation epoch")?;
    let wrapper = &worker["wrapper_process_identity"];
    let provider = &worker["provider_start_observation"];
    let wrapper_pid = wrapper["pid"]
        .as_u64()
        .ok_or("native Worker ready evidence omitted wrapper PID")?;
    let wrapper_start = wrapper["start_identity"]
        .as_str()
        .ok_or("native Worker ready evidence omitted wrapper birth token")?;
    let provider_pid = provider["provider_pid"]
        .as_u64()
        .ok_or("native Worker ready evidence omitted provider PID")?;
    let provider_start = provider["provider_start_identity"]
        .as_str()
        .ok_or("native Worker ready evidence omitted provider birth token")?;
    if session_id != request.rex_session
        || worker["server_instance_id"] != request.expected_instance
    {
        return Err("native Worker ready identity differs from the pinned Rex session".into());
    }
    let rex = RexCliTransport::connect(
        request.rex,
        &[],
        request.rex_server.to_owned(),
        request.expected_instance.to_owned(),
        session_id.to_owned(),
        BTreeMap::new(),
    )
    .map_err(|error| format!("connect to pinned Rex identity for native block loss: {error}"))?;
    let window = TicketWindow {
        server_instance_id: request.expected_instance.to_owned(),
        session_id: session_id.to_owned(),
        window_id: window_id.to_owned(),
        label: String::new(),
        initial_block_id: Some(block_id.to_owned()),
        disposition: CreateDisposition::Existing,
    };
    let database = Connection::open_with_flags(
        state_root.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|error| format!("open native Worker state read-only: {error}"))?;
    let initial_status = product(request, state_root, &["status", "--json"])?;
    require_success(
        "read native Worker controller before block loss",
        &initial_status,
    )?;
    let initial_status = json_stdout(&initial_status);
    let generation = initial_status
        .pointer("/owner/generation")
        .and_then(Value::as_u64)
        .ok_or("controller status omitted native Worker generation")?;
    let baseline = recovery_state(&database, run_id, block_id)?;
    let (slot_pool, slot_index): (String, u64) = database
        .query_row(
            "SELECT pool,slot_index FROM execution_slots WHERE owner_kind='agent_run' AND owner_id=?1 AND reservation_epoch=?2",
            params![run_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("read native Worker reservation slot: {error}"))?;
    if baseline.reservation_epoch != epoch
        || baseline.state != "running"
        || baseline.disposition != "live"
        || baseline.generation != generation
    {
        return Err("native Worker state did not match its ready run and live reservation".into());
    }
    let ready_deadline = ready_at + NATIVE_WORKER_READY_LIMIT;
    let terminal_deadline = ready_at + NATIVE_WORKER_TERMINAL_LIMIT;
    let mut last_order = baseline.observation_order;
    let mut advances = 0;
    let spool = RunStepSpool::open(&control_dir)
        .map_err(|error| format!("open native Worker run-step spool: {error}"))?;
    let binding = spool
        .read_run_family_binding()
        .map_err(|error| format!("read native Worker run-family binding: {error}"))?;
    if binding.agent_run_id.as_str() != run_id
        || binding.reservation_epoch != epoch
        || binding.wrapper_pid as u64 != wrapper_pid
        || binding.wrapper_start_identity != wrapper_start
    {
        return Ok(
            json!({"status":"inconclusive","reason":"native Worker run-family binding did not match its ready run, epoch, or wrapper","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
        );
    }
    let (sleep_identity, mut pre_close_process_identities) = loop {
        if Instant::now() >= ready_deadline {
            return Ok(
                json!({"status":"inconclusive","reason":"two live recovery observations and the exact sleep process did not arrive within the ready budget","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        let status = product(request, state_root, &["status", "--json"])?;
        let dashboard = product(request, state_root, &["dashboard", "--json"])?;
        require_success("read native Worker status before block loss", &status)?;
        require_success("read native Worker dashboard before block loss", &dashboard)?;
        let status = json_stdout(&status);
        let dashboard = json_stdout(&dashboard);
        let agent = dashboard_worker(&dashboard, run_id);
        if status.pointer("/owner/active") != Some(&Value::Bool(true))
            || status.pointer("/owner/generation").and_then(Value::as_u64)
                != Some(baseline.generation)
            || !agent.is_some_and(|agent| {
                agent["state"] == "running"
                    && agent["rex_session_id"] == session_id
                    && agent["rex_window_id"] == window_id
                    && agent["rex_block_id"] == block_id
            })
        {
            return Ok(
                json!({"status":"inconclusive","reason":"pinned Worker or controller identity changed before block loss","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        if !rex
            .agent_block_is_present(&window, run_id, block_id)
            .map_err(|error| format!("verify exact native Worker block before close: {error}"))?
        {
            return Ok(
                json!({"status":"inconclusive","reason":"exact owned Worker block disappeared before requested close","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        let family = match spool.read_run_family_record() {
            Ok(Some(family)) => family,
            Ok(None) => {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "read validated native Worker run-family record: {error}"
                ));
            }
        };
        if family.binding != binding
            || family.coverage != RunFamilyCoverage::Observing
            || family.wrapper_process.pid as u64 != wrapper_pid
            || family.wrapper_process.start_identity != wrapper_start
            || family.provider_root.pid as u64 != provider_pid
            || family.provider_root.start_identity != provider_start
        {
            return Ok(
                json!({"status":"inconclusive","reason":"current process-family receipt did not match the ready Worker run and epoch","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        let process_snapshot = inspect_process_table()
            .map_err(|error| format!("inspect native Worker process family: {error:?}"))?;
        let mut sleep = None;
        for identity in family
            .process_tree
            .iter()
            .filter(|identity| identity.command == "sleep")
        {
            if !process_snapshot.iter().any(|process| {
                process.pid == identity.pid
                    && process.start_identity == identity.start_identity
                    && process.quality == ProcessIdentityQuality::KernelBirthToken
            }) {
                continue;
            }
            let command = invoke(
                Path::new("/bin/ps"),
                &[
                    OsString::from("-p"),
                    OsString::from(identity.pid.to_string()),
                    OsString::from("-o"),
                    OsString::from("command="),
                ],
                None,
                None,
                STEP_TIMEOUT,
            )?;
            let command = String::from_utf8_lossy(&command.stdout);
            let argv = command.split_whitespace().collect::<Vec<_>>();
            if matches!(argv.as_slice(), ["/bin/sleep", "300"] | ["sleep", "300"]) {
                sleep = Some(identity);
                break;
            }
        }
        if let Some(sleep) = sleep {
            let cursor = recovery_state(&database, run_id, block_id)?;
            if cursor.generation != baseline.generation
                || cursor.reservation_epoch != epoch
                || cursor.disposition != "live"
                || cursor.state != "running"
            {
                return Ok(
                    json!({"status":"inconclusive","reason":"native Worker recovery cursor changed before block loss","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
                );
            }
            if observe_cursor_advance(&mut last_order, cursor.observation_order)? {
                advances += 1;
            }
            if advances == 2 {
                let sleep = serde_json::to_value(sleep).map_err(|error| {
                    format!("serialize validated native Worker process: {error}")
                })?;
                let process_tree = serde_json::to_value(&family.process_tree)
                    .map_err(|error| {
                        format!("serialize validated native Worker process tree: {error}")
                    })?
                    .as_array()
                    .cloned()
                    .ok_or("validated native Worker process tree is not an array")?;
                break (sleep, process_tree);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    };
    if let Some(ready_processes) = worker["live_process_identities"].as_array() {
        for identity in ready_processes {
            if !pre_close_process_identities.contains(identity) {
                pre_close_process_identities.push(identity.clone());
            }
        }
    }
    let mut post_fault_context = NativePostFaultContext {
        run_id,
        epoch,
        block_id,
        slot_pool: &slot_pool,
        slot_index,
        pre_close_process_identities: &pre_close_process_identities,
        reader_fault: None,
    };
    let mut reader_absent_close_deadline = None;
    if scenario == NativeBlockLossScenario::MissedEvent {
        match kill_owned_events_reader(request, state_root, generation, session_id) {
            Ok(fault) => {
                post_fault_context.reader_fault = Some(fault.evidence);
                reader_absent_close_deadline = Some(fault.close_deadline);
                if let Some(error) = fault.failure {
                    let (_, mut report) =
                        native_post_fault_report(&database, &post_fault_context, None, &[error]);
                    report["status"] = json!("incomplete");
                    return Ok(report);
                }
            }
            Err(error) => {
                return Ok(json!({
                    "status":"incomplete",
                    "reason":error,
                    "fault_injected":false,
                    "run_id":run_id,
                    "reservation_epoch":epoch,
                    "block_id":block_id,
                    "lifecycle_facts":{"event_received":false,"process_survived":null,"exit_confirmed":false,"slot_released":false}
                }));
            }
        }
    }
    match close_native_worker_block_before_deadline(
        reader_absent_close_deadline
            .map_or(ready_deadline, |deadline| deadline.min(ready_deadline)),
        || {
            if scenario == NativeBlockLossScenario::MissedEvent {
                verify_worker_still_live_after_reader_fault(
                    request,
                    state_root,
                    &database,
                    &rex,
                    &window,
                    &post_fault_context,
                    generation,
                    session_id,
                    &control_dir,
                    &binding,
                    wrapper_pid as u32,
                    wrapper_start,
                    provider_pid as u32,
                    provider_start,
                    sleep_identity["pid"].as_u64().unwrap_or_default() as u32,
                    sleep_identity["start_identity"]
                        .as_str()
                        .unwrap_or_default(),
                )
            } else {
                Ok(())
            }
        },
        || {
            rex.agent_block_is_present(&window, run_id, block_id)
                .map_err(|error| format!("recheck native Worker block before close: {error}"))
        },
        || {
            rex.close_agent_block(&window, run_id, block_id)
                .map_err(|error| format!("close exact native Worker block: {error}"))
        },
    ) {
        Ok(NativeBlockCloseOutcome::Closed) => {}
        Ok(NativeBlockCloseOutcome::BlockAbsent) => {
            if post_fault_context.reader_fault.is_some() {
                let (_, mut report) = native_post_fault_report(
                    &database,
                    &post_fault_context,
                    Some(true),
                    &["exact Worker block was already absent before the one allowed close".into()],
                );
                report["status"] = json!("incomplete");
                report["close_attempted_once"] = json!(false);
                report["block_close_outcome"] = json!("not_attempted");
                return Ok(report);
            }
            return Ok(
                json!({"status":"inconclusive","reason":"exact Worker block was absent before close","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        Ok(NativeBlockCloseOutcome::DeadlineExpired) => {
            if post_fault_context.reader_fault.is_some() {
                let (_, mut report) = native_post_fault_report(
                    &database,
                    &post_fault_context,
                    None,
                    &[
                        "five-second reader-absent close deadline expired before block close"
                            .into(),
                    ],
                );
                report["status"] = json!("incomplete");
                report["close_attempted_once"] = json!(false);
                report["block_close_outcome"] = json!("not_attempted_deadline_expired");
                return Ok(report);
            }
            return Ok(
                json!({"status":"inconclusive","reason":"ready budget expired after exact Worker block validation","run_id":run_id,"reservation_epoch":epoch,"fault_injected":false}),
            );
        }
        Ok(NativeBlockCloseOutcome::ClosedAfterDeadline) => {
            let (_, mut report) = native_post_fault_report(
                &database,
                &post_fault_context,
                None,
                &[
                    "block.close returned after the five-second reader-absent close deadline"
                        .into(),
                ],
            );
            report["status"] = json!("incomplete");
            report["close_attempted_once"] = json!(true);
            report["block_close_outcome"] = json!("returned_after_deadline");
            return Ok(report);
        }
        Err(error) => {
            let (_, mut report) =
                native_post_fault_report(&database, &post_fault_context, None, &[error]);
            report["status"] = json!("incomplete");
            report["fault_injected"] = Value::Null;
            if post_fault_context.reader_fault.is_some() {
                report["close_attempted_once"] = Value::Null;
                report["block_close_outcome"] = json!("unknown_after_attempt");
            }
            return Ok(report);
        }
    }
    if scenario == NativeBlockLossScenario::MissedEvent {
        let (Some(_close_deadline), Some(reader_fault)) = (
            reader_absent_close_deadline,
            post_fault_context.reader_fault.as_ref(),
        ) else {
            let (_, mut report) = native_post_fault_report(
                &database,
                &post_fault_context,
                None,
                &["missed-event reader fault evidence was incomplete after block.close".into()],
            );
            report["status"] = json!("incomplete");
            return Ok(report);
        };
        let Some(controller_pid) = reader_fault["controller_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            let (_, mut report) = native_post_fault_report(
                &database,
                &post_fault_context,
                None,
                &["reader fault evidence omitted controller PID".into()],
            );
            report["status"] = json!("incomplete");
            return Ok(report);
        };
        let Some(controller_start_identity) = reader_fault["controller_start_identity"].as_str()
        else {
            let (_, mut report) = native_post_fault_report(
                &database,
                &post_fault_context,
                None,
                &["reader fault evidence omitted controller birth identity".into()],
            );
            report["status"] = json!("incomplete");
            return Ok(report);
        };
        let replacement_deadline = match replacement_reader_wait_deadline(
            _close_deadline,
            Instant::now(),
            terminal_deadline,
        ) {
            Ok(deadline) => deadline,
            Err(error) => {
                let (_, mut report) =
                    native_post_fault_report(&database, &post_fault_context, None, &[error]);
                report["status"] = json!("incomplete");
                return Ok(report);
            }
        };
        if let Err(error) = wait_for_replacement_events_reader(
            request,
            state_root,
            generation,
            session_id,
            replacement_deadline,
            controller_pid,
            controller_start_identity,
        ) {
            let (_, mut report) =
                native_post_fault_report(&database, &post_fault_context, None, &[error]);
            report["status"] = json!("incomplete");
            return Ok(report);
        }
        if let Some(reader_fault) = post_fault_context.reader_fault.as_mut() {
            reader_fault["replacement_seen_after_close"] = json!(true);
        }
    }
    let event_deadline = (Instant::now() + NATIVE_WORKER_READY_LIMIT).min(terminal_deadline);
    loop {
        let presence = rex.agent_block_is_present(&window, run_id, block_id);
        if let Some(report) =
            native_post_close_presence_error_report(&database, &post_fault_context, &presence)
        {
            return Ok(report);
        }
        let block_absent = presence.map(|present| !present).ok();
        let facts = match native_lifecycle_facts(&database, run_id, epoch, block_id) {
            Ok(facts) => facts,
            Err(error) => {
                let (_, mut report) = native_post_fault_report(
                    &database,
                    &post_fault_context,
                    block_absent,
                    &[error],
                );
                report["status"] = json!("incomplete");
                return Ok(report);
            }
        };
        let event_condition = match scenario {
            NativeBlockLossScenario::DeliveredEvent => facts.event_received,
            NativeBlockLossScenario::MissedEvent => !facts.event_received,
        };
        if block_absent == Some(true) && event_condition {
            break;
        }
        if Instant::now() >= event_deadline {
            let (_, mut report) = native_post_fault_report(
                &database,
                &post_fault_context,
                block_absent,
                &["expected lifecycle event state or public block absence was not proven within 60 seconds".into()],
            );
            report["status"] = json!("incomplete");
            return Ok(report);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let block_absent = true;
    loop {
        let (_, mut report) =
            native_post_fault_report(&database, &post_fault_context, Some(block_absent), &[]);
        if report["observation_errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty())
        {
            report["status"] = json!("incomplete");
            return Ok(report);
        }
        let facts = match native_lifecycle_facts(&database, run_id, epoch, block_id) {
            Ok(facts) => facts,
            Err(error) => {
                report["status"] = json!("incomplete");
                report["observation_errors"] = json!([error]);
                return Ok(report);
            }
        };
        let terminal_proof_complete = native_terminal_proof_complete_for_event(
            &facts,
            report["run_state"].as_str(),
            report["launch_state"].as_str(),
            scenario == NativeBlockLossScenario::DeliveredEvent,
        );
        report["terminal_proof_complete"] = json!(terminal_proof_complete);
        if block_absent && report["local_family_absent"] == true && terminal_proof_complete {
            report["status"] = json!("passed");
            report["pre_close_sleep_identity"] = sleep_identity;
            return Ok(report);
        }
        if Instant::now() >= terminal_deadline {
            report["status"] = json!("incomplete");
            return Ok(report);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

struct NativeLifecycleFacts {
    event_received: bool,
    process_survived: Option<Value>,
    exit_confirmed: bool,
    exit_detail: Option<Value>,
    exit_proof_digest: Option<String>,
    slot_released: bool,
    slot_release_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeBlockLossScenario {
    DeliveredEvent,
    MissedEvent,
}

struct OwnedEventsReader {
    identity: ProcessIdentity,
    command: String,
    image_sha256: String,
}

struct NativeReaderFault {
    evidence: Value,
    close_deadline: Instant,
    failure: Option<String>,
}

fn owned_events_reader(
    request: &Request<'_>,
    controller: &ProcessIdentity,
    endpoint: &str,
    session_id: &str,
    current: &[ProcessIdentity],
) -> Result<Option<OwnedEventsReader>, String> {
    let rex_path = fs::canonicalize(request.rex)
        .map_err(|error| format!("resolve pinned Rex image: {error}"))?;
    let rex_digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&rex_path).map_err(|error| {
            format!("read pinned Rex image {}: {error}", rex_path.display())
        })?)
    );
    let command_fragment = format!("-S {endpoint} events -s {session_id} --json");
    let mut matches = Vec::new();
    for candidate in current.iter().filter(|process| {
        process.parent_pid == controller.pid
            && process.quality == ProcessIdentityQuality::KernelBirthToken
    }) {
        let Some(image_path) = executable_path_for_identity(candidate)
            .map_err(|error| format!("resolve Rex event child image: {error:?}"))?
        else {
            continue;
        };
        let Ok(image_bytes) = fs::read(&image_path) else {
            continue;
        };
        let image_sha256 = format!("{:x}", Sha256::digest(image_bytes));
        if image_sha256 != rex_digest {
            continue;
        }
        let command = invoke(
            Path::new("/bin/ps"),
            &[
                OsString::from("-p"),
                OsString::from(candidate.pid.to_string()),
                OsString::from("-o"),
                OsString::from("command="),
            ],
            None,
            None,
            STEP_TIMEOUT,
        )?;
        let flattened_command = String::from_utf8_lossy(&command.stdout).trim().to_owned();
        if !flattened_command.starts_with(rex_path.to_string_lossy().as_ref())
            || !flattened_command.contains(&command_fragment)
        {
            continue;
        }
        matches.push(OwnedEventsReader {
            identity: candidate.clone(),
            command: flattened_command,
            image_sha256,
        });
    }
    if matches.len() > 1 {
        return Err("multiple direct pinned Rex event readers matched the owned session".into());
    }
    Ok(matches.pop())
}

fn runtime_owner_projection_matches(
    request: &Request<'_>,
    state_root: &Path,
    generation: u64,
) -> Result<ProcessIdentity, String> {
    let path = state_root.join("runtime-owner.json");
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "read controller owner projection {}: {error}",
            path.display()
        )
    })?;
    let owner: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse controller owner projection: {error}"))?;
    let pid = owner["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("controller owner projection omitted PID")?;
    let start_identity = owner["process_start_identity"]
        .as_str()
        .ok_or("controller owner projection omitted process birth identity")?;
    let expected_product_digest = format!(
        "{:x}",
        Sha256::digest(
            fs::read(request.cli).map_err(|error| format!("read pinned product CLI: {error}"))?
        )
    );
    let expected_product_path = fs::canonicalize(request.cli)
        .map_err(|error| format!("resolve pinned product CLI path: {error}"))?;
    let projected_product_path = owner["executable_path"]
        .as_str()
        .ok_or("controller owner projection omitted executable path")?;
    if owner["schema_version"] != 1
        || owner["generation"].as_u64() != Some(generation)
        || owner["state_root"].as_str() != Some(state_root.to_string_lossy().as_ref())
        || owner["rex_endpoint"].as_str() != Some(request.rex_server)
        || owner["rex_server_identity"].as_str() != Some(request.expected_instance)
        || owner["rex_session_id"].as_str() != Some(request.rex_session)
        || owner["executable_digest"].as_str() != Some(expected_product_digest.as_str())
        || fs::canonicalize(projected_product_path).ok().as_ref() != Some(&expected_product_path)
    {
        return Err(
            "controller owner projection does not match the pinned product and Rex identity".into(),
        );
    }
    let identity = process_identity_for_pid(pid)
        .map_err(|error| format!("inspect controller process birth identity: {error:?}"))?
        .filter(|identity| {
            owner_projection_start_identity_matches(identity, start_identity)
                && identity.quality == ProcessIdentityQuality::KernelBirthToken
        })
        .ok_or("controller process no longer matches its owner projection")?;
    let executable = executable_path_for_identity(&identity)
        .map_err(|error| format!("resolve controller executable: {error:?}"))?
        .ok_or("controller executable changed during identity check")?;
    let digest = format!(
        "{:x}",
        Sha256::digest(
            fs::read(executable)
                .map_err(|error| format!("read controller executable image: {error}"))?
        )
    );
    if digest != expected_product_digest {
        return Err("controller executable image differs from the pinned product digest".into());
    }
    Ok(identity)
}

fn owner_projection_start_identity_matches(
    identity: &ProcessIdentity,
    projected_identity: &str,
) -> bool {
    #[cfg(target_os = "macos")]
    let identity = identity.start_identity.strip_prefix("macos-start:");
    #[cfg(target_os = "linux")]
    let identity = identity.start_identity.strip_prefix("linux-start-ticks:");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let identity: Option<&str> = None;
    identity == Some(projected_identity)
}

fn verify_public_controller_status(
    request: &Request<'_>,
    state_root: &Path,
    generation: u64,
    controller: &ProcessIdentity,
) -> Result<(), String> {
    let output = product(request, state_root, &["status", "--json"])?;
    require_success(
        "recheck controller status before Rex reader signal",
        &output,
    )?;
    let status = json_stdout(&output);
    if status.pointer("/owner/active") != Some(&Value::Bool(true))
        || status.pointer("/owner/generation").and_then(Value::as_u64) != Some(generation)
        || status.pointer("/owner/pid").and_then(Value::as_u64) != Some(controller.pid as u64)
        || status
            .pointer("/owner/rex_endpoint")
            .and_then(Value::as_str)
            != Some(request.rex_server)
        || status
            .pointer("/owner/rex_server_instance")
            .and_then(Value::as_str)
            != Some(request.expected_instance)
        || status.pointer("/owner/rex_session").and_then(Value::as_str) != Some(request.rex_session)
    {
        return Err("public controller status changed before Rex reader signal".into());
    }
    Ok(())
}

fn kill_owned_events_reader(
    request: &Request<'_>,
    state_root: &Path,
    generation: u64,
    session_id: &str,
) -> Result<NativeReaderFault, String> {
    let controller = runtime_owner_projection_matches(request, state_root, generation)?;
    let current = inspect_process_table()
        .map_err(|error| format!("inspect processes before Rex reader fault: {error:?}"))?;
    let reader = owned_events_reader(
        request,
        &controller,
        request.rex_server,
        session_id,
        &current,
    )?
    .ok_or("no direct child matched the pinned Rex event reader command")?;

    let checked_controller = runtime_owner_projection_matches(request, state_root, generation)?;
    verify_public_controller_status(request, state_root, generation, &checked_controller)?;
    let checked_processes = inspect_process_table()
        .map_err(|error| format!("recheck processes before Rex reader fault: {error:?}"))?;
    let checked_reader = owned_events_reader(
        request,
        &checked_controller,
        request.rex_server,
        session_id,
        &checked_processes,
    )?
    .ok_or("pinned Rex event reader changed before the requested fault")?;
    if checked_controller.pid != controller.pid
        || checked_controller.start_identity != controller.start_identity
        || checked_reader.identity.pid != reader.identity.pid
        || checked_reader.identity.start_identity != reader.identity.start_identity
        || checked_reader.command != reader.command
        || checked_reader.image_sha256 != reader.image_sha256
    {
        return Err("controller or pinned Rex event reader identity changed before signal".into());
    }
    let fault_at = Instant::now();
    let close_deadline = fault_at + Duration::from_secs(5);
    let mut evidence = json!({
        "fault":"single_pid_sigterm",
        "signal_attempted":true,
        "signal_result":"unknown",
        "pid":reader.identity.pid,
        "start_identity":reader.identity.start_identity,
        "image_sha256":reader.image_sha256,
        "flattened_command":reader.command,
        "original_identity_absent":false,
        "replacement_seen_before_close":false,
        "controller_pid":checked_controller.pid,
        "controller_start_identity":checked_controller.start_identity,
        "reader_absent_close_limit_seconds":5
    });
    let signalled = match signal_process_if_observed(
        &reader.identity,
        &checked_processes,
        ProcessSignal::Terminate,
    ) {
        Ok(signalled) => signalled,
        Err(error) => {
            evidence["signal_result"] = json!("unknown");
            return Ok(NativeReaderFault {
                evidence,
                close_deadline,
                failure: Some(format!("signal exact pinned Rex event reader: {error:?}")),
            });
        }
    };
    evidence["signal_result"] = json!(if signalled { "sent" } else { "already_absent" });
    if !signalled {
        return Ok(NativeReaderFault {
            evidence,
            close_deadline,
            failure: Some("pinned Rex event reader exited before the requested signal".into()),
        });
    }
    loop {
        let current = match inspect_process_table() {
            Ok(current) => current,
            Err(error) => {
                return Ok(NativeReaderFault {
                    evidence,
                    close_deadline,
                    failure: Some(format!("inspect after Rex reader fault: {error:?}")),
                });
            }
        };
        let original_live = current.iter().any(|process| {
            process.pid == reader.identity.pid
                && process.start_identity == reader.identity.start_identity
        });
        if !original_live {
            evidence["original_identity_absent"] = json!(true);
            let controller = match runtime_owner_projection_matches(request, state_root, generation)
            {
                Ok(controller) => controller,
                Err(error) => {
                    return Ok(NativeReaderFault {
                        evidence,
                        close_deadline,
                        failure: Some(error),
                    });
                }
            };
            if controller.pid != checked_controller.pid
                || controller.start_identity != checked_controller.start_identity
            {
                return Ok(NativeReaderFault {
                    evidence,
                    close_deadline,
                    failure: Some("controller identity changed after Rex reader fault".into()),
                });
            }
            let replacement = match owned_events_reader(
                request,
                &controller,
                request.rex_server,
                session_id,
                &current,
            ) {
                Ok(replacement) => replacement,
                Err(error) => {
                    return Ok(NativeReaderFault {
                        evidence,
                        close_deadline,
                        failure: Some(error),
                    });
                }
            };
            if replacement.is_none() {
                return Ok(NativeReaderFault {
                    evidence,
                    close_deadline,
                    failure: None,
                });
            }
            evidence["replacement_seen_before_close"] = json!(true);
            return Ok(NativeReaderFault {
                evidence,
                close_deadline,
                failure: Some(
                    "replacement Rex event reader appeared before the block could be closed".into(),
                ),
            });
        }
        if Instant::now() >= close_deadline {
            return Ok(NativeReaderFault {
                evidence,
                close_deadline,
                failure: Some(
                    "original Rex event reader did not exit within the bounded reconnect gap"
                        .into(),
                ),
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_replacement_events_reader(
    request: &Request<'_>,
    state_root: &Path,
    generation: u64,
    session_id: &str,
    deadline: Instant,
    expected_controller_pid: u32,
    expected_controller_start_identity: &str,
) -> Result<(), String> {
    wait_for_condition_before(
        deadline,
        POLL_INTERVAL,
        Instant::now,
        std::thread::sleep,
        || {
            let controller = runtime_owner_projection_matches(request, state_root, generation)?;
            if controller.pid != expected_controller_pid
                || controller.start_identity != expected_controller_start_identity
            {
                return Err(
                    "replacement event reader would belong to a different controller".into(),
                );
            }
            verify_public_controller_status(request, state_root, generation, &controller)?;
            let current = inspect_process_table()
                .map_err(|error| format!("inspect replacement Rex event reader: {error:?}"))?;
            Ok(owned_events_reader(
                request,
                &controller,
                request.rex_server,
                session_id,
                &current,
            )?
            .is_some())
        },
        "same controller did not start a live pinned Rex event reader within the readiness budget",
    )
}

fn wait_for_condition_before(
    deadline: Instant,
    interval: Duration,
    mut now: impl FnMut() -> Instant,
    mut pause: impl FnMut(Duration),
    mut condition: impl FnMut() -> Result<bool, String>,
    timeout_message: &str,
) -> Result<(), String> {
    loop {
        let satisfied = condition()?;
        if now() >= deadline {
            return Err(timeout_message.into());
        }
        if satisfied {
            return Ok(());
        }
        pause(interval);
    }
}

fn replacement_reader_wait_deadline(
    close_deadline: Instant,
    close_returned_at: Instant,
    terminal_deadline: Instant,
) -> Result<Instant, String> {
    if close_returned_at >= close_deadline {
        return Err("block.close returned outside the reader-absent gap".into());
    }
    Ok((close_returned_at + NATIVE_WORKER_READY_LIMIT).min(terminal_deadline))
}

#[allow(clippy::too_many_arguments)]
fn verify_worker_still_live_after_reader_fault(
    request: &Request<'_>,
    state_root: &Path,
    database: &Connection,
    rex: &RexCliTransport,
    window: &TicketWindow,
    context: &NativePostFaultContext<'_>,
    generation: u64,
    session_id: &str,
    control_dir: &Path,
    binding: &rex_projects::run_step_spool::RunFamilyBinding,
    wrapper_pid: u32,
    wrapper_start: &str,
    provider_pid: u32,
    provider_start: &str,
    sleep_pid: u32,
    sleep_start: &str,
) -> Result<(), String> {
    let fault = context
        .reader_fault
        .as_ref()
        .ok_or("post-fault Worker verification lacks reader fault evidence")?;
    let expected_controller_pid = fault["controller_pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("reader fault evidence omitted controller PID")?;
    let expected_controller_start = fault["controller_start_identity"]
        .as_str()
        .ok_or("reader fault evidence omitted controller birth identity")?;
    let status = product(request, state_root, &["status", "--json"])?;
    let dashboard = product(request, state_root, &["dashboard", "--json"])?;
    require_success("verify controller after Rex reader fault", &status)?;
    require_success("verify Worker after Rex reader fault", &dashboard)?;
    let status = json_stdout(&status);
    let dashboard = json_stdout(&dashboard);
    if status.pointer("/owner/active") != Some(&Value::Bool(true))
        || status.pointer("/owner/generation").and_then(Value::as_u64) != Some(generation)
        || !dashboard_worker(&dashboard, context.run_id).is_some_and(|agent| {
            agent["state"] == "running"
                && agent["rex_session_id"] == session_id
                && agent["rex_window_id"] == window.window_id
                && agent["rex_block_id"] == context.block_id
        })
    {
        return Err("controller or exact Worker state changed after the Rex reader fault".into());
    }
    let recovery = recovery_state(database, context.run_id, context.block_id)?;
    if recovery.generation != generation
        || recovery.reservation_epoch != context.epoch
        || recovery.disposition != "live"
        || recovery.state != "running"
        || recovery.event_received
    {
        return Err("Worker run or live reservation changed after the Rex reader fault".into());
    }
    let current = inspect_process_table()
        .map_err(|error| format!("verify Worker process family after reader fault: {error:?}"))?;
    let controller = runtime_owner_projection_matches(request, state_root, generation)?;
    if controller.pid != expected_controller_pid
        || controller.start_identity != expected_controller_start
    {
        return Err(
            "Worker recovery moved to a different controller after the reader fault".into(),
        );
    }
    verify_public_controller_status(request, state_root, generation, &controller)?;
    if !exact_process_identities_are_live(
        &[
            (wrapper_pid, wrapper_start),
            (provider_pid, provider_start),
            (sleep_pid, sleep_start),
        ],
        &current,
    ) {
        return Err(
            "Worker wrapper, provider, or foreground process exited after the Rex reader fault"
                .into(),
        );
    }
    let family = RunStepSpool::open(control_dir)
        .map_err(|error| format!("reopen Worker run-step spool after reader fault: {error}"))?
        .read_run_family_record()
        .map_err(|error| format!("read Worker family after Rex reader fault: {error}"))?
        .ok_or("Worker process-family receipt disappeared after reader fault")?;
    if &family.binding != binding
        || family.coverage != RunFamilyCoverage::Observing
        || family.wrapper_process.pid != wrapper_pid
        || family.wrapper_process.start_identity != wrapper_start
        || family.provider_root.pid != provider_pid
        || family.provider_root.start_identity != provider_start
    {
        return Err("Worker family receipt changed after the Rex reader fault".into());
    }
    if !rex
        .agent_block_is_present(window, context.run_id, context.block_id)
        .map_err(|error| format!("verify Worker block after reader fault: {error}"))?
    {
        return Err("exact Worker block disappeared before the one allowed close".into());
    }
    let process_table = inspect_process_table()
        .map_err(|error| format!("recheck event reader before block close: {error:?}"))?;
    if owned_events_reader(
        request,
        &controller,
        request.rex_server,
        session_id,
        &process_table,
    )?
    .is_some()
    {
        return Err("replacement event reader appeared before exact block close".into());
    }
    Ok(())
}

fn exact_process_identities_are_live(
    expected: &[(u32, &str)],
    current: &[ProcessIdentity],
) -> bool {
    expected.iter().all(|(pid, start)| {
        current.iter().any(|process| {
            process.pid == *pid
                && process.start_identity == *start
                && process.quality == ProcessIdentityQuality::KernelBirthToken
        })
    })
}

struct NativePostFaultContext<'a> {
    run_id: &'a str,
    epoch: u64,
    block_id: &'a str,
    slot_pool: &'a str,
    slot_index: u64,
    pre_close_process_identities: &'a [Value],
    reader_fault: Option<Value>,
}

#[derive(Debug)]
enum NativeBlockCloseOutcome {
    BlockAbsent,
    DeadlineExpired,
    ClosedAfterDeadline,
    Closed,
}

fn close_native_worker_block_before_deadline(
    deadline: Instant,
    before_close: impl FnOnce() -> Result<(), String>,
    is_present: impl FnOnce() -> Result<bool, String>,
    close: impl FnOnce() -> Result<(), String>,
) -> Result<NativeBlockCloseOutcome, String> {
    if Instant::now() >= deadline {
        return Ok(NativeBlockCloseOutcome::DeadlineExpired);
    }
    before_close()?;
    if !is_present()? {
        return Ok(NativeBlockCloseOutcome::BlockAbsent);
    }
    if Instant::now() >= deadline {
        return Ok(NativeBlockCloseOutcome::DeadlineExpired);
    }
    close()?;
    Ok(if Instant::now() > deadline {
        NativeBlockCloseOutcome::ClosedAfterDeadline
    } else {
        NativeBlockCloseOutcome::Closed
    })
}

fn native_post_fault_report(
    database: &Connection,
    context: &NativePostFaultContext<'_>,
    public_block_absent: Option<bool>,
    initial_errors: &[String],
) -> (bool, Value) {
    let NativePostFaultContext {
        run_id,
        epoch,
        block_id,
        slot_pool,
        slot_index,
        pre_close_process_identities,
        reader_fault,
    } = context;
    let mut observation_errors = initial_errors.to_vec();
    let facts = match native_lifecycle_facts(database, run_id, *epoch, block_id) {
        Ok(facts) => Some(facts),
        Err(error) => {
            observation_errors.push(error);
            None
        }
    };
    let run_state: Option<String> = match database
        .query_row(
            "SELECT state FROM agent_runs WHERE agent_run_id=?1",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
    {
        Ok(state) => state,
        Err(error) => {
            observation_errors.push(format!("read native Worker terminal run state: {error}"));
            None
        }
    };
    let launch_state: Option<String> = match database
        .query_row(
            "SELECT state FROM agent_launch_state WHERE agent_run_id=?1",
            [run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
    {
        Ok(state) => state,
        Err(error) => {
            observation_errors.push(format!("read native Worker terminal launch state: {error}"));
            None
        }
    };
    let current_slot_owner: Result<Option<Value>, String> = database
        .query_row("SELECT owner_kind,owner_id,reservation_epoch,disposition FROM execution_slots WHERE pool=?1 AND slot_index=?2", params![slot_pool, *slot_index], |row| Ok(json!({"owner_kind":row.get::<_,String>(0)?,"owner_id":row.get::<_,String>(1)?,"reservation_epoch":row.get::<_,u64>(2)?,"disposition":row.get::<_,String>(3)?})))
        .optional()
        .map_err(|error| format!("read current native Worker slot owner: {error}"));
    let current_slot_owner = match current_slot_owner {
        Ok(owner) => owner,
        Err(error) => {
            observation_errors.push(error);
            None
        }
    };
    let local_family_absent = match inspect_process_table() {
        Ok(current_processes) => Some(pre_close_process_identities.iter().all(|identity| {
            let pid = identity["pid"].as_u64().unwrap_or_default() as u32;
            let start = identity["start_identity"].as_str().unwrap_or_default();
            !current_processes
                .iter()
                .any(|process| process.pid == pid && process.start_identity == start)
        })),
        Err(error) => {
            observation_errors.push(format!(
                "inspect native Worker family after block loss: {error:?}"
            ));
            None
        }
    };
    let terminal_proof_complete = facts.as_ref().is_some_and(|facts| {
        native_terminal_proof_complete(facts, run_state.as_deref(), launch_state.as_deref())
    });
    let facts = facts.as_ref();
    let report = json!({
        "run_id":run_id,
        "reservation_epoch":epoch,
        "block_id":block_id,
        "lifecycle_facts":{
            "event_received":facts.map(|facts| facts.event_received),
            "process_survived":facts.and_then(|facts| facts.process_survived.clone()),
            "exit_confirmed":facts.map(|facts| facts.exit_confirmed),
            "process_tree_absent":facts.and_then(|facts| facts.exit_detail.as_ref()).and_then(|detail| detail["process_tree_absent"].as_bool()),
            "process_tree_digest":facts.and_then(|facts| facts.exit_detail.as_ref()).and_then(|detail| detail["process_tree_digest"].as_str()),
            "exit_proof_digest":facts.and_then(|facts| facts.exit_proof_digest.as_deref()),
            "slot_release_digest":facts.and_then(|facts| facts.slot_release_digest.as_deref()),
            "slot_released":facts.map(|facts| facts.slot_released)
        },
        "public_block_absent":public_block_absent,
        "terminal_proof_complete":terminal_proof_complete,
        "run_state":run_state,
        "launch_state":launch_state,
        "current_slot_owner":current_slot_owner,
        "pre_close_process_identities":pre_close_process_identities,
        "local_family_absent":local_family_absent,
        "fault_injected":true,
        "reader_fault":reader_fault,
        "reason":observation_errors.first(),
        "status":if observation_errors.is_empty() {"observing"} else {"incomplete"},
        "observation_errors":observation_errors
    });
    (terminal_proof_complete, report)
}

fn native_post_close_presence_error_report<E: std::fmt::Display>(
    database: &Connection,
    context: &NativePostFaultContext<'_>,
    presence: &Result<bool, E>,
) -> Option<Value> {
    let Err(error) = presence else {
        return None;
    };
    let (_, mut report) = native_post_fault_report(
        database,
        context,
        None,
        &[format!("verify native Worker block after close: {error}")],
    );
    report["status"] = json!("incomplete");
    Some(report)
}

fn native_terminal_proof_complete(
    facts: &NativeLifecycleFacts,
    run_state: Option<&str>,
    launch_state: Option<&str>,
) -> bool {
    native_terminal_proof_complete_for_event(facts, run_state, launch_state, true)
}

fn native_terminal_proof_complete_for_event(
    facts: &NativeLifecycleFacts,
    run_state: Option<&str>,
    launch_state: Option<&str>,
    expected_event_received: bool,
) -> bool {
    facts.event_received == expected_event_received
        && facts.exit_confirmed
        && facts.exit_detail.as_ref().is_some_and(|detail| {
            detail["process_tree_absent"] == true
                && detail["process_tree_digest"].as_str().is_some()
        })
        && facts.exit_proof_digest.is_some()
        && facts.exit_proof_digest == facts.slot_release_digest
        && facts.slot_released
        && run_state == Some("cancelled")
        && launch_state == Some("cancelled")
}

fn native_lifecycle_facts(
    database: &Connection,
    run_id: &str,
    epoch: u64,
    block_id: &str,
) -> Result<NativeLifecycleFacts, String> {
    let mut statement = database
        .prepare("SELECT fact_type,detail_json,proof_digest FROM agent_block_lifecycle_facts WHERE agent_run_id=?1 AND reservation_epoch=?2 AND rex_block_id=?3")
        .map_err(|error| format!("prepare immutable native lifecycle fact query: {error}"))?;
    let rows = statement
        .query_map(params![run_id, epoch, block_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|error| format!("query immutable native lifecycle facts: {error}"))?;
    let mut facts = NativeLifecycleFacts {
        event_received: false,
        process_survived: None,
        exit_confirmed: false,
        exit_detail: None,
        exit_proof_digest: None,
        slot_released: false,
        slot_release_digest: None,
    };
    for row in rows {
        let (fact_type, detail, proof_digest) =
            row.map_err(|error| format!("read immutable native lifecycle fact: {error}"))?;
        let detail: Value = serde_json::from_str(&detail)
            .map_err(|error| format!("parse native lifecycle detail: {error}"))?;
        match fact_type.as_str() {
            "event_received" => facts.event_received = true,
            "process_survived" => facts.process_survived = Some(detail),
            "exit_confirmed" => {
                facts.exit_confirmed = true;
                facts.exit_detail = Some(detail);
                facts.exit_proof_digest = proof_digest;
            }
            "slot_released" => {
                facts.slot_released = true;
                facts.slot_release_digest = proof_digest;
            }
            _ => {}
        }
    }
    Ok(facts)
}

fn parse_rex_window(stdout: &[u8]) -> Result<(String, String), String> {
    let value: Value = serde_json::from_slice(stdout)
        .map_err(|error| format!("Rex window creation returned invalid JSON: {error}"))?;
    let window = value
        .get("window_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("Rex window creation omitted window_id")?;
    let block = value
        .get("block_ids")
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("Rex window creation omitted its initial block ID")?;
    Ok((window, block))
}

fn json_stdout(output: &ProcessOutput) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&output.stdout).trim()}))
}

fn unsupported(
    fixture_root: &Path,
    trace: &[Value],
    capability: &str,
    resources_created: bool,
) -> Result<(), String> {
    let report = json!({
        "status":"UNSUPPORTED", "missing_capabilities":[capability], "trace":trace,
        "resources_created":resources_created, "provider_qualification":"not_claimed",
        "fixture_root":fixture_root
    });
    emit_report(fixture_root, &report)?;
    Ok(())
}

fn emit_report(fixture_root: &Path, report: &Value) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?;
    fs::write(fixture_root.join("acceptance-trace.json"), &encoded)
        .map_err(|error| format!("write acceptance trace: {error}"))?;
    println!(
        "{}",
        serde_json::to_string(report).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_projects::adapters::rex::owned_agent_block_label;
    use rex_projects::engine::orchestration::{RoleArtifactReference, RoleOutputKind};

    #[cfg(target_os = "macos")]
    fn production_process_start_identity(pid: u32) -> String {
        use std::ffi::{c_int, c_void};
        #[repr(C)]
        struct ProcBsdInfo {
            _prefix: [u32; 12],
            _command: [i8; 16],
            _name: [i8; 32],
            _middle: [u32; 5],
            _nice: i32,
            start_seconds: u64,
            start_microseconds: u64,
        }
        unsafe extern "C" {
            fn proc_pidinfo(
                pid: c_int,
                flavor: c_int,
                arg: u64,
                buffer: *mut c_void,
                size: c_int,
            ) -> c_int;
        }
        let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
        let size = std::mem::size_of::<ProcBsdInfo>() as c_int;
        let found = unsafe { proc_pidinfo(pid as c_int, 3, 0, info.as_mut_ptr().cast(), size) };
        assert_eq!(found, size);
        let info = unsafe { info.assume_init() };
        format!("{}:{}", info.start_seconds, info.start_microseconds)
    }

    #[cfg(target_os = "linux")]
    fn production_process_start_identity(pid: u32) -> String {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        stat.rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .to_owned()
    }

    #[cfg(unix)]
    #[test]
    fn runtime_owner_projection_consumer_accepts_public_runtime_output() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;

        struct ControllerGuard(std::process::Child);

        impl ControllerGuard {
            fn wait(&mut self, timeout: Duration) -> std::process::ExitStatus {
                let deadline = Instant::now() + timeout;
                loop {
                    if let Some(status) = self.0.try_wait().unwrap() {
                        return status;
                    }
                    assert!(Instant::now() < deadline, "fixture controller did not stop");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }

        impl Drop for ControllerGuard {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(None)) {
                    if let Ok(processes) = inspect_process_table() {
                        let _ = rex_projects::process::signal_process_group_if_observed(
                            self.0.id(),
                            &processes,
                            &processes,
                            rex_projects::process::ProcessSignal::Kill,
                        );
                    }
                    let _ = self.0.kill();
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                while matches!(self.0.try_wait(), Ok(None)) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }

        let temporary = tempfile::tempdir().unwrap();
        let fixture = temporary.path();
        let state_root = fixture.join("state");
        fs::create_dir(&state_root).unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let xtask_executable = current_exe.clone();
        let product_cli = current_exe
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("rex-projects");
        assert!(product_cli.is_file(), "build the production CLI first");
        let rex = fixture.join("rex");
        fs::write(
            &rex,
            r##"#!/bin/sh
case "$*" in
  *whoami*) printf '%s\n' '{"endpoint":"http://fixture","instance_id":"fixture-owner-server","host_id":"fixture-host","rex_version":"test"}' ;;
  *"api list"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"api call session.view"*) printf '%s\n' '{"session_id":"projection-session","windows":[{"window_id":"fixture-window","layers":[{"blocks":[{"block_id":"fixture-controller-block","label":"runtime-owner-projection-test","flavor":"shell"}]}]}]}' ;;
  *"events -s projection-session --json"*) exec /bin/sleep 2 ;;
  *) exit 0 ;;
esac
"##,
        )
        .unwrap();
        fs::set_permissions(&rex, fs::Permissions::from_mode(0o700)).unwrap();
        let request = Request {
            cli: &product_cli,
            rex: &rex,
            rex_server: "http://fixture",
            rex_session: "projection-session",
            expected_instance: "fixture-owner-server",
            fixture_root: fixture,
        };
        prepare_profiles(
            &request,
            &xtask_executable,
            &product_cli,
            ProfilePreparation::default(),
        )
        .unwrap();
        fs::write(
            fixture.join("config.toml"),
            config_text(&request, &xtask_executable, false),
        )
        .unwrap();
        let applied = product(&request, &state_root, &["config", "apply", "--bootstrap"]).unwrap();
        require_success("bootstrap runtime owner fixture", &applied).unwrap();

        let mut command = std::process::Command::new(&product_cli);
        command
            .args([
                "--config",
                fixture.join("config.toml").to_str().unwrap(),
                "--state-root",
                state_root.to_str().unwrap(),
                "runtime",
                "run",
                "--rex-server",
                "http://fixture",
            ])
            .env("REX_SESSION", request.rex_session)
            .env("REX_BLOCK", "fixture-controller-block")
            .env("XDG_STATE_HOME", fixture.join("xdg-state"))
            .env_remove("REX_PROJECTS_AGENT")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .process_group(0);
        let mut controller = ControllerGuard(command.spawn().unwrap());
        let controller_identity = process_identity_for_pid(controller.0.id())
            .unwrap()
            .unwrap();
        assert_eq!(
            controller_identity.process_group_id,
            controller.0.id(),
            "test controller must own the process group used by scoped cleanup"
        );
        let projection_path = state_root.join("runtime-owner.json");
        let startup_deadline = Instant::now() + Duration::from_secs(10);
        while !projection_path.is_file() && Instant::now() < startup_deadline {
            if let Some(status) = controller.0.try_wait().unwrap() {
                panic!("fixture controller exited before projection: {status}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            projection_path.is_file(),
            "public runtime did not write {} (state entries: {:?})",
            projection_path.display(),
            fs::read_dir(&state_root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        let projection: Value =
            serde_json::from_slice(&fs::read(&projection_path).unwrap()).unwrap();
        let generation = projection["generation"].as_u64().unwrap();
        assert_eq!(
            projection["pid"].as_u64(),
            Some(u64::from(controller.0.id()))
        );
        let status = product(&request, &state_root, &["--json", "status"]).unwrap();
        require_success("read public runtime owner status", &status).unwrap();
        let status: Value = serde_json::from_slice(&status.stdout).unwrap();
        assert_eq!(status.pointer("/owner/active"), Some(&Value::Bool(true)));
        assert_eq!(
            status.pointer("/owner/generation").and_then(Value::as_u64),
            Some(generation)
        );
        let observed = runtime_owner_projection_matches(&request, &state_root, generation).unwrap();
        assert_eq!(observed.pid, controller.0.id());
        assert_eq!(observed.quality, ProcessIdentityQuality::KernelBirthToken);

        let wrong_state_root = fixture.join("wrong-owner-projection");
        fs::create_dir(&wrong_state_root).unwrap();
        let mut wrong_projection = projection;
        wrong_projection["state_root"] = json!(wrong_state_root.to_string_lossy());
        wrong_projection["process_start_identity"] = json!("not-the-controller-birth-token");
        fs::write(
            wrong_state_root.join("runtime-owner.json"),
            serde_json::to_vec(&wrong_projection).unwrap(),
        )
        .unwrap();
        assert_eq!(
            runtime_owner_projection_matches(&request, &wrong_state_root, generation).unwrap_err(),
            "controller process no longer matches its owner projection"
        );

        let stopped = product(
            &request,
            &state_root,
            &["runtime", "stop", "--request-id", "owner-projection-stop"],
        )
        .unwrap();
        require_success("stop fixture runtime controller", &stopped).unwrap();
        assert!(controller.wait(Duration::from_secs(10)).success());
    }

    fn fixture_body_receipt(
        approved_body_digest: rex_projects::domain::ids::Digest,
    ) -> rex_projects::merge_executor::MergeStepReceipt {
        let pull = rex_projects::forge::PullRequestRef {
            repository: rex_projects::forge::RepositoryRef {
                host: "github.com".into(),
                owner: "fixture".into(),
                name: "repository".into(),
                expected_id: Some(1),
            },
            number: 7,
            expected_node_id: Some("fixture-pr-7".into()),
        };
        let operation_key = "body-operation:prepare-body".to_owned();
        let body = rex_projects::forge::BodyUpdateIntent {
            pull: pull.clone(),
            operation_key: operation_key.clone(),
            expected_head_sha: "a".repeat(40),
            expected_prior_body_digest: rex_projects::domain::ids::Digest::parse("b".repeat(64))
                .unwrap(),
            exact_body: "approved body\nCo-authored-by: Codex <noreply@openai.com>\n".into(),
            approved_body_digest,
        };
        let request_digest = serialized_sha256_digest(&body).unwrap();
        let effect_intent = rex_projects::forge::MergeEffectIntent {
            pull,
            operation_key: operation_key.clone(),
            request_digest: request_digest.clone(),
            operation: rex_projects::forge::MergeEffectOperation::UpdateBody(body),
            attempt_started_unix: 100,
        };
        rex_projects::merge_executor::MergeStepReceipt {
            step_key: "prepare-body".into(),
            operation_key: operation_key.clone(),
            certainty: rex_projects::forge::EffectCertainty::Recovered,
            request_digest: request_digest.clone(),
            effect_intent,
            acknowledgement: rex_projects::forge::EffectAcknowledgement {
                operation_key,
                request_digest,
                certainty: rex_projects::forge::EffectCertainty::Recovered,
                external_id: Some("7".into()),
                external_url: None,
                resulting_head_sha: None,
                resulting_merge_sha: None,
                reason: None,
            },
        }
    }

    #[test]
    fn native_worker_block_loss_stage_is_supported_and_unknown_stages_are_rejected() {
        assert_eq!(
            parse_acceptance_stage(Some(NATIVE_WORKER_BLOCK_LOSS_STAGE.into())).unwrap(),
            Some(NATIVE_WORKER_BLOCK_LOSS_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE.into()))
                .unwrap(),
            Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE.into())
        );
        assert_eq!(
            qualification_roles_for_stage(Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE)),
            &["planner", "worker", "supervisor", "coordinator"]
        );
        assert!(!bounded_stage_contract_valid(
            Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE),
            true,
            false
        ));
        assert!(parse_acceptance_stage(Some("unknown-stage".into())).is_err());
    }

    #[test]
    fn native_worker_dashboard_lookup_uses_production_run_key_and_owned_label() {
        let dashboard = json!({"agents":[{
            "agent_run_id":"agent-8a74cf92b3d564907f3caab948be4b0e",
            "role":"worker",
            "state":"running"
        }]});
        let worker = dashboard_worker(&dashboard, "agent-8a74cf92b3d564907f3caab948be4b0e")
            .expect("saved production dashboard shape identifies the live Worker");
        assert_eq!(worker["state"], "running");
        assert!(dashboard_worker(&dashboard, "missing-run").is_none());
        assert_eq!(
            owned_agent_block_label("agent-8a74cf92b3d564907f3caab948be4b0e").unwrap(),
            "rex-projects-run-9e13a3f483531832d02dc440"
        );
    }

    #[test]
    fn native_lifecycle_proof_requires_all_exact_epoch_facts_after_slot_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let writable = Connection::open(&path).unwrap();
        writable
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT PRIMARY KEY);
                 CREATE TABLE execution_slots(pool TEXT,slot_index INTEGER,owner_kind TEXT,owner_id TEXT,reservation_epoch INTEGER,disposition TEXT);
                 CREATE TABLE agent_block_lifecycle_facts(
                    fact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_run_id TEXT NOT NULL REFERENCES agent_runs(agent_run_id),
                    reservation_epoch INTEGER NOT NULL CHECK(reservation_epoch > 0),
                    rex_block_id TEXT NOT NULL,
                    fact_type TEXT NOT NULL CHECK(fact_type IN ('event_received','process_survived','exit_confirmed','slot_released')),
                    observed_at_unix INTEGER NOT NULL CHECK(observed_at_unix >= 0),
                    proof_digest TEXT CHECK(proof_digest IS NULL OR length(proof_digest)=64),
                    detail_json TEXT NOT NULL CHECK(length(detail_json) <= 65536),
                    UNIQUE(agent_run_id,reservation_epoch,rex_block_id,fact_type,observed_at_unix)
                 );
                 INSERT INTO agent_runs VALUES('run-old');
                 INSERT INTO execution_slots VALUES('worker',2,'agent_run','run-new',9,'live');",
            )
            .unwrap();
        let digest = "d".repeat(64);
        writable
            .execute(
                "INSERT INTO agent_block_lifecycle_facts(agent_run_id,reservation_epoch,rex_block_id,fact_type,observed_at_unix,proof_digest,detail_json) VALUES
                 ('run-old',8,'block-old','event_received',1,NULL,'{}'),
                 ('run-old',8,'block-old','process_survived',2,?1,'{\"surviving_process_count\":1}'),
                 ('run-old',8,'block-old','exit_confirmed',3,?1,'{\"process_tree_absent\":true,\"process_tree_digest\":\"' || ?1 || '\"}'),
                 ('run-old',8,'block-old','slot_released',4,?1,'{\"process_tree_digest\":\"' || ?1 || '\"}')",
                [&digest],
            )
            .unwrap();
        drop(writable);

        let readonly =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let facts = native_lifecycle_facts(&readonly, "run-old", 8, "block-old").unwrap();
        assert!(native_terminal_proof_complete(
            &facts,
            Some("cancelled"),
            Some("cancelled")
        ));
        let missed_event_facts = NativeLifecycleFacts {
            event_received: false,
            process_survived: facts.process_survived.clone(),
            exit_confirmed: facts.exit_confirmed,
            exit_detail: facts.exit_detail.clone(),
            exit_proof_digest: facts.exit_proof_digest.clone(),
            slot_released: facts.slot_released,
            slot_release_digest: facts.slot_release_digest.clone(),
        };
        assert!(native_terminal_proof_complete_for_event(
            &missed_event_facts,
            Some("cancelled"),
            Some("cancelled"),
            false
        ));
        assert!(!native_terminal_proof_complete_for_event(
            &facts,
            Some("cancelled"),
            Some("cancelled"),
            false
        ));
        assert_eq!(
            facts.process_survived.as_ref().unwrap()["surviving_process_count"],
            1
        );
        assert!(!native_terminal_proof_complete(
            &facts,
            Some("running"),
            Some("cancelled")
        ));
        assert!(
            !native_lifecycle_facts(&readonly, "run-old", 9, "block-old")
                .unwrap()
                .event_received
        );
        assert!(
            !native_lifecycle_facts(&readonly, "run-old", 8, "other-block")
                .unwrap()
                .event_received
        );
        let readiness_only = NativeLifecycleFacts {
            event_received: false,
            process_survived: None,
            exit_confirmed: false,
            exit_detail: None,
            exit_proof_digest: None,
            slot_released: false,
            slot_release_digest: None,
        };
        assert!(!native_terminal_proof_complete(
            &readiness_only,
            Some("running"),
            Some("running")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn native_block_loss_acceptance_runs_through_rex_transport_and_lifecycle_storage() {
        use std::os::unix::fs::PermissionsExt;

        use rex_projects::domain::ids::{AgentRunId, Digest};
        use rex_projects::run_step_spool::{
            RunFamilyBinding, RunFamilyCoverage, RunFamilyRecord, RunStepSpool,
        };

        let temporary = tempfile::tempdir().unwrap();
        let test_mode = std::env::var("REX_PROJECTS_NATIVE_BLOCK_LOSS_TEST_MODE").ok();
        if test_mode.is_none() {
            for mode in ["normal", "uncertain-close"] {
                let mode_root = temporary.path().join(mode);
                fs::create_dir(&mode_root).unwrap();
                let isolated_state = mode_root.join("xdg-state");
                fs::create_dir(&isolated_state).unwrap();
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "acceptance::tests::native_block_loss_acceptance_runs_through_rex_transport_and_lifecycle_storage",
                    ])
                    .env("REX_PROJECTS_NATIVE_BLOCK_LOSS_TEST_MODE", mode)
                    .env("REX_PROJECTS_NATIVE_BLOCK_LOSS_TEST_ROOT", &mode_root)
                    .env("XDG_STATE_HOME", isolated_state)
                    .status()
                    .unwrap();
                assert!(status.success(), "{mode} native block loss fixture failed");
            }
            return;
        }
        let fixture =
            PathBuf::from(std::env::var_os("REX_PROJECTS_NATIVE_BLOCK_LOSS_TEST_ROOT").unwrap());
        fs::create_dir_all(&fixture).unwrap();
        let state_root = fixture.join("state");
        let control_dir = fixture.join("control");
        fs::create_dir(&state_root).unwrap();
        fs::create_dir(&control_dir).unwrap();
        let product_cli = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("rex-projects");
        assert!(
            product_cli.is_file(),
            "build the real rex-projects CLI first"
        );
        let xtask_executable = std::env::current_exe().unwrap();
        let run_id = "agent-8a74cf92b3d564907f3caab948be4b0e";
        let block_id = "block-test";
        let session_id = "session-test";
        let window_id = "window-test";
        let instance_id = "instance-test";
        let endpoint = "unix:///fixture/rex.sock";
        let config_request = Request {
            cli: &product_cli,
            rex: Path::new("/usr/bin/true"),
            rex_server: endpoint,
            rex_session: session_id,
            expected_instance: instance_id,
            fixture_root: &fixture,
        };
        prepare_profiles(
            &config_request,
            &xtask_executable,
            &product_cli,
            ProfilePreparation::default(),
        )
        .unwrap();
        let config_path = fixture.join("config.toml");
        fs::write(
            &config_path,
            config_text(&config_request, &xtask_executable, false),
        )
        .unwrap();
        let mut store = rex_projects::store::ConfigStore::open(&state_root).unwrap();
        let generation = store
            .start_owner(&rex_projects::store::OwnerMetadata {
                owner_nonce: "native-block-loss-test-owner".into(),
                state_root: state_root.display().to_string(),
                config_source: config_path.display().to_string(),
                process_start_identity: production_process_start_identity(std::process::id()),
                executable_path: xtask_executable.display().to_string(),
                executable_digest: "a".repeat(64),
                rex_endpoint: Some(endpoint.into()),
                rex_server_identity: Some(instance_id.into()),
                rex_session_id: Some(session_id.into()),
                rex_block_id: Some(block_id.into()),
            })
            .unwrap();
        drop(store);
        let database_path = state_root.join("state.sqlite3");
        let writable = Connection::open(&database_path).unwrap();
        writable.pragma_update(None, "foreign_keys", "OFF").unwrap();
        writable.execute("INSERT INTO agent_runs(agent_run_id,project_id,config_source,config_revision,config_digest,role_session_id,logical_owner,finite_turn,launch_operation_id,rex_session_id,rex_window_id,rex_block_id,state,controller_generation,started_at_unix) VALUES (?1,'operations_project','fixture',1,?2,'fixture-worker','worker',1,'native-block-loss-test-operation',?3,?4,?5,'running',?6,1)", params![run_id,"b".repeat(64),session_id,window_id,block_id,generation]).unwrap();
        writable.execute("INSERT INTO execution_slots(pool,slot_index,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',1,'agent_run',?1,4,?2,'live')", params![run_id,generation]).unwrap();
        writable.execute("INSERT INTO agent_run_recovery_observations(agent_run_id,controller_generation,reservation_epoch,observation_order,observed_at_unix) VALUES (?1,?2,4,1,1)", params![run_id,generation]).unwrap();
        writable.execute("INSERT INTO agent_launch_state(agent_run_id,state,last_observed_at_unix,updated_at_unix) VALUES (?1,'running',1,1)", [run_id]).unwrap();
        drop(writable);

        let mut sleep = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap();
        let sleep_identity = (0..20)
            .find_map(|_| {
                let identity = inspect_process_table()
                    .unwrap()
                    .into_iter()
                    .find(|process| process.pid == sleep.id())?;
                (identity.quality == ProcessIdentityQuality::KernelBirthToken).then_some(identity)
            })
            .expect("test sleep process has a kernel birth token");
        let current_identity = inspect_process_table()
            .unwrap()
            .into_iter()
            .find(|process| process.pid == std::process::id())
            .expect("test process has an OS identity");
        let label = owned_agent_block_label(run_id).unwrap();
        let closed_marker = fixture.join("closed");
        let rex_view = fixture.join("rex-view.json");
        let rex_absent_view = fixture.join("rex-absent-view.json");
        let start_marker = fixture.join("started");
        fs::write(
            &rex_view,
            serde_json::to_vec(&json!({"session_id":session_id,"windows":[{"window_id":window_id,"layers":[{"blocks":[{"block_id":block_id,"label":label,"flavor":"shell"}]}]}]})).unwrap(),
        )
        .unwrap();
        fs::write(
            &rex_absent_view,
            serde_json::to_vec(&json!({"session_id":session_id,"windows":[{"window_id":window_id,"layers":[{"blocks":[]}]}]})).unwrap(),
        )
        .unwrap();
        let rex_script = fixture.join("rex");
        fs::write(
            &rex_script,
            format!(
                "#!/bin/sh\ncase \"$*\" in\n  *\"whoami --json\"*) if [ -f {closed:?} ] && [ \"{uncertain_mode}\" = true ]; then printf '%s\\n' '{{\"endpoint\":\"{endpoint}\",\"instance_id\":\"wrong-instance\",\"host_id\":\"host-test\",\"rex_version\":\"test\"}}'; else printf '%s\\n' '{{\"endpoint\":\"{endpoint}\",\"instance_id\":\"{instance_id}\",\"host_id\":\"host-test\",\"rex_version\":\"test\"}}'; fi ;;\n  *\"api list --json\"*) printf '%s\\n' '{{\"methods\":{{\"session.view\":{{}},\"session.new_window\":{{}},\"session.new_split\":{{}},\"session.focus_block\":{{}},\"session.zoom_block\":{{}},\"block.close\":{{}}}}}}' ;;\n  *\"api call session.view\"*) : > {started:?}; if [ -f {closed:?} ]; then cat {absent:?}; else cat {view:?}; fi ;;\n  *\"api call block.close\"*) : > {closed:?}; printf 'close\\n' >> {close_calls:?}; printf '{{}}\\n' ;;\n  *) exit 3 ;;\nesac\n",
                started = start_marker.display().to_string(),
                closed = closed_marker.display().to_string(),
                close_calls = fixture.join("close-calls").display().to_string(),
                absent = rex_absent_view.display().to_string(),
                view = rex_view.display().to_string(),
                uncertain_mode = (test_mode.as_deref() == Some("uncertain-close")),
            ),
        )
        .unwrap();
        fs::set_permissions(&rex_script, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            std::process::Command::new(&rex_script)
                .args(["whoami", "--json"])
                .output()
                .unwrap()
                .status
                .success()
        );

        let worker = json!({
            "run_id":run_id,
            "server_instance_id":instance_id,
            "session_id":session_id,
            "window_id":window_id,
            "block_id":block_id,
            "control_dir":control_dir,
            "reservation_epoch":4,
            "wrapper_process_identity":{"pid":current_identity.pid,"start_identity":current_identity.start_identity},
            "provider_start_observation":{"provider_pid":sleep_identity.pid,"provider_start_identity":sleep_identity.start_identity},
            "live_process_identities":[sleep_identity],
        });
        let binding = RunFamilyBinding {
            schema_version: 1,
            agent_run_id: AgentRunId::parse(run_id).unwrap(),
            reservation_epoch: 4,
            authority_digest: Digest::parse("b".repeat(64)).unwrap(),
            descriptor_digest: Digest::parse("c".repeat(64)).unwrap(),
            wrapper_pid: current_identity.pid,
            wrapper_start_identity: current_identity.start_identity.clone(),
            rex_launch_anchor: None,
        };
        let mut dead_sleep_identity = sleep_identity.clone();
        dead_sleep_identity.pid = sleep.id().saturating_add(1);
        dead_sleep_identity.start_identity = "dead-test-birth-token".into();
        let process_tree = vec![dead_sleep_identity, sleep_identity.clone()];
        let family = RunFamilyRecord {
            schema_version: 2,
            binding: binding.clone(),
            observed_at_unix: 1,
            coverage: RunFamilyCoverage::Observing,
            wrapper_process: current_identity,
            provider_root: sleep_identity,
            provider_executable_path: PathBuf::from("/bin/sleep"),
            provider_executable_digest: Digest::parse("d".repeat(64)).unwrap(),
            process_tree_digest: Digest::parse(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&process_tree).unwrap())
            ))
            .unwrap(),
            process_tree,
        };
        let spool = RunStepSpool::open(&control_dir).unwrap();
        spool.publish_run_family_binding_once(&binding).unwrap();
        spool.write_run_family_record(&family).unwrap();
        assert_eq!(
            spool.read_run_family_record().unwrap(),
            Some(family.clone())
        );

        let mut invalid_digest_family = family.clone();
        invalid_digest_family.process_tree_digest = Digest::parse("e".repeat(64)).unwrap();
        let invalid_records = [
            (
                "incomplete",
                br#"{"schema_version":2,"coverage":"observing","process_tree":[]}"#.to_vec(),
            ),
            (
                "incorrect-digest",
                serde_json::to_vec(&invalid_digest_family).unwrap(),
            ),
        ];
        let request = Request {
            cli: &product_cli,
            rex: &rex_script,
            rex_server: endpoint,
            rex_session: session_id,
            expected_instance: instance_id,
            fixture_root: &fixture,
        };
        for (case, invalid_record) in invalid_records {
            let invalid_control_dir = fixture.join(format!("invalid-control-{case}"));
            fs::create_dir(&invalid_control_dir).unwrap();
            let invalid_spool = RunStepSpool::open(&invalid_control_dir).unwrap();
            invalid_spool
                .publish_run_family_binding_once(&binding)
                .unwrap();
            fs::write(
                invalid_spool.directory().join("run-family.json"),
                invalid_record,
            )
            .unwrap();
            let invalid_worker = json!({
                "run_id":run_id,
                "server_instance_id":instance_id,
                "session_id":session_id,
                "window_id":window_id,
                "block_id":block_id,
                "control_dir":invalid_control_dir,
                "reservation_epoch":4,
                "wrapper_process_identity":{"pid":binding.wrapper_pid,"start_identity":binding.wrapper_start_identity},
                "provider_start_observation":{"provider_pid":family.provider_root.pid,"provider_start_identity":family.provider_root.start_identity},
                "live_process_identities":[family.provider_root],
            });
            assert!(
                observe_native_worker_block_loss(
                    &request,
                    &state_root,
                    &invalid_worker,
                    NativeBlockLossScenario::DeliveredEvent,
                )
                .unwrap_err()
                .contains("read validated native Worker run-family record")
            );
            assert!(
                !closed_marker.exists(),
                "invalid cumulative process evidence must stop before Rex block.close"
            );
        }
        let updater_db = database_path.clone();
        let updater_closed = closed_marker.clone();
        let updater_started = start_marker.clone();
        let updater = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut order = 1;
            while Instant::now() < deadline && !updater_closed.exists() {
                if updater_started.exists()
                    && let Ok(database) = Connection::open(&updater_db)
                {
                    order += 1;
                    let _ = database.execute("UPDATE agent_run_recovery_observations SET observation_order=?1 WHERE agent_run_id=?2", params![order, run_id]);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if updater_closed.exists() {
                let database = Connection::open(&updater_db).unwrap();
                database.execute_batch(
                    "INSERT INTO agent_block_lifecycle_facts(agent_run_id,reservation_epoch,rex_block_id,fact_type,observed_at_unix,proof_digest,detail_json) VALUES
                     ('agent-8a74cf92b3d564907f3caab948be4b0e',4,'block-test','event_received',1,NULL,'{}'),
                     ('agent-8a74cf92b3d564907f3caab948be4b0e',4,'block-test','process_survived',2,NULL,'{\"surviving_process_count\":1}');",
                ).unwrap();
                if sleep.try_wait().ok().flatten().is_none() {
                    let _ = sleep.kill();
                }
                let _ = sleep.wait();
                let digest = "e".repeat(64);
                database.execute(
                    "INSERT INTO agent_block_lifecycle_facts(agent_run_id,reservation_epoch,rex_block_id,fact_type,observed_at_unix,proof_digest,detail_json) VALUES ('agent-8a74cf92b3d564907f3caab948be4b0e',4,'block-test','exit_confirmed',3,?1,?2),('agent-8a74cf92b3d564907f3caab948be4b0e',4,'block-test','slot_released',4,?1,?3)",
                    params![digest, format!("{{\"process_tree_absent\":true,\"process_tree_digest\":\"{digest}\"}}"), format!("{{\"process_tree_digest\":\"{digest}\"}}")],
                ).unwrap();
                database.execute_batch("UPDATE agent_runs SET state='cancelled' WHERE agent_run_id='agent-8a74cf92b3d564907f3caab948be4b0e'; UPDATE agent_launch_state SET state='cancelled' WHERE agent_run_id='agent-8a74cf92b3d564907f3caab948be4b0e'; UPDATE execution_slots SET disposition='released' WHERE owner_id='agent-8a74cf92b3d564907f3caab948be4b0e';").unwrap();
            }
            sleep
        });

        let result = observe_native_worker_block_loss(
            &request,
            &state_root,
            &worker,
            NativeBlockLossScenario::DeliveredEvent,
        );
        if !closed_marker.exists() {
            fs::write(fixture.join("stop-updater"), "").unwrap();
        }
        let mut sleep = updater.join().unwrap();
        if sleep.try_wait().ok().flatten().is_none() {
            let _ = sleep.kill();
        }
        let _ = sleep.wait();
        let proof = result.unwrap();
        if test_mode.as_deref() == Some("uncertain-close") {
            assert!(closed_marker.exists(), "the stub applied block.close");
            assert_eq!(
                fs::read_to_string(fixture.join("close-calls"))
                    .unwrap()
                    .lines()
                    .count(),
                1
            );
            assert_eq!(proof["status"], "incomplete", "{proof}");
            assert_eq!(proof["fault_injected"], Value::Null, "{proof}");
            assert_eq!(proof["public_block_absent"], Value::Null, "{proof}");
            for fact in [
                "event_received",
                "process_survived",
                "exit_confirmed",
                "slot_released",
            ] {
                assert!(proof["lifecycle_facts"].get(fact).is_some(), "{proof}");
            }
            return;
        }
        assert_eq!(proof["status"], "passed", "{proof}");
        assert_eq!(proof["lifecycle_facts"]["event_received"], true);
        assert!(proof["lifecycle_facts"]["process_survived"].is_object());
        assert_eq!(proof["lifecycle_facts"]["exit_confirmed"], true);
        assert_eq!(proof["lifecycle_facts"]["slot_released"], true);
        assert_eq!(proof["current_slot_owner"]["owner_id"], run_id);

        let report_db = Connection::open(&database_path).unwrap();
        let report_context = NativePostFaultContext {
            run_id,
            epoch: 5,
            block_id,
            slot_pool: "agent",
            slot_index: 1,
            pre_close_process_identities: &[],
            reader_fault: None,
        };
        let (_, timeout_report) =
            native_post_fault_report(&report_db, &report_context, Some(true), &[]);
        assert_eq!(timeout_report["lifecycle_facts"]["event_received"], false);
        assert_eq!(
            timeout_report["lifecycle_facts"]["process_survived"],
            Value::Null
        );
        assert_eq!(timeout_report["lifecycle_facts"]["exit_confirmed"], false);
        assert_eq!(timeout_report["lifecycle_facts"]["slot_released"], false);
        assert_eq!(timeout_report["public_block_absent"], true);
        assert_eq!(timeout_report["terminal_proof_complete"], false);
        assert_eq!(timeout_report["current_slot_owner"]["owner_id"], run_id);
        assert_eq!(timeout_report["run_state"], "cancelled");

        let post_close_error_report = native_post_close_presence_error_report(
            &report_db,
            &report_context,
            &Err::<bool, String>("Rex query failed".into()),
        )
        .unwrap();
        assert!(
            closed_marker.exists(),
            "the exact close succeeded before the post-close observation failure"
        );
        assert_eq!(post_close_error_report["status"], "incomplete");
        assert_eq!(post_close_error_report["public_block_absent"], Value::Null);
        assert_eq!(
            post_close_error_report["reason"],
            "verify native Worker block after close: Rex query failed"
        );
        for fact in [
            "event_received",
            "process_survived",
            "exit_confirmed",
            "slot_released",
        ] {
            assert!(
                post_close_error_report["lifecycle_facts"]
                    .get(fact)
                    .is_some(),
                "missing {fact}: {post_close_error_report}"
            );
        }
        assert_eq!(post_close_error_report["terminal_proof_complete"], false);
    }

    #[test]
    fn native_block_close_skips_injection_when_presence_check_exhausts_deadline() {
        let deadline = Instant::now() + Duration::from_millis(10);
        let mut close_called = false;
        let outcome = close_native_worker_block_before_deadline(
            deadline,
            || Ok(()),
            || {
                std::thread::sleep(Duration::from_millis(20));
                Ok(true)
            },
            || {
                close_called = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(outcome, NativeBlockCloseOutcome::DeadlineExpired));
        assert!(!close_called);
    }

    #[test]
    fn native_block_close_stops_when_worker_identity_disappears_before_close() {
        let mut close_called = false;
        let expected = [(11, "wrapper"), (12, "provider"), (13, "sleep")];
        let current = vec![
            fixture_process_identity(11, "wrapper"),
            fixture_process_identity(12, "provider"),
        ];
        let outcome = close_native_worker_block_before_deadline(
            Instant::now() + Duration::from_secs(1),
            || {
                exact_process_identities_are_live(&expected, &current)
                    .then_some(())
                    .ok_or_else(|| {
                        "Worker provider or foreground birth identity disappeared".into()
                    })
            },
            || Ok(true),
            || {
                close_called = true;
                Ok(())
            },
        );
        assert_eq!(
            outcome.unwrap_err(),
            "Worker provider or foreground birth identity disappeared"
        );
        assert!(!close_called, "a stale Worker block must not be closed");
    }

    fn fixture_process_identity(pid: u32, start_identity: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            parent_pid: 1,
            process_group_id: 1,
            start_identity: start_identity.into(),
            command: "fixture".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        }
    }

    #[test]
    fn native_block_close_records_when_the_close_call_returns_after_deadline() {
        let deadline = Instant::now() + Duration::from_millis(5);
        let mut close_called = false;
        let outcome = close_native_worker_block_before_deadline(
            deadline,
            || Ok(()),
            || Ok(true),
            || {
                close_called = true;
                std::thread::sleep(Duration::from_millis(10));
                Ok(())
            },
        )
        .unwrap();
        assert!(close_called);
        assert!(matches!(
            outcome,
            NativeBlockCloseOutcome::ClosedAfterDeadline
        ));
    }

    #[test]
    fn replacement_reader_wait_accepts_a_delayed_reader_after_the_close_gap() {
        let fault_at = Instant::now();
        let close_deadline = fault_at + Duration::from_secs(5);
        let close_returned_at = fault_at + Duration::from_secs(1);
        let replacement_ready_at = fault_at + Duration::from_millis(5_800);
        let terminal_deadline = fault_at + NATIVE_WORKER_TERMINAL_LIMIT;
        let replacement_deadline =
            replacement_reader_wait_deadline(close_deadline, close_returned_at, terminal_deadline)
                .unwrap();
        assert!(replacement_ready_at > close_deadline);
        assert!(replacement_ready_at < replacement_deadline);
        assert_eq!(
            replacement_deadline,
            close_returned_at + NATIVE_WORKER_READY_LIMIT
        );
        assert!(
            replacement_reader_wait_deadline(close_deadline, close_deadline, terminal_deadline)
                .is_err()
        );
        let fake_now = std::cell::Cell::new(close_returned_at);
        wait_for_condition_before(
            replacement_deadline,
            Duration::from_millis(20),
            || fake_now.get(),
            |interval| fake_now.set(fake_now.get() + interval),
            || Ok(fake_now.get() >= replacement_ready_at),
            "replacement reader was not observed within the readiness budget",
        )
        .unwrap();
        assert!(fake_now.get() >= replacement_ready_at);

        let late_probe_now = std::cell::Cell::new(close_returned_at);
        assert_eq!(
            wait_for_condition_before(
                replacement_deadline,
                Duration::from_millis(20),
                || late_probe_now.get(),
                |interval| late_probe_now.set(late_probe_now.get() + interval),
                || {
                    late_probe_now.set(replacement_deadline + Duration::from_millis(1));
                    Ok(true)
                },
                "replacement reader observation exceeded the readiness budget",
            )
            .unwrap_err(),
            "replacement reader observation exceeded the readiness budget"
        );
    }

    #[test]
    fn native_post_fault_report_keeps_required_facts_when_state_database_is_unavailable() {
        let database = Connection::open_in_memory().unwrap();
        let context = NativePostFaultContext {
            run_id: "run-test",
            epoch: 1,
            block_id: "block-test",
            slot_pool: "agent",
            slot_index: 0,
            pre_close_process_identities: &[],
            reader_fault: None,
        };
        let (_, report) = native_post_fault_report(&database, &context, None, &[]);
        assert_eq!(report["status"], "incomplete");
        assert_eq!(report["terminal_proof_complete"], false);
        for fact in [
            "event_received",
            "process_survived",
            "exit_confirmed",
            "slot_released",
        ] {
            assert_eq!(report["lifecycle_facts"][fact], Value::Null, "{report}");
        }
        assert!(!report["observation_errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn generated_direct_merge_context_uses_supported_typed_procedure() {
        let temporary = tempfile::tempdir().unwrap();
        let fixture_root = temporary.path().join("acceptance");
        fs::create_dir(&fixture_root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &fixture_root,
        };
        prepare_profiles(
            &request,
            Path::new("/opt/xtask"),
            request.cli,
            ProfilePreparation::default(),
        )
        .unwrap();

        let context: Value = serde_json::from_slice(
            &fs::read(fixture_root.join("contexts/merge_decision.json")).unwrap(),
        )
        .unwrap();
        let generated = context["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["kind"] == "merge_intent")
            .unwrap();
        let payload = resolve_test_references(generated["structured_result"].clone());
        assert_eq!(
            generated["structured_result"]["steps"][1]["instruction_reference"],
            "repository:fixture:merge#procedure"
        );
        assert_eq!(
            generated["structured_result"]["steps"][2]["instruction_reference"],
            "repository:fixture:merge#verification"
        );
        assert_eq!(
            generated["structured_result"]["steps"][0]["instruction_reference"],
            "repository:fixture:merge#prepare-body"
        );
        assert_eq!(
            payload["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| step["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "update_pull_request_body",
                "direct_merge",
                "verify_merge_commit"
            ]
        );
        assert_eq!(
            payload["post_merge_verification"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            payload["post_merge_verification"][0]["kind"],
            "merge_commit_recorded"
        );
        crate::fixtures::agent::validate_payload(RoleOutputKind::MergeIntent, &payload).unwrap();
    }

    #[test]
    fn request_merge_stage_generates_loadable_request_executor_and_typed_context() {
        let temporary = tempfile::tempdir().unwrap();
        let fixture_root = temporary.path().join("acceptance");
        fs::create_dir(&fixture_root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &fixture_root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(
            &request,
            &executable,
            request.cli,
            ProfilePreparation {
                host_worker: true,
                request_merge_stage: true,
                ..ProfilePreparation::default()
            },
        )
        .unwrap();
        let config_path = fixture_root.join("config.toml");
        fs::write(
            &config_path,
            config_text_for_stage(&request, &executable, false, true),
        )
        .unwrap();

        let loaded = rex_projects::config::load(&config_path).unwrap();
        let fixture_repository = rex_projects::domain::ids::RepositoryId::parse("fixture").unwrap();
        assert_eq!(
            loaded.config.repositories[&fixture_repository]
                .merge
                .executor,
            Some(rex_projects::domain::types::MergeExecutor::Request)
        );
        assert_eq!(
            loaded.config.repositories[&fixture_repository]
                .merge
                .instructions
                .as_deref(),
            Some(
                "Request merge by posting the configured command.\n/merge\nVerify the provider records the squash merge commit and required Co-authored-by trailers."
            )
        );
        assert!(
            loaded.config.repositories[&fixture_repository]
                .merge
                .instructions
                .as_deref()
                .unwrap()
                .lines()
                .any(|line| line == "/merge")
        );

        let context_bytes = fs::read(fixture_root.join("contexts/merge_decision.json")).unwrap();
        let parsed: crate::fixtures::agent::AgentContext =
            serde_json::from_slice(&context_bytes).unwrap();
        assert_eq!(parsed.messages.len(), 3);
        let intent = parsed
            .messages
            .iter()
            .find(|message| message.kind == RoleOutputKind::MergeIntent)
            .unwrap();
        assert_eq!(
            intent.recipe.structured_result["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| step["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "update_pull_request_body",
                "request_merge",
                "verify_merge_commit"
            ]
        );
        assert_eq!(
            intent.recipe.structured_result["steps"][1]["instruction_reference"],
            "repository:fixture:merge#request-merge"
        );
        for step in intent.recipe.structured_result["steps"]
            .as_array()
            .unwrap()
            .iter()
            .chain(
                intent.recipe.structured_result["post_merge_verification"]
                    .as_array()
                    .unwrap(),
            )
        {
            assert!(
                step["instruction_reference"]
                    .as_str()
                    .unwrap()
                    .starts_with("repository:fixture:merge#")
            );
        }
        crate::fixtures::agent::validate_payload(
            RoleOutputKind::MergeIntent,
            &resolve_test_references(intent.recipe.structured_result.clone()),
        )
        .unwrap();
        assert!(config_text(&request, &executable, false).contains("executor = \"direct\""));
    }

    #[test]
    fn request_merge_acceptance_reports_only_unproven_milestones() {
        let mut evidence = RequestMergeEvidence::default();
        assert_eq!(
            evidence.next_missing_milestone(false),
            "exact TicketReview was not presented through public human list/show"
        );
        evidence.presented_review = true;
        evidence.approval_response_queued = true;
        evidence.human_approval_accepted = true;
        evidence.body_update_recovered = true;
        evidence.request_comment_succeeded = true;
        evidence.verify_pending_while_open = true;
        evidence.separate_merge_observed = true;
        evidence.host_merge_verified = true;
        assert_eq!(
            evidence.missing_milestones(false),
            vec!["external ticket has not reached Done"]
        );
        assert!(evidence.passed(true));
        assert!(evidence.missing_milestones(true).is_empty());
    }

    #[test]
    fn request_merge_receipt_chain_checks_body_bytes_and_exact_prerequisites() {
        let body = "approved body\nCo-authored-by: Codex <noreply@openai.com>\n";
        let body_digest = rex_projects::domain::ids::Digest::parse(format!(
            "{:x}",
            Sha256::digest(body.as_bytes())
        ))
        .unwrap();
        let body_receipt = fixture_body_receipt(body_digest);
        validate_recovered_body_update_receipt(
            &body_receipt,
            "prepare-body",
            "body-operation",
            body,
            &"a".repeat(40),
        )
        .unwrap();

        let canonical_body_request = match &body_receipt.effect_intent.operation {
            rex_projects::forge::MergeEffectOperation::UpdateBody(body) => {
                serialized_sha256_digest(body).unwrap()
            }
            _ => unreachable!(),
        };
        let wrong_digest_receipt = fixture_body_receipt(canonical_body_request);
        assert!(
            validate_recovered_body_update_receipt(
                &wrong_digest_receipt,
                "prepare-body",
                "body-operation",
                body,
                &"a".repeat(40),
            )
            .is_err()
        );

        let pull = body_receipt.effect_intent.pull.clone();
        let operation_key = "request-operation:request-merge".to_owned();
        let comment = rex_projects::forge::CommentIntent {
            pull: pull.clone(),
            operation_key: operation_key.clone(),
            expected_head_sha: "a".repeat(40),
            expected_base_sha: "b".repeat(40),
            exact_body: "/merge".into(),
            authenticated_actor: "fixture-bot".into(),
            attempt_started_unix: 101,
        };
        let request_digest = serialized_sha256_digest(&comment).unwrap();
        let request_receipt = rex_projects::merge_executor::MergeStepReceipt {
            step_key: "request-merge".into(),
            operation_key: operation_key.clone(),
            certainty: rex_projects::forge::EffectCertainty::Applied,
            request_digest: request_digest.clone(),
            effect_intent: rex_projects::forge::MergeEffectIntent {
                pull,
                operation_key: operation_key.clone(),
                request_digest: request_digest.clone(),
                operation: rex_projects::forge::MergeEffectOperation::RequestComment(comment),
                attempt_started_unix: 101,
            },
            acknowledgement: rex_projects::forge::EffectAcknowledgement {
                operation_key,
                request_digest,
                certainty: rex_projects::forge::EffectCertainty::Applied,
                external_id: Some("comment-9".into()),
                external_url: None,
                resulting_head_sha: None,
                resulting_merge_sha: None,
                reason: None,
            },
        };
        let mut request_effect = rex_projects::merge_executor::MergeStepEffectRequest {
            schema_version: 1,
            work_id: rex_projects::domain::ids::Digest::parse("c".repeat(64)).unwrap(),
            request_id: rex_projects::domain::ids::HumanRequestId::parse("review-1").unwrap(),
            assessed_revision: rex_projects::domain::ids::Revision(4),
            awaiting_merge_revision: rex_projects::domain::ids::Revision(6),
            step_key: "request-merge".into(),
            prior_receipts: vec![body_receipt.clone()],
        };
        validate_request_comment_receipt(
            &request_receipt,
            &request_effect,
            "request-merge",
            "request-operation",
            "/merge",
            &body_receipt,
        )
        .unwrap();
        request_effect.prior_receipts.clear();
        assert!(
            validate_request_comment_receipt(
                &request_receipt,
                &request_effect,
                "request-merge",
                "request-operation",
                "/merge",
                &body_receipt,
            )
            .is_err()
        );

        let mut verify_effect = request_effect;
        verify_effect.step_key = "verify-merge".into();
        verify_effect.prior_receipts = vec![body_receipt.clone(), request_receipt.clone()];
        validate_pending_verify_effect(
            &verify_effect,
            Some("pull request has not merged yet"),
            200,
            &body_receipt,
            &request_receipt,
        )
        .unwrap();
        verify_effect.prior_receipts.swap(0, 1);
        assert!(
            validate_pending_verify_effect(
                &verify_effect,
                Some("pull request has not merged yet"),
                200,
                &body_receipt,
                &request_receipt,
            )
            .is_err()
        );
    }

    #[test]
    fn native_worker_timeout_cannot_pass_on_the_coordinator_boundary_alone() {
        assert!(!bounded_stage_contract_valid(
            Some(NATIVE_WORKER_BLOCK_LOSS_STAGE),
            true,
            false
        ));
        assert!(bounded_stage_contract_valid(
            Some(NATIVE_WORKER_BLOCK_LOSS_STAGE),
            true,
            true
        ));
        assert!(bounded_stage_contract_valid(
            Some(NATIVE_WORKER_MISSED_EVENT_BLOCK_LOSS_STAGE),
            true,
            true
        ));
        assert!(bounded_stage_contract_valid(
            Some(COORDINATOR_INBOX_STAGE),
            true,
            false
        ));
    }

    #[test]
    fn native_worker_qualifies_planner_and_worker_before_project_start() {
        use std::cell::RefCell;
        use std::collections::{BTreeSet, HashMap};

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let cli = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .expect("xtask unit-test binary is under target/debug/deps")
            .join("rex-projects");
        assert!(
            cli.is_file(),
            "the actual product CLI is built beside xtask"
        );
        let rex = Path::new("/usr/bin/true");
        let request = Request {
            cli: &cli,
            rex,
            rex_server: "unix:///fixture.sock",
            rex_session: "qualification-sequence-test",
            expected_instance: "fixture-instance",
            fixture_root: root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(&request, &executable, &cli, ProfilePreparation::default()).unwrap();
        fs::write(
            root.join("config.toml"),
            config_text(&request, &executable, true),
        )
        .unwrap();
        let state_root = root.join("state");
        fs::create_dir(&state_root).unwrap();
        prepare_local_repository(&request, &executable).unwrap();
        let applied = product(
            &request,
            &state_root,
            &["config", "apply", "--bootstrap", "--json"],
        )
        .unwrap();
        require_success("apply isolated test configuration", &applied).unwrap();

        let verified_roles = RefCell::new(BTreeSet::new());
        let queued = RefCell::new(HashMap::<String, Value>::new());
        let commands = RefCell::new(Vec::<Vec<String>>::new());
        let mut trace = Vec::new();
        let roles = qualification_roles_for_stage(Some(NATIVE_WORKER_BLOCK_LOSS_STAGE));
        let qualification = qualify_profiles(
            &request,
            roles,
            true,
            &mut trace,
            |words| {
                let words = words.iter().map(|word| (*word).to_owned()).collect::<Vec<_>>();
                let command = words.iter().map(String::as_str).collect::<Vec<_>>();
                assert_product_command_reaches_expected_runtime_error(
                    &request,
                    &state_root,
                    &words,
                );
                commands.borrow_mut().push(words.clone());
                match command.as_slice() {
                    ["provider", "qualify", "--project", project, "--role", role, "--request-id", request_id, "--json"] => {
                        assert_eq!(*project, "operations_project");
                        let request_digest = format!("{:x}", Sha256::digest(request_id.as_bytes()));
                        let response = json!({
                            "request_id":request_id,
                            "request_digest":request_digest,
                            "status":"queued",
                            "project_id":project,
                            "role":role,
                            "profile_id":format!("fixture_{role}"),
                            "profile_digest":"d".repeat(64),
                            "config_revision":1,
                            "config_digest":"c".repeat(64)
                        });
                        queued.borrow_mut().insert(request_id.to_string(), response.clone());
                        Ok(successful_process_output(response))
                    }
                    ["--json", "provider", "status", "--request-id", request_id] => {
                        let mut response = queued
                            .borrow()
                            .get(*request_id)
                            .expect("status follows a queued request")
                            .clone();
                        response["status"] = json!("verified");
                        response["qualification_receipt_digest"] = json!("e".repeat(64));
                        verified_roles
                            .borrow_mut()
                            .insert(response["role"].as_str().unwrap().to_owned());
                        Ok(successful_process_output(response))
                    }
                    ["project", "start", project, "--json"] => {
                        assert_eq!(*project, "operations_project");
                        let verified = verified_roles.borrow();
                        assert!(
                            verified.contains("planner") && verified.contains("worker"),
                            "Planner and Worker qualifications must be verified before Project start; got {verified:?}"
                        );
                        assert!(
                            !verified.contains("coordinator"),
                            "Coordinator must remain unqualified for the existing missing-qualification guard"
                        );
                        Ok(successful_process_output(json!({"accepted":true,"state":"queued"})))
                    }
                    other => panic!("qualification loop generated unexpected command: {other:?}"),
                }
            },
            || {
                assert!(!verified_roles.borrow().contains("coordinator"));
                json!({"status":"passed","parked_diagnostic":"missing exact Coordinator qualification"})
            },
        )
        .unwrap();

        assert!(qualification.project_started);
        assert_eq!(
            qualification.coordinator_qualification_wait_proof.unwrap()["status"],
            "passed"
        );
        assert!(
            qualification
                .terminal_qualifications
                .values()
                .all(|status| status == "verified")
        );
        assert_eq!(
            qualification
                .qualifications
                .iter()
                .map(|(_, role, _, _, _)| role.as_str())
                .collect::<Vec<_>>(),
            ["planner", "worker", "supervisor", "coordinator"]
        );
        assert_eq!(
            commands.borrow().last().unwrap(),
            &[
                "--json".to_owned(),
                "provider".to_owned(),
                "status".to_owned(),
                "--request-id".to_owned(),
                "acceptance-operations_project-coordinator".to_owned()
            ]
        );
    }

    fn successful_process_output(value: Value) -> ProcessOutput {
        let status = std::process::Command::new("/usr/bin/true")
            .status()
            .expect("test success status helper is available");
        ProcessOutput {
            status: Some(status),
            stdout: serde_json::to_vec(&value).unwrap(),
            stderr_tail: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            cleanup_confirmed: true,
        }
    }

    fn assert_product_command_reaches_expected_runtime_error(
        request: &Request<'_>,
        state_root: &Path,
        words: &[String],
    ) {
        let mut args = vec![
            OsString::from("--config"),
            request.fixture_root.join("config.toml").into_os_string(),
            OsString::from("--state-root"),
            state_root.as_os_str().to_owned(),
        ];
        args.extend(words.iter().map(OsString::from));
        let xdg_state = OsString::from("XDG_STATE_HOME");
        let xdg_state_value = request.fixture_root.join("xdg-state").into_os_string();
        let output = invoke(
            request.cli,
            &args,
            Some(request.fixture_root),
            Some((xdg_state, xdg_state_value)),
            STEP_TIMEOUT,
        )
        .expect("actual product CLI can parse the generated command vector");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr_tail)
        );
        let command = words.iter().map(String::as_str).collect::<Vec<_>>();
        let expected = match command.as_slice() {
            ["provider", "qualify", ..] => "no foreground machine controller is running",
            ["project", "start", ..] => "no foreground machine controller is running",
            ["--json", "provider", "status", ..] => "provider qualification request",
            _ => panic!("unexpected product command vector: {words:?}"),
        };
        assert!(
            text.contains(expected),
            "actual product CLI did not reach expected post-parse response `{expected}` for {words:?}: {text}"
        );
    }

    #[test]
    fn native_worker_readiness_marker_rejects_missing_or_pending_slot_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let marker_path = temporary.path().join("native-worker-ready.json");
        assert!(!native_worker_ready_marker_is_valid(&marker_path));

        let pending_marker = json!({
            "status":"native_worker_running",
            "worker":{
                "agent_state":"running",
                "launch_state":"running",
                "slot_disposition":"launch_pending",
                "live_process_identities":[{"pid":1},{"pid":2}]
            }
        });
        fs::write(&marker_path, serde_json::to_vec(&pending_marker).unwrap()).unwrap();
        assert!(!native_worker_ready_marker_is_valid(&marker_path));

        let anchored_marker = json!({
            "status":"native_worker_running",
            "worker":{
                "agent_state":"running",
                "launch_state":"running",
                "slot_disposition":"live",
                "anchored_topology_verified":true,
                "wrapper_process_identity":{
                    "pid":11,
                    "start_identity":"supervisor-born",
                    "rex_launch_anchor":{"pid":10,"start_identity":"shim-born"}
                },
                "rex_process_observation":{"child":{"pid":10}},
                "live_process_identities":[
                    {"pid":10,"parent_pid":1,"start_identity":"shim-born"},
                    {"pid":11,"parent_pid":10,"start_identity":"supervisor-born"}
                ]
            }
        });
        fs::write(&marker_path, serde_json::to_vec(&anchored_marker).unwrap()).unwrap();
        assert!(native_worker_ready_marker_is_valid(&marker_path));

        let mut wrong_anchor = anchored_marker.clone();
        wrong_anchor["worker"]["rex_process_observation"]["child"]["pid"] = json!(12);
        fs::write(&marker_path, serde_json::to_vec(&wrong_anchor).unwrap()).unwrap();
        assert!(!native_worker_ready_marker_is_valid(&marker_path));

        let mut wrong_parent = anchored_marker;
        wrong_parent["worker"]["live_process_identities"][1]["parent_pid"] = json!(99);
        fs::write(&marker_path, serde_json::to_vec(&wrong_parent).unwrap()).unwrap();
        assert!(!native_worker_ready_marker_is_valid(&marker_path));
    }

    #[test]
    fn native_worker_anchor_topology_requires_exact_rex_anchor_and_supervisor_parent() {
        use rex_projects::launch::LaunchAnchorIdentity;

        let wrapper = ObservedWrapperIdentity {
            pid: 11,
            start_identity: "supervisor-born".into(),
            rex_session_id: "session".into(),
            rex_block_id: "block".into(),
            runtime_binary_digest: rex_projects::domain::ids::Digest::parse("c".repeat(64))
                .unwrap(),
            rex_launch_anchor: Some(LaunchAnchorIdentity {
                pid: 10,
                start_identity: "shim-born".into(),
            }),
        };
        let process = |pid, parent_pid, start_identity: &str| ProcessIdentity {
            pid,
            parent_pid,
            process_group_id: pid,
            start_identity: start_identity.into(),
            command: "rex-projects".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        };
        let rex_process = |pid| rex_projects::adapters::rex::RexProcessInfo {
            pid,
            user_id: 1,
            name: "rex-projects".into(),
            argv0: None,
            path: None,
            invoked_path: None,
            script: None,
            cwd: None,
            user: None,
        };
        let rex = RexProcessObservation {
            last_exit: None,
            child: Some(rex_process(10)),
            foreground: Some(rex_process(22)),
            ancestors: None,
        };
        let live = vec![
            process(10, 1, "shim-born"),
            process(11, 10, "supervisor-born"),
            process(22, 11, "provider-born"),
        ];
        assert!(native_worker_anchor_topology_is_live(
            &wrapper, 22, &rex, &live
        ));

        let mut wrong_rex_anchor = rex.clone();
        wrong_rex_anchor.child = Some(rex_process(12));
        assert!(!native_worker_anchor_topology_is_live(
            &wrapper,
            22,
            &wrong_rex_anchor,
            &live
        ));
        assert!(!native_worker_anchor_topology_is_live(
            &wrapper,
            22,
            &rex,
            &[
                process(10, 1, "reused-shim"),
                process(11, 10, "supervisor-born")
            ]
        ));
        assert!(!native_worker_anchor_topology_is_live(
            &wrapper,
            22,
            &rex,
            &[
                process(10, 1, "shim-born"),
                process(11, 9, "supervisor-born")
            ]
        ));
    }

    #[test]
    #[ignore = "requires explicit frozen replay fixture, product CLI, and xtask paths"]
    fn native_worker_qualification_replay_checks_generated_argv_schema_and_probe() {
        use rex_projects::domain::types::{AgentAdapter, Role};
        use rex_projects::providers::{InvocationPaths, build_invocation, project_result_schema};

        let input_path = |name: &str| {
            PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name}")))
                .canonicalize()
                .unwrap_or_else(|error| panic!("resolve {name}: {error}"))
        };
        let frozen_root = input_path("REX_PROJECTS_ACCEPTANCE_REPLAY_FIXTURE_ROOT");
        let runtime = input_path("REX_PROJECTS_ACCEPTANCE_REPLAY_RUNTIME");
        let driver = input_path("REX_PROJECTS_ACCEPTANCE_REPLAY_DRIVER");
        assert!(runtime.is_file());
        assert!(driver.is_file());

        let frozen_package_bytes = fs::read(frozen_root.join("package.json")).unwrap();
        let mut package: Value = serde_json::from_slice(&frozen_package_bytes).unwrap();
        let frozen_runtime = PathBuf::from(package["runtime_binary_path"].as_str().unwrap());
        let runtime_digest = format!("{:x}", Sha256::digest(fs::read(&runtime).unwrap()));
        assert_eq!(package["runtime_binary_digest"], runtime_digest);

        let runtime_schema =
            serde_json::to_value(rex_projects::roles::result_schema(Role::Supervisor)).unwrap();
        let fixture_schema: Value = serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../schemas/agent-results/supervisor-v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let package_schema = package["descriptor"]["result_schema"].clone();
        assert_eq!(runtime_schema, fixture_schema);
        assert_eq!(runtime_schema, package_schema);
        let source_schema_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&runtime_schema).unwrap())
        );

        let argv_capture: Value =
            serde_json::from_slice(&fs::read(frozen_root.join("invocation-argv.json")).unwrap())
                .unwrap();
        let captured_args = argv_capture["args"]
            .as_array()
            .expect("frozen fixture must contain generated argv")
            .iter()
            .map(|value| value.as_str().expect("argv entries are strings").to_owned())
            .collect::<Vec<_>>();

        let temporary = tempfile::tempdir().unwrap();
        // Keep this replay workspace so a failed inner qualification probe leaves its
        // bounded persisted diagnostic available for investigation.
        let root = temporary.keep().canonicalize().unwrap();
        eprintln!("qualification replay workspace: {}", root.display());
        let workspace = root.join("workspace");
        let control = root.join("control");
        let contexts = root.join("contexts");
        let state = root.join("agent-state");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&control).unwrap();
        fs::create_dir_all(&contexts).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::copy(
            frozen_root.join("contexts/supervisor.json"),
            contexts.join("supervisor.json"),
        )
        .unwrap();

        let frozen_root_text = frozen_root.to_string_lossy();
        let root_text = root.to_string_lossy();
        let runtime_text = runtime.to_string_lossy();
        let frozen_runtime_text = frozen_runtime.to_string_lossy();
        let relocate = |value: &str| {
            value
                .replace(frozen_root_text.as_ref(), root_text.as_ref())
                .replace(frozen_runtime_text.as_ref(), runtime_text.as_ref())
        };
        let set_path = |value: &mut Value, pointer: &str, path: &Path| {
            *value
                .pointer_mut(pointer)
                .expect("frozen package path exists") =
                Value::String(path.to_string_lossy().into_owned());
        };
        let prompt = relocate(package["prompt"].as_str().unwrap());
        package["prompt"] = Value::String(prompt.clone());
        package["runtime_binary_path"] = Value::String(runtime.to_string_lossy().into_owned());
        set_path(&mut package, "/workspace_root", &root);
        set_path(
            &mut package,
            "/environment_handoff",
            &control.join("environment-handoff.env"),
        );
        set_path(&mut package, "/result_path", &control.join("result.json"));
        set_path(
            &mut package,
            "/marker_probe_path",
            &workspace.join("marker-probe.json"),
        );
        set_path(&mut package, "/descriptor/workspace", &workspace);
        set_path(&mut package, "/descriptor/control_dir", &control);
        let package_path = root.join("package.json");
        fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();

        let profile_path = frozen_root.join("profiles/fixture_supervisor/config.toml");
        let mut profile: rex_projects::config::Profile =
            toml::from_str(&fs::read_to_string(profile_path).unwrap()).unwrap();
        for argument in &mut profile.command {
            *argument = relocate(argument);
        }
        profile.command[0] = driver.to_string_lossy().into_owned();
        let schema_path = root.join("provider-schema.json");
        let projection = project_result_schema(&runtime_schema).unwrap();
        fs::write(
            &schema_path,
            serde_json::to_vec(&projection.schema).unwrap(),
        )
        .unwrap();

        let invocation = build_invocation(
            &profile,
            package["role_contract"].as_str().unwrap(),
            &prompt,
            &runtime_schema,
            InvocationPaths {
                schema_path: &schema_path,
                control_dir: None,
            },
            None,
        )
        .unwrap();
        let generated_args = invocation
            .args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let mut expected_args = captured_args
            .iter()
            .map(|argument| relocate(argument))
            .collect::<Vec<_>>();
        let mut generated_comparison = generated_args.clone();
        if let Some(last) = expected_args.last_mut() {
            *last = last.trim_end_matches('\n').to_owned();
        }
        if let Some(last) = generated_comparison.last_mut() {
            *last = last.trim_end_matches('\n').to_owned();
        }
        assert_eq!(generated_comparison, expected_args);

        let mut environment = BTreeMap::new();
        environment.insert(OsString::from("REX_PROJECTS_AGENT"), OsString::from("1"));
        environment.insert(
            OsString::from("REX_PROJECTS_CONTEXT"),
            OsString::from("agent"),
        );
        environment.insert(
            OsString::from("REX_PROJECTS_PROJECT_ID"),
            OsString::from(package["project_id"].as_str().unwrap()),
        );
        environment.insert(
            OsString::from("REX_PROJECTS_ROLE"),
            OsString::from("supervisor"),
        );
        environment.insert(
            OsString::from("REX_PROJECTS_RUN_ID"),
            OsString::from(package["descriptor"]["run_id"].as_str().unwrap()),
        );
        let output = run_process(ProcessRequest {
            executable: invocation.executable,
            args: invocation.args,
            stdin: Vec::new(),
            cwd: Some(workspace.clone()),
            clear_environment: false,
            environment,
            timeout: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(2),
            stdout_limit: OUTPUT_LIMIT,
            stderr_tail_limit: 8 * 1024,
        })
        .unwrap();
        assert!(!output.timed_out);
        assert!(output.cleanup_confirmed);
        assert!(
            output.status.is_some_and(|status| status.success()),
            "qualification fixture CLI failed: status={:?}, stderr_tail={}, stdout={}",
            output.status,
            String::from_utf8_lossy(&output.stderr_tail),
            String::from_utf8_lossy(&output.stdout)
        );
        rex_projects::providers::parse_result(AgentAdapter::Codex, &output.stdout, &runtime_schema)
            .unwrap();

        let report_path = workspace.join("marker-probe.json");
        let metadata = fs::symlink_metadata(&report_path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= 16 * 1024);
        let report: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
        assert_eq!(report["tool_binary_digest"], runtime_digest);
        assert!(report["tool_pid"].as_u64().is_some_and(|pid| pid > 0));
        assert!(report["descendant_pid"].as_u64().is_some_and(|pid| pid > 0));
        eprintln!("qualification replay schema SHA256: {source_schema_digest}");
    }

    #[test]
    fn native_worker_profile_requests_only_the_bounded_foreground_lifecycle_task() {
        let messages = profile_messages_for_native_worker("planner", false, true).unwrap();
        let plan = &messages[1]["structured_result"]["plan"]["nodes"][0];
        assert_eq!(plan["task"], NATIVE_WORKER_LIFECYCLE_TASK);
        assert_eq!(
            plan["required_evidence"][0],
            "The bounded foreground process remains active until the host closes the Worker Rex block."
        );
        assert!(!plan["task"].as_str().unwrap().contains("git "));
    }

    #[test]
    fn native_worker_profile_builder_emits_absolute_codex_argv_and_lifecycle_context() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        let codex = Path::new("/opt/codex/0.166.0/bin/codex");
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        prepare_profiles(
            &request,
            Path::new("/opt/xtask"),
            request.cli,
            ProfilePreparation {
                host_worker: true,
                native_worker_codex: Some(codex),
                ..ProfilePreparation::default()
            },
        )
        .unwrap();

        let profile: toml::Value = toml::from_str(
            &fs::read_to_string(root.join("profiles/fixture_worker/config.toml")).unwrap(),
        )
        .unwrap();
        assert_eq!(profile["adapter"].as_str(), Some("codex"));
        assert_eq!(profile["commit_mode"].as_str(), Some("host"));
        assert_eq!(
            profile["command"][0].as_str(),
            Some(codex.to_str().unwrap())
        );
        assert_eq!(profile["command"].as_array().unwrap().len(), 1);
        assert!(profile.get("model").is_none());

        let context: Value =
            serde_json::from_slice(&fs::read(root.join("contexts/planner.json")).unwrap()).unwrap();
        let plan = &context["messages"][1]["structured_result"]["plan"]["nodes"][0];
        assert_eq!(plan["task"], NATIVE_WORKER_LIFECYCLE_TASK);
    }

    #[test]
    fn native_worker_persisted_provider_envelope_reaches_readiness_and_rejects_bad_bindings() {
        use rex_projects::domain::ids::{AgentRunId, Digest, OperationId};
        use rex_projects::launch::ProviderProcessIdentity;

        let wrapper = ObservedWrapperIdentity {
            pid: 11,
            start_identity: "wrapper-born".into(),
            rex_launch_anchor: None,
            rex_session_id: "session".into(),
            rex_block_id: "block".into(),
            runtime_binary_digest: Digest::parse("c".repeat(64)).unwrap(),
        };
        let tree = vec![
            ProviderProcessIdentity {
                pid: 11,
                parent_pid: 1,
                process_group_id: 11,
                start_identity: "wrapper-born".into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
            ProviderProcessIdentity {
                pid: 22,
                parent_pid: 11,
                process_group_id: 11,
                start_identity: "provider-born".into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
            ProviderProcessIdentity {
                pid: 33,
                parent_pid: 22,
                process_group_id: 33,
                start_identity: "finished-hook-born".into(),
                identity_quality: ProcessIdentityQuality::KernelBirthToken,
            },
        ];
        let tree_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&tree).unwrap())
        ))
        .unwrap();
        let observation = ObservedProviderStart {
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            operation_id: OperationId::parse("op-1").unwrap(),
            provider_pid: 22,
            provider_start_identity: "provider-born".into(),
            executable_digest: Digest::parse("a".repeat(64)).unwrap(),
            process_tree_digest: tree_digest,
            process_tree_confirmed: true,
            process_tree: tree,
        };
        // Serialize the same typed envelope that ConfigStore persists in provider_process_tree_json.
        let saved = serde_json::to_string(&observation).unwrap();
        let parsed = parse_native_worker_provider_start(
            &saved,
            "run-1",
            "op-1",
            &"a".repeat(64),
            &"c".repeat(64),
            &wrapper,
        )
        .unwrap();
        let live = [
            ProcessIdentity {
                pid: 11,
                parent_pid: 1,
                process_group_id: 11,
                start_identity: "wrapper-born".into(),
                command: "rex".into(),
                quality: ProcessIdentityQuality::KernelBirthToken,
            },
            ProcessIdentity {
                pid: 22,
                parent_pid: 11,
                process_group_id: 11,
                start_identity: "provider-born".into(),
                command: "codex".into(),
                quality: ProcessIdentityQuality::KernelBirthToken,
            },
        ];
        assert!(native_worker_processes_are_live(&wrapper, &parsed, &live));

        let wrong_run = parse_native_worker_provider_start(
            &saved,
            "different-run",
            "op-1",
            &"a".repeat(64),
            &"c".repeat(64),
            &wrapper,
        );
        assert!(wrong_run.is_err());
        let mut missing_provider = observation.clone();
        missing_provider
            .process_tree
            .retain(|identity| identity.pid != 22);
        assert!(!native_worker_processes_are_live(
            &wrapper,
            &missing_provider,
            &live
        ));
        let mut duplicate_wrapper = observation.clone();
        duplicate_wrapper
            .process_tree
            .push(duplicate_wrapper.process_tree[0].clone());
        assert!(!native_worker_processes_are_live(
            &wrapper,
            &duplicate_wrapper,
            &live
        ));
        let mut unverified_transient = observation.clone();
        unverified_transient.process_tree[2].identity_quality =
            ProcessIdentityQuality::SecondPrecision;
        assert!(!native_worker_processes_are_live(
            &wrapper,
            &unverified_transient,
            &live
        ));
        let mut stale_birth = live;
        stale_birth[1].start_identity = "reused-pid".into();
        assert!(!native_worker_processes_are_live(
            &wrapper,
            &parsed,
            &stale_birth
        ));
    }

    #[test]
    fn native_worker_readiness_query_executes_against_production_database_schema() {
        let temporary = tempfile::tempdir().unwrap();
        if std::env::var_os("REX_PROJECTS_READINESS_QUERY_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "acceptance::tests::native_worker_readiness_query_executes_against_production_database_schema",
                ])
                .env("REX_PROJECTS_READINESS_QUERY_TEST_CHILD", "1")
                .env("XDG_STATE_HOME", temporary.path())
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let _store = rex_projects::store::ConfigStore::open(temporary.path()).unwrap();
        let database = Connection::open_with_flags(
            temporary.path().join("state.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let row: Option<String> = database
            .query_row(
                NATIVE_WORKER_LAUNCH_EVIDENCE_QUERY,
                params!["fixture-instance", "fixture-session", "f".repeat(64)],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn saved_recovery_worker_observation_uses_the_typed_snapshot_digest() {
        let saved_snapshot = r#"{"schema_version":1,"project_id":"operations_project","role_session_id":"ticket:run-190b18e04a0397a4d95da694ce92b900fa8f151721c469c2:worker:acceptance-node","agent_run_id":"agent-624e2526960c60d5008d6459a85dfbb9","digest":"ff25c466db5c1c3e94ff57531ab53c77756bac6862b273e8bdc1e49280fc54fb","inputs":[{"wake_input_id":12,"source_type":"worker_recovery_authorization","source_id":"589ff35b2a7ff2c47e1cb3f97926441148610e84ea0717fc5b654c2081e60555","source_revision":3,"priority":10,"payload_json":{"authorization":{"accepted_plan_digest":"1234609ed0689d9694a9c5d0ea3d6a601dc3ea6d554e3429745b00b92a927102","expected_head":"5e56202ae6671c051089454edcc2f4614f1c713f","prior_absence_digest":"5818daba39bbd06006f59597e3f62237f588f02af10b07fa9662b88209983dc7","prior_artifact_refs":[],"prior_host_commit_operation_id":null,"prior_host_commit_receipt_digest":null,"prior_terminal_digest":"75dda941d697241a74181e327c45bcc179a4bbfe832c5ac4270cde73d13d093f","prior_worker_agent_run_id":"agent-b50ec39c8c2d89b27525c53497f93abb","prior_worker_result_evidence_id":"589ff35b2a7ff2c47e1cb3f97926441148610e84ea0717fc5b654c2081e60555","schema_version":1,"source_coordinator_evidence_id":"d83133795ad61f7ee4fc84ea2fee45e5b2918e07d3cb07901c575cd9310781c3","ticket_revision":3,"ticket_run_id":"run-190b18e04a0397a4d95da694ce92b900fa8f151721c469c2","work_node_id":"acceptance-node"},"kind":"worker_recovery_authorization","schema_version":1}}]}"#;
        let snapshot: Value = serde_json::from_str(saved_snapshot).unwrap();
        let snapshot_bytes = serde_json::to_vec_pretty(&snapshot).unwrap();
        let typed_snapshot = parse_recovery_wake_snapshot(&snapshot_bytes).unwrap();
        assert_eq!(typed_snapshot.digest.as_str(), snapshot["digest"]);
        let raw_file_digest = format!("{:x}", Sha256::digest(&snapshot_bytes));
        assert_ne!(raw_file_digest, snapshot["digest"].as_str().unwrap());

        let directory = tempfile::tempdir().unwrap();
        let snapshot_path = directory.path().join("snapshot.json");
        fs::write(&snapshot_path, &snapshot_bytes).unwrap();
        let authorization = snapshot["inputs"][0]["payload_json"]["authorization"].clone();
        let prior_run_id = authorization["prior_worker_agent_run_id"].as_str().unwrap();
        let expected_head = authorization["expected_head"].as_str().unwrap();
        let package_path = directory.path().join("run-step.package.json");
        let package_bytes = serde_json::to_vec(&json!({
            "descriptor":{
                "role":"worker",
                "ticket_run_id":authorization["ticket_run_id"]
            },
            "prompt":format!(
                "Retry {prior_run_id} from head {expected_head}. Prior uncommitted changes may remain."
            )
        }))
        .unwrap();
        fs::write(&package_path, &package_bytes).unwrap();
        let input = &snapshot["inputs"][0];
        let mut observation = json!({
            "role":"worker",
            "run_id":snapshot["agent_run_id"],
            "ticket_run_id":authorization["ticket_run_id"],
            "inbox_inputs":[{
                "source_type":"worker_recovery_authorization",
                "source_revision":input["source_revision"],
                "payload_json":{"authorization":authorization}
            }],
            "input_files":{
                "package_path":package_path,
                "package_sha256":format!("{:x}", Sha256::digest(&package_bytes)),
                "snapshot_path":snapshot_path,
                "snapshot_digest":snapshot["digest"]
            },
            "worker_assignment":{
                "node_id":authorization["work_node_id"],
                "accepted_plan_digest":authorization["accepted_plan_digest"]
            }
        });
        assert!(
            worker_recovery_inbox_evidence(&observation)
                .unwrap()
                .is_some()
        );
        observation["input_files"]["snapshot_digest"] = json!(raw_file_digest);
        assert!(
            worker_recovery_inbox_evidence(&observation)
                .unwrap()
                .is_none()
        );
        observation["input_files"]["snapshot_digest"] = snapshot["digest"].clone();
        let package_without_guidance = serde_json::to_vec(&json!({
            "descriptor":{
                "role":"worker",
                "ticket_run_id":authorization["ticket_run_id"]
            },
            "prompt":format!("Retry {prior_run_id} from head {expected_head}")
        }))
        .unwrap();
        fs::write(&package_path, &package_without_guidance).unwrap();
        observation["input_files"]["package_sha256"] =
            json!(format!("{:x}", Sha256::digest(&package_without_guidance)));
        assert!(
            worker_recovery_inbox_evidence(&observation)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reviewer_boundary_requires_applied_review_ready_at_the_current_assessing_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let writable = Connection::open(&path).unwrap();
        writable.execute_batch(
            r#"CREATE TABLE ticket_runs(ticket_run_id TEXT,project_id TEXT,revision INTEGER,internal_phase TEXT);
             CREATE TABLE agent_runs(agent_run_id TEXT,project_id TEXT,role TEXT,state TEXT);
             CREATE TABLE agent_result_evidence(evidence_id TEXT,agent_run_id TEXT,project_id TEXT,ticket_run_id TEXT,role TEXT,outcome TEXT,result_json TEXT);
             CREATE TABLE agent_result_reducer_ack(evidence_id TEXT,reducer_revision INTEGER,disposition TEXT);
             INSERT INTO ticket_runs VALUES('ticket-run','project',6,'assessing');
             INSERT INTO agent_runs VALUES('reviewer-run','project','reviewer','completed');
             INSERT INTO agent_result_evidence VALUES('review-evidence','reviewer-run','project','ticket-run','reviewer','completed','{"kind":"review_ready","structured_result":{"subject_kind":"implementation_publication_set"}}');
             INSERT INTO agent_result_reducer_ack VALUES('review-evidence',6,'applied');"#
        ).unwrap();
        let readonly =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let accepted =
            accepted_reviewer_result(&readonly, "ticket-run", "reviewer-run", "assessing")
                .unwrap()
                .expect("applied ReviewReady advances Reviewing to Assessing");
        assert_eq!(accepted["reducer_revision"], 6);
        assert_eq!(accepted["result"]["kind"], "review_ready");
        for update in [
            "UPDATE agent_result_reducer_ack SET disposition='retained_as_claim'",
            "UPDATE agent_result_reducer_ack SET reducer_revision=5",
            "UPDATE agent_runs SET state='running'",
            "UPDATE agent_result_evidence SET ticket_run_id='other-ticket'",
            "UPDATE agent_result_evidence SET project_id='other-project'",
            "UPDATE agent_result_evidence SET result_json='{\"kind\":\"progress\"}'",
            "UPDATE ticket_runs SET internal_phase='reviewing'",
        ] {
            writable.execute_batch(update).unwrap();
            assert!(
                accepted_reviewer_result(&readonly, "ticket-run", "reviewer-run", "assessing")
                    .unwrap()
                    .is_none(),
                "{update}"
            );
            writable.execute_batch(r#"
                UPDATE agent_result_reducer_ack SET disposition='applied',reducer_revision=6;
                UPDATE agent_runs SET state='completed';
                UPDATE agent_result_evidence SET ticket_run_id='ticket-run',project_id='project',result_json='{"kind":"review_ready","structured_result":{"subject_kind":"implementation_publication_set"}}';
                UPDATE ticket_runs SET internal_phase='assessing';
            "#).unwrap();
        }
    }

    #[test]
    fn private_acceptance_stages_keep_inbox_and_add_block_loss_selector() {
        assert_eq!(parse_acceptance_stage(None).unwrap(), None);
        assert_eq!(
            parse_acceptance_stage(Some(COORDINATOR_INBOX_STAGE.into())).unwrap(),
            Some(COORDINATOR_INBOX_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some(COORDINATOR_BLOCK_LOSS_STAGE.into())).unwrap(),
            Some(COORDINATOR_BLOCK_LOSS_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some(COORDINATOR_WORKER_INBOX_STAGE.into())).unwrap(),
            Some(COORDINATOR_WORKER_INBOX_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some(HOST_COMMIT_REVIEWER_INBOX_STAGE.into())).unwrap(),
            Some(HOST_COMMIT_REVIEWER_INBOX_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some(WORKER_RECOVERY_INBOX_STAGE.into())).unwrap(),
            Some(WORKER_RECOVERY_INBOX_STAGE.into())
        );
        assert_eq!(
            parse_acceptance_stage(Some("request_merge".into())).unwrap(),
            Some("request_merge".into())
        );
        assert_eq!(
            qualification_roles_for_stage(Some("request_merge")),
            &PROVIDER_ROLES
        );
        assert!(parse_acceptance_stage(Some("unknown".into())).is_err());
    }

    #[test]
    fn coordinator_qualification_wait_query_requires_pending_wake_and_no_launch_state() {
        let database = Connection::open_in_memory().unwrap();
        database
            .execute_batch(
                "CREATE TABLE controller_owners(singleton INTEGER,generation INTEGER,heartbeat_at_unix INTEGER,stopped_at_unix INTEGER);
                 CREATE TABLE ticket_runs(ticket_run_id TEXT,project_id TEXT,namespace TEXT,ticket_id TEXT,generation INTEGER,internal_phase TEXT);
                 CREATE TABLE role_wake_inputs(project_id TEXT,role_session_id TEXT,source_type TEXT,source_id TEXT,lifecycle TEXT);
                 CREATE TABLE provider_qualifications(project_id TEXT,profile_id TEXT,status TEXT);
                 CREATE TABLE agent_launch_authority(project_id TEXT,ticket_run_id TEXT,role TEXT,agent_run_id TEXT);
                 CREATE TABLE agent_runs(agent_run_id TEXT);
                 CREATE TABLE execution_slots(owner_kind TEXT,owner_id TEXT,disposition TEXT);
                 INSERT INTO controller_owners VALUES (1,5,100,NULL);
                 INSERT INTO ticket_runs VALUES ('ticket-run-1','operations_project','fixture/acceptance','ticket-1',1,'planning');
                 INSERT INTO role_wake_inputs VALUES ('operations_project','ticket_run:ticket-run-1:coordinator','ticket_run_dispatch','ticket-run-1','pending');",
            )
            .unwrap();
        let state = coordinator_qualification_wait_state(
            &database,
            "operations_project",
            "fixture/acceptance",
            "ticket-1",
            "fixture_coordinator",
        )
        .unwrap();
        assert_eq!(state.generation, 5);
        assert_eq!(state.heartbeat_at_unix, 100);
        assert!(state.owner_active);
        assert_eq!(state.ticket_run_id.as_deref(), Some("ticket-run-1"));
        assert_eq!(state.pending_wake_count, 1);
        assert_eq!(state.verified_qualification_count, 0);
        assert_eq!(state.agent_run_count, 0);
        assert_eq!(state.active_slot_count, 0);

        database
            .execute(
                "INSERT INTO provider_qualifications VALUES ('operations_project','fixture_coordinator','verified')",
                [],
            )
            .unwrap();
        assert_eq!(
            coordinator_qualification_wait_state(
                &database,
                "operations_project",
                "fixture/acceptance",
                "ticket-1",
                "fixture_coordinator",
            )
            .unwrap()
            .verified_qualification_count,
            1
        );
    }

    #[test]
    fn coordinator_warmup_counts_distinct_per_run_cursor_values_not_numeric_delta() {
        let mut last = Some(5);
        assert!(observe_cursor_advance(&mut last, Some(15)).unwrap());
        assert!(!observe_cursor_advance(&mut last, Some(15)).unwrap());
        assert!(observe_cursor_advance(&mut last, Some(20)).unwrap());
        assert_eq!(last, Some(20));

        let mut initially_missing = None;
        assert!(!observe_cursor_advance(&mut initially_missing, Some(40)).unwrap());
        assert!(observe_cursor_advance(&mut initially_missing, Some(41)).unwrap());
        assert!(!observe_cursor_advance(&mut initially_missing, Some(41)).unwrap());
        assert!(observe_cursor_advance(&mut initially_missing, Some(50)).unwrap());
        assert!(observe_cursor_advance(&mut initially_missing, Some(49)).is_err());
    }

    #[test]
    fn block_loss_state_query_reads_exact_epoch_facts_from_read_only_sqlite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite3");
        let writable = Connection::open(&path).unwrap();
        writable
            .execute_batch(
                "CREATE TABLE agent_runs(agent_run_id TEXT,controller_generation INTEGER,state TEXT);
                 CREATE TABLE execution_slots(owner_kind TEXT,owner_id TEXT,reservation_epoch INTEGER,disposition TEXT);
                 CREATE TABLE agent_run_recovery_observations(agent_run_id TEXT,controller_generation INTEGER,reservation_epoch INTEGER,observation_order INTEGER);
                 CREATE TABLE agent_block_lifecycle_facts(agent_run_id TEXT,reservation_epoch INTEGER,rex_block_id TEXT,fact_type TEXT,detail_json TEXT);
                 INSERT INTO agent_runs VALUES('run-1',3,'running');
                 INSERT INTO execution_slots VALUES('agent_run','run-1',8,'live');",
            )
            .unwrap();
        drop(writable);

        let readonly =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let missing_cursor = recovery_state(&readonly, "run-1", "block-1").unwrap();
        assert_eq!(missing_cursor.observation_order, None);
        assert_eq!(missing_cursor.state, "running");
        assert_eq!(missing_cursor.disposition, "live");
        assert!(
            readonly
                .execute("UPDATE agent_runs SET state='cancelled'", [])
                .is_err()
        );
        drop(readonly);

        let writable = Connection::open(&path).unwrap();
        writable
            .execute_batch(
                "UPDATE agent_runs SET state='cancelled';
                 UPDATE execution_slots SET disposition='released';
                 INSERT INTO agent_run_recovery_observations VALUES('run-1',3,8,42);
                 INSERT INTO agent_block_lifecycle_facts VALUES('run-1',8,'block-1','event_received','{}');
                 INSERT INTO agent_block_lifecycle_facts VALUES('run-1',8,'block-1','exit_confirmed','{}');
                 INSERT INTO agent_block_lifecycle_facts VALUES('run-1',8,'block-1','slot_released','{}');
                 INSERT INTO agent_block_lifecycle_facts VALUES('run-1',8,'block-1','process_survived','{\"surviving_processes\":[23]}');",
            )
            .unwrap();
        drop(writable);

        let readonly =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let state = recovery_state(&readonly, "run-1", "block-1").unwrap();
        assert_eq!(state.reservation_epoch, 8);
        assert_eq!(state.observation_order, Some(42));
        assert_eq!(state.disposition, "released");
        assert!(state.event_received && state.exit_confirmed && state.slot_released);
        assert_eq!(
            state.process_survived.unwrap()["surviving_processes"][0],
            23
        );
        let other_block = recovery_state(&readonly, "run-1", "different-block").unwrap();
        assert!(
            !other_block.event_received
                && !other_block.exit_confirmed
                && !other_block.slot_released
        );
        drop(readonly);
        let writable = Connection::open(&path).unwrap();
        writable
            .execute(
                "UPDATE agent_run_recovery_observations SET controller_generation=4 WHERE agent_run_id='run-1'",
                [],
            )
            .unwrap();
        drop(writable);
        let readonly =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert!(recovery_state(&readonly, "run-1", "block-1").is_err());
    }

    #[test]
    fn acceptance_preflight_rejects_reused_fixture_windows_but_allows_harmless_windows() {
        let fixture_labels = [
            CONTROLLER_WINDOW_LABEL.to_owned(),
            owned_supervisor_window_label(FIXTURE_PROJECT_ID),
            owned_ticket_window_label(FIXTURE_TICKET_NAMESPACE, FIXTURE_TICKET_ID).unwrap(),
        ];
        for label in fixture_labels {
            let session = json!({"windows":[{"label":label,"layers":[]}]});
            let error = verify_fixture_session_is_fresh(&session).unwrap_err();
            assert!(error.contains("fresh session"), "{error}");
        }
        verify_fixture_session_is_fresh(&json!({"windows":[{"label":"Harmless","layers":[]}]}))
            .unwrap();
    }

    #[test]
    fn acceptance_preflight_accepts_empty_session_without_windows_field() {
        let session: Value =
            serde_json::from_slice(br#"{"session_id":"fixture-session","label":"empty-session"}"#)
                .unwrap();
        verify_fixture_session_is_fresh(&session).unwrap();
        for windows in [Value::Null, json!("not-an-array")] {
            assert!(verify_fixture_session_is_fresh(&json!({"windows":windows})).is_err());
        }
    }

    #[test]
    fn generated_fixture_contexts_deserialize_with_the_agent_contract() {
        for role in PROVIDER_ROLES {
            let scenario = format!("acceptance_{role}");
            let context = serde_json::json!({
                "schema_version": 1,
                "scenario": scenario,
                "messages": profile_messages(role, false).unwrap(),
            });
            serde_json::from_value::<crate::fixtures::agent::AgentContext>(context)
                .unwrap_or_else(|error| panic!("{role} fixture context is invalid: {error}"));
        }
        let host_worker = serde_json::json!({
            "schema_version":1,
            "scenario":"acceptance_worker",
            "messages":profile_messages("worker", true).unwrap()
        });
        serde_json::from_value::<crate::fixtures::agent::AgentContext>(host_worker)
            .expect("host Worker fixture context follows the closed Agent contract");
    }

    #[test]
    fn held_coordinator_profile_uses_the_direct_executable_from_product_config_parser() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(
            &request,
            &executable,
            request.cli,
            ProfilePreparation {
                hold_coordinator_after_inbox: true,
                ..ProfilePreparation::default()
            },
        )
        .unwrap();
        fs::write(
            root.join("config.toml"),
            config_text(&request, &executable, false),
        )
        .unwrap();

        let applied = rex_projects::config::load(&root.join("config.toml")).unwrap();
        let profile = applied
            .profiles
            .iter()
            .find(|(profile_id, _)| profile_id.as_str() == "fixture_coordinator")
            .map(|(_, profile)| profile)
            .unwrap();
        let configured_executable = Path::new(&profile.command[0]).canonicalize().unwrap();
        assert_eq!(configured_executable, executable.canonicalize().unwrap());
        assert_eq!(profile.command[1..3], ["fixture", "agent"]);
        assert!(profile.command.iter().all(|argument| {
            argument != "/usr/bin/env" && !argument.starts_with("REX_PROJECTS_FIXTURE_HOLD_")
        }));

        let context =
            crate::fixtures::agent::read_context(&root.join("contexts/coordinator.json")).unwrap();
        assert!(context.hold_after_inbox);

        let probe = std::process::Command::new(&configured_executable)
            .arg("--list")
            .output()
            .unwrap();
        assert!(probe.status.success());
    }

    #[test]
    fn generated_worker_profile_resolves_the_stage_commit_contract() {
        for (hold_worker, expected_mode) in [
            (false, rex_projects::domain::types::CommitMode::Native),
            (true, rex_projects::domain::types::CommitMode::Host),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("acceptance");
            fs::create_dir(&root).unwrap();
            let request = Request {
                cli: Path::new("/usr/bin/true"),
                rex: Path::new("/usr/bin/true"),
                rex_server: "unix:///fixture.sock",
                rex_session: "acceptance-session",
                expected_instance: "fixture-instance",
                fixture_root: &root,
            };
            let executable = std::env::current_exe().unwrap();
            prepare_profiles(
                &request,
                &executable,
                request.cli,
                ProfilePreparation {
                    hold_worker_after_inbox: hold_worker,
                    host_worker: expected_mode == rex_projects::domain::types::CommitMode::Host,
                    ..ProfilePreparation::default()
                },
            )
            .unwrap();
            fs::write(
                root.join("config.toml"),
                config_text(&request, &executable, false),
            )
            .unwrap();
            let applied = rex_projects::config::load(&root.join("config.toml")).unwrap();
            let worker = applied
                .profiles
                .iter()
                .find(|(id, _)| id.as_str() == "fixture_worker")
                .map(|(_, profile)| profile)
                .unwrap();
            assert_eq!(worker.commit_mode, expected_mode);
            assert!(applied.profiles.iter().all(|(id, profile)| {
                id.as_str() == "fixture_worker"
                    || profile.commit_mode == rex_projects::domain::types::CommitMode::Native
            }));
            let context =
                crate::fixtures::agent::read_context(&root.join("contexts/worker.json")).unwrap();
            assert_eq!(context.hold_after_inbox, hold_worker);
        }
    }

    #[test]
    fn generated_supervisor_context_passes_the_actual_fixture_recipe_parser() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(
            &request,
            &executable,
            request.cli,
            ProfilePreparation::default(),
        )
        .unwrap();

        let context =
            crate::fixtures::agent::read_context(&root.join("contexts/supervisor.json")).unwrap();
        let dispatch = context
            .messages
            .iter()
            .find(|message| {
                message.lane == Some(crate::fixtures::agent::FixtureLane::Workflow)
                    && message.kind == RoleOutputKind::DispatchRequest
            })
            .expect("generated Supervisor dispatch recipe exists");
        assert_eq!(
            dispatch.recipe.structured_result["coordinator_profile"]["$fixture_ref"],
            "inbox.coordinator_profile"
        );
    }

    #[test]
    fn generated_review_rework_context_preserves_the_reviewer_parent_request() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("review-rework");
        fs::create_dir(&root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        prepare_profiles(
            &request,
            &std::env::current_exe().unwrap(),
            request.cli,
            ProfilePreparation {
                host_worker: true,
                worker_review_rework_stage: true,
                ..ProfilePreparation::default()
            },
        )
        .unwrap();
        let context =
            crate::fixtures::agent::read_context(&root.join("contexts/coordinator.json")).unwrap();
        let workflow = context
            .messages
            .iter()
            .filter(|item| item.lane == Some(crate::fixtures::agent::FixtureLane::Workflow))
            .collect::<Vec<_>>();
        assert_eq!(workflow.len(), 4);
        assert_eq!(workflow[2].kind, RoleOutputKind::SpawnRequest);
        assert_eq!(workflow[2].recipe.structured_result["role"], "reviewer");
        assert_eq!(workflow[3].kind, RoleOutputKind::Progress);
    }

    #[test]
    fn generated_verification_context_uses_registered_receipts_and_preserves_role_parents() {
        let temporary = tempfile::tempdir().unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "fixture-session",
            expected_instance: "fixture-instance",
            fixture_root: temporary.path(),
        };
        prepare_profiles(
            &request,
            &std::env::current_exe().unwrap(),
            request.cli,
            ProfilePreparation {
                host_worker: true,
                worker_verification_stage: true,
                worker_review_rework_stage: true,
                ..ProfilePreparation::default()
            },
        )
        .unwrap();
        for role in PROVIDER_ROLES {
            let context = crate::fixtures::agent::read_context(
                &temporary.path().join(format!("contexts/{role}.json")),
            )
            .unwrap();
            let workflow = context
                .messages
                .iter()
                .filter(|message| {
                    message.lane == Some(crate::fixtures::agent::FixtureLane::Workflow)
                })
                .collect::<Vec<_>>();
            match role {
                "worker" => {
                    assert_eq!(workflow.len(), 2);
                    assert_eq!(workflow[1].kind, RoleOutputKind::VerificationReady);
                    assert_eq!(workflow[1].actions.len(), 2);
                    let encoded = serde_json::to_value(&workflow[1].actions[1]).unwrap();
                    assert_eq!(encoded["action"], "register_artifact");
                    assert_eq!(encoded["remove_after_registration"], true);
                }
                "reviewer" => {
                    assert_eq!(workflow.len(), 2);
                    assert_eq!(
                        workflow[0].recipe.structured_result["disposition"],
                        "changes_requested"
                    );
                    assert_eq!(
                        workflow[1].recipe.structured_result["disposition"],
                        "approved"
                    );
                }
                "coordinator" => {
                    let request: rex_projects::engine::orchestration::SpawnRequestPayload =
                        serde_json::from_value(resolve_test_references(
                            workflow[3].recipe.structured_result.clone(),
                        ))
                        .expect("the correction Worker result must prompt an immediate Reviewer request");
                    assert_eq!(request.role, rex_projects::domain::types::Role::Reviewer);
                    assert_eq!(request.work_node.as_str(), "acceptance-node");
                    assert_eq!(
                        workflow
                            .iter()
                            .filter(|message| message.kind == RoleOutputKind::SpawnRequest
                                && message.recipe.structured_result["role"] == "reviewer")
                            .count(),
                        2
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn emulated_workflow_messages_match_current_role_schemas() {
        for role in PROVIDER_ROLES {
            for message in profile_messages(role, false)
                .unwrap()
                .into_iter()
                .chain(profile_messages_with_review_rework(role).unwrap())
                .chain(profile_messages_with_worker_verification(role).unwrap())
            {
                if message["lane"] != "workflow" {
                    continue;
                }
                let kind: RoleOutputKind = serde_json::from_value(message["kind"].clone()).unwrap();
                let payload = resolve_test_references(message["structured_result"].clone());
                crate::fixtures::agent::validate_payload(kind, &payload).unwrap_or_else(|error| {
                    panic!(
                        "{role} {:?} payload does not match the current schema: {error}; {payload}",
                        kind
                    )
                });
                for reference in message["artifact_refs"].as_array().into_iter().flatten() {
                    let resolved = resolve_test_references(reference.clone());
                    serde_json::from_value::<RoleArtifactReference>(resolved).unwrap_or_else(
                        |error| panic!("{role} artifact ref has invalid schema: {error}"),
                    );
                }
            }
        }
        for message in profile_messages("worker", true).unwrap() {
            if message["lane"] == "workflow" {
                let kind: RoleOutputKind = serde_json::from_value(message["kind"].clone()).unwrap();
                let payload = resolve_test_references(message["structured_result"].clone());
                crate::fixtures::agent::validate_payload(kind, &payload).unwrap();
            }
        }
    }

    #[test]
    fn fixture_git_environment_retains_signature_verification_and_authentication_config() {
        let root = tempfile::tempdir().unwrap();
        let signers = root.path().join("allowed_signers");
        fs::write(&signers, "configured public signer\n").unwrap();
        let snapshot = BTreeMap::from([
            ("GIT_CONFIG_COUNT".into(), "2".into()),
            (
                "GIT_CONFIG_KEY_0".into(),
                "gpg.ssh.allowedSignersFile".into(),
            ),
            ("GIT_CONFIG_VALUE_0".into(), signers.as_os_str().to_owned()),
            ("GIT_CONFIG_KEY_1".into(), "credential.helper".into()),
            ("GIT_CONFIG_VALUE_1".into(), "configured-user-helper".into()),
        ]);
        let environment = fixture_git_environment(root.path(), &snapshot).unwrap();
        for (key, expected) in [
            ("gpg.ssh.allowedSignersFile", signers.to_str().unwrap()),
            ("credential.helper", "configured-user-helper"),
            (
                &format!(
                    "url.file://{}.insteadOf",
                    root.path().join("git/fixture/repository.git").display()
                ),
                "https://github.com/fixture/repository.git",
            ),
        ] {
            let output = std::process::Command::new("git")
                .args(["config", "--get", key])
                .envs(&environment)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git config failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
        }
    }

    #[test]
    fn supervisor_dispatch_uses_observed_ticket_and_coordinator_waits_for_planner() {
        let supervisor = profile_messages("supervisor", false).unwrap();
        let dispatch = &supervisor
            .iter()
            .find(|message| message["lane"] == "workflow")
            .unwrap()["structured_result"];
        assert_eq!(
            dispatch["ticket_reference"]["$fixture_ref"],
            "inbox.ticket_id"
        );
        assert_eq!(
            dispatch["expected_ticket_revision"]["$fixture_ref"],
            "inbox.external_revision"
        );

        let coordinator = profile_messages("coordinator", false).unwrap();
        let workflow = coordinator
            .iter()
            .filter(|message| message["lane"] == "workflow")
            .collect::<Vec<_>>();
        assert_eq!(workflow[0]["kind"], "spawn_request");
        assert_eq!(workflow[0]["structured_result"]["role"], "planner");
        assert!(workflow[0]["structured_result"]["plan_digest"].is_null());
        assert_eq!(workflow[1]["kind"], "plan_ready");
        assert_eq!(
            workflow[1]["structured_result"]["$fixture_ref"],
            "inbox.planner_result"
        );
    }

    #[test]
    fn worker_recovery_fixture_spawns_same_node_from_a_prompt_candidate() {
        let coordinator = profile_messages_with_worker_recovery("coordinator", true).unwrap();
        let workflow = coordinator
            .iter()
            .filter(|message| message["lane"] == "workflow")
            .collect::<Vec<_>>();
        assert_eq!(workflow.len(), 3);
        assert_eq!(workflow[2]["kind"], "spawn_request");
        assert_eq!(workflow[2]["structured_result"]["role"], "worker");
        assert_eq!(
            workflow[2]["structured_result"]["work_node"],
            "acceptance-node"
        );
        assert_eq!(
            workflow[2]["structured_result"]["worker_recovery"]["$fixture_ref"],
            "prompt.recovery_candidate"
        );
        assert_eq!(
            workflow[2]["structured_result"]["plan_digest"]["$fixture_ref"],
            "prompt.accepted_plan_digest"
        );

        let worker = profile_messages_with_worker_recovery("worker", true).unwrap();
        let workflow = worker
            .iter()
            .filter(|message| message["lane"] == "workflow")
            .collect::<Vec<_>>();
        assert_eq!(workflow[0]["kind"], "progress");
        assert_eq!(workflow[0]["assertion"]["assertion"], "blocked");
        assert_eq!(workflow[1]["kind"], "implementation_ready");
    }

    #[test]
    fn recovery_context_uses_the_production_fixture_reader() {
        let root = tempfile::tempdir().unwrap();
        let context_path = root.path().join("coordinator.json");
        fs::write(
            &context_path,
            serde_json::to_vec(&json!({
                "schema_version":1,
                "scenario":"acceptance_coordinator",
                "messages":profile_messages_with_worker_recovery("coordinator", true).unwrap()
            }))
            .unwrap(),
        )
        .unwrap();

        let context = crate::fixtures::agent::read_context(&context_path)
            .expect("production fixture reader accepts the generated recovery recipe");
        assert_eq!(context.scenario, "acceptance_coordinator");
    }

    #[test]
    fn generated_supervisor_context_keeps_qualification_progress_separate_from_dispatch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(
            &request,
            &executable,
            request.cli,
            ProfilePreparation::default(),
        )
        .unwrap();
        let context =
            crate::fixtures::agent::read_context(&root.join("contexts/supervisor.json")).unwrap();
        let supervisor_messages = context
            .messages
            .iter()
            .filter(|message| message.role == rex_projects::domain::types::Role::Supervisor)
            .collect::<Vec<_>>();
        assert_eq!(supervisor_messages.len(), 2);
        assert_eq!(
            supervisor_messages[0].lane,
            Some(crate::fixtures::agent::FixtureLane::Qualification)
        );
        assert_eq!(
            supervisor_messages[0].kind,
            rex_projects::engine::orchestration::RoleOutputKind::Progress
        );
        assert_eq!(
            supervisor_messages[1].lane,
            Some(crate::fixtures::agent::FixtureLane::Workflow)
        );
        assert_eq!(
            supervisor_messages[1].kind,
            rex_projects::engine::orchestration::RoleOutputKind::DispatchRequest
        );
    }

    #[test]
    fn fake_forge_reads_the_owned_fixture_bare_repository() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("state")).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        prepare_local_repository(&request, &std::env::current_exe().unwrap()).unwrap();
        let args = ["api", "repos/fixture/repository"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        crate::fixtures::github::run_cli(&root, &args).unwrap();
    }

    #[test]
    fn owned_fake_gh_survives_production_executable_resolution() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("state")).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_local_repository(&request, &executable).unwrap();

        let fake_gh = root.join("bin/gh");
        assert_eq!(
            rex_projects::process::resolve_executable(
                Path::new("gh"),
                std::slice::from_ref(&root.join("bin")),
            ),
            Some(root.join("bin").canonicalize().unwrap().join("gh")),
        );
        let metadata = fs::symlink_metadata(&fake_gh).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
    }

    #[test]
    fn generated_operations_fixture_config_passes_product_config_validation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("acceptance");
        fs::create_dir(&root).unwrap();
        let request = Request {
            cli: Path::new("/usr/bin/true"),
            rex: Path::new("/usr/bin/true"),
            rex_server: "unix:///fixture.sock",
            rex_session: "acceptance-session",
            expected_instance: "fixture-instance",
            fixture_root: &root,
        };
        let executable = std::env::current_exe().unwrap();
        prepare_profiles(
            &request,
            &executable,
            request.cli,
            ProfilePreparation::default(),
        )
        .unwrap();
        let config = root.join("config.toml");
        fs::write(&config, config_text(&request, &executable, false)).unwrap();
        rex_projects::config::load(&config).unwrap();
    }

    #[test]
    fn generated_native_config_selects_native_worker_capacity_and_low_retention_without_changing_defaults()
     {
        for (native_stage, expected_max_agent_runs, expected_max_blocks, expected_completed_keep) in
            [(false, 8, 8, 1), (true, 1, 2, 0)]
        {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("acceptance");
            fs::create_dir(&root).unwrap();
            let request = Request {
                cli: Path::new("/usr/bin/true"),
                rex: Path::new("/usr/bin/true"),
                rex_server: "unix:///fixture.sock",
                rex_session: "acceptance-session",
                expected_instance: "fixture-instance",
                fixture_root: &root,
            };
            let executable = std::env::current_exe().unwrap();
            prepare_profiles(
                &request,
                &executable,
                request.cli,
                ProfilePreparation::default(),
            )
            .unwrap();
            let config_path = root.join("config.toml");
            fs::write(
                &config_path,
                config_text(&request, &executable, native_stage),
            )
            .unwrap();

            let loaded = rex_projects::config::load(&config_path).unwrap();
            assert_eq!(
                loaded.config.runtime.max_agent_runs, expected_max_agent_runs,
                "native_stage={native_stage}"
            );
            assert_eq!(
                loaded.config.runtime.max_blocks_per_tab, expected_max_blocks,
                "native_stage={native_stage}"
            );
            assert_eq!(
                loaded.config.runtime.completed_blocks_to_keep, expected_completed_keep,
                "native_stage={native_stage}"
            );
        }
    }

    fn resolve_test_references(value: Value) -> Value {
        match value {
            Value::Object(mut map) if map.len() == 1 && map.contains_key("$fixture_ref") => {
                let name = map
                    .remove("$fixture_ref")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned();
                match name.as_str() {
                    "worker.commit_shas" => json!(["1".repeat(40)]),
                    "worker.host_commit_operation_id" => json!("repo-commit-fixture"),
                    "worker.commit_mode" => json!("native"),
                    "worker.base_sha"
                    | "worker.previous_head"
                    | "worker.branch_head"
                    | "prompt.source_commit" => json!("1".repeat(40)),
                    "worker.repository_id" => json!("fixture"),
                    "artifact.test_receipt.artifact_id" => json!("c".repeat(64)),
                    "prompt.published_head" => json!("1".repeat(40)),
                    "prompt.publication_operation_id" => json!("publish-fixture"),
                    name if name.starts_with("artifact.") => {
                        artifact_ref(name.trim_start_matches("artifact."))
                    }
                    name if name.starts_with("prompt.") => {
                        let field = name.trim_start_matches("prompt.");
                        match field {
                            "node_key" => json!("acceptance-node"),
                            "environment" => json!("test"),
                            "remote_receipt" => json!({}),
                            "pr_reference" => json!("fixture/repository#1"),
                            "evidence_coverage" => json!(["acceptance-node"]),
                            _ => json!("a".repeat(64)),
                        }
                    }
                    "ticket_revision" => json!(1),
                    "inbox.ticket_id" => json!("T-1"),
                    "inbox.external_revision" => json!("rev-1"),
                    "inbox.coordinator_profile" => json!("fixture_coordinator"),
                    "inbox.planner_result" => json!({
                        "plan":{"nodes":[{"id":"acceptance-node","repository":"fixture","task":ACCEPTANCE_WORK_TASK,"depends_on":[],"required_evidence":["The exact committed source change is visible in the prepared worktree."],"investigation":false}],"requested_investigation_children":0},
                        "unresolved_questions":[]
                    }),
                    _ => json!("acceptance-node"),
                }
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| (key, resolve_test_references(value)))
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.into_iter().map(resolve_test_references).collect())
            }
            primitive => primitive,
        }
    }

    fn artifact_ref(kind: &str) -> Value {
        let bytes = 16;
        let path = format!("evidence/{kind}.md");
        let digest = "b".repeat(64);
        let kind = if kind == "operation" {
            "operation_receipt"
        } else {
            kind
        };
        json!({"kind":kind,"artifact_id":"c".repeat(64),"schema_version":1,"path":path,"digest":digest,"bytes":bytes})
    }
}
