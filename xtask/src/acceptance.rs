use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rex_projects::adapters::rex::{
    CreateDisposition, RexCliTransport, TicketWindow, owned_supervisor_window_label,
    owned_ticket_window_label,
};
use rex_projects::process::{ProcessOutput, ProcessRequest, run as run_process};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const OUTPUT_LIMIT: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const POLL_LIMIT: Duration = Duration::from_secs(20);
const FULL_FLOW_LIMIT: Duration = Duration::from_secs(30 * 60);
const QUALIFICATION_LIMIT: Duration = Duration::from_secs(180);
const COORDINATOR_STAGE_LIMIT: Duration = Duration::from_secs(180);
const ACCEPTANCE_STAGE_ENV: &str = "REX_PROJECTS_ACCEPTANCE_STAGE";
const COORDINATOR_INBOX_STAGE: &str = "supervisor_coordinator_inbox";
const COORDINATOR_BLOCK_LOSS_STAGE: &str = "supervisor_coordinator_block_loss";
const CONTROLLER_WINDOW_LABEL: &str = "rex-projects-controller";
const FIXTURE_PROJECT_ID: &str = "operations_project";
const FIXTURE_TICKET_NAMESPACE: &str = "fixture/acceptance";
const FIXTURE_TICKET_ID: &str = "ticket-1";
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
            if stage == COORDINATOR_INBOX_STAGE || stage == COORDINATOR_BLOCK_LOSS_STAGE =>
        {
            Ok(Some(stage))
        }
        Some(_) => Err(format!(
            "unsupported acceptance stage in {ACCEPTANCE_STAGE_ENV}"
        )),
    }
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
    let bounded_coordinator_stage = stage.is_some();
    let coordinator_block_loss_stage = stage.as_deref() == Some(COORDINATOR_BLOCK_LOSS_STAGE);
    let provider_roles: &[&str] = if bounded_coordinator_stage {
        &["supervisor", "coordinator"]
    } else {
        &PROVIDER_ROLES
    };
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
        bounded_coordinator_stage,
    )?;
    trace.push(json!({"step":"local_bare_repository_and_profiles","status":"passed","provider":"EMULATED"}));

    let config_path = request.fixture_root.join("config.toml");
    fs::write(&config_path, config_text(&request, &executable))
        .map_err(|error| format!("write fixture config: {error}"))?;
    let seeded_ticket = seed_operations_ticket(&request, &executable)?;
    trace.push(json!({"step":"external_ticket_seeded_through_adapter_protocol","status":"observed","evidence":seeded_ticket}));
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
        OsString::from("GIT_CONFIG_COUNT=1"),
        OsString::from(format!(
            "GIT_CONFIG_KEY_0=url.file://{}.insteadOf",
            request
                .fixture_root
                .join("git/fixture/repository.git")
                .display()
        )),
        OsString::from("GIT_CONFIG_VALUE_0=https://github.com/fixture/repository.git"),
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
            let output = product(
                &request,
                &state_root,
                &[
                    "provider",
                    "qualify",
                    "--project",
                    project,
                    "--role",
                    role,
                    "--request-id",
                    &request_id,
                    "--json",
                ],
            )?;
            if !output.status.is_some_and(|status| status.success()) {
                trace.push(json!({"step":"provider_qualification_queue","project":project,"role":role,"status":"rejected","stderr":String::from_utf8_lossy(&output.stderr_tail)}));
                break;
            }
            let response = json_stdout(&output);
            let digest = response["request_digest"]
                .as_str()
                .ok_or("provider qualify response omitted request_digest")?;
            trace.push(json!({"step":"provider_qualification_queue","project":project,"role":role,"status":"queued","request_id":request_id,"request_digest":digest,"emulator":"EMULATED"}));
            qualifications.push((project, role, request_id, digest.to_owned(), response));
        }
        loop {
            let mut phase_pending = false;
            for (project, role, request_id, expected_digest, queued) in
                &qualifications[phase_start..]
            {
                if terminal_qualifications.contains_key(request_id) {
                    continue;
                }
                let output = product(
                    &request,
                    &state_root,
                    &["--json", "provider", "status", "--request-id", request_id],
                )?;
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
            let output = product(
                &request,
                &state_root,
                &["project", "start", project, "--json"],
            )?;
            if !output.status.is_some_and(|status| status.success()) {
                trace.push(json!({"step":"project_start_after_supervisor_qualification","project":project,"status":"rejected","evidence":json_stdout(&output)}));
                qualification_failure = true;
                break;
            }
            project_started = true;
            trace.push(json!({"step":"project_start_after_supervisor_qualification","project":project,"status":"queued","evidence":json_stdout(&output)}));
            let proof = observe_coordinator_qualification_wait(
                &request,
                &state_root,
                &block,
                "fixture_coordinator",
            );
            trace.push(json!({"step":"coordinator_missing_qualification_wait","status":proof["status"],"evidence":proof}));
            if proof["status"] != "passed" {
                qualification_failure = true;
                coordinator_qualification_wait_proof = Some(proof);
                break;
            }
            coordinator_qualification_wait_proof = Some(proof);
        }
    }
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
    let mut coordinator_block_loss_proof = None;
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
        if bounded_coordinator_stage {
            let observations = read_public_inbox_observations(request.fixture_root)?;
            if let Some(coordinator) = observations
                .iter()
                .find(|observation| is_coordinator_dispatch_observation(observation))
            {
                trace.push(json!({"step":"coordinator_inbox_boundary_observed","status":"passed","evidence":coordinator}));
                coordinator_boundary_reached = true;
                if coordinator_block_loss_stage {
                    let proof = observe_coordinator_block_loss(&request, &state_root, coordinator);
                    let proof = proof.unwrap_or_else(
                        |error| json!({"status":"failed","reason":error,"fault_injected":false}),
                    );
                    trace.push(json!({"step":"coordinator_block_loss_recovery","status":proof["status"],"evidence":proof}));
                    coordinator_block_loss_proof = Some(proof);
                    break;
                }
                let stop = product(&request, &state_root, &["runtime", "stop", "--json"])?;
                if !stop.status.is_some_and(|status| status.success()) {
                    trace.push(json!({"step":"bounded_stage_stop_request","status":"rejected","evidence":json_stdout(&stop)}));
                    break;
                }
                trace.push(json!({"step":"bounded_stage_stop_request","status":"queued","evidence":json_stdout(&stop)}));
                break;
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
    let current_stop = if external_done {
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
    let coordinator_observation = inbox_observations
        .iter()
        .find(|observation| is_coordinator_dispatch_observation(observation));
    let supervisor_observation = inbox_observations
        .iter()
        .find(|observation| observation["role"] == "supervisor");
    let stage_valid = bounded_coordinator_stage
        && coordinator_qualification_wait_proof
            .as_ref()
            .is_some_and(|proof| proof["status"] == "passed")
        && coordinator_boundary_reached
        && stopped
        && coordinator_observation.is_some()
        && (!coordinator_block_loss_stage
            || coordinator_block_loss_proof
                .as_ref()
                .is_some_and(|proof| proof["status"] == "passed"))
        && supervisor_observation.is_some_and(|observation| {
            observation
                .pointer("/input_files/effective_role_profiles/coordinator")
                .and_then(Value::as_str)
                == Some("fixture_coordinator")
        });
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
        "missing_capabilities":if bounded_coordinator_stage {vec!["This bounded emulated stage does not claim downstream role completion or external Done."]} else {vec!["This emulated lane does not establish host-verified completion of every required role stage and external Done."]},
        "fixture_provider":"EMULATED",
        "resources_created":true,
        "owned_rex_session":request.rex_session,
        "owned_rex_windows":[window],
        "fixture_root":request.fixture_root
    });
    emit_report(request.fixture_root, &report)?;
    if bounded_coordinator_stage && !stage_valid {
        return Err("bounded Supervisor-to-Coordinator connection stage did not reach its contract boundary".into());
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

fn prepare_local_repository(request: &Request<'_>, executable: &Path) -> Result<(), String> {
    let bare = request.fixture_root.join("git/fixture/repository.git");
    fs::create_dir_all(
        bare.parent()
            .ok_or("fixture bare repository has no parent directory")?,
    )
    .map_err(|error| error.to_string())?;
    fs::create_dir_all(request.fixture_root.join("bin")).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(executable, request.fixture_root.join("bin/gh"))
        .map_err(|error| format!("link owned fake gh transport: {error}"))?;
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

fn prepare_profiles(
    request: &Request<'_>,
    executable: &Path,
    runtime_binary: &Path,
    hold_coordinator_after_inbox: bool,
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
        let messages = profile_messages(role)?;
        let hold = hold_coordinator_after_inbox && role == "coordinator";
        fs::write(
            &context,
            serde_json::to_vec(
                &json!({"schema_version":1,"scenario":scenario,"hold_after_inbox":hold,"messages":messages}),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let command = format!(
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
        );
        let config = format!(
            "adapter = \"codex\"\ncommand = {command}\nmodel = \"fixture-emulator\"\n\n[options]\nsandbox = \"workspace_write\"\napproval = \"never\"\n"
        );
        fs::write(profile.join("config.toml"), config).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn profile_messages(role: &str) -> Result<Vec<Value>, String> {
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
                "work_node":"acceptance-node","role":"worker","profile_id":"fixture_worker",
                "plan_digest":{"$fixture_ref":"prompt.accepted_plan_digest"},
                "allowed_repositories":["fixture"],"artifact_inputs":[],"parent_run_id":null
            })),
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
            "plan":{"nodes":[{"id":"acceptance-node","repository":"fixture","task":"Create and commit a bounded acceptance fixture artifact.","depends_on":[],"required_evidence":["The exact committed source change is visible in the prepared worktree."],"investigation":false}],"requested_investigation_children":0},
            "unresolved_questions":[]
        }))],
        "worker" => vec![message("worker", "implementation_ready", json!({
            "change_references":[{"repository":{"$fixture_ref":"worker.repository_id"},"worktree_id":{"$fixture_ref":"worker_node_id"},"commit_mode":{"$fixture_ref":"worker.commit_mode"},"base_commit":{"$fixture_ref":"worker.base_sha"},"previous_head":{"$fixture_ref":"worker.previous_head"},"branch_head":{"$fixture_ref":"worker.branch_head"},"commit_shas":{"$fixture_ref":"worker.commit_shas"}}],
            "completed_acceptance_items":["The fixture artifact was committed in the assigned managed worktree."],
            "unresolved_items":[],"irregularity_references":[]
        })).with_actions(vec![
            json!({"action":"write_file","path":"fixture-change.md","contents":"# Acceptance fixture change\n\nCreated by the bounded emulated Worker action.\n"}),
            json!({"action":"git_commit","action_id":"worker-change","message":"test: record acceptance fixture change"}),
            json!({"action":"register_artifact","action_id":"change","path":"fixture-change.md","kind":"change","schema_version":1,"message_id":"fixture-change-artifact"})
        ]).with_artifact_ref(json!({"$fixture_ref":"artifact.change"}))],
        "reviewer" => vec![message("reviewer", "review_ready", json!({
            "subject_kind":"patch","subject_digest":{"$fixture_ref":"prompt.subject_digest"},
            "findings":[],"evidence_coverage":["The assigned change and acceptance criterion were inspected."],
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
            message("merge_decision", "merge_intent", json!({
                "assessment_id":{"$fixture_ref":"prompt.assessment_id"},
                "pr_identities":[{"$fixture_ref":"prompt.pr_reference"}],
                "policy_digest":{"$fixture_ref":"prompt.policy_digest"},"prepared_body_digest":{"$fixture_ref":"prompt.prepared_body_digest"},
                "steps":[{"kind":"direct_merge","instruction_reference":"repository.merge.instructions#procedure","rationale":"Use the fixture repository's declared merge procedure."},{"kind":"verify_merge_commit","instruction_reference":"repository.merge.instructions#verification","rationale":"Verify the host-observed target commit."}],
                "post_merge_verification":[{"kind":"merge_commit_recorded","instruction_reference":"repository.merge.instructions#verification","rationale":"Confirm the forge records the merge commit."},{"kind":"target_branch_contains_commit","instruction_reference":"repository.merge.instructions#verification","rationale":"Confirm the target branch contains the merged head."}]
            }))
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

fn config_text(request: &Request<'_>, executable: &Path) -> String {
    let db = request.fixture_root.join("tickets.sqlite");
    format!(
        r#"schema_version = 1
state_root = {:?}

[runtime]
rex_binary = {:?}
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
executor = "direct"
instructions = "Use the repository's configured merge procedure."
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
        executable.display().to_string(),
        db.display().to_string(),
        executable.display().to_string(),
        request
            .fixture_root
            .join("operations")
            .display()
            .to_string(),
    )
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
    let windows = session
        .get("windows")
        .and_then(Value::as_array)
        .ok_or("Rex session inspect omitted its windows array")?;
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
    .map_err(|error| error.to_string())
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
    use rex_projects::engine::orchestration::{RoleArtifactReference, RoleOutputKind};

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
    fn generated_fixture_contexts_deserialize_with_the_agent_contract() {
        for role in PROVIDER_ROLES {
            let scenario = format!("acceptance_{role}");
            let context = serde_json::json!({
                "schema_version": 1,
                "scenario": scenario,
                "messages": profile_messages(role).unwrap(),
            });
            serde_json::from_value::<crate::fixtures::agent::AgentContext>(context)
                .unwrap_or_else(|error| panic!("{role} fixture context is invalid: {error}"));
        }
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
        prepare_profiles(&request, &executable, request.cli, true).unwrap();
        fs::write(root.join("config.toml"), config_text(&request, &executable)).unwrap();

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
        prepare_profiles(&request, &executable, request.cli, false).unwrap();

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
    fn emulated_workflow_messages_match_current_role_schemas() {
        for role in PROVIDER_ROLES {
            for message in profile_messages(role).unwrap() {
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
    }

    #[test]
    fn supervisor_dispatch_uses_observed_ticket_and_coordinator_waits_for_planner() {
        let supervisor = profile_messages("supervisor").unwrap();
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

        let coordinator = profile_messages("coordinator").unwrap();
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
        prepare_profiles(&request, &executable, request.cli, false).unwrap();
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
        prepare_profiles(&request, &executable, request.cli, false).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, config_text(&request, &executable)).unwrap();
        rex_projects::config::load(&config).unwrap();
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
                    "worker.commit_mode" => json!("native"),
                    "worker.base_sha"
                    | "worker.previous_head"
                    | "worker.branch_head"
                    | "prompt.source_commit" => json!("1".repeat(40)),
                    "worker.repository_id" => json!("fixture"),
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
                            _ => json!("a".repeat(64)),
                        }
                    }
                    "ticket_revision" => json!(1),
                    "inbox.ticket_id" => json!("T-1"),
                    "inbox.external_revision" => json!("rev-1"),
                    "inbox.coordinator_profile" => json!("fixture_coordinator"),
                    "inbox.planner_result" => json!({
                        "plan":{"nodes":[{"id":"acceptance-node","repository":"fixture","task":"Create and commit a bounded acceptance fixture artifact.","depends_on":[],"required_evidence":["The exact committed source change is visible in the prepared worktree."],"investigation":false}],"requested_investigation_children":0},
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
