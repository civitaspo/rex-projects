//! Reconciles persisted Rex views with exact windows and owned blocks.

use crate::adapters::rex::{
    AgentBlockSpec, CreateDisposition, RexBlockConfiguration, RexCliTransport, RexWindow,
    WindowBlock, owned_agent_block_label, owned_supervisor_window_label, owned_ticket_window_label,
};
use crate::domain::ids::ProjectId;
use crate::launch::{
    RexBlockLifecycle, RexBlockOwnership, RexViewCleanupCandidate, RexViewKind, RexViewRecord,
};
use crate::store::ConfigStore;
use sha2::{Digest as _, Sha256};

const MAX_BLOCKS_PER_TICK: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RexViewLifecyclePolicy {
    pub max_blocks_per_tab: usize,
    pub completed_blocks_to_keep: usize,
    pub completed_ticket_tab_retention_seconds: u64,
}

pub fn anchor_command_digest(spec: &AgentBlockSpec) -> Result<crate::domain::ids::Digest, String> {
    let identity = serde_json::json!({
        "run_id": spec.run_id,
        "command": spec.command.display().to_string(),
        "args": spec.args,
        "cwd": spec.cwd.display().to_string(),
        "path_prepend": spec.path_prepend.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&identity).map_err(|error| error.to_string())?;
    crate::domain::ids::Digest::parse(format!("{:x}", Sha256::digest(&bytes)))
}

pub(crate) fn record_created_view_anchor(
    store: &mut ConfigStore,
    owner_generation: u64,
    view: &crate::launch::RexView,
    window: &RexWindow,
    spec: &AgentBlockSpec,
    transport: &RexCliTransport,
) -> Result<(), String> {
    if window.disposition != CreateDisposition::Created {
        return Ok(());
    }
    let Some(block_id) = window.initial_block_id.as_deref() else {
        return Ok(());
    };
    let label = owned_agent_block_label(&spec.run_id).map_err(|error| error.to_string())?;
    let (expected_run_id, expected_window_label) = match view.kind {
        RexViewKind::Ticket => {
            let ticket_id = view
                .ticket_id
                .as_deref()
                .ok_or("ticket view is missing its ticket ID")?;
            (
                format!("ticket-{ticket_id}-view-{}", view.view_epoch),
                owned_ticket_window_label(
                    view.ticket_namespace
                        .as_deref()
                        .ok_or("ticket view is missing its namespace")?,
                    ticket_id,
                )
                .map_err(|error| error.to_string())?,
            )
        }
        RexViewKind::Supervisor => (
            format!("project-{}-view-{}", view.project_id, view.view_epoch),
            owned_supervisor_window_label(view.project_id.as_str()),
        ),
    };
    if spec.run_id != expected_run_id
        || view.rex_server_identity != window.server_instance_id
        || view.rex_session_id != window.session_id
        || view.rex_window_id != window.window_id
        || view.rex_server_identity != transport.capabilities().server_instance_id
        || view.rex_session_id != transport.session_id()
        || window.label != expected_window_label
    {
        return Ok(());
    }
    let blocks = transport
        .list_window_blocks(window, &expected_window_label)
        .map_err(|error| error.to_string())?;
    let matching_block_count = blocks
        .iter()
        .filter(|block| {
            block.block_id == block_id
                && block.label == label
                && block.flavor == "com.superlogical.terminal.shell"
        })
        .count();
    let matching_label_count = blocks.iter().filter(|block| block.label == label).count();
    if matching_block_count != 1
        || matching_label_count != 1
        || transport
            .observe_block_configuration(window, spec, block_id)
            .map_err(|error| error.to_string())?
            == RexBlockConfiguration::Mismatch
        || !transport
            .agent_block_is_present(window, &spec.run_id, block_id)
            .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    let command_digest = anchor_command_digest(spec)?;
    store.register_rex_view_anchor(
        owner_generation,
        &view.view_id,
        block_id,
        &spec.run_id,
        &label,
        &command_digest,
    )?;
    Ok(())
}

impl RexViewLifecyclePolicy {
    pub fn validate(self) -> Result<Self, String> {
        if self.max_blocks_per_tab < 2
            || self.completed_blocks_to_keep >= self.max_blocks_per_tab
            || self.completed_ticket_tab_retention_seconds == 0
        {
            return Err("Rex view lifecycle policy is invalid".into());
        }
        Ok(self)
    }
}

/// Reconcile one view per controller call so a large project set cannot turn a
/// foreground scheduling iteration into an unbounded Rex scan.
pub fn maintain_view(
    store: &mut ConfigStore,
    owner_generation: u64,
    now_unix: u64,
    view: &RexViewRecord,
    transport: &RexCliTransport,
    policy: RexViewLifecyclePolicy,
    anchor_spec: Option<&AgentBlockSpec>,
) -> Result<(), String> {
    let policy = policy.validate()?;
    view.view.validate()?;
    if view.lifecycle != "active"
        || view.view.rex_server_identity != transport.capabilities().server_instance_id
        || view.view.rex_session_id != transport.session_id()
    {
        return Err("Rex lifecycle view does not match the pinned ticket session".into());
    }
    let label = match view.view.kind {
        RexViewKind::Ticket => {
            let namespace = view
                .view
                .ticket_namespace
                .as_deref()
                .ok_or("ticket namespace is missing")?;
            let ticket = view
                .view
                .ticket_id
                .as_deref()
                .ok_or("ticket ID is missing")?;
            owned_ticket_window_label(namespace, ticket).map_err(|error| error.to_string())?
        }
        RexViewKind::Supervisor => owned_supervisor_window_label(view.view.project_id.as_str()),
    };
    let window = RexWindow {
        server_instance_id: view.view.rex_server_identity.clone(),
        session_id: view.view.rex_session_id.clone(),
        window_id: view.view.rex_window_id.clone(),
        label: label.clone(),
        initial_block_id: None,
        disposition: CreateDisposition::Existing,
    };
    let rex_blocks = transport
        .list_window_blocks(&window, &label)
        .map_err(|error| error.to_string())?;
    let mut records = store.rex_view_blocks(&view.view.view_id)?;
    let mut anchor = store.rex_view_anchor(&view.view.view_id)?;
    if anchor.is_none()
        && let Some(spec) = anchor_spec
        && let Some(block_id) = find_exact_anchor_block(&rex_blocks, spec, &window, transport)?
    {
        let owned_label =
            owned_agent_block_label(&spec.run_id).map_err(|error| error.to_string())?;
        let command_digest = anchor_command_digest(spec)?;
        store.register_rex_view_anchor(
            owner_generation,
            &view.view.view_id,
            &block_id,
            &spec.run_id,
            &owned_label,
            &command_digest,
        )?;
        anchor = store.rex_view_anchor(&view.view.view_id)?;
    }
    for rex_block in &rex_blocks {
        if is_tracked_view_block(&records, anchor.as_ref(), &rex_block.block_id) {
            continue;
        }
        store.register_rex_view_block(
            owner_generation,
            &crate::launch::RexViewBlock {
                view_id: view.view.view_id.clone(),
                block_id: rex_block.block_id.clone(),
                agent_run_id: None,
                role: None,
                ownership: RexBlockOwnership::User,
                lifecycle: RexBlockLifecycle::Unknown,
                process_absent_confirmed: false,
                retained_until_unix: None,
            },
        )?;
    }

    maintain_anchor(
        store,
        owner_generation,
        &window,
        &rex_blocks,
        anchor.as_ref(),
        anchor_spec,
        transport,
    )?;
    records = store.rex_view_blocks(&view.view.view_id)?;

    for record in records
        .iter()
        .filter(|record| record.block.lifecycle != RexBlockLifecycle::Closed)
        .take(policy.max_blocks_per_tab.min(MAX_BLOCKS_PER_TICK))
    {
        let block = &record.block;
        if block.ownership != RexBlockOwnership::Factory
            || block.lifecycle == RexBlockLifecycle::Closed
        {
            continue;
        }
        let Some(run_id) = block.agent_run_id.as_ref() else {
            continue;
        };
        let Some(observed_block) = rex_blocks
            .iter()
            .find(|candidate| candidate.block_id == block.block_id)
        else {
            store.observe_rex_view_block(
                owner_generation,
                &view.view.view_id,
                &block.block_id,
                RexBlockLifecycle::Unknown,
                false,
                None,
            )?;
            continue;
        };
        let expected_label =
            owned_agent_block_label(run_id.as_str()).map_err(|error| error.to_string())?;
        if observed_block.label != expected_label {
            store.observe_rex_view_block(
                owner_generation,
                &view.view.view_id,
                &block.block_id,
                RexBlockLifecycle::Unknown,
                false,
                None,
            )?;
            continue;
        }
        let observation = match transport.observe_process(&window, run_id.as_str(), &block.block_id)
        {
            Ok(observation) => observation,
            Err(_) => {
                store.observe_rex_view_block(
                    owner_generation,
                    &view.view.view_id,
                    &block.block_id,
                    RexBlockLifecycle::Unknown,
                    false,
                    None,
                )?;
                continue;
            }
        };
        let absent = observation.last_exit.is_some()
            && observation.child.is_none()
            && observation.foreground.is_none()
            && observation.ancestors.as_ref().is_none_or(Vec::is_empty)
            && matches!(
                crate::store::agent_results::verify_agent_terminal_if_recorded(
                    store,
                    owner_generation,
                    run_id,
                ),
                Ok(Some(_))
            );
        let mut lifecycle = match (absent, observation.last_exit.as_ref()) {
            (true, Some(exit)) if exit.exit_code == 0 => RexBlockLifecycle::Completed,
            (true, Some(_)) => RexBlockLifecycle::Failed,
            (_, _) if observation.child.is_some() || observation.foreground.is_some() => {
                RexBlockLifecycle::Active
            }
            _ => RexBlockLifecycle::Unknown,
        };
        if matches!(
            record.block.lifecycle,
            RexBlockLifecycle::Completed | RexBlockLifecycle::Failed
        ) && lifecycle == RexBlockLifecycle::Active
        {
            lifecycle = RexBlockLifecycle::Unknown;
        }
        if lifecycle != block.lifecycle || absent != block.process_absent_confirmed {
            store.observe_rex_view_block(
                owner_generation,
                &view.view.view_id,
                &block.block_id,
                lifecycle,
                absent,
                absent.then_some(now_unix),
            )?;
        }
        if absent && record.archive_digest.is_none() {
            let output = transport
                .capture_agent_block(&window, run_id.as_str(), &block.block_id)
                .map_err(|error| error.to_string())?;
            store.archive_rex_view_block(
                owner_generation,
                &view.view.view_id,
                &block.block_id,
                &output,
            )?;
        }
    }

    records = store.rex_view_blocks(&view.view.view_id)?;
    recycle_archived_blocks(
        store,
        owner_generation,
        &window,
        &rex_blocks,
        &records,
        transport,
        policy.completed_blocks_to_keep,
    )?;

    if view.view.kind == RexViewKind::Ticket {
        store.mark_rex_view_terminal(owner_generation, &view.view.view_id, now_unix)?;
    }
    let retention_seconds = policy.completed_ticket_tab_retention_seconds;
    let candidate = store
        .rex_view_cleanup_candidates(now_unix, retention_seconds)?
        .into_iter()
        .find(|candidate| candidate.view.view_id == view.view.view_id);
    if let Some(candidate) = candidate {
        if has_unregistered_or_user_blocks(store, &candidate, &rex_blocks)? {
            return Ok(());
        }
        store.begin_rex_view_close(owner_generation, &candidate, now_unix, retention_seconds)?;
        let close_result = close_archived_window_blocks(
            store,
            owner_generation,
            &window,
            transport,
            &candidate,
            anchor_spec,
        );
        let observed_closed = close_result.is_ok()
            && !transport
                .window_exists(&window)
                .map_err(|error| error.to_string())?;
        store.finish_rex_view_close(owner_generation, &candidate.view.view_id, observed_closed)?;
        close_result?;
    }
    Ok(())
}

fn is_tracked_view_block(
    records: &[crate::launch::RexViewBlockRecord],
    anchor: Option<&crate::launch::RexViewAnchorRecord>,
    block_id: &str,
) -> bool {
    records
        .iter()
        .any(|record| record.block.block_id == block_id)
        || anchor.is_some_and(|anchor| anchor.block_id == block_id)
}

fn find_exact_anchor_block(
    rex_blocks: &[WindowBlock],
    spec: &AgentBlockSpec,
    window: &RexWindow,
    transport: &RexCliTransport,
) -> Result<Option<String>, String> {
    let label = owned_agent_block_label(&spec.run_id).map_err(|error| error.to_string())?;
    let mut exact = Vec::new();
    for block in rex_blocks.iter().filter(|block| block.label == label) {
        if transport
            .observe_block_configuration(window, spec, &block.block_id)
            .map_err(|error| error.to_string())?
            == RexBlockConfiguration::Matches
        {
            exact.push(block.block_id.clone());
        }
    }
    Ok((exact.len() == 1).then(|| exact.pop().expect("one exact anchor checked")))
}

fn maintain_anchor(
    store: &mut ConfigStore,
    owner_generation: u64,
    window: &RexWindow,
    rex_blocks: &[WindowBlock],
    anchor: Option<&crate::launch::RexViewAnchorRecord>,
    anchor_spec: Option<&AgentBlockSpec>,
    transport: &RexCliTransport,
) -> Result<(), String> {
    let Some(anchor) = anchor else {
        return Ok(());
    };
    let Some(spec) = anchor_spec.filter(|spec| spec.run_id == anchor.run_id) else {
        store.observe_rex_view_anchor(
            owner_generation,
            &anchor.view_id,
            RexBlockLifecycle::Unknown,
            false,
        )?;
        return Ok(());
    };
    let expected_label =
        owned_agent_block_label(&anchor.run_id).map_err(|error| error.to_string())?;
    if expected_label != anchor.owned_label
        || anchor_command_digest(spec)? != anchor.command_digest
        || !rex_blocks
            .iter()
            .any(|block| block.block_id == anchor.block_id && block.label == anchor.owned_label)
        || rex_blocks
            .iter()
            .filter(|block| block.label == anchor.owned_label)
            .count()
            != 1
        || rex_blocks
            .iter()
            .find(|block| block.block_id == anchor.block_id)
            .is_none_or(|block| block.flavor != "com.superlogical.terminal.shell")
        || !transport
            .agent_block_is_present(window, &anchor.run_id, &anchor.block_id)
            .map_err(|error| error.to_string())?
    {
        store.observe_rex_view_anchor(
            owner_generation,
            &anchor.view_id,
            RexBlockLifecycle::Unknown,
            false,
        )?;
        return Ok(());
    }
    let configuration = transport
        .observe_block_configuration(window, spec, &anchor.block_id)
        .map_err(|error| error.to_string())?;
    if configuration == RexBlockConfiguration::Mismatch
        || (configuration == RexBlockConfiguration::NotExposed && !is_one_shot_status_anchor(spec))
    {
        store.observe_rex_view_anchor(
            owner_generation,
            &anchor.view_id,
            RexBlockLifecycle::Unknown,
            false,
        )?;
        return Ok(());
    }
    let observation = match transport.observe_process(window, &anchor.run_id, &anchor.block_id) {
        Ok(observation) => observation,
        Err(_) => {
            store.observe_rex_view_anchor(
                owner_generation,
                &anchor.view_id,
                RexBlockLifecycle::Unknown,
                false,
            )?;
            return Ok(());
        }
    };
    let absent = anchor_process_absent(spec, &observation);
    let observed_lifecycle = match (absent, observation.last_exit.as_ref()) {
        (true, Some(exit)) if exit.exit_code == 0 => RexBlockLifecycle::Completed,
        (true, Some(_)) => RexBlockLifecycle::Failed,
        (false, _) if observation.child.is_some() || observation.foreground.is_some() => {
            RexBlockLifecycle::Active
        }
        _ => RexBlockLifecycle::Unknown,
    };
    let lifecycle = if anchor.lifecycle != RexBlockLifecycle::Active
        && anchor.lifecycle != RexBlockLifecycle::Unknown
        && observed_lifecycle == RexBlockLifecycle::Active
    {
        RexBlockLifecycle::Unknown
    } else {
        observed_lifecycle
    };
    store.observe_rex_view_anchor(
        owner_generation,
        &anchor.view_id,
        lifecycle,
        absent && lifecycle != RexBlockLifecycle::Unknown,
    )?;
    if absent
        && matches!(
            lifecycle,
            RexBlockLifecycle::Completed | RexBlockLifecycle::Failed
        )
    {
        let output = transport
            .capture_agent_block(window, &anchor.run_id, &anchor.block_id)
            .map_err(|error| error.to_string())?;
        if let Some(existing) =
            store.read_rex_view_anchor_archive(&anchor.view_id, &anchor.block_id)?
        {
            if existing != output {
                store.observe_rex_view_anchor(
                    owner_generation,
                    &anchor.view_id,
                    RexBlockLifecycle::Unknown,
                    false,
                )?;
            }
        } else {
            store.archive_rex_view_anchor(
                owner_generation,
                &anchor.view_id,
                &anchor.block_id,
                &output,
            )?;
        }
    }
    Ok(())
}

fn is_one_shot_status_anchor(spec: &AgentBlockSpec) -> bool {
    let [
        binary,
        config_flag,
        config,
        state_flag,
        state,
        command,
        json_flag,
    ] = spec.args.as_slice()
    else {
        return false;
    };
    spec.command == std::path::Path::new("/usr/bin/env")
        && std::path::Path::new(binary).is_absolute()
        && config_flag == "--config"
        && std::path::Path::new(config).is_absolute()
        && state_flag == "--state-root"
        && std::path::Path::new(state).is_absolute()
        && spec.cwd == std::path::Path::new(state)
        && command == "status"
        && json_flag == "--json"
}

fn anchor_process_absent(
    spec: &AgentBlockSpec,
    observation: &crate::adapters::rex::RexProcessObservation,
) -> bool {
    observation.last_exit.is_some()
        && observation.child.is_none()
        && observation.foreground.is_none()
        && match observation.ancestors.as_ref() {
            Some(ancestors) => ancestors.is_empty(),
            None => is_one_shot_status_anchor(spec),
        }
}

pub fn has_block_capacity(
    records: &[crate::launch::RexViewBlockRecord],
    rex_blocks: &[WindowBlock],
    max_blocks_per_tab: usize,
) -> bool {
    let mut occupied = rex_blocks
        .iter()
        .map(|block| block.block_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    occupied.extend(records.iter().filter_map(|record| {
        (record.block.lifecycle != RexBlockLifecycle::Closed
            && !rex_blocks
                .iter()
                .any(|block| block.block_id == record.block.block_id))
        .then_some(record.block.block_id.as_str())
    }));
    occupied.len() < max_blocks_per_tab
}

fn recycle_archived_blocks(
    store: &mut ConfigStore,
    owner_generation: u64,
    window: &RexWindow,
    rex_blocks: &[WindowBlock],
    records: &[crate::launch::RexViewBlockRecord],
    transport: &RexCliTransport,
    keep: usize,
) -> Result<(), String> {
    let mut archived = records
        .iter()
        .filter(|record| {
            record.block.ownership == RexBlockOwnership::Factory
                && matches!(
                    record.block.lifecycle,
                    RexBlockLifecycle::Completed
                        | RexBlockLifecycle::Failed
                        | RexBlockLifecycle::Closed
                )
                && record.block.process_absent_confirmed
                && record.archive_digest.is_some()
        })
        .collect::<Vec<_>>();
    archived.sort_by_key(|record| std::cmp::Reverse(record.terminal_at_unix.unwrap_or(0)));
    let view_id = records.first().map(|record| record.block.view_id.clone());
    let Some(view_id) = view_id else {
        return Ok(());
    };
    for record in archived.into_iter().skip(keep) {
        if record.block.lifecycle == RexBlockLifecycle::Closed {
            continue;
        }
        if let Some(observed) = rex_blocks
            .iter()
            .find(|block| block.block_id == record.block.block_id)
        {
            let Some(run_id) = record.block.agent_run_id.as_ref() else {
                continue;
            };
            if observed.label
                != owned_agent_block_label(run_id.as_str()).map_err(|error| error.to_string())?
            {
                continue;
            }
            transport
                .close_agent_block(window, run_id.as_str(), &record.block.block_id)
                .map_err(|error| error.to_string())?;
            if transport
                .list_window_blocks(window, &window.label)
                .map_err(|error| error.to_string())?
                .iter()
                .any(|block| block.block_id == record.block.block_id)
            {
                return Err("Rex block remains after its close request".into());
            }
        }
        store.observe_rex_view_block(
            owner_generation,
            &view_id,
            &record.block.block_id,
            RexBlockLifecycle::Closed,
            true,
            record.block.retained_until_unix,
        )?;
    }
    Ok(())
}

fn close_archived_window_blocks(
    store: &mut ConfigStore,
    owner_generation: u64,
    window: &RexWindow,
    transport: &RexCliTransport,
    candidate: &RexViewCleanupCandidate,
    anchor_spec: Option<&AgentBlockSpec>,
) -> Result<(), String> {
    let records = store.rex_view_blocks(&candidate.view.view_id)?;
    for record in records.iter().filter(|record| {
        record.block.ownership == RexBlockOwnership::Factory
            && record.block.lifecycle != RexBlockLifecycle::Closed
            && record.block.process_absent_confirmed
            && record.archive_digest.is_some()
    }) {
        let run_id = record
            .block
            .agent_run_id
            .as_ref()
            .ok_or("factory block has no AgentRun")?;
        if transport
            .window_exists(window)
            .map_err(|error| error.to_string())?
        {
            let blocks = transport
                .list_window_blocks(window, &window.label)
                .map_err(|error| error.to_string())?;
            if let Some(block) = blocks
                .iter()
                .find(|block| block.block_id == record.block.block_id)
            {
                let expected =
                    owned_agent_block_label(run_id.as_str()).map_err(|error| error.to_string())?;
                if block.label != expected {
                    return Err("Rex block identity changed before view closure".into());
                }
                transport
                    .close_agent_block(window, run_id.as_str(), &record.block.block_id)
                    .map_err(|error| error.to_string())?;
                if transport
                    .list_window_blocks(window, &window.label)
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|block| block.block_id == record.block.block_id)
                {
                    return Err("Rex block remains after its close request".into());
                }
            }
        }
        store.observe_rex_view_block(
            owner_generation,
            &candidate.view.view_id,
            &record.block.block_id,
            RexBlockLifecycle::Closed,
            true,
            record.block.retained_until_unix,
        )?;
    }
    if let Some(anchor) = store.rex_view_anchor(&candidate.view.view_id)?
        && anchor.lifecycle != RexBlockLifecycle::Closed
        && anchor.process_absent_confirmed
        && store
            .read_rex_view_anchor_archive(&anchor.view_id, &anchor.block_id)?
            .is_some()
    {
        let spec = anchor_spec
            .filter(|spec| {
                spec.run_id == anchor.run_id
                    && anchor_command_digest(spec)
                        .is_ok_and(|digest| digest == anchor.command_digest)
            })
            .ok_or("owned Rex view anchor command binding changed before close")?;
        if transport
            .window_exists(window)
            .map_err(|error| error.to_string())?
        {
            let blocks = transport
                .list_window_blocks(window, &window.label)
                .map_err(|error| error.to_string())?;
            if let Some(block) = blocks
                .iter()
                .find(|block| block.block_id == anchor.block_id)
            {
                let configuration = transport
                    .observe_block_configuration(window, spec, &anchor.block_id)
                    .map_err(|error| error.to_string())?;
                if block.label != anchor.owned_label
                    || configuration == RexBlockConfiguration::Mismatch
                    || (configuration == RexBlockConfiguration::NotExposed
                        && !is_one_shot_status_anchor(spec))
                {
                    return Err("Rex view anchor identity changed before close".into());
                }
                let process = transport
                    .observe_process(window, &anchor.run_id, &anchor.block_id)
                    .map_err(|error| error.to_string())?;
                if !anchor_process_absent(spec, &process) {
                    return Err("Rex view anchor process absence is no longer confirmed".into());
                }
                let observed = transport
                    .capture_agent_block(window, &anchor.run_id, &anchor.block_id)
                    .map_err(|error| error.to_string())?;
                let archived = store
                    .read_rex_view_anchor_archive(&anchor.view_id, &anchor.block_id)?
                    .ok_or("Rex view anchor archive disappeared before close")?;
                if observed != archived {
                    return Err("Rex view anchor output changed after archival".into());
                }
                transport
                    .close_agent_block(window, &anchor.run_id, &anchor.block_id)
                    .map_err(|error| error.to_string())?;
                if transport
                    .agent_block_is_present(window, &anchor.run_id, &anchor.block_id)
                    .map_err(|error| error.to_string())?
                {
                    return Err("Rex view anchor remains after its close request".into());
                }
            }
        }
        store.observe_rex_view_anchor(
            owner_generation,
            &anchor.view_id,
            RexBlockLifecycle::Closed,
            true,
        )?;
    }
    Ok(())
}

fn has_unregistered_or_user_blocks(
    store: &ConfigStore,
    candidate: &RexViewCleanupCandidate,
    rex_blocks: &[WindowBlock],
) -> Result<bool, String> {
    let known = store
        .rex_view_blocks(&candidate.view.view_id)?
        .into_iter()
        .filter(|record| record.block.ownership == RexBlockOwnership::Factory)
        .map(|record| record.block.block_id)
        .collect::<std::collections::BTreeSet<_>>();
    let anchor = store.rex_view_anchor(&candidate.view.view_id)?;
    Ok(rex_blocks.iter().any(|block| {
        !known.contains(&block.block_id)
            && !anchor
                .as_ref()
                .is_some_and(|anchor| anchor.block_id == block.block_id)
    }))
}

pub fn project_views(
    store: &ConfigStore,
    projects: &[ProjectId],
    server_instance_id: &str,
    session_id: &str,
) -> Result<Vec<RexViewRecord>, String> {
    let mut result = Vec::new();
    for project in projects {
        result.extend(
            store
                .rex_view_history(project)?
                .into_iter()
                .filter(|record| {
                    record.lifecycle == "active"
                        && record.view.rex_server_identity == server_instance_id
                        && record.view.rex_session_id == session_id
                }),
        );
    }
    result.sort_by_key(|record| record.updated_at_unix);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ids::AgentRunId;
    use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
    use crate::launch::{RexView, RexViewBlock, RexViewKind};
    use std::os::unix::fs::PermissionsExt;

    fn record(block_id: &str, lifecycle: RexBlockLifecycle) -> crate::launch::RexViewBlockRecord {
        crate::launch::RexViewBlockRecord {
            block: RexViewBlock {
                view_id: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
                block_id: block_id.into(),
                agent_run_id: Some(AgentRunId::parse("run-1").unwrap()),
                role: Some(crate::domain::types::Role::Coordinator),
                ownership: RexBlockOwnership::Factory,
                lifecycle,
                process_absent_confirmed: lifecycle != RexBlockLifecycle::Active,
                retained_until_unix: None,
            },
            terminal_at_unix: None,
            archive_digest: None,
        }
    }

    #[test]
    fn capacity_counts_unknown_blocks_and_ignores_closed_history() {
        let records = vec![
            record("not-listed", RexBlockLifecycle::Unknown),
            record("already-closed", RexBlockLifecycle::Closed),
        ];
        let rex_blocks = vec![WindowBlock {
            block_id: "user-pane".into(),
            label: "notes".into(),
            flavor: "shell".into(),
        }];
        assert!(!has_block_capacity(&records, &rex_blocks, 2));
        assert!(has_block_capacity(&records, &rex_blocks, 3));
    }

    #[test]
    fn host_status_anchor_is_tracked_without_an_agent_run_record() {
        let anchor = crate::launch::RexViewAnchorRecord {
            view_id: crate::domain::ids::Digest::parse("a".repeat(64)).unwrap(),
            block_id: "status-anchor".into(),
            run_id: "ticket-T-1-view-1".into(),
            owned_label: "rex-projects-run-ticket-T-1-view-1".into(),
            command_digest: crate::domain::ids::Digest::parse("b".repeat(64)).unwrap(),
            lifecycle: RexBlockLifecycle::Unknown,
            process_absent_confirmed: false,
            terminal_at_unix: None,
            archive_digest: None,
        };
        assert!(is_tracked_view_block(&[], Some(&anchor), "status-anchor"));
        assert!(!is_tracked_view_block(&[], Some(&anchor), "user-pane"));
    }

    #[cfg(unix)]
    struct StatusAnchorFixture {
        terminal: crate::store::agent_results::host_validation_fixture::TestTerminalResultFixture,
        view: RexViewRecord,
        spec: AgentBlockSpec,
        window: RexWindow,
        transport: RexCliTransport,
        root: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl StatusAnchorFixture {
        fn new(process: serde_json::Value, preexisting: bool) -> Self {
            let mut terminal = crate::store::agent_results::host_validation_fixture::host_validated_terminal_result(
                crate::domain::types::Role::Coordinator,
                crate::roles::RoleResultMessage {
                    schema_version: 1,
                    message_id: "status-anchor-provenance".into(),
                    kind: RoleOutputKind::PlanReady,
                    assertion: AgentAssertion::Succeeded,
                    result_digest: None,
                    structured_result: serde_json::json!({
                        "plan": {"nodes": [], "requested_investigation_children": 0},
                        "unresolved_questions": []
                    }),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
            let authority = terminal
                .store
                .agent_launch_authority(terminal.terminal.agent_run_id())
                .unwrap()
                .unwrap();
            let root = terminal._temp.path().join("status-anchor-fixture");
            std::fs::create_dir(&root).unwrap();
            let project_id = authority.project_id.clone();
            let run_id = "ticket-STATUS-1-view-1".to_owned();
            let spec = AgentBlockSpec {
                run_id,
                command: "/usr/bin/env".into(),
                args: vec![
                    "/opt/rex-projects".into(),
                    "--config".into(),
                    root.join("config.toml").display().to_string(),
                    "--state-root".into(),
                    root.join("state").display().to_string(),
                    "status".into(),
                    "--json".into(),
                ],
                cwd: root.join("state"),
                path_prepend: Vec::new(),
            };
            let block_id = "status-block";
            let window_id = "status-window";
            let window_label = owned_ticket_window_label("fixture", "STATUS-1").unwrap();
            let block_label = owned_agent_block_label(&spec.run_id).unwrap();
            let inventory = serde_json::json!({
                "session_id": "fixture-session",
                "windows": [{
                    "window_id": window_id,
                    "label": window_label,
                    "layers": [{"blocks": [{
                        "block_id": block_id,
                        "label": block_label,
                        "creator_name": "com.superlogical.terminal",
                        "flavor": "com.superlogical.terminal.shell",
                        "host_id": "fixture-host"
                    }]}]
                }]
            });
            let empty_inventory = serde_json::json!({
                "session_id": "fixture-session",
                "windows": []
            });
            std::fs::write(
                root.join("inventory.json"),
                serde_json::to_vec(&inventory).unwrap(),
            )
            .unwrap();
            std::fs::write(
                root.join("empty-inventory.json"),
                serde_json::to_vec(&empty_inventory).unwrap(),
            )
            .unwrap();
            std::fs::write(
                root.join("process.json"),
                serde_json::to_vec(&process).unwrap(),
            )
            .unwrap();
            std::fs::write(root.join("capture.txt"), "rex-projects status output\n").unwrap();
            if preexisting {
                std::fs::write(root.join("preexisting"), "").unwrap();
            }
            let script = root.join("rex");
            std::fs::write(
                &script,
                r#"#!/bin/sh
fixture_dir=${0%/*}
case "$*" in
  *"whoami --json"*) printf '%s\n' '{"endpoint":"unix:///tmp/status-anchor.sock","instance_id":"fixture-instance","host_id":"fixture-host","rex_version":"fixture"}' ;;
  *"api list --json"*) printf '%s\n' '{"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}' ;;
  *"api call session.view"*)
    if [ -f "$fixture_dir/closed" ]; then /bin/cat "$fixture_dir/empty-inventory.json"; elif [ -f "$fixture_dir/preexisting" ] || [ -f "$fixture_dir/created" ]; then /bin/cat "$fixture_dir/inventory.json"; else /bin/cat "$fixture_dir/empty-inventory.json"; fi ;;
  *"api call session.new_window"*) : > "$fixture_dir/created"; printf '%s\n' '{"window_id":"status-window","block_ids":["status-block"]}' ;;
  *"api call block.close"*) printf '%s\n' "$*" > "$fixture_dir/closed"; printf '{}\n' ;;
  *"terminal.process"*) : > "$fixture_dir/process-observed"; /bin/cat "$fixture_dir/process.json" ;;
  *"capture"*) /bin/cat "$fixture_dir/capture.txt" ;;
  *) exit 3 ;;
esac
"#,
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let transport = RexCliTransport::connect(
                &script,
                &[],
                "unix:///tmp/status-anchor.sock".into(),
                "fixture-instance".into(),
                "fixture-session".into(),
                std::collections::BTreeMap::new(),
            )
            .unwrap();
            let window = transport
                .find_or_create_ticket_window("fixture", "STATUS-1", &spec)
                .unwrap();
            let view = RexView {
                view_id: RexView::derive_id(
                    &project_id,
                    RexViewKind::Ticket,
                    Some("fixture"),
                    Some("STATUS-1"),
                    1,
                )
                .unwrap(),
                project_id: project_id.clone(),
                kind: RexViewKind::Ticket,
                ticket_namespace: Some("fixture".into()),
                ticket_id: Some("STATUS-1".into()),
                view_epoch: 1,
                rex_server_identity: window.server_instance_id.clone(),
                rex_session_id: window.session_id.clone(),
                rex_window_id: window.window_id.clone(),
            };
            terminal
                .store
                .register_rex_view(terminal.owner_generation, &view)
                .unwrap();
            let view = terminal
                .store
                .rex_view_history(&project_id)
                .unwrap()
                .into_iter()
                .find(|record| record.view.view_id == view.view_id)
                .unwrap();
            Self {
                terminal,
                view,
                spec,
                window,
                transport,
                root,
            }
        }

        fn record_created(&mut self) {
            record_created_view_anchor(
                &mut self.terminal.store,
                self.terminal.owner_generation,
                &self.view.view,
                &self.window,
                &self.spec,
                &self.transport,
            )
            .unwrap();
        }

        fn maintain(&mut self) {
            maintain_view(
                &mut self.terminal.store,
                self.terminal.owner_generation,
                100,
                &self.view,
                &self.transport,
                RexViewLifecyclePolicy {
                    max_blocks_per_tab: 2,
                    completed_blocks_to_keep: 1,
                    completed_ticket_tab_retention_seconds: 3600,
                },
                Some(&self.spec),
            )
            .unwrap();
        }

        fn update_inventory(&self, update: impl FnOnce(&mut serde_json::Value)) {
            let path = self.root.join("inventory.json");
            let mut inventory = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            update(&mut inventory);
            std::fs::write(path, serde_json::to_vec(&inventory).unwrap()).unwrap();
        }

        fn close_archived_anchor(&mut self) -> Result<(), String> {
            close_archived_window_blocks(
                &mut self.terminal.store,
                self.terminal.owner_generation,
                &self.window,
                &self.transport,
                &RexViewCleanupCandidate {
                    view: self.view.view.clone(),
                    close_after_unix: 100,
                },
                Some(&self.spec),
            )
        }
    }

    #[cfg(unix)]
    #[test]
    fn created_status_anchor_uses_creation_response_and_archives_only_with_complete_process_evidence()
     {
        let mut fixture = StatusAnchorFixture::new(
            serde_json::json!({"last_exit":{"exit_code":0},"home":"/fixture/home","ancestors":[]}),
            false,
        );
        assert_eq!(fixture.window.disposition, CreateDisposition::Created);
        fixture.record_created();
        let anchor = fixture
            .terminal
            .store
            .rex_view_anchor(&fixture.view.view.view_id)
            .unwrap()
            .expect("successful Created response records the status anchor");
        assert_eq!(anchor.block_id, "status-block");
        assert_eq!(anchor.run_id, fixture.spec.run_id);
        assert_eq!(
            anchor.owned_label,
            owned_agent_block_label(&fixture.spec.run_id).unwrap()
        );
        assert_eq!(
            anchor.command_digest,
            anchor_command_digest(&fixture.spec).unwrap()
        );
        assert!(
            fixture
                .terminal
                .store
                .register_rex_view_anchor(
                    fixture.terminal.owner_generation,
                    &fixture.view.view.view_id,
                    "different-status-block",
                    &fixture.spec.run_id,
                    &anchor.owned_label,
                    &anchor.command_digest,
                )
                .is_err()
        );

        fixture.maintain();

        let anchor = fixture
            .terminal
            .store
            .rex_view_anchor(&fixture.view.view.view_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.lifecycle, RexBlockLifecycle::Completed);
        assert!(anchor.process_absent_confirmed);
        assert!(anchor.archive_digest.is_some());
        assert!(
            fixture
                .terminal
                .store
                .rex_view_blocks(&fixture.view.view.view_id)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_matching_label_without_creation_provenance_stays_unadopted() {
        let mut fixture = StatusAnchorFixture::new(
            serde_json::json!({"last_exit":{"exit_code":0},"ancestors":[]}),
            true,
        );
        assert_eq!(fixture.window.disposition, CreateDisposition::Existing);
        fixture.record_created();

        fixture.maintain();

        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_none()
        );
        let records = fixture
            .terminal
            .store
            .rex_view_blocks(&fixture.view.view.view_id)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].block.ownership, RexBlockOwnership::User);
        assert_eq!(records[0].block.lifecycle, RexBlockLifecycle::Unknown);
        assert!(!records[0].block.process_absent_confirmed);
    }

    #[cfg(unix)]
    #[test]
    fn created_anchor_rejects_wrong_server_window_block_and_label() {
        let mut fixture = StatusAnchorFixture::new(
            serde_json::json!({"last_exit":{"exit_code":0},"home":"/fixture/home","ancestors":[]}),
            false,
        );
        let server_instance_id = fixture.window.server_instance_id.clone();
        fixture.window.server_instance_id = "wrong-instance".into();
        fixture.record_created();
        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_none()
        );

        fixture.window.server_instance_id = server_instance_id;
        let window_id = fixture.window.window_id.clone();
        fixture.window.window_id = "wrong-window".into();
        fixture.record_created();
        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_none()
        );

        fixture.window.window_id = window_id;
        let initial_block_id = fixture.window.initial_block_id.clone();
        fixture.window.initial_block_id = Some("wrong-block".into());
        fixture.record_created();
        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_none()
        );

        fixture.window.initial_block_id = initial_block_id;
        let inventory_path = fixture.root.join("inventory.json");
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&inventory_path).unwrap()).unwrap();
        inventory["windows"][0]["layers"][0]["blocks"][0]["label"] =
            serde_json::Value::String("unrelated-label".into());
        std::fs::write(&inventory_path, serde_json::to_vec(&inventory).unwrap()).unwrap();
        fixture.record_created();
        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn actual_rex_process_shape_archives_a_proven_one_shot_status_anchor() {
        let mut fixture = StatusAnchorFixture::new(
            serde_json::json!({"last_exit":{"exit_code":0},"home":"/fixture/home"}),
            false,
        );
        let run_id = fixture.terminal.terminal.agent_run_id().clone();
        let authority = fixture
            .terminal
            .store
            .agent_launch_authority(&run_id)
            .unwrap();
        let reservation = fixture
            .terminal
            .store
            .agent_launch_reservation_for_run(&run_id)
            .unwrap();
        let occupied_slots = ConfigStore::status(fixture.terminal._temp.path())
            .unwrap()
            .occupied_slots;
        fixture.record_created();
        assert!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .is_some()
        );

        fixture.maintain();
        assert!(fixture.root.join("process-observed").exists());

        let anchor = fixture
            .terminal
            .store
            .rex_view_anchor(&fixture.view.view.view_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.lifecycle, RexBlockLifecycle::Completed);
        assert!(anchor.process_absent_confirmed);
        assert!(anchor.archive_digest.is_some());
        assert!(!fixture.root.join("closed").exists());

        fixture.close_archived_anchor().unwrap();

        assert_eq!(
            fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            RexBlockLifecycle::Closed
        );
        let close_request = std::fs::read_to_string(fixture.root.join("closed")).unwrap();
        assert!(close_request.contains("\"block_id\":\"status-block\""));
        assert!(!fixture.transport.window_exists(&fixture.window).unwrap());
        assert_eq!(
            fixture
                .terminal
                .store
                .agent_launch_authority(&run_id)
                .unwrap(),
            authority
        );
        assert_eq!(
            fixture
                .terminal
                .store
                .agent_launch_reservation_for_run(&run_id)
                .unwrap(),
            reservation
        );
        assert_eq!(
            ConfigStore::status(fixture.terminal._temp.path())
                .unwrap()
                .occupied_slots,
            occupied_slots
        );
    }

    #[cfg(unix)]
    #[test]
    fn status_anchor_with_live_or_incomplete_process_evidence_is_not_archived_or_closed() {
        let process = serde_json::json!({"pid":42,"user_id":501,"name":"running"});
        for observation in [
            serde_json::json!({"last_exit":null}),
            serde_json::json!({}),
            serde_json::json!({"last_exit":{"exit_code":0},"child":process}),
            serde_json::json!({"last_exit":{"exit_code":0},"foreground":process}),
            serde_json::json!({"last_exit":{"exit_code":0},"ancestors":[process]}),
        ] {
            let mut fixture = StatusAnchorFixture::new(observation.clone(), false);
            fixture.record_created();
            fixture.maintain();
            fixture.close_archived_anchor().unwrap();
            let anchor = fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .unwrap();
            assert!(!anchor.process_absent_confirmed, "{observation}");
            assert!(anchor.archive_digest.is_none(), "{observation}");
            assert!(!fixture.root.join("closed").exists(), "{observation}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn omitted_rex_fields_do_not_complete_other_anchor_commands() {
        for change in [
            "command", "binary", "config", "state", "cwd", "extra", "status",
        ] {
            let mut fixture =
                StatusAnchorFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}), false);
            match change {
                "command" => fixture.spec.command = "/bin/sh".into(),
                "binary" => fixture.spec.args[0] = "rex-projects".into(),
                "config" => fixture.spec.args[2] = "config.toml".into(),
                "state" => fixture.spec.args[4] = "state".into(),
                "cwd" => fixture.spec.cwd = fixture.root.clone(),
                "extra" => fixture.spec.args.push("extra".into()),
                "status" => fixture.spec.args[5] = "runtime".into(),
                _ => unreachable!(),
            }
            fixture.record_created();
            fixture.maintain();
            let anchor = fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .unwrap();
            assert_eq!(anchor.lifecycle, RexBlockLifecycle::Unknown, "{change}");
            assert!(!anchor.process_absent_confirmed, "{change}");
            assert!(anchor.archive_digest.is_none(), "{change}");
            assert!(!fixture.root.join("closed").exists(), "{change}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn status_anchor_refuses_exposed_conflicting_or_malformed_options() {
        for options in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"command":["other"]}),
            serde_json::json!([]),
        ] {
            let mut fixture =
                StatusAnchorFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}), false);
            fixture.record_created();
            fixture.update_inventory(|inventory| {
                inventory["windows"][0]["layers"][0]["blocks"][0]["options"] = options
            });
            fixture.maintain();
            let anchor = fixture
                .terminal
                .store
                .rex_view_anchor(&fixture.view.view.view_id)
                .unwrap()
                .unwrap();
            assert_eq!(anchor.lifecycle, RexBlockLifecycle::Unknown);
            assert!(!anchor.process_absent_confirmed);
            assert!(anchor.archive_digest.is_none());
            fixture.close_archived_anchor().unwrap();
            assert!(!fixture.root.join("closed").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn status_anchor_with_duplicate_block_id_in_another_window_stays_unknown() {
        let mut fixture =
            StatusAnchorFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}), false);
        fixture.record_created();
        fixture.update_inventory(|inventory| {
            let mut duplicate = inventory["windows"][0].clone();
            duplicate["window_id"] = "different-window".into();
            duplicate["label"] = "unrelated".into();
            inventory["windows"].as_array_mut().unwrap().push(duplicate);
        });

        fixture.maintain();

        let anchor = fixture
            .terminal
            .store
            .rex_view_anchor(&fixture.view.view.view_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.lifecycle, RexBlockLifecycle::Unknown);
        assert!(!anchor.process_absent_confirmed);
        assert!(anchor.archive_digest.is_none());
        fixture.close_archived_anchor().unwrap();
        assert!(!fixture.root.join("closed").exists());
    }

    #[cfg(unix)]
    #[test]
    fn archived_status_anchor_rechecks_identity_process_and_output_before_close() {
        for change in [
            "label",
            "duplicate",
            "block",
            "other-window",
            "session",
            "host",
            "creator",
            "options",
            "output",
            "process",
        ] {
            let mut fixture =
                StatusAnchorFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}), false);
            fixture.record_created();
            fixture.maintain();
            match change {
                "output" => {
                    std::fs::write(fixture.root.join("capture.txt"), "changed output").unwrap()
                }
                "process" => std::fs::write(
                    fixture.root.join("process.json"),
                    r#"{"last_exit":null,"child":{"pid":42,"user_id":501,"name":"running"}}"#,
                )
                .unwrap(),
                _ => fixture.update_inventory(|inventory| {
                    if change == "session" {
                        inventory["session_id"] = "different-session".into();
                        return;
                    }
                    if change == "other-window" {
                        let mut duplicate = inventory["windows"][0].clone();
                        duplicate["window_id"] = "different-window".into();
                        duplicate["label"] = "unrelated".into();
                        inventory["windows"].as_array_mut().unwrap().push(duplicate);
                        return;
                    }
                    let blocks = inventory["windows"][0]["layers"][0]["blocks"]
                        .as_array_mut()
                        .unwrap();
                    match change {
                        "label" => blocks[0]["label"] = "unrelated".into(),
                        "duplicate" => {
                            let mut duplicate = blocks[0].clone();
                            duplicate["block_id"] = "different-block".into();
                            blocks.push(duplicate);
                        }
                        "block" => {
                            let mut duplicate = blocks[0].clone();
                            duplicate["label"] = "unrelated".into();
                            blocks.push(duplicate);
                        }
                        "host" => blocks[0]["host_id"] = "different-host".into(),
                        "creator" => blocks[0]["creator_name"] = "different-creator".into(),
                        "options" => blocks[0]["options"] = serde_json::Value::Null,
                        _ => unreachable!(),
                    }
                }),
            }
            assert!(fixture.close_archived_anchor().is_err(), "{change}");
            assert!(!fixture.root.join("closed").exists(), "{change}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn changed_status_anchor_command_digest_stays_unknown_without_archive() {
        let mut fixture = StatusAnchorFixture::new(
            serde_json::json!({"last_exit":{"exit_code":0},"home":"/fixture/home","ancestors":[]}),
            false,
        );
        fixture.record_created();
        fixture.spec.args.push("different-command".into());

        fixture.maintain();

        let anchor = fixture
            .terminal
            .store
            .rex_view_anchor(&fixture.view.view.view_id)
            .unwrap()
            .unwrap();
        assert_eq!(anchor.lifecycle, RexBlockLifecycle::Unknown);
        assert!(!anchor.process_absent_confirmed);
        assert!(anchor.archive_digest.is_none());
    }

    #[cfg(unix)]
    struct CompletedBlockFixture {
        terminal: crate::store::agent_results::host_validation_fixture::TestTerminalResultFixture,
        view: RexViewRecord,
        transport: RexCliTransport,
        root: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl CompletedBlockFixture {
        fn new(observation: serde_json::Value) -> Self {
            use crate::engine::orchestration::{AgentAssertion, RoleOutputKind};
            use std::os::unix::fs::PermissionsExt;

            let mut terminal = crate::store::agent_results::host_validation_fixture::host_validated_terminal_result(
                crate::domain::types::Role::Coordinator,
                crate::roles::RoleResultMessage {
                    schema_version: 1,
                    message_id: "view-completed-plan".into(),
                    kind: RoleOutputKind::PlanReady,
                    assertion: AgentAssertion::Succeeded,
                    result_digest: None,
                    structured_result: serde_json::json!({
                        "plan": {"nodes": [], "requested_investigation_children": 0},
                        "unresolved_questions": []
                    }),
                    artifact_refs: Vec::new(),
                },
            )
            .unwrap();
            let authority = terminal
                .store
                .agent_launch_authority(terminal.terminal.agent_run_id())
                .unwrap()
                .unwrap();
            let view = terminal
                .store
                .rex_view_history(&authority.project_id)
                .unwrap()
                .into_iter()
                .find(|view| view.view.view_id == authority.rex_view_id)
                .unwrap();
            terminal
                .store
                .register_rex_view_block(
                    terminal.owner_generation,
                    &crate::launch::RexViewBlock {
                        view_id: view.view.view_id.clone(),
                        block_id: authority.rex_block_id.clone(),
                        agent_run_id: Some(authority.agent_run_id.clone()),
                        role: Some(authority.role),
                        ownership: RexBlockOwnership::Factory,
                        lifecycle: RexBlockLifecycle::Unknown,
                        process_absent_confirmed: false,
                        retained_until_unix: None,
                    },
                )
                .unwrap();
            let root = terminal._temp.path().join("rex-view-fixture");
            std::fs::create_dir(&root).unwrap();
            let label = owned_ticket_window_label("fixture", "T-1").unwrap();
            let user_block = serde_json::json!({"block_id":"user-notes", "label":"notes", "flavor":"com.superlogical.terminal.shell"});
            let make_view = |blocks: Vec<serde_json::Value>| {
                serde_json::json!({
                    "session_id": authority.rex_session_id,
                    "windows": [{"window_id":authority.rex_window_id,"label":label,"layers":[{"blocks":blocks}]}]
                })
            };
            let before = make_view(vec![
                user_block.clone(),
                serde_json::json!({"block_id": authority.rex_block_id, "label":owned_agent_block_label(authority.agent_run_id.as_str()).unwrap(),"flavor":"com.superlogical.terminal.shell"}),
            ]);
            for (name, value) in [
                ("before.json", before),
                ("after.json", make_view(vec![user_block])),
                ("process.json", observation),
                (
                    "whoami.json",
                    serde_json::json!({"endpoint":"unix:///tmp/view-fixture.sock","instance_id":authority.rex_server_identity,"host_id":"fixture-host","rex_version":"fixture"}),
                ),
                (
                    "api.json",
                    serde_json::json!({"methods":{"session.view":{},"session.new_window":{},"session.new_split":{},"session.focus_block":{},"session.zoom_block":{},"block.close":{}}}),
                ),
            ] {
                std::fs::write(root.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
            }
            let script = root.join("rex");
            std::fs::write(
                &script,
                r#"#!/bin/sh
fixture_dir=${0%/*}
case "$*" in
  *"whoami --json"*) /bin/cat "$fixture_dir/whoami.json" ;;
  *"api list --json"*) /bin/cat "$fixture_dir/api.json" ;;
  *"session.view"*)
    if [ -f "$fixture_dir/closed" ]; then
      /bin/cat "$fixture_dir/after.json"
    else
      /bin/cat "$fixture_dir/before.json"
    fi ;;
  *"terminal.process"*) /bin/cat "$fixture_dir/process.json" ;;
  *"block.close"*) /usr/bin/touch "$fixture_dir/closed"; printf '{}\n' ;;
  *"capture"*) printf 'Archived completed Agent output\n' ;;
  *) exit 3 ;;
esac
"#,
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let transport = RexCliTransport::connect(
                &script,
                &[],
                "unix:///tmp/view-fixture.sock".into(),
                authority.rex_server_identity,
                authority.rex_session_id,
                std::collections::BTreeMap::new(),
            )
            .unwrap();
            Self {
                terminal,
                view,
                transport,
                root,
            }
        }

        fn maintain(&mut self, keep: usize) {
            maintain_view(
                &mut self.terminal.store,
                self.terminal.owner_generation,
                100,
                &self.view,
                &self.transport,
                RexViewLifecyclePolicy {
                    max_blocks_per_tab: 2,
                    completed_blocks_to_keep: keep,
                    completed_ticket_tab_retention_seconds: 3600,
                },
                None,
            )
            .unwrap();
        }

        fn owned_block(&self) -> crate::launch::RexViewBlockRecord {
            self.terminal
                .store
                .rex_view_blocks(&self.view.view.view_id)
                .unwrap()
                .into_iter()
                .find(|record| record.block.agent_run_id.is_some())
                .unwrap()
        }
    }

    #[cfg(unix)]
    #[test]
    fn completed_block_with_omitted_ancestors_is_archived_then_recycled_from_terminal_proof() {
        let mut fixture =
            CompletedBlockFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}));
        fixture.maintain(1);
        fixture.maintain(1);
        let record = fixture.owned_block();
        assert_eq!(record.block.lifecycle, RexBlockLifecycle::Completed);
        assert!(record.block.process_absent_confirmed);
        assert!(record.archive_digest.is_some());
        assert!(!fixture.root.join("closed").exists());
        fixture.maintain(0);
        assert!(fixture.root.join("closed").exists());
        let records = fixture
            .terminal
            .store
            .rex_view_blocks(&fixture.view.view.view_id)
            .unwrap();
        assert_eq!(
            fixture.owned_block().block.lifecycle,
            RexBlockLifecycle::Closed
        );
        let window = RexWindow {
            server_instance_id: fixture.view.view.rex_server_identity.clone(),
            session_id: fixture.view.view.rex_session_id.clone(),
            window_id: fixture.view.view.rex_window_id.clone(),
            label: owned_ticket_window_label("fixture", "T-1").unwrap(),
            initial_block_id: None,
            disposition: CreateDisposition::Existing,
        };
        let observed = fixture
            .transport
            .list_window_blocks(&window, &window.label)
            .unwrap();
        assert!(has_block_capacity(&records, &observed, 2));
        assert_eq!(observed[0].block_id, "user-notes");
    }

    #[cfg(unix)]
    #[test]
    fn completed_receipt_never_overrides_live_or_incomplete_rex_observations() {
        let process = serde_json::json!({"pid":42,"user_id":501,"name":"running"});
        for observation in [
            serde_json::json!({"last_exit":{"exit_code":0},"child":process}),
            serde_json::json!({"last_exit":{"exit_code":0},"foreground":process}),
            serde_json::json!({"last_exit":{"exit_code":0},"ancestors":[process]}),
            serde_json::json!({}),
        ] {
            let mut fixture = CompletedBlockFixture::new(observation);
            fixture.maintain(0);
            let record = fixture.owned_block();
            assert!(!record.block.process_absent_confirmed);
            assert!(record.archive_digest.is_none());
            assert!(!fixture.root.join("closed").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn omitted_ancestors_with_invalid_terminal_evidence_retains_block_capacity() {
        let mut fixture =
            CompletedBlockFixture::new(serde_json::json!({"last_exit":{"exit_code":0}}));
        fixture
            .terminal
            .store
            .test_connection()
            .execute(
                "UPDATE agent_runs SET state='unknown' WHERE agent_run_id=?1",
                [fixture.terminal.terminal.agent_run_id().as_str()],
            )
            .unwrap();
        fixture.maintain(0);
        let record = fixture.owned_block();
        assert_eq!(record.block.lifecycle, RexBlockLifecycle::Unknown);
        assert!(!record.block.process_absent_confirmed);
        assert!(record.archive_digest.is_none());
        assert!(!fixture.root.join("closed").exists());
    }
}
