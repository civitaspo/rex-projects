//! Bounded file protocol between a Rex block wrapper and the foreground host controller.
//!
//! The wrapper never opens SQLite. It publishes its start observation once, waits for the
//! controller's durable decision, then may publish a bounded result envelope. These files carry
//! evidence only; the controller must still validate them against persisted launch authority.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::domain::ids::{AgentRunId, Digest};
use crate::launch::{AgentLaunchReceipt, AgentStartRequest};
use crate::process::{ProcessIdentity, ProcessIdentityQuality};
use crate::run_step::{RunReceipt, TurnResult};

const PROTOCOL_VERSION: u32 = 1;
pub(crate) const BLOCK_LOSS_SNAPSHOT_VERSION: u32 = 2;
const RUN_FAMILY_VERSION: u32 = 1;
const RUN_FAMILY_RECORD_VERSION: u32 = 2;
const MAX_START_BYTES: usize = 32 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_BLOCK_LOSS_SNAPSHOT_BYTES: usize = 33 * 1024 * 1024;
const MAX_RUN_FAMILY_BYTES: usize = crate::process::MAX_PROCESS_EVIDENCE_ENVELOPE_BYTES;
const MAX_AGENT_TURN_RESULT_BYTES: usize = crate::process::MAX_PROCESS_EVIDENCE_ENVELOPE_BYTES;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequestEnvelope {
    pub schema_version: u32,
    pub request_digest: String,
    pub request: AgentStartRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartReceiptEnvelope {
    pub schema_version: u32,
    pub request_digest: String,
    pub receipt: AgentLaunchReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurnResult {
    pub schema_version: u32,
    pub start_request_digest: String,
    pub receipt: RunReceipt,
    pub structured_result: Option<serde_json::Value>,
    pub result_digest: String,
}

/// Host-owned cumulative process evidence used only after a managed Rex block disappears.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockLossCleanupSnapshot {
    pub schema_version: u32,
    pub agent_run_id: AgentRunId,
    pub reservation_epoch: u64,
    pub authority_digest: Digest,
    pub launch_tree_digest: Digest,
    pub observed_at_unix: i64,
    pub cleanup_covered: bool,
    pub process_tree: Vec<ProcessIdentity>,
    pub process_tree_digest: Digest,
}

/// Immutable host-issued binding that lets the run-step producer checkpoint without SQLite.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunFamilyBinding {
    pub schema_version: u32,
    pub agent_run_id: AgentRunId,
    pub reservation_epoch: u64,
    pub authority_digest: Digest,
    pub descriptor_digest: Digest,
    pub wrapper_pid: u32,
    pub wrapper_start_identity: String,
}

impl RunFamilyBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != RUN_FAMILY_VERSION
            || self.reservation_epoch == 0
            || self.wrapper_pid == 0
            || self.wrapper_start_identity.trim().is_empty()
        {
            return Err("run-family binding is outside its bounds".into());
        }
        Ok(())
    }
}

/// Durable cumulative identities observed by the provider-owning run-step process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunFamilyRecord {
    pub schema_version: u32,
    pub binding: RunFamilyBinding,
    pub observed_at_unix: i64,
    pub coverage: RunFamilyCoverage,
    pub wrapper_process: ProcessIdentity,
    pub provider_root: ProcessIdentity,
    pub provider_executable_path: PathBuf,
    pub provider_executable_digest: Digest,
    pub process_tree: Vec<ProcessIdentity>,
    pub process_tree_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunFamilyCoverage {
    Observing,
    Complete,
    Interrupted,
}

impl RunFamilyRecord {
    pub fn validate(&self) -> Result<(), String> {
        self.binding.validate()?;
        if self.schema_version != RUN_FAMILY_RECORD_VERSION
            || self.observed_at_unix < 0
            || self.process_tree.is_empty()
            || !self.provider_executable_path.is_absolute()
        {
            return Err("run-family record is outside its bounds".into());
        }
        if self.wrapper_process.pid != self.binding.wrapper_pid
            || self.wrapper_process.start_identity != self.binding.wrapper_start_identity
            || self.wrapper_process.quality != ProcessIdentityQuality::KernelBirthToken
            || self.wrapper_process.process_group_id == 0
            || self.wrapper_process.start_identity.trim().is_empty()
            || self.provider_root.parent_pid != self.wrapper_process.pid
        {
            return Err("run-family record does not identify the exact live wrapper parent".into());
        }
        if self.provider_root.pid == 0
            || self.provider_root.process_group_id == 0
            || self.provider_root.quality != ProcessIdentityQuality::KernelBirthToken
            || self.provider_root.start_identity.trim().is_empty()
            || !self.process_tree.iter().any(|process| {
                process.pid == self.provider_root.pid
                    && process.start_identity == self.provider_root.start_identity
                    && process.quality == self.provider_root.quality
            })
        {
            return Err("run-family record has no exact provider root anchor".into());
        }
        crate::process::validate_process_evidence_tree(&self.process_tree)?;
        let mut identities = std::collections::BTreeSet::new();
        for process in &self.process_tree {
            if process.pid == 0
                || process.process_group_id == 0
                || process.quality != ProcessIdentityQuality::KernelBirthToken
                || process.start_identity.trim().is_empty()
                || !identities.insert((process.pid, process.start_identity.as_str()))
            {
                return Err("run-family record has invalid process identities".into());
            }
        }
        let bytes = serde_json::to_vec(&self.process_tree).map_err(|error| error.to_string())?;
        if self.process_tree_digest != Digest::parse(sha256(&bytes))? {
            return Err("run-family record digest does not match its process tree".into());
        }
        Ok(())
    }
}

impl BlockLossCleanupSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != BLOCK_LOSS_SNAPSHOT_VERSION
            || self.reservation_epoch == 0
            || self.observed_at_unix < 0
            || self.process_tree.is_empty()
        {
            return Err("block-loss cleanup snapshot is outside its bounds".into());
        }
        crate::process::validate_process_evidence_tree(&self.process_tree)?;
        let mut identities = std::collections::BTreeSet::new();
        for process in &self.process_tree {
            if process.pid == 0
                || process.process_group_id == 0
                || process.quality != ProcessIdentityQuality::KernelBirthToken
                || process.start_identity.trim().is_empty()
                || !identities.insert((process.pid, process.start_identity.as_str()))
            {
                return Err("block-loss cleanup snapshot has invalid process identities".into());
            }
        }
        let bytes = serde_json::to_vec(&self.process_tree).map_err(|error| error.to_string())?;
        if self.process_tree_digest != Digest::parse(sha256(&bytes))? {
            return Err(
                "block-loss cleanup snapshot digest does not match its process tree".into(),
            );
        }
        Ok(())
    }
}

/// Files scoped to one immutable launch authority's control directory.
#[derive(Clone, Debug)]
pub struct RunStepSpool {
    directory: PathBuf,
}

impl RunStepSpool {
    /// Opens or creates the private `run-step` child of an already registered control directory.
    pub fn open(control_dir: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(control_dir)
            .map_err(|error| format!("control directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("control directory must be a real directory".into());
        }
        let canonical_parent = fs::canonicalize(control_dir)
            .map_err(|error| format!("canonicalize control directory: {error}"))?;
        let directory = canonical_parent.join("run-step");
        match fs::create_dir(&directory) {
            Ok(()) => set_private_dir(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create run-step spool: {error}")),
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|error| format!("run-step spool: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("run-step spool must be a real directory".into());
        }
        let canonical = fs::canonicalize(&directory)
            .map_err(|error| format!("canonicalize run-step spool: {error}"))?;
        if canonical != directory {
            return Err("run-step spool path changed during canonicalization".into());
        }
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Publishes the wrapper observation exactly once and returns its canonical content digest.
    pub fn publish_start_once(
        &self,
        request: AgentStartRequest,
    ) -> Result<StartRequestEnvelope, String> {
        request.validate()?;
        let request_bytes = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        let envelope = StartRequestEnvelope {
            schema_version: PROTOCOL_VERSION,
            request_digest: sha256(&request_bytes),
            request,
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
        publish_once(
            &self.directory,
            "start.request.json",
            &bytes,
            MAX_START_BYTES,
        )?;
        Ok(envelope)
    }

    pub fn publish_run_family_binding_once(
        &self,
        binding: &RunFamilyBinding,
    ) -> Result<(), String> {
        binding.validate()?;
        let bytes = serde_json::to_vec(binding).map_err(|error| error.to_string())?;
        publish_once(
            &self.directory,
            "run-family-binding.json",
            &bytes,
            MAX_START_BYTES,
        )
    }

    pub fn read_run_family_binding(&self) -> Result<RunFamilyBinding, String> {
        let bytes = read_bounded(
            &self.directory.join("run-family-binding.json"),
            MAX_START_BYTES,
        )?;
        let binding: RunFamilyBinding = parse_unique(&bytes)?;
        binding.validate()?;
        Ok(binding)
    }

    pub fn read_run_family_record(&self) -> Result<Option<RunFamilyRecord>, String> {
        match read_bounded(
            &self.directory.join("run-family.json"),
            MAX_RUN_FAMILY_BYTES,
        ) {
            Ok(bytes) => {
                let record: RunFamilyRecord = parse_unique(&bytes)?;
                record.validate()?;
                Ok(Some(record))
            }
            Err(error) if error == "run-step spool file is not present" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Atomically replaces cumulative producer evidence without allowing rebinding or promotion
    /// from an interrupted producer to a clean terminal.
    pub fn write_run_family_record(&self, record: &RunFamilyRecord) -> Result<(), String> {
        record.validate()?;
        if self.read_run_family_binding()? != record.binding {
            return Err("run-family record does not match its immutable binding".into());
        }
        if let Some(previous) = self.read_run_family_record()? {
            if previous == *record {
                return Ok(());
            }
            if previous.binding != record.binding
                || previous.provider_root.pid != record.provider_root.pid
                || previous.provider_root.start_identity != record.provider_root.start_identity
                || previous.provider_root.process_group_id != record.provider_root.process_group_id
                || previous.provider_root.quality != record.provider_root.quality
                || previous.wrapper_process != record.wrapper_process
                || previous.provider_executable_path != record.provider_executable_path
                || previous.provider_executable_digest != record.provider_executable_digest
                || record.observed_at_unix < previous.observed_at_unix
                || !process_tree_contains(&record.process_tree, &previous.process_tree)
                || previous.coverage != RunFamilyCoverage::Observing
            {
                return Err(
                    "run-family record changed its binding, root, identities, or phase".into(),
                );
            }
        } else if record.coverage != RunFamilyCoverage::Observing {
            return Err("run-family terminal phase has no preceding observation".into());
        }
        let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
        replace_bounded(
            &self.directory,
            "run-family.json",
            &bytes,
            MAX_RUN_FAMILY_BYTES,
        )
    }

    /// Host-side read. The caller must authorize this request against durable store state.
    pub fn read_start_request(&self) -> Result<StartRequestEnvelope, String> {
        let bytes = read_bounded(&self.directory.join("start.request.json"), MAX_START_BYTES)?;
        let envelope: StartRequestEnvelope = parse_unique(&bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Host-side single publication after `ConfigStore::authorize_agent_start` succeeds.
    pub fn publish_start_receipt(
        &self,
        request: &StartRequestEnvelope,
        receipt: AgentLaunchReceipt,
    ) -> Result<(), String> {
        request.validate()?;
        receipt.validate_for(&request.request)?;
        let envelope = StartReceiptEnvelope {
            schema_version: PROTOCOL_VERSION,
            request_digest: request.request_digest.clone(),
            receipt,
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
        publish_once(
            &self.directory,
            "start.receipt.json",
            &bytes,
            MAX_START_BYTES,
        )
    }

    /// Host-side read of an already published start receipt. Existing receipts remain
    /// immutable; callers compare them with the durable host decision before replaying.
    pub fn read_start_receipt(
        &self,
        request: &StartRequestEnvelope,
    ) -> Result<Option<AgentLaunchReceipt>, String> {
        request.validate()?;
        match read_bounded(&self.directory.join("start.receipt.json"), MAX_START_BYTES) {
            Ok(bytes) => {
                let envelope: StartReceiptEnvelope = parse_unique(&bytes)?;
                envelope.validate_for(request)?;
                Ok(Some(envelope.receipt))
            }
            Err(error) if error == "run-step spool file is not present" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Wrapper-side bounded wait. Timeout is an unresolved start, never permission to proceed.
    pub fn wait_start_receipt(
        &self,
        request: &StartRequestEnvelope,
        timeout: Duration,
    ) -> Result<AgentLaunchReceipt, String> {
        request.validate()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "start receipt deadline overflow".to_owned())?;
        loop {
            if let Some(receipt) = self.read_start_receipt(request)? {
                return Ok(receipt);
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for the host start decision".into());
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Publishes already bounded, serialized result evidence exactly once.
    /// The controller owns deserialization into its strict role-result and process evidence types.
    pub fn publish_result_once(&self, bytes: &[u8]) -> Result<String, String> {
        if bytes.len() > MAX_RESULT_BYTES {
            return Err("Agent turn result exceeds the 1 MiB limit".into());
        }
        let _: serde_json::Value = parse_unique(bytes)?;
        let digest = sha256(bytes);
        publish_once(&self.directory, "turn.result.json", bytes, MAX_RESULT_BYTES)?;
        Ok(digest)
    }

    pub fn publish_turn_result_once(
        &self,
        request: &StartRequestEnvelope,
        result: TurnResult,
    ) -> Result<AgentTurnResult, String> {
        request.validate()?;
        let family = match self.read_run_family_record()? {
            Some(family) => family,
            None => {
                let message = result
                    .receipt
                    .cleanup_detail
                    .as_deref()
                    .filter(|detail| {
                        detail.starts_with("provider process-family checkpoint failed: ")
                    })
                    .map(|detail| {
                        format!(
                            "run-step producer has no durable process-family evidence: {detail}"
                        )
                    })
                    .unwrap_or_else(|| {
                        "run-step producer has no durable process-family evidence".into()
                    });
                return Err(message);
            }
        };
        if family.binding.agent_run_id != request.request.agent_run_id
            || family.binding.descriptor_digest != request.request.descriptor_digest
            || family.binding.wrapper_pid != request.request.wrapper_pid
            || family.binding.wrapper_start_identity != request.request.wrapper_start_identity
            || family.coverage != RunFamilyCoverage::Complete
        {
            return Err(
                "run-step producer did not durably complete this exact process family".into(),
            );
        }
        let mut envelope = AgentTurnResult {
            schema_version: PROTOCOL_VERSION,
            start_request_digest: request.request_digest.clone(),
            receipt: result.receipt,
            structured_result: result.structured_result,
            result_digest: String::new(),
        };
        if envelope.receipt.run_id != request.request.agent_run_id {
            return Err("provider result belongs to a different AgentRun".into());
        }
        envelope.result_digest = "0".repeat(64);
        envelope.validate_payload_bounds()?;
        envelope.result_digest = envelope.payload_digest()?;
        let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
        publish_once(
            &self.directory,
            "turn.result.json",
            &bytes,
            MAX_AGENT_TURN_RESULT_BYTES,
        )?;
        Ok(envelope)
    }

    /// Host-side bounded read; callers must validate the envelope and treat its claims as evidence.
    pub fn read_result(&self) -> Result<Vec<u8>, String> {
        read_bounded(&self.directory.join("turn.result.json"), MAX_RESULT_BYTES)
    }

    pub fn read_block_loss_cleanup_snapshot(
        &self,
    ) -> Result<Option<BlockLossCleanupSnapshot>, String> {
        match read_bounded(
            &self.directory.join("block-loss-cleanup.json"),
            MAX_BLOCK_LOSS_SNAPSHOT_BYTES,
        ) {
            Ok(bytes) => {
                let snapshot: BlockLossCleanupSnapshot = parse_unique(&bytes)?;
                snapshot.validate()?;
                Ok(Some(snapshot))
            }
            Err(error) if error == "run-step spool file is not present" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Atomically replaces the private cumulative cleanup snapshot after validating its binding.
    pub fn write_block_loss_cleanup_snapshot(
        &self,
        snapshot: &BlockLossCleanupSnapshot,
    ) -> Result<(), String> {
        snapshot.validate()?;
        if let Some(previous) = self.read_block_loss_cleanup_snapshot()? {
            if previous.agent_run_id != snapshot.agent_run_id
                || previous.reservation_epoch != snapshot.reservation_epoch
                || previous.authority_digest != snapshot.authority_digest
                || previous.launch_tree_digest != snapshot.launch_tree_digest
                || snapshot.observed_at_unix < previous.observed_at_unix
                || !process_tree_contains(&snapshot.process_tree, &previous.process_tree)
            {
                return Err(
                    "block-loss cleanup snapshot changed its binding or lost identities".into(),
                );
            }
            if snapshot.cleanup_covered && !previous.cleanup_covered {
                let same_identities = snapshot.process_tree.len() == previous.process_tree.len();
                if !same_identities {
                    return Err(
                        "block-loss cleanup coverage cannot include unobserved identities".into(),
                    );
                }
            }
        }
        let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        replace_bounded(
            &self.directory,
            "block-loss-cleanup.json",
            &bytes,
            MAX_BLOCK_LOSS_SNAPSHOT_BYTES,
        )
    }

    pub fn read_turn_result(
        &self,
        request: &StartRequestEnvelope,
    ) -> Result<AgentTurnResult, String> {
        request.validate()?;
        let bytes = read_bounded(
            &self.directory.join("turn.result.json"),
            MAX_AGENT_TURN_RESULT_BYTES,
        )?;
        let family = self
            .read_run_family_record()?
            .ok_or("run-step producer has no durable process-family evidence")?;
        if family.binding.agent_run_id != request.request.agent_run_id
            || family.binding.descriptor_digest != request.request.descriptor_digest
            || family.binding.wrapper_pid != request.request.wrapper_pid
            || family.binding.wrapper_start_identity != request.request.wrapper_start_identity
            || family.coverage != RunFamilyCoverage::Complete
        {
            return Err(
                "run-step producer did not durably complete this exact process family".into(),
            );
        }
        let envelope: AgentTurnResult = parse_unique(&bytes)?;
        envelope.validate_for(request)?;
        Ok(envelope)
    }
}

fn process_tree_contains(tree: &[ProcessIdentity], required: &[ProcessIdentity]) -> bool {
    required.iter().all(|process| {
        tree.iter().any(|candidate| {
            candidate.pid == process.pid
                && candidate.start_identity == process.start_identity
                && candidate.quality == process.quality
        })
    })
}

impl StartRequestEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PROTOCOL_VERSION {
            return Err("unsupported run-step start request schema".into());
        }
        self.request.validate()?;
        let bytes = serde_json::to_vec(&self.request).map_err(|error| error.to_string())?;
        if self.request_digest != sha256(&bytes) {
            return Err("run-step start request digest does not match its payload".into());
        }
        Ok(())
    }
}

impl StartReceiptEnvelope {
    pub fn validate_for(&self, request: &StartRequestEnvelope) -> Result<(), String> {
        if self.schema_version != PROTOCOL_VERSION || self.request_digest != request.request_digest
        {
            return Err("host start receipt is not bound to this start request".into());
        }
        self.receipt.validate_for(&request.request)
    }
}

impl AgentTurnResult {
    pub fn validate_for(&self, request: &StartRequestEnvelope) -> Result<(), String> {
        if self.schema_version != PROTOCOL_VERSION
            || self.start_request_digest != request.request_digest
            || self.receipt.run_id != request.request.agent_run_id
        {
            return Err("Agent result is not bound to this acknowledged launch".into());
        }
        self.validate_payload_bounds()?;
        if self.result_digest != self.payload_digest()? {
            return Err("Agent result digest does not match its payload".into());
        }
        Ok(())
    }

    fn validate_payload_bounds(&self) -> Result<(), String> {
        crate::process::validate_process_evidence_tree(&self.receipt.processes)?;
        if let Some(result) = &self.structured_result
            && crate::process::serialized_json_size_at_most(result, MAX_RESULT_BYTES).is_err()
        {
            return Err("Agent structured result exceeds the 1 MiB limit".into());
        }
        crate::process::serialized_json_size_at_most(self, MAX_AGENT_TURN_RESULT_BYTES)
            .map_err(|_| "Agent turn result envelope exceeds the 34 MiB limit".to_owned())?;
        Ok(())
    }

    fn payload_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            start_request_digest: &'a str,
            receipt: &'a RunReceipt,
            structured_result: &'a Option<serde_json::Value>,
        }
        let bytes = serde_json::to_vec(&Payload {
            schema_version: self.schema_version,
            start_request_digest: &self.start_request_digest,
            receipt: &self.receipt,
            structured_result: &self.structured_result,
        })
        .map_err(|error| error.to_string())?;
        Ok(sha256(&bytes))
    }
}

fn publish_once(directory: &Path, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
    if bytes.len() > limit {
        return Err("run-step spool payload exceeds its byte limit".into());
    }
    let temporary = directory.join(format!(".{name}.{}.tmp", nonce()));
    let destination = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create run-step temporary file: {error}"))?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write run-step spool file: {error}"));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    match fs::hard_link(&temporary, &destination) {
        Ok(()) => {
            fs::remove_file(&temporary)
                .map_err(|error| format!("remove run-step temporary file: {error}"))?;
            sync_directory(directory)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(format!(
                    "run-step spool file `{name}` was already published"
                ))
            } else {
                Err(format!("publish run-step spool file: {error}"))
            }
        }
    }
}

fn replace_bounded(directory: &Path, name: &str, bytes: &[u8], limit: usize) -> Result<(), String> {
    if bytes.len() > limit {
        return Err("run-step spool payload exceeds its byte limit".into());
    }
    let temporary = directory.join(format!(".{name}.{}.tmp", nonce()));
    let destination = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create run-step temporary file: {error}"))?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write run-step spool file: {error}"));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("replace run-step spool file: {error}"));
    }
    sync_directory(directory)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("run-step spool file is not present".into());
        }
        Err(error) => return Err(format!("open run-step spool file: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect run-step spool file: {error}"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("run-step spool file is not regular or exceeds its byte limit".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read run-step spool file: {error}"))?;
    if bytes.len() > limit {
        return Err("run-step spool file exceeds its byte limit".into());
    }
    Ok(bytes)
}

fn parse_unique<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut deserializer)
        .map_err(|error| format!("invalid run-step spool JSON at {}", error.path()))?;
    deserializer
        .end()
        .map_err(|_| "trailing data in run-step spool JSON".to_owned())?;
    Ok(value)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn nonce() -> String {
    let mut bytes = [0_u8; 16];
    use std::io::Read as _;
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        bytes.copy_from_slice(&now.to_le_bytes()[..16]);
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("secure run-step spool: {error}"))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync run-step spool directory: {error}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AgentTurnResult, BLOCK_LOSS_SNAPSHOT_VERSION, BlockLossCleanupSnapshot, RunFamilyBinding,
        RunFamilyCoverage, RunFamilyRecord, RunStepSpool, StartReceiptEnvelope,
        StartRequestEnvelope,
    };
    use crate::domain::ids::{AgentRunId, Digest, OperationId, ProjectId};
    use crate::launch::{AgentLaunchReceipt, AgentStartRequest, LaunchDecision};
    use crate::process::{ProcessIdentity, ProcessIdentityQuality};
    use crate::run_step::{CleanupState, ObservedProcess, RunReceipt, TurnOutcome, TurnResult};
    use sha2::Digest as _;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;

    fn request() -> AgentStartRequest {
        AgentStartRequest {
            schema_version: 1,
            operation_id: OperationId::parse("op-1").unwrap(),
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            project_id: ProjectId::parse("project-a").unwrap(),
            controller_generation: 1,
            descriptor_digest: digest('a'),
            runtime_binary_digest: digest('b'),
            environment_snapshot_id: digest('c'),
            qualification_receipt_digest: digest('d'),
            wrapper_pid: 100,
            wrapper_start_identity: "birth-100".into(),
            rex_session_id: "session-1".into(),
            rex_block_id: "block-1".into(),
        }
    }

    fn digest(c: char) -> Digest {
        Digest::parse(c.to_string().repeat(64)).unwrap()
    }

    fn process(pid: u32, start_identity: &str, group_id: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            parent_pid: 1,
            process_group_id: group_id,
            start_identity: start_identity.into(),
            command: "/bin/sleep".into(),
            quality: ProcessIdentityQuality::KernelBirthToken,
        }
    }

    fn cleanup_snapshot(process_tree: Vec<ProcessIdentity>) -> BlockLossCleanupSnapshot {
        let bytes = serde_json::to_vec(&process_tree).unwrap();
        BlockLossCleanupSnapshot {
            schema_version: BLOCK_LOSS_SNAPSHOT_VERSION,
            agent_run_id: AgentRunId::parse("run-1").unwrap(),
            reservation_epoch: 2,
            authority_digest: digest('a'),
            launch_tree_digest: digest('b'),
            observed_at_unix: 10,
            cleanup_covered: false,
            process_tree,
            process_tree_digest: Digest::parse(format!("{:x}", sha2::Sha256::digest(bytes)))
                .unwrap(),
        }
    }

    fn family_binding(request: &AgentStartRequest) -> RunFamilyBinding {
        RunFamilyBinding {
            schema_version: 1,
            agent_run_id: request.agent_run_id.clone(),
            reservation_epoch: 2,
            authority_digest: digest('f'),
            descriptor_digest: request.descriptor_digest.clone(),
            wrapper_pid: request.wrapper_pid,
            wrapper_start_identity: request.wrapper_start_identity.clone(),
        }
    }

    fn family_record(
        binding: RunFamilyBinding,
        mut process_tree: Vec<ProcessIdentity>,
    ) -> RunFamilyRecord {
        let mut provider_root = process_tree[0].clone();
        provider_root.parent_pid = binding.wrapper_pid;
        process_tree[0] = provider_root.clone();
        RunFamilyRecord {
            schema_version: 2,
            wrapper_process: ProcessIdentity {
                pid: binding.wrapper_pid,
                parent_pid: 1,
                process_group_id: binding.wrapper_pid,
                start_identity: binding.wrapper_start_identity.clone(),
                command: String::new(),
                quality: ProcessIdentityQuality::KernelBirthToken,
            },
            binding,
            observed_at_unix: 10,
            coverage: RunFamilyCoverage::Observing,
            provider_root,
            provider_executable_path: PathBuf::from("/bin/sleep"),
            provider_executable_digest: digest('e'),
            process_tree_digest: Digest::parse(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(&process_tree).unwrap())
            ))
            .unwrap(),
            process_tree,
        }
    }

    fn receipt(request: &AgentStartRequest) -> AgentLaunchReceipt {
        AgentLaunchReceipt {
            schema_version: 1,
            operation_id: request.operation_id.clone(),
            agent_run_id: request.agent_run_id.clone(),
            controller_generation: request.controller_generation,
            descriptor_digest: request.descriptor_digest.clone(),
            runtime_binary_digest: request.runtime_binary_digest.clone(),
            qualification_receipt_digest: request.qualification_receipt_digest.clone(),
            decision: LaunchDecision::Accepted,
            reason: None,
        }
    }

    fn turn_result(request: &AgentStartRequest) -> TurnResult {
        TurnResult {
            receipt: RunReceipt {
                run_id: request.agent_run_id.clone(),
                attempt: 1,
                provider: crate::domain::types::AgentAdapter::Codex,
                effective_permission_mode: "workspace_write".into(),
                conversation_id: None,
                provider_version: Some("test-version".into()),
                capability_receipt_digest: Some(request.qualification_receipt_digest.clone()),
                schema_projection: crate::providers::project_result_schema(
                    &serde_json::json!({"type":"object"}),
                )
                .unwrap()
                .identity,
                launch_pid_hint: Some(100),
                exit_code: Some(0),
                timed_out: false,
                cancellation_signal: None,
                cleanup: CleanupState::Confirmed,
                cleanup_detail: None,
                processes: vec![],
                result_digest: None,
                provider_result_failure: None,
                provider_process_failure: None,
                outcome: TurnOutcome::MissingResult,
            },
            structured_result: None,
        }
    }

    #[test]
    fn host_ack_is_bound_to_exact_published_request_and_is_single_publish() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let envelope = spool.publish_start_once(request()).unwrap();
        let host_read = spool.read_start_request().unwrap();
        assert_eq!(host_read.request_digest, envelope.request_digest);
        spool
            .publish_start_receipt(&host_read, receipt(&host_read.request))
            .unwrap();
        assert!(
            spool
                .publish_start_receipt(&host_read, receipt(&host_read.request))
                .is_err()
        );
        assert_eq!(
            spool.wait_start_receipt(&envelope, Duration::ZERO).unwrap(),
            receipt(&envelope.request)
        );
    }

    #[test]
    fn start_request_and_receipt_reject_tampering_and_wrong_request_digest() {
        let mut envelope = StartRequestEnvelope {
            schema_version: 1,
            request_digest: "0".repeat(64),
            request: request(),
        };
        assert!(envelope.validate().is_err());
        envelope.request_digest = {
            let bytes = serde_json::to_vec(&envelope.request).unwrap();
            format!("{:x}", sha2::Sha256::digest(bytes))
        };
        envelope.validate().unwrap();
        let ack = StartReceiptEnvelope {
            schema_version: 1,
            request_digest: "f".repeat(64),
            receipt: receipt(&envelope.request),
        };
        assert!(ack.validate_for(&envelope).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reader_rejects_symlinked_start_receipt() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let envelope = spool.publish_start_once(request()).unwrap();
        let target = temp.path().join("outside.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(target, spool.directory().join("start.receipt.json")).unwrap();
        assert!(spool.wait_start_receipt(&envelope, Duration::ZERO).is_err());
    }

    #[test]
    fn bounded_turn_result_is_bound_to_start_and_detects_tampering() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();
        assert_eq!(
            spool.read_turn_result(&request).unwrap_err(),
            "run-step spool file is not present"
        );
        let mut failed_turn = turn_result(&request.request);
        failed_turn.receipt.cleanup_detail = Some(
            "provider process-family checkpoint failed: provider root exited during image inspection"
                .into(),
        );
        assert_eq!(
            spool
                .publish_turn_result_once(&request, failed_turn)
                .unwrap_err(),
            "run-step producer has no durable process-family evidence: provider process-family checkpoint failed: provider root exited during image inspection"
        );
        assert!(
            spool
                .publish_turn_result_once(&request, turn_result(&request.request))
                .is_err()
        );
        let binding = family_binding(&request.request);
        spool.publish_run_family_binding_once(&binding).unwrap();
        let mut family = family_record(binding, vec![process(200, "birth-200", 200)]);
        spool.write_run_family_record(&family).unwrap();
        assert!(
            spool
                .publish_turn_result_once(&request, turn_result(&request.request))
                .is_err()
        );
        family.coverage = RunFamilyCoverage::Complete;
        spool.write_run_family_record(&family).unwrap();
        spool
            .publish_turn_result_once(&request, turn_result(&request.request))
            .unwrap();
        let read = spool.read_turn_result(&request).unwrap();
        read.validate_for(&request).unwrap();

        let mut forged: AgentTurnResult =
            serde_json::from_slice(&spool.read_result().unwrap()).unwrap();
        forged.receipt.exit_code = Some(99);
        assert!(forged.validate_for(&request).is_err());
    }

    #[test]
    fn producer_family_retains_late_child_and_rejects_rebinding_or_lost_history() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let binding = family_binding(&request());
        spool.publish_run_family_binding_once(&binding).unwrap();
        let initial = family_record(binding.clone(), vec![process(200, "birth-200", 200)]);
        spool.write_run_family_record(&initial).unwrap();
        let mut cumulative = family_record(
            binding,
            vec![
                process(200, "birth-200", 200),
                process(201, "late-birth-201", 201),
            ],
        );
        cumulative.observed_at_unix = 11;
        spool.write_run_family_record(&cumulative).unwrap();
        assert_eq!(
            spool.read_run_family_record().unwrap(),
            Some(cumulative.clone())
        );

        let mut lost_child = initial;
        lost_child.observed_at_unix = 12;
        assert!(spool.write_run_family_record(&lost_child).is_err());
        let mut rebound = cumulative.clone();
        rebound.binding.reservation_epoch += 1;
        assert!(spool.write_run_family_record(&rebound).is_err());
        let mut moved_root = cumulative.clone();
        moved_root.provider_root.process_group_id += 1;
        assert!(spool.write_run_family_record(&moved_root).is_err());
        let mut reused_wrapper_pid = cumulative.clone();
        reused_wrapper_pid.wrapper_process.start_identity = "different-wrapper-birth".into();
        assert!(spool.write_run_family_record(&reused_wrapper_pid).is_err());
        let mut wrong_executable = cumulative.clone();
        wrong_executable.provider_executable_path = PathBuf::from("/tmp/unqualified-provider");
        assert!(spool.write_run_family_record(&wrong_executable).is_err());
        let mut wrong_root_parent = cumulative.clone();
        wrong_root_parent.provider_root.parent_pid = 999;
        assert!(spool.write_run_family_record(&wrong_root_parent).is_err());

        cumulative.coverage = RunFamilyCoverage::Interrupted;
        spool.write_run_family_record(&cumulative).unwrap();
        spool.write_run_family_record(&cumulative).unwrap();
        let mut false_completion = cumulative.clone();
        false_completion.coverage = RunFamilyCoverage::Complete;
        assert!(spool.write_run_family_record(&false_completion).is_err());
        assert_eq!(spool.read_run_family_record().unwrap(), Some(cumulative));
    }

    #[test]
    fn producer_family_crosses_1024_and_interrupted_history_cannot_publish_result() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();
        let binding = family_binding(&request.request);
        spool.publish_run_family_binding_once(&binding).unwrap();

        let initial = (200..1224)
            .map(|pid| process(pid, &format!("birth-{pid}"), pid))
            .collect::<Vec<_>>();
        let mut family = family_record(binding, initial);
        spool.write_run_family_record(&family).unwrap();
        family.process_tree.push(process(1224, "birth-1224", 1224));
        family.provider_root = family.process_tree[0].clone();
        family.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&family.process_tree).unwrap())
        ))
        .unwrap();
        family.observed_at_unix += 1;
        spool.write_run_family_record(&family).unwrap();

        let snapshot = cleanup_snapshot(family.process_tree.clone());
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();
        assert_eq!(
            spool.read_block_loss_cleanup_snapshot().unwrap(),
            Some(snapshot)
        );

        family.coverage = RunFamilyCoverage::Interrupted;
        family.observed_at_unix += 1;
        spool.write_run_family_record(&family).unwrap();
        assert_eq!(spool.read_run_family_record().unwrap(), Some(family));
        assert!(
            spool
                .publish_turn_result_once(&request, turn_result(&request.request))
                .is_err()
        );
    }

    #[test]
    fn turn_result_envelope_allows_large_process_evidence_but_keeps_structured_result_bound() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let request = spool.publish_start_once(request()).unwrap();
        let binding = family_binding(&request.request);
        spool.publish_run_family_binding_once(&binding).unwrap();

        let mut process_tree = (200..8_392)
            .map(|pid| {
                let mut process = process(pid, &format!("birth-{pid}"), pid);
                process.command = format!("/provider/{}", "x".repeat(128));
                process
            })
            .collect::<Vec<_>>();
        let mut family = family_record(binding, std::mem::take(&mut process_tree));
        spool.write_run_family_record(&family).unwrap();
        family.coverage = RunFamilyCoverage::Complete;
        family.observed_at_unix += 1;
        spool.write_run_family_record(&family).unwrap();

        let mut result = turn_result(&request.request);
        result.receipt.processes = family
            .process_tree
            .iter()
            .map(|process| ObservedProcess {
                pid: process.pid,
                parent_pid: process.parent_pid,
                process_group_id: process.process_group_id,
                start_identity: process.start_identity.clone(),
                command: process.command.clone(),
                identity_quality: "kernel_birth_token".into(),
            })
            .collect();
        spool.publish_turn_result_once(&request, result).unwrap();
        assert!(
            std::fs::metadata(spool.directory().join("turn.result.json"))
                .unwrap()
                .len()
                > 1024 * 1024
        );
        assert!(spool.read_result().is_err());
        let read = spool.read_turn_result(&request).unwrap();
        assert_eq!(read.receipt.processes.len(), 8_192);

        let mut too_large_result = turn_result(&request.request);
        too_large_result.structured_result =
            Some(serde_json::Value::String("x".repeat(1024 * 1024 + 1)));
        let mut envelope = AgentTurnResult {
            schema_version: 1,
            start_request_digest: request.request_digest.clone(),
            receipt: too_large_result.receipt,
            structured_result: too_large_result.structured_result,
            result_digest: String::new(),
        };
        envelope.result_digest = envelope.payload_digest().unwrap();
        assert_eq!(
            envelope.validate_for(&request).unwrap_err(),
            "Agent structured result exceeds the 1 MiB limit"
        );
    }

    #[test]
    fn legacy_run_family_record_without_image_proof_is_not_promoted() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let binding = family_binding(&request());
        spool.publish_run_family_binding_once(&binding).unwrap();
        let current = family_record(binding, vec![process(200, "birth-200", 200)]);
        let mut legacy = serde_json::to_value(current).unwrap();
        legacy["schema_version"] = serde_json::json!(1);
        legacy.as_object_mut().unwrap().remove("wrapper_process");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("provider_executable_path");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("provider_executable_digest");
        std::fs::write(
            spool.directory().join("run-family.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert!(spool.read_run_family_record().is_err());
    }

    #[test]
    fn producer_completion_cannot_reopen_observation_or_accept_corrupt_history() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let binding = family_binding(&request());
        spool.publish_run_family_binding_once(&binding).unwrap();
        let mut family = family_record(binding, vec![process(200, "birth-200", 200)]);
        family.coverage = RunFamilyCoverage::Complete;
        assert!(spool.write_run_family_record(&family).is_err());
        family.coverage = RunFamilyCoverage::Observing;
        spool.write_run_family_record(&family).unwrap();
        family.coverage = RunFamilyCoverage::Complete;
        spool.write_run_family_record(&family).unwrap();
        spool.write_run_family_record(&family).unwrap();
        family.coverage = RunFamilyCoverage::Observing;
        assert!(spool.write_run_family_record(&family).is_err());
        std::fs::write(spool.directory().join("run-family.json"), b"{bad}").unwrap();
        assert!(spool.read_run_family_record().is_err());
        assert!(spool.write_run_family_record(&family).is_err());
    }

    #[test]
    fn block_loss_snapshot_is_atomic_bound_and_cumulative() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let first = process(20, "birth-20", 20);
        let mut snapshot = cleanup_snapshot(vec![first]);
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();
        assert_eq!(
            spool.read_block_loss_cleanup_snapshot().unwrap(),
            Some(snapshot.clone())
        );

        let second = process(21, "birth-21", 21);
        snapshot.process_tree.push(second);
        snapshot.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&snapshot.process_tree).unwrap())
        ))
        .unwrap();
        snapshot.observed_at_unix = 11;
        spool.write_block_loss_cleanup_snapshot(&snapshot).unwrap();
        assert_eq!(
            spool.read_block_loss_cleanup_snapshot().unwrap(),
            Some(snapshot.clone())
        );

        let mut truncated = snapshot.clone();
        truncated.process_tree.pop();
        truncated.process_tree_digest = Digest::parse(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&truncated.process_tree).unwrap())
        ))
        .unwrap();
        assert!(spool.write_block_loss_cleanup_snapshot(&truncated).is_err());

        let mut rebound = snapshot;
        rebound.authority_digest = digest('c');
        assert!(spool.write_block_loss_cleanup_snapshot(&rebound).is_err());
    }

    #[test]
    fn block_loss_snapshot_corruption_stays_an_error() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let path = spool.directory().join("block-loss-cleanup.json");
        std::fs::write(path, b"{\"schema_version\":1}").unwrap();
        assert!(spool.read_block_loss_cleanup_snapshot().is_err());
    }

    #[test]
    fn legacy_signal_only_snapshot_cannot_prove_cleanup() {
        let temp = tempdir().unwrap();
        let spool = RunStepSpool::open(temp.path()).unwrap();
        let mut legacy = cleanup_snapshot(vec![process(20, "birth-20", 20)]);
        legacy.schema_version = 1;
        legacy.cleanup_covered = true;
        let path = spool.directory().join("block-loss-cleanup.json");
        std::fs::write(path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(spool.read_block_loss_cleanup_snapshot().is_err());
        let mut replacement = legacy;
        replacement.schema_version = BLOCK_LOSS_SNAPSHOT_VERSION;
        assert!(
            spool
                .write_block_loss_cleanup_snapshot(&replacement)
                .is_err()
        );
    }
}
