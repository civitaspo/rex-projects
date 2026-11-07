//! Strict external ticket effect payloads shared by the scheduler and host adapters.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::domain::ids::{Digest, ProjectId, TicketId, TicketNamespace, TicketRunId};
use crate::domain::types::TicketStatus;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishTicketStatus {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub namespace: TicketNamespace,
    pub ticket_id: TicketId,
    pub ticket_run_id: TicketRunId,
    pub ticket_run_revision: u64,
    pub expected_external_revision: Option<String>,
    pub desired_status: TicketStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketCreationRequest {
    pub scope: BTreeMap<String, String>,
    pub creation_key: String,
    pub title: String,
    pub body: String,
    pub status: Option<TicketStatus>,
    pub template: Option<String>,
    pub parent: Option<String>,
    pub dependencies: Option<Vec<String>>,
    pub project: Option<String>,
    pub milestone: Option<String>,
    pub assignee: Option<String>,
    pub priority: Option<i64>,
    pub due_date: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGoalTicket {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub namespace: TicketNamespace,
    pub goal_revision: u64,
    pub request_key: String,
    pub request_digest: Digest,
    pub proposal: GoalTicketProposal,
    pub request: TicketCreationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalTicketProposal {
    pub project_id: ProjectId,
    pub goal_revision: u64,
    pub title: String,
    pub body: String,
    pub labels: std::collections::BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveDuplicateTicket {
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub namespace: TicketNamespace,
    pub duplicate_ticket_id: TicketId,
    pub canonical_ticket_id: TicketId,
    pub expected_external_revision: Option<String>,
    pub comment_body: String,
}

/// Host proof that permits the final Completing → Done transition. Fields are private so an
/// Agent result or effect payload cannot manufacture completion authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketCompletionProof {
    project_id: ProjectId,
    ticket_run_id: TicketRunId,
    expected_revision: u64,
    plan_digest: Digest,
    postmortem_receipt_digest: Digest,
    knowledge_operation_id: String,
    knowledge_manifest_digest: Digest,
}

impl TicketCompletionProof {
    pub(crate) fn from_validated_host_receipts(
        project_id: ProjectId,
        ticket_run_id: TicketRunId,
        expected_revision: u64,
        plan_digest: Digest,
        postmortem_receipt_digest: Digest,
        knowledge_operation_id: String,
        knowledge_manifest_digest: Digest,
    ) -> Self {
        Self {
            project_id,
            ticket_run_id,
            expected_revision,
            plan_digest,
            postmortem_receipt_digest,
            knowledge_operation_id,
            knowledge_manifest_digest,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }
    pub fn ticket_run_id(&self) -> &TicketRunId {
        &self.ticket_run_id
    }
    pub fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    pub fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }
    pub fn postmortem_receipt_digest(&self) -> &Digest {
        &self.postmortem_receipt_digest
    }
    pub fn knowledge_operation_id(&self) -> &str {
        &self.knowledge_operation_id
    }
    pub fn knowledge_manifest_digest(&self) -> &Digest {
        &self.knowledge_manifest_digest
    }
}

impl PublishTicketStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.ticket_run_revision == 0
            || self.reason.trim().is_empty()
            || self.reason.len() > 4096
            || self
                .expected_external_revision
                .as_ref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 512)
        {
            return Err("ticket status effect payload is invalid".into());
        }
        Ok(())
    }
}

impl CreateGoalTicket {
    pub fn validate(&self) -> Result<(), String> {
        let request = &self.request;
        if self.schema_version != 1
            || self.goal_revision == 0
            || self.request_key.is_empty()
            || self.proposal.project_id != self.project_id
            || self.proposal.goal_revision != self.goal_revision
            || self.proposal.title != request.title
            || self.proposal.body != request.body
            || self.proposal.labels
                != request
                    .labels
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            || request.creation_key != self.request_key
            || request.title.trim().is_empty()
            || request.title.len() > 512
            || request.body.len() > 65_536
            || request
                .labels
                .as_ref()
                .is_some_and(|labels| labels.len() > 128)
            || request
                .scope
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err("goal ticket creation effect payload is invalid".into());
        }
        let proposal_value =
            serde_json::to_value(&self.proposal).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&proposal_value).map_err(|error| error.to_string())?;
        use sha2::Digest as _;
        let computed = format!("{:x}", sha2::Sha256::digest(bytes));
        let expected_key = format!("goal-{computed}");
        if self.request_key != expected_key {
            return Err("goal ticket request key does not match its canonical proposal".into());
        }
        let computed = Digest::parse(computed)?;
        if computed != self.request_digest {
            return Err("goal ticket request digest does not match its normalized payload".into());
        }
        Ok(())
    }
}

impl ResolveDuplicateTicket {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.duplicate_ticket_id == self.canonical_ticket_id
            || self.comment_body.trim().is_empty()
            || self.comment_body.len() > 16_384
            || self
                .expected_external_revision
                .as_ref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 512)
        {
            return Err("duplicate ticket resolution payload is invalid".into());
        }
        Ok(())
    }
}
