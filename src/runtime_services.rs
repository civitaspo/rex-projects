//! Concrete host adapters assembled for one foreground controller.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::adapters::tickets::{
    NormalizedTicketStatus, TicketAdapter, TicketListRequest, TicketScope, build_ticket_adapter,
};
use crate::config::Config;
use crate::domain::ids::{AdapterId, TicketId, TicketNamespace};
use crate::domain::types::TicketStatus;
use crate::effects::EffectHandler;
use crate::engine::factory_runtime::{ExternalTicketPage, FactoryRuntimeServices};
use crate::protocol::RequestId;
use crate::store::ConfigStore;
use crate::store::scheduler::{ObservedTicket, TicketScanKey};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Long-lived adapters and effect handlers for a single controller process.
/// Adapter namespaces are learned once and pinned by their `describe` call.
pub struct RuntimeServices {
    tickets: Box<dyn TicketAdapter>,
    namespaces: BTreeMap<AdapterId, TicketNamespace>,
    handlers: Vec<Box<dyn EffectHandler>>,
    config: Config,
}

impl RuntimeServices {
    pub fn new(
        config: &Config,
        environment: &BTreeMap<OsString, OsString>,
        config_dir: &Path,
        _state_root: &Path,
        _owner_generation: u64,
    ) -> Result<Self, String> {
        let tickets = build_ticket_adapter(config, environment, config_dir)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            tickets,
            namespaces: BTreeMap::new(),
            handlers: Vec::new(),
            config: config.clone(),
        })
    }

    fn request_id(&self, purpose: &str) -> Result<RequestId, String> {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!("rex-projects-{purpose}-{sequence}"))
    }
}

impl FactoryRuntimeServices for RuntimeServices {
    fn ingest_one_agent_result(
        &mut self,
        _store: &mut ConfigStore,
        _owner_generation: u64,
        _now_unix: i64,
    ) -> Result<bool, String> {
        // Mailbox decoding is wired when the provider run-step bridge is composed.
        Ok(false)
    }

    fn ticket_namespace(&mut self, adapter: &AdapterId) -> Result<TicketNamespace, String> {
        if let Some(namespace) = self.namespaces.get(adapter) {
            return Ok(namespace.clone());
        }
        if adapter.as_str() != "tickets" {
            return Err(format!("unknown configured ticket adapter `{adapter}`"));
        }
        let description = self
            .tickets
            .describe(self.request_id("describe")?)
            .map_err(|error| error.to_string())?;
        let namespace = TicketNamespace::parse(description.ticket_namespace)?;
        self.namespaces.insert(adapter.clone(), namespace.clone());
        Ok(namespace)
    }

    fn list_ticket_page(
        &mut self,
        key: &TicketScanKey,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<ExternalTicketPage, String> {
        if limit == 0 || limit > 100 {
            return Err("ticket page limit must be between 1 and 100".into());
        }
        let project = self
            .config
            .projects
            .get(&key.project_id)
            .ok_or_else(|| format!("missing configured Project `{}`", key.project_id))?;
        if project.ticket_adapter != key.adapter_id {
            return Err("ticket scan adapter does not match Project configuration".into());
        }
        let scope_values = project
            .ticket_scope
            .iter()
            .map(|(key, value)| {
                value
                    .as_str()
                    .map(|value| (key.clone(), value.to_owned()))
                    .ok_or_else(|| format!("ticket scope `{key}` must be a string"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let scope = TicketScope::new(scope_values).map_err(|error| error.to_string())?;
        let page = self
            .tickets
            .list(
                self.request_id("list")?,
                None,
                TicketListRequest {
                    scope,
                    status: Some(normalized_status(key.status)),
                    assignee: None,
                    project: None,
                    milestone: None,
                    release: None,
                    labels: None,
                    query: None,
                    cursor: cursor.map(str::to_owned),
                    page_size: Some(limit as u32),
                    updated_since: None,
                },
            )
            .map_err(|error| error.to_string())?;
        let namespace = TicketNamespace::parse(page.ticket_namespace)?;
        if namespace != key.namespace {
            return Err("ticket adapter namespace changed after it was pinned".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs() as i64;
        let tickets = page
            .tickets
            .into_iter()
            .map(|ticket| {
                let ticket_namespace = TicketNamespace::parse(ticket.ticket_namespace)?;
                if ticket_namespace != key.namespace
                    || ticket.status.value != normalized_status(key.status)
                {
                    return Err("ticket adapter returned an out-of-scope ticket".to_owned());
                }
                Ok(ObservedTicket {
                    id: TicketId::parse(ticket.id)?,
                    revision: ticket.revision,
                    status: key.status,
                    title: ticket.title,
                    labels: ticket.labels,
                    created_at: ticket.created_at,
                    observed_at_unix: now,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ExternalTicketPage {
            tickets,
            next_cursor: page.next_cursor,
        })
    }

    fn effect_handlers(&self) -> Vec<&dyn EffectHandler> {
        self.handlers.iter().map(Box::as_ref).collect()
    }
}

fn normalized_status(status: TicketStatus) -> NormalizedTicketStatus {
    match status {
        TicketStatus::Triage => NormalizedTicketStatus::Triage,
        TicketStatus::Backlog => NormalizedTicketStatus::Backlog,
        TicketStatus::Ready => NormalizedTicketStatus::Ready,
        TicketStatus::InProgress => NormalizedTicketStatus::InProgress,
        TicketStatus::InReview => NormalizedTicketStatus::InReview,
        TicketStatus::Done => NormalizedTicketStatus::Done,
        TicketStatus::Canceled => NormalizedTicketStatus::Canceled,
    }
}
