use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use crate::engine::reducer::EffectKind;
use crate::engine::reducer::effect_name;
use crate::store::{ClaimedEffect, ConfigStore, EffectClaimState, EffectIntent, EffectOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectMode {
    Submit,
    Reconcile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsentProof {
    handler_kind: String,
    operation_id: String,
    request_digest: String,
    project_id: String,
    subject_type: String,
    subject_id: String,
    authority: String,
    evidence: String,
}

impl AbsentProof {
    pub fn from_authoritative_lookup(
        handler_kind: EffectKind,
        request: &EffectRequest,
        authority: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Result<Self, String> {
        let authority = authority.into();
        let evidence = evidence.into();
        if authority.trim().is_empty() || evidence.trim().is_empty() {
            return Err("authoritative absence requires a named authority and evidence".into());
        }
        Ok(Self {
            handler_kind: effect_name(&handler_kind).into(),
            operation_id: request.intent.operation_id.clone(),
            request_digest: request.intent.request_digest.clone(),
            project_id: request.intent.project_id.as_str().into(),
            subject_type: request.intent.subject_type.clone(),
            subject_id: request.intent.subject_id.clone(),
            authority,
            evidence,
        })
    }

    pub(crate) fn matches_effect(&self, kind: EffectKind, intent: &EffectIntent) -> bool {
        self.handler_kind == effect_name(&kind)
            && self.operation_id == intent.operation_id
            && self.request_digest == intent.request_digest
            && self.project_id == intent.project_id.as_str()
            && self.subject_type == intent.subject_type
            && self.subject_id == intent.subject_id
            && !self.authority.trim().is_empty()
            && !self.evidence.trim().is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    Applied { receipt: String },
    AuthoritativelyAbsent { proof: AbsentProof },
    Pending { receipt: String },
    Rejected { receipt: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRequest {
    pub intent: EffectIntent,
    pub attempt_count: u32,
    pub created_at_unix: i64,
}

/// Host-owned context for handlers that must persist a domain receipt through
/// the controller's existing database connection. No second ConfigStore may be
/// opened while the foreground controller owns the machine lock.
pub struct EffectContext<'a> {
    pub store: &'a mut ConfigStore,
    pub owner_generation: u64,
    pub now_unix: i64,
}

impl From<ClaimedEffect> for EffectRequest {
    fn from(claimed: ClaimedEffect) -> Self {
        Self {
            intent: claimed.intent,
            attempt_count: claimed.attempt_count,
            created_at_unix: claimed.created_at_unix,
        }
    }
}

/// Host-owned adapter. Agent output must never be deserialized directly into an observation.
pub trait EffectHandler: Send + Sync {
    fn kind(&self) -> EffectKind;

    /// Implementations must enforce their own bounded subprocess/network timeout.
    fn handle(
        &self,
        mode: EffectMode,
        request: &EffectRequest,
        context: &mut EffectContext<'_>,
    ) -> Result<EffectObservation, String>;
}

#[derive(Clone, Copy, Debug)]
pub struct EffectLimits {
    pub max_attempts: u32,
    pub max_age: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
}

impl EffectLimits {
    fn validate(self) -> Result<Self, EffectDispatchError> {
        if self.max_attempts == 0
            || self.max_age.as_secs() == 0
            || self.retry_base.as_secs() == 0
            || self.retry_max.as_secs() == 0
            || self.retry_max < self.retry_base
        {
            return Err(EffectDispatchError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchTick {
    Idle,
    Completed { operation_id: String },
    RetryScheduled { operation_id: String, attempt: u32 },
    WaitingForReconciliation { operation_id: String },
    StoppedAtLimit { operation_id: String },
}

#[derive(Debug)]
pub enum EffectDispatchError {
    InvalidLimits,
    Store(String),
    InvalidAbsenceProof,
    DuplicateHandler(EffectKind),
}

impl std::fmt::Display for EffectDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => {
                f.write_str("effect limits must be positive and retry_max >= retry_base")
            }
            Self::Store(error) => write!(f, "effect store operation failed: {error}"),
            Self::InvalidAbsenceProof => {
                f.write_str("absence proof does not match the immutable effect identity")
            }
            Self::DuplicateHandler(kind) => write!(
                f,
                "more than one handler registered for {}",
                effect_name(kind)
            ),
        }
    }
}

impl std::error::Error for EffectDispatchError {}

pub struct EffectDispatcher;

impl EffectDispatcher {
    /// Claims at most one registered effect. The claim transaction is closed before calling a
    /// handler, so an external operation never runs while SQLite is locked.
    pub fn tick(
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        handlers: &[&dyn EffectHandler],
        limits: EffectLimits,
    ) -> Result<DispatchTick, EffectDispatchError> {
        let limits = limits.validate()?;
        let kinds = registered_kinds(handlers)?;
        if kinds.is_empty() {
            return Ok(DispatchTick::Idle);
        }
        let kind_names = kinds
            .iter()
            .map(|kind| effect_name(kind).to_owned())
            .collect::<Vec<_>>();

        let Some(claimed) = store
            .claim_next_due_effect(owner_generation, now_unix, &kind_names)
            .map_err(EffectDispatchError::Store)?
        else {
            return Ok(DispatchTick::Idle);
        };
        let mode = match claimed.state {
            EffectClaimState::Pending => EffectMode::Submit,
            EffectClaimState::Uncertain => EffectMode::Reconcile,
        };
        Self::run_claim(
            store,
            owner_generation,
            now_unix,
            handlers,
            limits,
            mode,
            claimed,
        )
    }

    fn run_claim(
        store: &mut ConfigStore,
        owner_generation: u64,
        now_unix: i64,
        handlers: &[&dyn EffectHandler],
        limits: EffectLimits,
        mode: EffectMode,
        claimed: ClaimedEffect,
    ) -> Result<DispatchTick, EffectDispatchError> {
        let request = EffectRequest::from(claimed);
        let age = now_unix.saturating_sub(request.created_at_unix).max(0) as u64;
        if mode == EffectMode::Submit
            && (age >= limits.max_age.as_secs() || request.attempt_count > limits.max_attempts)
        {
            store
                .finish_effect(
                    &request.intent.operation_id,
                    owner_generation,
                    EffectOutcome::Failed,
                    Some("{\"error\":\"effect exceeded configured attempt or age limit\"}"),
                )
                .map_err(EffectDispatchError::Store)?;
            return Ok(DispatchTick::StoppedAtLimit {
                operation_id: request.intent.operation_id,
            });
        }
        let handler = handlers
            .iter()
            .find(|handler| effect_name(&handler.kind()) == request.intent.kind)
            .ok_or_else(|| {
                EffectDispatchError::Store("claimed effect kind has no registered handler".into())
            })?;
        let observation = {
            let mut context = EffectContext {
                store,
                owner_generation,
                now_unix,
            };
            handler.handle(mode, &request, &mut context)
        };
        match observation {
            Ok(EffectObservation::Applied { receipt }) => {
                store
                    .finish_effect(
                        &request.intent.operation_id,
                        owner_generation,
                        EffectOutcome::Succeeded,
                        Some(&receipt),
                    )
                    .map_err(EffectDispatchError::Store)?;
                Ok(DispatchTick::Completed {
                    operation_id: request.intent.operation_id,
                })
            }
            Ok(EffectObservation::Rejected { receipt }) => {
                store
                    .finish_effect(
                        &request.intent.operation_id,
                        owner_generation,
                        EffectOutcome::Failed,
                        Some(&receipt),
                    )
                    .map_err(EffectDispatchError::Store)?;
                Ok(DispatchTick::Completed {
                    operation_id: request.intent.operation_id,
                })
            }
            Ok(EffectObservation::Pending { receipt }) => {
                store
                    .defer_effect_reconciliation(
                        &request.intent.operation_id,
                        owner_generation,
                        Some(&receipt),
                        None,
                        now_unix.saturating_add(duration_seconds(retry_delay_for_age(limits, age))),
                    )
                    .map_err(EffectDispatchError::Store)?;
                Ok(DispatchTick::WaitingForReconciliation {
                    operation_id: request.intent.operation_id,
                })
            }
            Err(error) => {
                let diagnostic = matches!(request.intent.kind.as_str(), "start_agent" | "merge")
                    .then(|| bounded_handler_error(&error));
                store
                    .defer_effect_reconciliation(
                        &request.intent.operation_id,
                        owner_generation,
                        None,
                        diagnostic.as_deref(),
                        now_unix.saturating_add(duration_seconds(retry_delay_for_age(limits, age))),
                    )
                    .map_err(EffectDispatchError::Store)?;
                Ok(DispatchTick::WaitingForReconciliation {
                    operation_id: request.intent.operation_id,
                })
            }
            Ok(EffectObservation::AuthoritativelyAbsent { proof }) => {
                if mode != EffectMode::Reconcile
                    || !proof_matches(&proof, handler.kind(), &request.intent)
                {
                    store
                        .defer_effect_reconciliation(
                            &request.intent.operation_id,
                            owner_generation,
                            Some("{\"error\":\"invalid absence proof\"}"),
                            None,
                            now_unix
                                .saturating_add(duration_seconds(retry_delay_for_age(limits, age))),
                        )
                        .map_err(EffectDispatchError::Store)?;
                    return Err(EffectDispatchError::InvalidAbsenceProof);
                }
                let proof_json = serde_json::to_string(&proof)
                    .map_err(|error| EffectDispatchError::Store(error.to_string()))?;
                if age >= limits.max_age.as_secs() || request.attempt_count >= limits.max_attempts {
                    store
                        .finish_effect(
                            &request.intent.operation_id,
                            owner_generation,
                            EffectOutcome::Failed,
                            Some(&proof_json),
                        )
                        .map_err(EffectDispatchError::Store)?;
                    return Ok(DispatchTick::StoppedAtLimit {
                        operation_id: request.intent.operation_id,
                    });
                }
                let next_attempt =
                    now_unix.saturating_add(duration_seconds(retry_delay_for_age(limits, age)));
                store
                    .retry_effect_after_absence(
                        &request.intent.operation_id,
                        owner_generation,
                        &request.intent.request_digest,
                        &proof_json,
                        next_attempt,
                    )
                    .map_err(EffectDispatchError::Store)?;
                Ok(DispatchTick::RetryScheduled {
                    operation_id: request.intent.operation_id,
                    attempt: request.attempt_count,
                })
            }
        }
    }
}

fn registered_kinds(
    handlers: &[&dyn EffectHandler],
) -> Result<Vec<EffectKind>, EffectDispatchError> {
    let mut kinds = handlers
        .iter()
        .map(|handler| handler.kind())
        .collect::<Vec<_>>();
    kinds.sort_unstable();
    if let Some(duplicate) = kinds.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(EffectDispatchError::DuplicateHandler(duplicate[0]));
    }
    Ok(kinds)
}

fn proof_matches(proof: &AbsentProof, kind: EffectKind, intent: &EffectIntent) -> bool {
    proof.handler_kind == effect_name(&kind)
        && proof.operation_id == intent.operation_id
        && proof.request_digest == intent.request_digest
        && proof.project_id == intent.project_id.as_str()
        && proof.subject_type == intent.subject_type
        && proof.subject_id == intent.subject_id
        && !proof.authority.trim().is_empty()
        && !proof.evidence.trim().is_empty()
}

fn retry_delay_for_age(limits: EffectLimits, age_secs: u64) -> Duration {
    let base = limits.retry_base.as_secs();
    let ratio = age_secs.checked_div(base).unwrap_or(0).max(1);
    let exponent = (u64::BITS - 1 - ratio.leading_zeros()).min(30);
    let multiplier = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
    limits
        .retry_base
        .saturating_mul(multiplier)
        .min(limits.retry_max)
}

fn duration_seconds(duration: Duration) -> i64 {
    duration.as_secs().min(i64::MAX as u64) as i64
}

fn bounded_handler_error(error: &str) -> String {
    let mut diagnostic = String::new();
    for character in error.chars() {
        if diagnostic.len() + character.len_utf8() > 512 {
            break;
        }
        diagnostic.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::bounded_handler_error;

    #[test]
    fn handler_error_diagnostic_is_bounded_and_single_line() {
        let error = format!("{}\nend", "x".repeat(600));
        let diagnostic = bounded_handler_error(&error);
        assert_eq!(diagnostic.len(), 512);
        assert!(!diagnostic.chars().any(char::is_control));
    }
}
