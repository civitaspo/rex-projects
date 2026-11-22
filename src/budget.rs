//! Pure budget resolution and accounting for a Ticket.

use std::time::Duration;

use anyhow::Result;

use crate::{
    domain::{BudgetKind, Event},
    playbook::{BudgetSpec, TicketPreparation},
    policy::PolicyBudgets,
    store::StoredEvent,
};

/// The strictest limit declared by the Ticket's Playbook and Project Policy.
/// `None` means that the corresponding resource is unbounded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectiveBudget {
    pub helpers: Option<u32>,
    pub minutes: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct BudgetRemaining {
    pub helpers: Option<u32>,
    pub minutes: Option<u64>,
}

/// Calculate current remaining budget from the immutable preparation snapshot
/// and event history. Helper usage is cumulative; verifier Agents are internal
/// to the verification protocol and do not consume helper budget.
pub fn remaining(
    preparation: Option<&TicketPreparation>,
    events: &[StoredEvent],
) -> Result<BudgetRemaining> {
    let spec = preparation
        .and_then(|p| p.playbook.as_ref())
        .and_then(|p| p.spec.as_ref());
    let effective = effective(
        spec.and_then(|s| s.budgets.as_ref()),
        preparation
            .and_then(|p| p.policy.as_ref())
            .map(|p| &p.budgets),
    );
    let verifier_role = spec
        .and_then(|s| s.verification.as_ref())
        .and_then(|v| v.verifier.as_ref())
        .map(|v| v.role.as_str());
    let helpers_used = events.iter().filter(|e| matches!(&e.event, Event::AgentCreated { role, .. } if role != "coordinator" && Some(role.as_str()) != verifier_role)).count() as u32;
    let helpers = effective
        .helpers
        .map(|limit| limit.saturating_sub(helpers_used));
    let extensions = events
        .iter()
        .filter(|e| {
            matches!(
                e.event,
                Event::BudgetExtended {
                    budget: BudgetKind::Minutes,
                    ..
                }
            )
        })
        .count() as u32;
    let minutes = match effective.minutes {
        Some(limit) => {
            let dispatch = events
                .iter()
                .find(|e| matches!(e.event, Event::TicketDispatched { .. }))
                .and_then(|e| chrono::DateTime::parse_from_rfc3339(&e.at).ok());
            let elapsed = dispatch
                .map(|at| {
                    chrono::Utc::now()
                        .signed_duration_since(at)
                        .to_std()
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let left = remaining_time(Some(limit), extensions, elapsed)?
                .unwrap_or_default()
                .as_secs();
            Some(left.div_ceil(60))
        }
        None => None,
    };
    Ok(BudgetRemaining { helpers, minutes })
}

pub fn exceeded_question(limit: u32, round: u32) -> String {
    format!("Budget minutes exceeded ({limit}). Continue? (extension {round})")
}

/// Resolve the effective budget. A limit declared by only one source applies;
/// when both sources declare it, the smaller value wins.
pub fn effective(playbook: Option<&BudgetSpec>, policy: Option<&PolicyBudgets>) -> EffectiveBudget {
    EffectiveBudget {
        helpers: stricter(
            playbook.and_then(|budget| budget.helpers),
            policy.and_then(|budget| budget.helpers),
        ),
        minutes: stricter(
            playbook.and_then(|budget| budget.minutes),
            policy.and_then(|budget| budget.minutes),
        ),
    }
}

fn stricter(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(limit), None) | (None, Some(limit)) => Some(limit),
        (None, None) => None,
    }
}

/// Whether another helper may be created under this limit.
pub fn may_spawn_helper(limit: Option<u32>, already_spawned: u32) -> bool {
    limit.is_none_or(|limit| already_spawned < limit)
}

/// Return the elapsed-time allowance after `extensions` answers to budget
/// questions. Each answer adds one copy of the original minute allowance.
pub fn time_allowance(minutes: Option<u32>, extensions: u32) -> Result<Option<Duration>> {
    let Some(minutes) = minutes else {
        return Ok(None);
    };
    let multiplier = u64::from(extensions)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("budget extension count overflow"))?;
    let seconds = u64::from(minutes)
        .checked_mul(60)
        .and_then(|seconds| seconds.checked_mul(multiplier))
        .ok_or_else(|| anyhow::anyhow!("time budget overflow"))?;
    Ok(Some(Duration::from_secs(seconds)))
}

/// Return how much time remains. Zero means the limit is reached or exceeded;
/// callers can use [`time_exceeded`] to distinguish equality from overrun.
pub fn remaining_time(
    minutes: Option<u32>,
    extensions: u32,
    elapsed: Duration,
) -> Result<Option<Duration>> {
    let Some(allowance) = time_allowance(minutes, extensions)? else {
        return Ok(None);
    };
    Ok(Some(allowance.saturating_sub(elapsed)))
}

/// The plan says a Ticket exceeds its budget only after elapsed time is
/// strictly greater than the allowance. An unbounded Ticket never exceeds it.
pub fn time_exceeded(minutes: Option<u32>, extensions: u32, elapsed: Duration) -> Result<bool> {
    let Some(allowance) = time_allowance(minutes, extensions)? else {
        return Ok(false);
    };
    Ok(elapsed > allowance)
}

/// Validate an extension before recording it, preventing the counter from
/// wrapping and making a previously exceeded budget appear smaller.
pub fn next_extension_count(extensions: u32) -> Result<u32> {
    extensions
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("budget extension count overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_each_limit_to_the_stricter_declared_value() {
        let playbook = BudgetSpec {
            helpers: Some(6),
            minutes: Some(240),
        };
        let policy = PolicyBudgets {
            helpers: Some(8),
            minutes: Some(120),
        };
        assert_eq!(
            effective(Some(&playbook), Some(&policy)),
            EffectiveBudget {
                helpers: Some(6),
                minutes: Some(120),
            }
        );
    }

    #[test]
    fn a_limit_from_either_source_applies_and_missing_limits_are_unbounded() {
        let playbook = BudgetSpec {
            helpers: Some(0),
            minutes: None,
        };
        assert_eq!(
            effective(Some(&playbook), None),
            EffectiveBudget {
                helpers: Some(0),
                minutes: None,
            }
        );
        assert_eq!(
            effective(None, None),
            EffectiveBudget {
                helpers: None,
                minutes: None,
            }
        );
        assert_eq!(
            effective(
                None,
                Some(&PolicyBudgets {
                    helpers: None,
                    minutes: Some(5),
                })
            ),
            EffectiveBudget {
                helpers: None,
                minutes: Some(5),
            }
        );
    }

    #[test]
    fn helper_limit_refuses_only_after_reaching_the_count() {
        assert!(may_spawn_helper(None, u32::MAX));
        assert!(may_spawn_helper(Some(2), 1));
        assert!(!may_spawn_helper(Some(2), 2));
        assert!(!may_spawn_helper(Some(0), 0));
    }

    #[test]
    fn each_extension_adds_one_original_allowance() {
        let minute = Duration::from_secs(60);
        assert_eq!(time_allowance(Some(10), 0).unwrap(), Some(10 * minute));
        assert_eq!(time_allowance(Some(10), 2).unwrap(), Some(30 * minute));
        assert_eq!(
            remaining_time(Some(10), 1, 15 * minute).unwrap(),
            Some(5 * minute)
        );
    }

    #[test]
    fn distinguishes_at_limit_from_overrun_and_keeps_unbounded_tickets_unbounded() {
        let limit = Duration::from_secs(60);
        assert_eq!(
            remaining_time(Some(1), 0, limit).unwrap(),
            Some(Duration::ZERO)
        );
        assert!(!time_exceeded(Some(1), 0, limit).unwrap());
        assert!(time_exceeded(Some(1), 0, limit + Duration::from_nanos(1)).unwrap());
        assert_eq!(remaining_time(None, u32::MAX, limit).unwrap(), None);
        assert!(!time_exceeded(None, u32::MAX, limit).unwrap());
    }

    #[test]
    fn rejects_extension_counter_overflow() {
        assert_eq!(next_extension_count(3).unwrap(), 4);
        assert!(next_extension_count(u32::MAX).is_err());
        assert!(time_allowance(Some(u32::MAX), 0).is_ok());
        assert!(time_allowance(Some(u32::MAX), u32::MAX).is_err());
    }
}
