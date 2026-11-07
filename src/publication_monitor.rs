//! Comparison of host-owned publication expectations with fresh remote observations.

use serde::{Deserialize, Serialize};

use crate::delivery_forge::{ObservationCapability, ObservedPullRequest};
use crate::delivery_runtime::RepositoryPublicationObservation;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPublicationState {
    pub remote_head: Option<String>,
    pub pull_requests: Vec<ObservedPullRequest>,
}

/// Only intents already in the durable effects journal may explain an observation. A handler
/// passes these values after reconciling pending effects and checking confirmed receipts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconciledHostEffects {
    pub pending_push_head: Option<String>,
    pub confirmed_push_head: Option<String>,
    pub pending_pull_request: Option<ObservedPullRequest>,
    pub confirmed_pull_request: Option<ObservedPullRequest>,
    pub pending_merge_number: Option<u64>,
    pub confirmed_merge_number: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationClassification {
    Unchanged,
    HostEffectConfirmed,
    UnknownCapability,
    Unexpected { reason: String },
}

pub fn classify(
    expected: &ExpectedPublicationState,
    observed: &RepositoryPublicationObservation,
    host: &ReconciledHostEffects,
) -> PublicationClassification {
    let ObservationCapability::Known(current_prs) = &observed.pull_requests else {
        return PublicationClassification::UnknownCapability;
    };
    if expected
        .pull_requests
        .iter()
        .any(|pull| !matches!(&pull.timeline, ObservationCapability::Known(_)))
        || current_prs
            .iter()
            .any(|pull| !matches!(&pull.timeline, ObservationCapability::Known(_)))
    {
        return PublicationClassification::UnknownCapability;
    }

    let branch_changed = observed.remote_head != expected.remote_head;
    let allowed_head = host
        .pending_push_head
        .as_ref()
        .or(host.confirmed_push_head.as_ref());
    if branch_changed && allowed_head != observed.remote_head.as_ref() {
        return PublicationClassification::Unexpected {
            reason: "owned remote branch changed outside a reconciled host push".into(),
        };
    }

    let merge_numbers = current_prs
        .iter()
        .filter(|pull| {
            pull.merged
                && expected
                    .pull_requests
                    .iter()
                    .find(|prior| prior.number == pull.number)
                    .is_none_or(|prior| !prior.merged)
        })
        .map(|pull| pull.number)
        .collect::<Vec<_>>();
    for prior in &expected.pull_requests {
        let Some(current) = current_prs.iter().find(|pull| pull.number == prior.number) else {
            return PublicationClassification::Unexpected {
                reason: "a previously observed pull request disappeared".into(),
            };
        };
        if prior.merged != current.merged {
            let allowed = host.pending_merge_number == Some(current.number)
                || host.confirmed_merge_number == Some(current.number);
            if !allowed {
                return PublicationClassification::Unexpected {
                    reason: "pull request merge state changed outside a reconciled host merge"
                        .into(),
                };
            }
        }
        let added_comments = timeline_additions(prior, current);
        if !added_comments.is_empty() {
            return PublicationClassification::Unexpected {
                reason: "pull request timeline gained an uncorrelated event or comment".into(),
            };
        }
        if current.source_head != prior.source_head
            || current.title != prior.title
            || current.body != prior.body
            || current.base_branch != prior.base_branch
            || current.source_branch != prior.source_branch
            || (current.state != prior.state
                && !(current.merged
                    && (host.pending_merge_number == Some(current.number)
                        || host.confirmed_merge_number == Some(current.number))))
        {
            let allowed = host.pending_pull_request.as_ref() == Some(current)
                || host.confirmed_pull_request.as_ref() == Some(current);
            if !allowed {
                return PublicationClassification::Unexpected {
                    reason: "pull request changed outside a reconciled host publication effect"
                        .into(),
                };
            }
        }
    }
    for current in current_prs {
        if !expected
            .pull_requests
            .iter()
            .any(|prior| prior.number == current.number)
            && host.pending_pull_request.as_ref() != Some(current)
            && host.confirmed_pull_request.as_ref() != Some(current)
        {
            return PublicationClassification::Unexpected {
                reason: "an uncorrelated pull request appeared for the owned branch".into(),
            };
        }
    }
    if !merge_numbers.is_empty()
        && !merge_numbers.iter().any(|number| {
            host.pending_merge_number == Some(*number)
                || host.confirmed_merge_number == Some(*number)
        })
    {
        return PublicationClassification::Unexpected {
            reason: "an actual pull request merge was observed without a matching host effect"
                .into(),
        };
    }

    if branch_changed
        || expected.pull_requests != *current_prs
        || expected.remote_head != observed.remote_head
    {
        PublicationClassification::HostEffectConfirmed
    } else {
        PublicationClassification::Unchanged
    }
}

fn timeline_additions(
    prior: &ObservedPullRequest,
    current: &ObservedPullRequest,
) -> Vec<crate::delivery_forge::ObservedTimelineEntry> {
    match (&prior.timeline, &current.timeline) {
        (ObservationCapability::Known(before), ObservationCapability::Known(after)) => after
            .iter()
            .filter(|entry| !before.contains(entry))
            .cloned()
            .collect(),
        // If comments were not fully observable before, never claim the current timeline proves
        // that no command arrived during that gap.
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_forge::{ObservationCapability, ObservedTimelineEntry};

    fn pull(
        number: u64,
        merged: bool,
        comments: Vec<ObservedTimelineEntry>,
    ) -> ObservedPullRequest {
        ObservedPullRequest {
            number,
            node_id: format!("PR_{number}"),
            url: format!("https://github.com/acme/demo/pull/{number}"),
            state: if merged { "closed" } else { "open" }.into(),
            merged,
            merged_at: merged.then(|| "2026-11-07T00:00:00Z".into()),
            source_branch: "rex-projects/work".into(),
            source_head: "a".repeat(40),
            base_branch: "main".into(),
            base_sha: "b".repeat(40),
            title: "Change".into(),
            body: Some("Body".into()),
            timeline: ObservationCapability::Known(comments),
        }
    }

    fn comment(id: &str, body: &str) -> ObservedTimelineEntry {
        ObservedTimelineEntry {
            event: "issue_comment".into(),
            reference: id.into(),
            actor: Some("external-user".into()),
            created_at: Some("2026-11-07T00:00:00Z".into()),
            body: Some(body.into()),
        }
    }

    fn expected(pulls: Vec<ObservedPullRequest>) -> ExpectedPublicationState {
        ExpectedPublicationState {
            remote_head: Some("a".repeat(40)),
            pull_requests: pulls,
        }
    }

    fn observed(
        head: Option<String>,
        pulls: ObservationCapability<Vec<ObservedPullRequest>>,
    ) -> RepositoryPublicationObservation {
        RepositoryPublicationObservation {
            remote_head: head,
            pull_requests: pulls,
        }
    }

    #[test]
    fn reconciled_lost_push_reply_is_not_an_irregularity() {
        let result = classify(
            &expected(vec![]),
            &observed(Some("b".repeat(40)), ObservationCapability::Known(vec![])),
            &ReconciledHostEffects {
                pending_push_head: Some("b".repeat(40)),
                ..ReconciledHostEffects::default()
            },
        );
        assert_eq!(result, PublicationClassification::HostEffectConfirmed);
    }

    #[test]
    fn unexpected_push_creates_irregularity() {
        let result = classify(
            &expected(vec![]),
            &observed(Some("b".repeat(40)), ObservationCapability::Known(vec![])),
            &ReconciledHostEffects::default(),
        );
        assert!(matches!(
            result,
            PublicationClassification::Unexpected { .. }
        ));
    }

    #[test]
    fn uncorrelated_pr_creation_is_an_irregularity() {
        let result = classify(
            &expected(vec![]),
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![pull(7, false, vec![])]),
            ),
            &ReconciledHostEffects::default(),
        );
        assert!(matches!(
            result,
            PublicationClassification::Unexpected { .. }
        ));
    }

    #[test]
    fn uncorrelated_timeline_comment_is_an_irregularity() {
        let before = pull(7, false, vec![]);
        let after = pull(7, false, vec![comment("comment-1", "/merge")]);
        let result = classify(
            &expected(vec![before]),
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![after]),
            ),
            &ReconciledHostEffects::default(),
        );
        assert!(matches!(
            result,
            PublicationClassification::Unexpected { .. }
        ));
    }

    #[test]
    fn external_actual_merge_is_an_irregularity() {
        let result = classify(
            &expected(vec![pull(7, false, vec![])]),
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![pull(7, true, vec![])]),
            ),
            &ReconciledHostEffects::default(),
        );
        assert!(matches!(
            result,
            PublicationClassification::Unexpected { .. }
        ));
    }

    #[test]
    fn lost_merge_reply_reconciles_matching_pending_effect() {
        let result = classify(
            &expected(vec![pull(7, false, vec![])]),
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![pull(7, true, vec![])]),
            ),
            &ReconciledHostEffects {
                pending_merge_number: Some(7),
                ..ReconciledHostEffects::default()
            },
        );
        assert_eq!(result, PublicationClassification::HostEffectConfirmed);
    }

    #[test]
    fn unknown_forge_observation_never_proves_absence() {
        let result = classify(
            &expected(vec![]),
            &observed(Some("a".repeat(40)), ObservationCapability::Unknown),
            &ReconciledHostEffects::default(),
        );
        assert_eq!(result, PublicationClassification::UnknownCapability);
    }

    #[test]
    fn unknown_timeline_never_proves_no_comment() {
        let result = classify(
            &expected(vec![ObservedPullRequest {
                timeline: ObservationCapability::Unknown,
                ..pull(7, false, vec![])
            }]),
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![pull(7, false, vec![])]),
            ),
            &ReconciledHostEffects::default(),
        );
        assert_eq!(result, PublicationClassification::UnknownCapability);
    }

    #[test]
    fn exact_host_pr_creation_reconciles_lost_reply() {
        let expected_state = expected(vec![]);
        let published = pull(7, false, vec![]);
        let result = classify(
            &expected_state,
            &observed(
                Some("a".repeat(40)),
                ObservationCapability::Known(vec![published.clone()]),
            ),
            &ReconciledHostEffects {
                pending_pull_request: Some(published),
                ..ReconciledHostEffects::default()
            },
        );
        assert_eq!(result, PublicationClassification::HostEffectConfirmed);
    }
}
