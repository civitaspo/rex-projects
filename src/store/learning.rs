//! Durable learning and knowledge-publication records owned by the machine controller.
//! Migration 10 is intentionally standalone until controller migrations 7–9 are integrated.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use super::{ConfigStore, validate_active_generation};
use crate::domain::ids::{Digest, HumanRequestId, OperationId, ProfileId, ProjectId, TicketRunId};
use crate::human_runtime::HumanRuntimeRequest;
use crate::knowledge::{
    DEFAULT_MAX_ARTICLE_BYTES, PostmortemInput, PublicationManifest, validate_postmortem_input,
};
use crate::learning::{
    CandidateLedger, CandidateRevision, CandidateStatus, ProfilePackage, ProfilePublicationReceipt,
    ProfilePublicationStatus, TrialEvidence, TrialObservation, evaluate_trials,
    validated_promotion_claims,
};
use crate::learning_trials::{
    ProfileTrialAuthorization, ProfileTrialLaunchCapsule, ProfileTrialRunReceipt, TrialSide,
    accept_profile_trial_approval, bind_profile_trial_human_request,
};

const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRIALS: usize = 10;
const MAX_SUPERVISOR_KNOWLEDGE_ITEMS: usize = 12;
const MAX_SUPERVISOR_CANDIDATES: usize = 20;
const MAX_SUPERVISOR_CONTEXT_BYTES: usize = 256 * 1024;
const MAX_SUPERVISOR_TARGET_BYTES: usize = 64 * 1024;
const MAX_SUPERVISOR_BATCH_BYTES: usize = 768 * 1024;
const LEARNING_BATCH_TRIGGER_FINDINGS: usize = 5;
const LEARNING_BATCH_MAX_FINDINGS: usize = 20;

struct TopicSourceDbRow {
    ticket_run_id: String,
    publication_digest: String,
    ordinal: u32,
    finding_text: String,
    request_digest: String,
    request_json: String,
    manifest_json: String,
    manifest_digest: String,
}

struct SupervisorTopicPublicationDbRow {
    project_id: String,
    topic_key: String,
    destination_root: String,
    intent_json: String,
    receipt_json: Option<String>,
    receipt_digest: Option<String>,
}

struct PublishedTopicVersionDbRow {
    operation_id: String,
    intent_json: String,
    intent_digest: String,
    receipt_json: String,
    receipt_digest: String,
    destination_root: String,
    revision: i64,
    prior_content_digest: Option<String>,
}

fn sorted_source_ids(sources: &[crate::topic::TopicSourceProof]) -> Vec<Digest> {
    let mut ids = sources
        .iter()
        .map(|source| source.finding_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn sorted_source_publication_digests(sources: &[crate::topic::TopicSourceProof]) -> Vec<Digest> {
    let mut digests = sources
        .iter()
        .map(|source| source.publication_digest.clone())
        .collect::<Vec<_>>();
    digests.sort();
    digests
}

fn applied_config_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    revision: u64,
    digest: &str,
) -> Result<crate::config::AppliedConfig, String> {
    let row: (String, String, String, String) = tx.query_row(
        "SELECT p.config_source,s.effective_config_json,s.source_manifest_json,s.digest FROM projects p JOIN config_snapshots s ON s.source_identity=p.config_source AND s.revision=p.config_revision WHERE p.project_id=?1 AND p.config_revision=?2 AND p.config_digest=?3",
        params![project.as_str(), revision, digest],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).map_err(|error| format!("issued Project config snapshot is unavailable: {error}"))?;
    let (_source_identity, effective_json, manifest_json, stored_digest) = row;
    if stored_digest != digest {
        return Err("stored Project config digest differs from issued batch".into());
    }
    let effective: super::EffectiveConfig =
        crate::protocol::parse_unique(effective_json.as_bytes())?;
    let source_files: Vec<crate::config::SourceFile> =
        crate::protocol::parse_unique(manifest_json.as_bytes())?;
    for source in source_files
        .iter()
        .filter(|source| matches!(source.kind, crate::config::SourceKind::File))
    {
        let bytes = source.contents.as_bytes();
        if bytes.len() as u64 != source.bytes
            || format!("{:x}", Sha256::digest(bytes)) != source.sha256.as_str()
        {
            return Err(format!(
                "stored applied source `{}` has invalid bytes",
                source.path
            ));
        }
    }
    let calculated =
        crate::config::digest_manifest(&effective.config, &effective.profiles, &source_files)?;
    if calculated != digest {
        return Err("stored applied config snapshot does not match its digest".into());
    }
    Ok(crate::config::AppliedConfig {
        config: effective.config,
        profiles: effective.profiles,
        source_root: effective.source_root,
        source_files,
        digest: Digest::parse(stored_digest)?,
    })
}

fn profile_source_digest(
    snapshot: &crate::config::AppliedConfig,
    profile_id: &ProfileId,
) -> Result<Digest, String> {
    let profile = snapshot
        .profiles
        .get(profile_id)
        .ok_or("configured profile is missing")?;
    crate::store::agent_profile_digest(profile)
}

fn supervisor_candidate_targets(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
) -> Result<(Vec<crate::learning::SupervisorCandidateTarget>, usize), String> {
    let (revision, digest): (u64, String) = tx
        .query_row(
            "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
            [project.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let snapshot = applied_config_in_transaction(tx, project, revision, &digest)?;
    let project_config = snapshot
        .config
        .projects
        .get(project)
        .ok_or("Project config is missing")?;
    let mut bindings = crate::config::effective_project_roles(project, &snapshot.config.projects)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    for operation in &project_config.operation_matches {
        if let Some(recipe) = snapshot.config.operation_recipes.get(&operation.recipe) {
            bindings.extend(
                recipe
                    .roles
                    .iter()
                    .map(|(role, profile)| (*role, profile.clone())),
            );
        }
    }
    let repositories = project_config
        .repositories
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut targets = Vec::new();
    let mut omitted = 0;
    let catalog_bytes = |targets: &[crate::learning::SupervisorCandidateTarget]| {
        serde_json::to_vec(targets)
            .map(|bytes| bytes.len())
            .map_err(|error| error.to_string())
    };
    for (role, profile_id) in bindings {
        let profile = snapshot
            .profiles
            .get(&profile_id)
            .ok_or("configured profile is missing")?;
        let profile_digest = profile_source_digest(&snapshot, &profile_id)?;
        let logical_root = std::path::Path::new(&snapshot.source_root)
            .join("profiles")
            .join(profile_id.as_str());
        let canonical_root = snapshot
            .source_files
            .iter()
            .find(|source| {
                matches!(source.kind, crate::config::SourceKind::Directory)
                    && std::path::Path::new(&source.path) == logical_root
            })
            .map(|source| std::path::PathBuf::from(&source.canonical_path));
        let learned_guidance = profile.learned_guidance.as_ref().and_then(|learned| {
            let path = canonical_root.as_ref()?.join(&learned.file);
            snapshot
                .source_files
                .iter()
                .find(|source| {
                    matches!(source.kind, crate::config::SourceKind::File)
                        && std::path::Path::new(&source.path) == path
                })
                .map(|source| source.contents.clone())
        });
        targets.push(crate::learning::SupervisorCandidateTarget {
            role,
            profile_id,
            profile_digest,
            description: profile.description.clone(),
            learned_guidance,
            omitted_description_bytes: 0,
            omitted_learned_guidance_bytes: 0,
            repository_ids: repositories.clone(),
        });
        if catalog_bytes(&targets)? > MAX_SUPERVISOR_TARGET_BYTES {
            let target = targets.last_mut().expect("just appended a target");
            target.omitted_learned_guidance_bytes =
                target.learned_guidance.take().map_or(0, |text| text.len());
        }
        if catalog_bytes(&targets)? > MAX_SUPERVISOR_TARGET_BYTES {
            let target = targets.last_mut().expect("just appended a target");
            target.omitted_description_bytes =
                target.description.take().map_or(0, |text| text.len());
        }
        if catalog_bytes(&targets)? > MAX_SUPERVISOR_TARGET_BYTES {
            targets.pop();
            omitted += 1;
        }
    }
    Ok((targets, omitted))
}

fn resolve_topic_source(
    tx: &rusqlite::Transaction<'_>,
    project_id: &ProjectId,
    finding_id: &Digest,
) -> Result<Option<crate::topic::TopicSourceProof>, String> {
    let row: Option<TopicSourceDbRow> = tx
        .query_row(
            "SELECT f.ticket_run_id,f.publication_digest,f.ordinal,f.finding_text,p.request_digest,p.request_json,p.manifest_json,p.manifest_digest FROM learning_findings f JOIN knowledge_publications p ON p.project_id=f.project_id AND p.ticket_run_id=f.ticket_run_id AND p.state='published' WHERE f.finding_id=?1 AND f.project_id=?2 AND p.manifest_digest=f.publication_digest",
            params![finding_id.as_str(), project_id.as_str()],
            |row| Ok(TopicSourceDbRow { ticket_run_id: row.get(0)?, publication_digest: row.get(1)?, ordinal: row.get(2)?, finding_text: row.get(3)?, request_digest: row.get(4)?, request_json: row.get(5)?, manifest_json: row.get(6)?, manifest_digest: row.get(7)? }),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(row) = row else {
        return Ok(None);
    };
    verify_digest(&row.request_json, &Digest::parse(row.request_digest)?)?;
    let input: PostmortemInput = crate::protocol::parse_unique(row.request_json.as_bytes())?;
    validate_postmortem_input(&input).map_err(|error| error.to_string())?;
    let manifest: PublicationManifest =
        crate::protocol::parse_unique(row.manifest_json.as_bytes())?;
    let manifest_digest = Digest::parse(row.manifest_digest)?;
    let calculated = Digest::parse(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&manifest).map_err(|error| error.to_string())?)
    ))?;
    let run_id = TicketRunId::parse(row.ticket_run_id.clone())?;
    let publication_digest = Digest::parse(row.publication_digest)?;
    let expected_path = format!(
        "projects/{}/postmortems/{:x}.md",
        project_id,
        Sha256::digest(run_id.as_str().as_bytes())
    );
    if input.project_id != *project_id
        || input.ticket_run_id != run_id
        || manifest.project_id != *project_id
        || manifest.ticket_run_id != run_id
        || manifest.operation_id != input.operation_id
        || manifest.relative_path != expected_path
        || manifest_digest != publication_digest
        || calculated != manifest_digest
        || input.findings.get(row.ordinal as usize) != Some(&row.finding_text)
        || learning_finding_id(&publication_digest, row.ordinal, &row.finding_text)? != *finding_id
    {
        return Err("published Supervisor Finding provenance is invalid".into());
    }
    Ok(Some(crate::topic::TopicSourceProof {
        finding_id: finding_id.clone(),
        publication_digest,
        ordinal: row.ordinal,
        ticket_run_id: row.ticket_run_id,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LearningFinding {
    pub id: Digest,
    pub ticket_run_id: TicketRunId,
    pub publication_digest: Digest,
    pub ordinal: u32,
    pub text: String,
    pub source_digests: Vec<Digest>,
}

fn learning_finding_id(publication: &Digest, ordinal: u32, text: &str) -> Result<Digest, String> {
    let mut hash = Sha256::new();
    for part in [
        b"rex-supervisor-finding-v1".as_slice(),
        publication.as_str().as_bytes(),
        &ordinal.to_be_bytes(),
        text.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Digest::parse(format!("{:x}", hash.finalize()))
}

fn validate_learning_run_owner(
    connection: &rusqlite::Connection,
    binding: &crate::engine::orchestration::RoleResultBinding,
    terminal: &crate::store::agent_results::VerifiedAgentTerminal,
) -> Result<crate::launch::AgentLaunchAuthority, String> {
    let (authority_json, stored_digest): (String, String) = connection
        .query_row(
            "SELECT authority_json,authority_digest FROM agent_launch_authority WHERE agent_run_id=?1",
            [binding.agent_run_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "learning result has no immutable launch authority")?;
    let authority: crate::launch::AgentLaunchAuthority =
        crate::protocol::parse_unique(authority_json.as_bytes())?;
    authority.validate()?;
    let authority_digest = authority.digest()?;
    if stored_digest != authority_digest.as_str()
        || authority.agent_run_id != binding.agent_run_id
        || authority.project_id != binding.project_id
        || authority.role != crate::domain::types::Role::Supervisor
        || authority.role_session_id != binding.role_session_id.as_str()
        || authority.config_revision != binding.config_revision
        || authority.config_digest.as_str() != binding.config_digest.as_str()
        || authority.run_epoch != binding.run_epoch
        || authority.controller_generation != binding.controller_generation
    {
        return Err(
            "learning result binding differs from immutable Supervisor launch authority".into(),
        );
    }
    if terminal.agent_run_id() != &binding.agent_run_id
        || terminal.project_id() != &binding.project_id
        || terminal.controller_generation() != authority.controller_generation
        || terminal.authority_digest() != &authority_digest
    {
        return Err(
            "verified learning terminal differs from immutable Supervisor launch authority".into(),
        );
    }
    Ok(authority)
}

fn supervisor_learning_snapshot_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    now_utc: &str,
    knowledge_limit: usize,
    topic_destination_root: Option<&std::path::Path>,
) -> Result<ProjectSupervisorMaintenance, String> {
    let mut ledger = CandidateLedger::default();
    let mut revisions_stmt = tx.prepare("SELECT revision_json FROM learning_candidates WHERE project_id=?1 ORDER BY created_at_unix,candidate_id,digest").map_err(|e|e.to_string())?;
    let rows = revisions_stmt
        .query_map([project.as_str()], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    for row in rows {
        ledger.revisions.push(crate::protocol::parse_unique(
            row.map_err(|e| e.to_string())?.as_bytes(),
        )?);
    }
    drop(revisions_stmt);
    let mut pinned_candidates = BTreeSet::new();
    for revision in ledger
        .revisions
        .iter()
        .filter(|revision| revision.status == CandidateStatus::Proposed)
    {
        if candidate_revision_is_pinned(tx, project, &revision.candidate_id, &revision.digest)? {
            pinned_candidates.insert((revision.candidate_id.clone(), revision.digest.clone()));
        }
    }
    let expired_candidates = ledger
        .expire_due_except(now_utc, &pinned_candidates)
        .map_err(|e| e.to_string())?;
    for revision in ledger
        .revisions
        .iter()
        .filter(|r| r.status == CandidateStatus::Expired)
    {
        set_candidate_revision_status(
            tx,
            project,
            &revision.candidate_id,
            &revision.digest,
            CandidateStatus::Expired,
        )?;
    }
    let mut knowledge_stmt=tx.prepare("SELECT ticket_run_id,request_digest,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE project_id=?1 AND state='published' ORDER BY created_at_unix DESC,ticket_run_id DESC LIMIT ?2").map_err(|e|e.to_string())?;
    let knowledge_rows = knowledge_stmt
        .query_map(params![project.as_str(), knowledge_limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut knowledge = Vec::new();
    for row in knowledge_rows {
        let (run_id, request_digest, request_json, manifest_json, digest) =
            row.map_err(|e| e.to_string())?;
        verify_digest(&request_json, &Digest::parse(request_digest)?)?;
        let input: PostmortemInput = crate::protocol::parse_unique(request_json.as_bytes())?;
        validate_postmortem_input(&input).map_err(|e| e.to_string())?;
        let manifest: PublicationManifest =
            crate::protocol::parse_unique(manifest_json.as_bytes())?;
        let manifest_digest = Digest::parse(digest)?;
        if manifest.project_id != *project
            || manifest.ticket_run_id.as_str() != run_id
            || manifest.operation_id != input.operation_id
            || input.project_id != *project
            || input.ticket_run_id != manifest.ticket_run_id
            || manifest_digest.as_str()
                != format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
                )
                .as_str()
        {
            return Err("stored Supervisor knowledge publication has invalid provenance".into());
        }
        knowledge.push(SupervisorKnowledgeEntry {
            ticket_run_id: manifest.ticket_run_id,
            generated_at: input.generated_at,
            title: input.title,
            summary: input.summary,
            findings: input.findings,
            source_digests: manifest.source_digests,
        });
    }
    drop(knowledge_stmt);
    if topic_destination_root.is_some_and(|root| !root.is_absolute()) {
        return Err("Supervisor Topic destination root must be absolute".into());
    }
    let topic_destination_root =
        topic_destination_root.map(|root| root.to_string_lossy().into_owned());
    let total_published_topics: usize = tx.query_row(
        "SELECT COUNT(DISTINCT topic_key) FROM supervisor_topic_publications WHERE project_id=?1 AND state='published' AND destination_root=?2",
        params![project.as_str(), topic_destination_root.as_deref()],
        |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    let mut topic_stmt = tx.prepare(
        "SELECT p.operation_id,p.topic_key,p.intent_json,p.intent_digest,p.receipt_json,p.receipt_digest,p.revision,p.prior_content_digest
         FROM supervisor_topic_publications p
         JOIN (SELECT topic_key,MAX(revision) AS revision FROM supervisor_topic_publications
               WHERE project_id=?1 AND state='published' AND destination_root=?2 GROUP BY topic_key) latest
           ON latest.topic_key=p.topic_key AND latest.revision=p.revision
         WHERE p.project_id=?1 AND p.state='published' AND p.destination_root=?2
         ORDER BY p.published_at_unix DESC,p.operation_id DESC LIMIT 5",
    ).map_err(|error| error.to_string())?;
    let topic_rows = topic_stmt
        .query_map(
            params![project.as_str(), topic_destination_root.as_deref()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(topic_stmt);
    let mut topics = Vec::new();
    for (
        stored_operation_id,
        topic_key,
        intent_json,
        intent_digest,
        receipt_json,
        receipt_digest,
        revision,
        prior_digest,
    ) in topic_rows
    {
        verify_digest(&intent_json, &Digest::parse(intent_digest)?)?;
        verify_digest(&receipt_json, &Digest::parse(receipt_digest)?)?;
        let intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(intent_json.as_bytes())?;
        let receipt: crate::topic::TopicReceipt =
            crate::protocol::parse_unique(receipt_json.as_bytes())?;
        if intent.project_id != *project
            || intent.operation_id != stored_operation_id
            || intent.key.as_str() != topic_key
            || i64::try_from(intent.revision).ok() != Some(revision)
            || intent.expected_prior_digest.as_ref().map(Digest::as_str) != prior_digest.as_deref()
            || crate::topic::validate_version_identity(&intent).is_err()
            || crate::topic::expected_operation_id(&intent)? != intent.operation_id
            || !intent.destination_root.is_absolute()
            || topic_destination_root
                .as_deref()
                .is_none_or(|root| intent.destination_root.to_string_lossy() != root)
            || intent.content_digest != crate::topic::content_digest(&intent.content)
            || receipt.manifest.operation_id != intent.operation_id
            || receipt.manifest.project_id != *project
            || receipt.manifest.topic_key.as_str() != topic_key
            || receipt.manifest.format != "okf-0.2"
            || receipt.manifest.content_sha256 != intent.content_digest
            || receipt.manifest.relative_path != crate::topic::publication_relative_path(&intent)?
            || receipt.manifest.byte_count != intent.content.len()
            || receipt.manifest.source_finding_ids != sorted_source_ids(&intent.sources)
            || receipt.manifest.source_publication_digests
                != sorted_source_publication_digests(&intent.sources)
            || receipt.manifest_digest
                != Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&receipt.manifest).map_err(|e| e.to_string())?
                    )
                ))?
        {
            return Err("stored Supervisor Topic publication has invalid provenance".into());
        }
        if let Some(prior_digest) = &intent.expected_prior_digest {
            let prior: Option<(String, String, String, String)> = tx.query_row(
                "SELECT operation_id,intent_json,intent_digest,destination_root FROM supervisor_topic_publications WHERE project_id=?1 AND topic_key=?2 AND destination_root=?3 AND state='published' AND revision<?4 ORDER BY revision DESC LIMIT 1",
                params![project.as_str(), topic_key, topic_destination_root.as_deref(), revision],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().map_err(|error| error.to_string())?;
            let Some((prior_operation_id, prior_json, prior_digest_json, prior_root)) = prior
            else {
                return Err("stored Supervisor Topic revision has no published predecessor".into());
            };
            verify_digest(&prior_json, &Digest::parse(prior_digest_json)?)?;
            let prior_intent: crate::topic::TopicIntent =
                crate::protocol::parse_unique(prior_json.as_bytes())?;
            if prior_root != topic_destination_root.as_deref().unwrap_or_default()
                || prior_intent.operation_id != prior_operation_id
                || prior_intent.project_id != *project
                || prior_intent.key.as_str() != topic_key
                || prior_intent.revision >= intent.revision
                || crate::topic::expected_operation_id(&prior_intent)? != prior_intent.operation_id
                || prior_intent.content_digest
                    != crate::topic::content_digest(&prior_intent.content)
                || prior_intent.content_digest != *prior_digest
            {
                return Err("stored Supervisor Topic revision predecessor is inconsistent".into());
            }
        }
        topics.push(SupervisorTopicEntry {
            topic_key: intent.key,
            content: intent.content,
            content_digest: receipt.manifest.content_sha256,
        });
    }
    let omitted_topics = total_published_topics.saturating_sub(topics.len());
    let candidates = current_supervisor_candidate_entries(tx, project)?;
    let (candidate_targets, omitted_candidate_targets) = supervisor_candidate_targets(tx, project)?;
    let mut snapshot = ProjectSupervisorMaintenance {
        project_id: project.clone(),
        expired_candidates,
        knowledge,
        topics,
        omitted_topics,
        candidates,
        candidate_targets,
        omitted_candidate_targets,
    };
    trim_supervisor_snapshot(&mut snapshot)?;
    Ok(snapshot)
}

fn current_supervisor_candidate_entries(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
) -> Result<Vec<SupervisorCandidateEntry>, String> {
    let mut statement = tx.prepare("SELECT revision_json,profile_id,package_manifest_digest,expected_pairs,evidence_json,package_files_json,package_json FROM learning_candidates WHERE project_id=?1 AND status IN ('proposed','trialing','awaiting_approval') ORDER BY created_at_unix,candidate_id,digest LIMIT ?2").map_err(|e|e.to_string())?;
    let rows = statement
        .query_map(
            params![project.as_str(), MAX_SUPERVISOR_CANDIDATES as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, usize>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let mut candidates = Vec::new();
    for row in rows {
        let (
            revision_json,
            profile_id,
            manifest_digest,
            expected_pairs,
            evidence_json,
            files_json,
            package_json,
        ) = row.map_err(|error| error.to_string())?;
        let revision: CandidateRevision = crate::protocol::parse_unique(revision_json.as_bytes())?;
        let evidence = evidence_json
            .map(|json| crate::protocol::parse_unique(json.as_bytes()))
            .transpose()?;
        let files: BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        let profile_id = ProfileId::parse(profile_id)?;
        let manifest_digest = Digest::parse(manifest_digest)?;
        let metadata = files
            .get(crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
            .map(|bytes| crate::protocol::parse_unique(bytes))
            .transpose()?;
        if let Some(metadata) = &metadata {
            validate_profile_candidate_metadata(
                project,
                &revision,
                &profile_id,
                &manifest_digest,
                &files,
                &package_json,
                metadata,
            )?;
        }
        candidates.push(SupervisorCandidateEntry {
            revision,
            profile_id,
            package_manifest_digest: manifest_digest,
            expected_pairs,
            evidence,
            metadata: metadata
                .as_ref()
                .map(crate::learning::ProfileCandidateSummary::from),
        });
    }
    drop(statement);
    Ok(candidates)
}

fn trim_supervisor_snapshot(snapshot: &mut ProjectSupervisorMaintenance) -> Result<(), String> {
    while serde_json::to_vec(snapshot)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_SUPERVISOR_CONTEXT_BYTES
        && !snapshot.knowledge.is_empty()
    {
        snapshot.knowledge.pop();
    }
    while serde_json::to_vec(snapshot)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_SUPERVISOR_CONTEXT_BYTES
        && !snapshot.topics.is_empty()
    {
        snapshot.topics.pop();
        snapshot.omitted_topics = snapshot.omitted_topics.saturating_add(1);
    }
    if serde_json::to_vec(snapshot)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_SUPERVISOR_CONTEXT_BYTES
    {
        return Err("Supervisor learning context exceeds its aggregate byte limit".into());
    }
    Ok(())
}

struct LearningBatchDbRow {
    project: String,
    digest: String,
    config_revision: u64,
    config_digest: String,
    wake_id: i64,
    findings_json: String,
    snapshot_json: String,
    status: String,
}

fn latest_supervisor_checkpoint(
    connection: &Connection,
    project_id: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    connection
        .query_row(
            "SELECT json_extract(decision_json,'$.checkpoint') FROM learning_decisions d JOIN learning_batches b USING(batch_id) WHERE b.project_id=?1 ORDER BY d.decision_sequence DESC LIMIT 1",
            [project_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .flatten()
        .map(|json| {
            serde_json::from_str(&json)
                .map_err(|error| format!("stored Supervisor checkpoint is invalid: {error}"))
        })
        .transpose()
        .map(|checkpoint| checkpoint.unwrap_or_default())
}

struct PreparedLearningCandidate {
    record: Option<LearningCandidateRecord>,
    supersedes: Option<Digest>,
}

fn validate_profile_candidate_metadata(
    project: &ProjectId,
    revision: &crate::learning::CandidateRevision,
    profile_id: &ProfileId,
    manifest_digest: &Digest,
    files: &BTreeMap<String, Vec<u8>>,
    package_json: &str,
    metadata: &crate::learning::ProfileCandidateMetadata,
) -> Result<(), String> {
    let rows = files
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                Digest::parse(format!("{:x}", Sha256::digest(bytes)))
                    .expect("SHA-256 digest is valid"),
            )
        })
        .collect::<Vec<_>>();
    if serde_json::to_string(&rows).map_err(|error| error.to_string())? != package_json
        || crate::learning::manifest_digest(files).map_err(|error| error.to_string())?
            != *manifest_digest
        || crate::learning::candidate_revision_digest(files).map_err(|error| error.to_string())?
            != revision.digest
    {
        return Err(
            "stored candidate package manifest or revision digest does not match its files".into(),
        );
    }
    let base_profile: crate::config::Profile =
        crate::protocol::parse_unique(metadata.base_profile_json.as_bytes())?;
    let config_profile: crate::config::Profile = toml::from_str(
        std::str::from_utf8(
            files
                .get("config.toml")
                .ok_or("candidate package lacks config.toml")?,
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("candidate config.toml is invalid: {error}"))?;
    let base_config: crate::config::Profile = toml::from_str(&metadata.base_config_toml)
        .map_err(|error| format!("candidate base config.toml is invalid: {error}"))?;
    let expected_scope = metadata.repository_ids.clone();
    let learned = config_profile
        .learned_guidance
        .as_ref()
        .ok_or("candidate config lacks learned guidance binding")?;
    if metadata.schema_version != 1
        || metadata.project_id != *project
        || revision.project_id != *project
        || metadata.candidate_id != revision.candidate_id
        || metadata.profile_id != *profile_id
        || revision.role != metadata.role
        || crate::learning::candidate_slot_id(
            project,
            metadata.role,
            &metadata.base_profile_id,
            &metadata.topic_key,
        ) != (metadata.candidate_id.clone(), profile_id.clone())
        || crate::store::agent_profile_digest(&base_profile)? != metadata.base_profile_digest
        || super::canonical_json(&base_profile)? != super::canonical_json(&base_config)?
        || config_profile.description.as_deref() != Some(metadata.description.as_str())
        || config_profile
            .learned_guidance
            .as_ref()
            .is_none_or(|binding| {
                binding.file != metadata.learned_guidance_path
                    || binding.project_id != *project
                    || binding.role != metadata.role
                    || binding.repository_ids != expected_scope
            })
        || learned.file != metadata.learned_guidance_path
        || files
            .get(&metadata.learned_guidance_path)
            .map(Vec::as_slice)
            != Some(metadata.learned_guidance.as_bytes())
    {
        return Err("stored candidate metadata is not bound to its Project, revision, profile, or learned layer".into());
    }
    let mut normalized = config_profile;
    normalized.description = base_profile.description.clone();
    normalized.learned_guidance = base_profile.learned_guidance.clone();
    if super::canonical_json(&normalized)? != super::canonical_json(&base_profile)? {
        return Err(
            "candidate config changes execution settings beyond description and learned guidance"
                .into(),
        );
    }
    for (source, packaged) in &metadata.external_sources {
        if source.is_empty() || files.get(packaged).is_none() {
            return Err("candidate metadata references an absent external source file".into());
        }
    }
    Ok(())
}

pub(crate) fn migrate_v19_learning_batches(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != 18 {
        return Err(format!(
            "learning batch migration requires schema v18, found v{version}"
        ));
    }
    tx.execute_batch(
        "CREATE TABLE learning_findings(
            finding_id TEXT PRIMARY KEY CHECK(length(finding_id)=64),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            ticket_run_id TEXT NOT NULL REFERENCES ticket_runs(ticket_run_id),
            publication_digest TEXT NOT NULL CHECK(length(publication_digest)=64),
            ordinal INTEGER NOT NULL CHECK(ordinal>=0),
            finding_text TEXT NOT NULL CHECK(length(finding_text)<=262144),
            source_digests_json TEXT NOT NULL DEFAULT '[]',
            consumed_batch_id TEXT REFERENCES learning_batches(batch_id),
            created_at_unix INTEGER NOT NULL,
            UNIQUE(publication_digest,ordinal)
        );
        CREATE INDEX learning_findings_eligible ON learning_findings(project_id,consumed_batch_id,created_at_unix,ticket_run_id,ordinal);
        CREATE TABLE learning_batches(
            batch_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            batch_digest TEXT NOT NULL CHECK(length(batch_digest)=64),
            config_revision INTEGER NOT NULL CHECK(config_revision>0),
            config_digest TEXT NOT NULL CHECK(length(config_digest)=64),
            owner_generation INTEGER NOT NULL CHECK(owner_generation>0),
            wake_input_id INTEGER NOT NULL UNIQUE REFERENCES role_wake_inputs(wake_input_id),
            findings_json TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('issued','completed','superseded')),
            created_at_unix INTEGER NOT NULL,
            completed_at_unix INTEGER
        );
        CREATE UNIQUE INDEX learning_batches_one_issued_per_project ON learning_batches(project_id) WHERE status='issued';
        CREATE TABLE learning_decisions(
            decision_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL UNIQUE REFERENCES learning_batches(batch_id),
            evidence_id TEXT NOT NULL UNIQUE REFERENCES agent_result_evidence(evidence_id),
            result_digest TEXT NOT NULL CHECK(length(result_digest)=64),
            decision_json TEXT NOT NULL,
            accepted_at_unix INTEGER NOT NULL
        );"
    ).map_err(|e| e.to_string())?;
    let mut stmt = tx.prepare("SELECT project_id,ticket_run_id,request_digest,request_json,manifest_json,manifest_digest,created_at_unix FROM knowledge_publications WHERE state='published' ORDER BY created_at_unix,ticket_run_id").map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    drop(stmt);
    for (project, run, request_digest, request_json, manifest_json, manifest_raw, created) in rows {
        verify_digest(&request_json, &Digest::parse(request_digest)?)?;
        let project_id = ProjectId::parse(project)?;
        let input: PostmortemInput = crate::protocol::parse_unique(request_json.as_bytes())?;
        validate_postmortem_input(&input).map_err(|e| e.to_string())?;
        let manifest: PublicationManifest =
            crate::protocol::parse_unique(manifest_json.as_bytes())?;
        let publication = Digest::parse(manifest_raw)?;
        if manifest.project_id != project_id
            || manifest.ticket_run_id.as_str() != run
            || input.project_id != project_id
            || input.ticket_run_id != manifest.ticket_run_id
            || input.operation_id != manifest.operation_id
            || format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)
            ) != publication.as_str()
        {
            return Err("published Finding backfill has invalid provenance".into());
        }
        let source_digests_json =
            serde_json::to_string(&manifest.source_digests).map_err(|e| e.to_string())?;
        for (ordinal, text) in input.findings.iter().enumerate() {
            let ordinal =
                u32::try_from(ordinal).map_err(|_| "Finding ordinal exceeds supported range")?;
            let id = learning_finding_id(&publication, ordinal, text)?;
            tx.execute("INSERT INTO learning_findings(finding_id,project_id,ticket_run_id,publication_digest,ordinal,finding_text,source_digests_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![id.as_str(),project_id.as_str(),run,publication.as_str(),ordinal,text,source_digests_json,created]).map_err(|e|e.to_string())?;
        }
    }
    tx.execute_batch("INSERT INTO schema_migrations(version,applied_at_unix) VALUES (19,unixepoch()); PRAGMA user_version=19;").map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

pub(crate) fn migrate_v20_topic_publications(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != 19 {
        return Err(format!(
            "Topic publication migration requires schema v19, found v{version}"
        ));
    }
    tx.execute_batch(
        "CREATE TABLE supervisor_topic_publications (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            topic_key TEXT NOT NULL,
            destination_root TEXT NOT NULL,
            intent_json TEXT NOT NULL CHECK(length(intent_json)<=1048576),
            intent_digest TEXT NOT NULL CHECK(length(intent_digest)=64),
            state TEXT NOT NULL CHECK(state IN ('pending','published','conflict')),
            receipt_json TEXT,
            receipt_digest TEXT CHECK(receipt_digest IS NULL OR length(receipt_digest)=64),
            conflict_json TEXT,
            created_at_unix INTEGER NOT NULL,
            published_at_unix INTEGER,
            UNIQUE(project_id,topic_key),
            CHECK((state='published' AND receipt_json IS NOT NULL AND receipt_digest IS NOT NULL AND published_at_unix IS NOT NULL AND conflict_json IS NULL)
               OR (state='pending' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NULL)
               OR (state='conflict' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NOT NULL))
        );
        CREATE INDEX supervisor_topic_publications_project ON supervisor_topic_publications(project_id,state,created_at_unix DESC,topic_key);
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (20,unixepoch());
        PRAGMA user_version=20;"
    ).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

pub(crate) fn validate_v20_topic_publications(connection: &Connection) -> Result<(), String> {
    let mut stmt = connection
        .prepare("PRAGMA table_info(supervisor_topic_publications)")
        .map_err(|e| e.to_string())?;
    let actual = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|e| e.to_string())?;
    let required = [
        "operation_id",
        "project_id",
        "topic_key",
        "destination_root",
        "intent_json",
        "intent_digest",
        "state",
        "receipt_json",
        "receipt_digest",
        "conflict_json",
        "created_at_unix",
        "published_at_unix",
    ];
    if required.iter().any(|column| !actual.contains(*column)) {
        return Err("database claims schema v20 but Topic publication ledger is incomplete".into());
    }
    Ok(())
}

pub(crate) fn migrate_v21_topic_revisions(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != 20 {
        return Err(format!(
            "Topic revision migration requires schema v20, found v{version}"
        ));
    }
    tx.execute_batch(
        "ALTER TABLE supervisor_topic_publications RENAME TO supervisor_topic_publications_v20;
        CREATE TABLE supervisor_topic_publications (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            topic_key TEXT NOT NULL,
            destination_root TEXT NOT NULL,
            intent_json TEXT NOT NULL CHECK(length(intent_json)<=1048576),
            intent_digest TEXT NOT NULL CHECK(length(intent_digest)=64),
            state TEXT NOT NULL CHECK(state IN ('pending','published','conflict')),
            receipt_json TEXT,
            receipt_digest TEXT CHECK(receipt_digest IS NULL OR length(receipt_digest)=64),
            conflict_json TEXT,
            created_at_unix INTEGER NOT NULL,
            published_at_unix INTEGER,
            revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
            prior_content_digest TEXT CHECK(prior_content_digest IS NULL OR length(prior_content_digest)=64),
            UNIQUE(project_id,topic_key,revision),
            CHECK((revision=0 AND prior_content_digest IS NULL) OR (revision>0 AND prior_content_digest IS NOT NULL)),
            CHECK((state='published' AND receipt_json IS NOT NULL AND receipt_digest IS NOT NULL AND published_at_unix IS NOT NULL AND conflict_json IS NULL)
               OR (state='pending' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NULL)
               OR (state='conflict' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NOT NULL))
        );
        INSERT INTO supervisor_topic_publications(
            operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,
            receipt_json,receipt_digest,conflict_json,created_at_unix,published_at_unix,revision,prior_content_digest
        ) SELECT operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,
            receipt_json,receipt_digest,conflict_json,created_at_unix,published_at_unix,0,NULL
          FROM supervisor_topic_publications_v20;
        DROP TABLE supervisor_topic_publications_v20;
        CREATE INDEX supervisor_topic_publications_project ON supervisor_topic_publications(project_id,state,created_at_unix DESC,topic_key);
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (21,unixepoch());
        PRAGMA user_version=21;"
    )
    .map_err(|e| e.to_string())?;
    let foreign_key_failure: Option<(String, i64, String)> = tx
        .query_row(
            "PRAGMA foreign_key_check(supervisor_topic_publications)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some((table, rowid, parent)) = foreign_key_failure {
        return Err(format!(
            "Topic revision migration found foreign key violation in {table} row {rowid} referencing {parent}"
        ));
    }
    tx.commit().map_err(|e| e.to_string())
}

pub(crate) fn validate_v21_topic_publications(connection: &Connection) -> Result<(), String> {
    validate_v20_topic_publications(connection)?;
    let mut stmt = connection
        .prepare("PRAGMA table_info(supervisor_topic_publications)")
        .map_err(|e| e.to_string())?;
    let actual = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|e| e.to_string())?;
    if !actual.contains("revision") || !actual.contains("prior_content_digest") {
        return Err("database claims schema v21 but Topic revision ledger is incomplete".into());
    }
    let mut index_stmt = connection
        .prepare("PRAGMA index_list(supervisor_topic_publications)")
        .map_err(|e| e.to_string())?;
    let indexes = index_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, i64>(4)? != 0,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    drop(index_stmt);
    let mut has_revision_unique = false;
    let mut has_legacy_unique = false;
    for (name, unique, partial) in indexes {
        if !unique {
            continue;
        }
        let quoted_name = name.replace('"', "\"\"");
        let sql = format!("PRAGMA index_info(\"{quoted_name}\")");
        let mut columns_stmt = connection.prepare(&sql).map_err(|e| e.to_string())?;
        let columns = columns_stmt
            .query_map([], |row| row.get::<_, String>(2))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        has_revision_unique |= !partial && columns == ["project_id", "topic_key", "revision"];
        has_legacy_unique |= columns == ["project_id", "topic_key"];
    }
    if !has_revision_unique || has_legacy_unique {
        return Err("database claims schema v21 but Topic revision uniqueness is invalid".into());
    }
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='supervisor_topic_publications'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    let normalized = table_sql
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("");
    for required in [
        "revisionintegernotnulldefault0check(revision>=0)",
        "prior_content_digesttextcheck(prior_content_digestisnullorlength(prior_content_digest)=64)",
        "check((revision=0andprior_content_digestisnull)or(revision>0andprior_content_digestisnotnull))",
        "check(statein('pending','published','conflict'))",
        "check(receipt_digestisnullorlength(receipt_digest)=64)",
        "check(length(intent_digest)=64)",
        "check(length(intent_json)<=1048576)",
        "check((state='published'andreceipt_jsonisnotnullandreceipt_digestisnotnullandpublished_at_unixisnotnullandconflict_jsonisnull)or(state='pending'andreceipt_jsonisnullandreceipt_digestisnullandpublished_at_unixisnullandconflict_jsonisnull)or(state='conflict'andreceipt_jsonisnullandreceipt_digestisnullandpublished_at_unixisnullandconflict_jsonisnotnull))",
    ] {
        if !normalized.contains(required) {
            return Err(
                "database claims schema v21 but Topic ledger constraints are incomplete".into(),
            );
        }
    }
    let foreign_key_to_projects: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_list('supervisor_topic_publications') WHERE \"table\"='projects' AND \"from\"='project_id' AND \"to\"='project_id')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !foreign_key_to_projects {
        return Err(
            "database claims schema v21 but Topic Project ownership is not constrained".into(),
        );
    }
    let invalid: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM supervisor_topic_publications WHERE revision<0 OR (revision=0 AND prior_content_digest IS NOT NULL) OR (revision>0 AND (prior_content_digest IS NULL OR length(prior_content_digest)<>64)))",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if invalid {
        return Err("database claims schema v21 but Topic revision identities are invalid".into());
    }
    Ok(())
}

pub(crate) fn validate_v19_learning_batches(connection: &Connection) -> Result<(), String> {
    for (table, required) in [
        (
            "learning_findings",
            vec![
                "finding_id",
                "project_id",
                "ticket_run_id",
                "publication_digest",
                "ordinal",
                "finding_text",
                "source_digests_json",
                "consumed_batch_id",
            ],
        ),
        (
            "learning_batches",
            vec![
                "batch_id",
                "project_id",
                "batch_digest",
                "config_revision",
                "config_digest",
                "owner_generation",
                "wake_input_id",
                "findings_json",
                "snapshot_json",
                "status",
            ],
        ),
        (
            "learning_decisions",
            vec![
                "decision_sequence",
                "batch_id",
                "evidence_id",
                "result_digest",
                "decision_json",
            ],
        ),
    ] {
        let mut stmt = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|e| e.to_string())?;
        let actual = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|e| e.to_string())?
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        if required.iter().any(|c| !actual.contains(*c)) {
            return Err(format!(
                "database claims schema v19 but {table} is incomplete"
            ));
        }
    }
    Ok(())
}
type PublicationDbRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);
type PromotionDbRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<u64>,
    Option<String>,
    Option<u64>,
    Option<String>,
);
type PromotionIntentRow = (
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
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePublicationIntent {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub ticket_run_id: TicketRunId,
    pub request_digest: Digest,
    pub request_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePublicationReceipt {
    pub manifest: PublicationManifest,
    pub manifest_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedKnowledgeRecord {
    pub input: PostmortemInput,
    pub manifest: PublicationManifest,
    pub manifest_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfilePromotionIntent {
    pub operation_id: OperationId,
    pub project_id: ProjectId,
    pub candidate_id: String,
    pub profile_id: ProfileId,
    pub role: crate::domain::types::Role,
    pub manifest_digest: Digest,
    pub profile_material_digest: Digest,
    pub expected_config_revision: Digest,
    pub config_source: String,
    pub config_file: String,
    pub human_request_id: HumanRequestId,
    pub approval_subject_digest: Digest,
    pub approval_configuration_digest: Digest,
    pub approval_policy_digest: Digest,
    pub response_receipt_digest: Digest,
    pub package: StoredApprovedProfilePackage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LearningCandidateRecord {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub package_manifest_digest: Digest,
    /// Canonical JSON encoding of the exact UTF-8 file path/content manifest.
    pub package_files_json: String,
    pub package_json: String,
    pub expected_pairs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LearningCandidatePackage {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub manifest_digest: Digest,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub evidence: Option<TrialEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredTrial {
    pub pair_index: usize,
    pub observation: TrialObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CandidateRegistration {
    Registered,
    AlreadyRegistered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrialProgress {
    pub trials: Vec<StoredTrial>,
    pub evidence: TrialEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorKnowledgeEntry {
    pub ticket_run_id: TicketRunId,
    pub generated_at: String,
    pub title: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub source_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorCandidateEntry {
    pub revision: CandidateRevision,
    pub profile_id: ProfileId,
    pub package_manifest_digest: Digest,
    pub expected_pairs: usize,
    pub evidence: Option<TrialEvidence>,
    #[serde(default)]
    pub metadata: Option<crate::learning::ProfileCandidateSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectSupervisorMaintenance {
    pub project_id: ProjectId,
    pub expired_candidates: usize,
    pub knowledge: Vec<SupervisorKnowledgeEntry>,
    pub topics: Vec<SupervisorTopicEntry>,
    pub omitted_topics: usize,
    pub candidates: Vec<SupervisorCandidateEntry>,
    #[serde(default)]
    pub candidate_targets: Vec<crate::learning::SupervisorCandidateTarget>,
    #[serde(default)]
    pub omitted_candidate_targets: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorTopicEntry {
    pub topic_key: crate::topic::TopicKey,
    pub content: String,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfilePromotionRequest {
    pub operation_id: OperationId,
    pub candidate_id: String,
    pub config_source: String,
    pub config_file: String,
    pub human_request_id: HumanRequestId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredProfilePublicationReceipt {
    profile_path: String,
    manifest_digest: Digest,
    human_response_receipt_digest: Digest,
    already_published: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredApprovedProfilePackage {
    pub project_id: ProjectId,
    pub role: crate::domain::types::Role,
    pub profile_id: ProfileId,
    pub candidate_digest: Digest,
    pub evidence: TrialEvidence,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub approver: String,
    pub rationale: String,
    pub authorized_at: String,
    pub human_request_id: HumanRequestId,
    pub approval_subject_digest: Digest,
    pub approval_configuration_digest: Digest,
    pub approval_policy_digest: Digest,
    pub response_receipt_digest: Digest,
    pub config_revision: Digest,
    pub profile_material_digest: Digest,
}

fn prepare_learning_candidate(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    payload: &crate::engine::orchestration::LearningDecisionPayload,
    issued_snapshot: &serde_json::Value,
    findings: &[LearningFinding],
    now_unix: i64,
) -> Result<PreparedLearningCandidate, String> {
    let proposal = payload
        .candidate_change
        .as_ref()
        .ok_or("candidate proposal is missing")?;
    let topic_key = crate::topic::TopicKey::parse(&proposal.topic_key)?;
    let revision = payload.config_revision.0;
    let digest = issued_snapshot["config_digest"]
        .as_str()
        .ok_or("issued candidate input has no config digest")?;
    let current_snapshot = applied_config_in_transaction(tx, project, revision, digest)?;
    let (current_targets, omitted_targets) = supervisor_candidate_targets(tx, project)?;
    let mut projected: ProjectSupervisorMaintenance =
        serde_json::from_value(issued_snapshot["maintenance"].clone()).map_err(|error| {
            format!("issued Supervisor maintenance context is invalid: {error}")
        })?;
    if current_targets != projected.candidate_targets
        || omitted_targets != projected.omitted_candidate_targets
    {
        return Err("configured candidate target catalog changed after batch issuance".into());
    }
    if proposal.description.trim().is_empty()
        || proposal.description.len() > crate::learning::MAX_CANDIDATE_TEXT_BYTES
        || proposal.evaluation_criterion.trim().is_empty()
        || proposal.evaluation_criterion.len() > crate::learning::MAX_CANDIDATE_TEXT_BYTES
        || proposal.learned_guidance.trim().is_empty()
        || proposal.learned_guidance.len() > crate::learning::MAX_CANDIDATE_GUIDANCE_BYTES
        || proposal.repository_ids.is_empty()
        || proposal
            .repository_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != proposal.repository_ids.len()
        || proposal.source_finding_ids.len() < 2
        || proposal.source_finding_ids.len() > 20
        || proposal
            .source_finding_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != proposal.source_finding_ids.len()
    {
        return Err(
            "candidate proposal is empty, oversized, or contains duplicate evidence or scope"
                .into(),
        );
    }
    let target = projected
        .candidate_targets
        .iter()
        .find(|target| {
            target.role == proposal.role
                && target.profile_id == proposal.base_profile_id
                && target.profile_digest == proposal.base_profile_digest
        })
        .ok_or("candidate target is not a configured Project or selected recipe role/profile")?;
    if target.omitted_learned_guidance_bytes != 0 {
        return Err(
            "candidate target guidance was omitted from the issued learning context".into(),
        );
    }
    let repository_scope = proposal
        .repository_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !repository_scope.is_subset(&target.repository_ids) {
        return Err(
            "candidate repository scope exceeds the configured Project repositories".into(),
        );
    }
    let base_profile = current_snapshot
        .profiles
        .get(&proposal.base_profile_id)
        .ok_or("candidate base profile is missing")?;
    if let Some(learned) = &base_profile.learned_guidance
        && (learned.project_id != *project
            || learned.role != proposal.role
            || learned.repository_ids != repository_scope)
    {
        return Err(
            "candidate scope must exactly replace the existing managed guidance scope".into(),
        );
    }
    let finding_map = findings
        .iter()
        .map(|finding| (finding.id.clone(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut source_runs = BTreeSet::new();
    for source_id in &proposal.source_finding_ids {
        if !finding_map.contains_key(source_id) {
            return Err("candidate evidence must come from the exact issued Finding batch".into());
        }
        let proof = resolve_topic_source(tx, project, source_id)?
            .ok_or("candidate evidence is not a published Finding in this Project")?;
        source_runs.insert(TicketRunId::parse(proof.ticket_run_id)?);
    }
    if source_runs.len() < 2 {
        return Err("candidate evidence must cover at least two distinct TicketRuns".into());
    }
    let (candidate_id, profile_id) = crate::learning::candidate_slot_id(
        project,
        proposal.role,
        &proposal.base_profile_id,
        &topic_key,
    );
    let active: Vec<(String, String, String, String)> = {
        let mut statement = tx.prepare("SELECT digest,revision_json,package_files_json,package_manifest_digest FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND status IN ('proposed','trialing','awaiting_approval') ORDER BY digest").map_err(|error| error.to_string())?;
        statement
            .query_map(params![project.as_str(), candidate_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
    };
    if active.len() > 1 {
        return Err("candidate slot contains multiple active revisions".into());
    }
    let current_prior = active
        .first()
        .map(|row| Digest::parse(row.0.clone()))
        .transpose()?;
    if current_prior != proposal.expected_prior_digest {
        return Err("candidate predecessor digest is stale or missing".into());
    }
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let logical_root = std::path::Path::new(&current_snapshot.source_root)
        .join("profiles")
        .join(proposal.base_profile_id.as_str());
    let profile_directory = current_snapshot
        .source_files
        .iter()
        .find(|source| {
            matches!(source.kind, crate::config::SourceKind::Directory)
                && std::path::Path::new(&source.path) == logical_root
        })
        .ok_or("candidate base profile directory is absent from the applied source manifest")?;
    let canonical_root = std::path::PathBuf::from(&profile_directory.canonical_path);
    let config_path = canonical_root.join("config.toml");
    let base_config_toml = current_snapshot
        .source_files
        .iter()
        .find(|source| {
            matches!(source.kind, crate::config::SourceKind::File)
                && std::path::Path::new(&source.path) == config_path
        })
        .ok_or("candidate base profile config.toml is absent from the applied source manifest")?
        .contents
        .clone();
    let mut external_sources = BTreeMap::new();
    let (skill_roots, skill_files) =
        captured_skill_sources(&current_snapshot, base_profile, &canonical_root)?;
    for source in current_snapshot
        .source_files
        .iter()
        .filter(|source| matches!(source.kind, crate::config::SourceKind::File))
    {
        let source_path = std::path::Path::new(&source.path);
        let canonical_source_path = std::path::Path::new(&source.canonical_path);
        let package_path = if canonical_source_path.starts_with(&canonical_root) {
            let relative = source_path
                .strip_prefix(&canonical_root)
                .map_err(|error| error.to_string())?;
            let relative = relative.to_string_lossy().into_owned();
            if relative == "config.toml" {
                continue;
            }
            relative
        } else if skill_roots
            .iter()
            .any(|root| canonical_source_path.starts_with(root))
            || skill_files.iter().any(|path| canonical_source_path == path)
        {
            let relative = std::path::Path::new(&source.canonical_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("skill-data");
            let path = format!("external/{}/{}", &source.sha256.as_str()[..16], relative);
            external_sources.insert(source.canonical_path.clone(), path.clone());
            path
        } else {
            continue;
        };
        let relative = std::path::Path::new(&package_path);
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("candidate source path is unsafe to package".into());
        }
        let contents = source.contents.as_bytes().to_vec();
        if let Some(existing) = files.get(&package_path) {
            if !external_sources.contains_key(&source.canonical_path) || existing != &contents {
                return Err("candidate package contains colliding source paths".into());
            }
        } else {
            files.insert(package_path, contents);
        }
    }
    let learned_guidance_path = base_profile
        .learned_guidance
        .as_ref()
        .map(|learned| learned.file.clone())
        .unwrap_or_else(|| ".rex-projects/learned-guidance.md".into());
    let base_guidance = base_profile.learned_guidance.as_ref().and_then(|learned| {
        let path = canonical_root.join(&learned.file);
        current_snapshot
            .source_files
            .iter()
            .find(|source| std::path::Path::new(&source.path) == path)
            .map(|source| source.contents.clone())
    });
    let mut candidate_profile = base_profile.clone();
    candidate_profile.description = Some(proposal.description.clone());
    candidate_profile.learned_guidance = Some(crate::config::LearnedGuidance {
        file: learned_guidance_path.clone(),
        project_id: project.clone(),
        role: proposal.role,
        repository_ids: repository_scope.clone(),
    });
    if base_profile.learned_guidance.is_none() && files.contains_key(&learned_guidance_path) {
        return Err(
            "reserved candidate learned-guidance path collides with a base profile source".into(),
        );
    }
    files.insert(
        learned_guidance_path.clone(),
        proposal.learned_guidance.as_bytes().to_vec(),
    );
    let candidate_config_toml =
        toml::to_string(&candidate_profile).map_err(|error| error.to_string())?;
    files.insert("config.toml".into(), candidate_config_toml.into_bytes());
    let metadata = crate::learning::ProfileCandidateMetadata {
        schema_version: 1,
        project_id: project.clone(),
        candidate_id: candidate_id.clone(),
        profile_id: profile_id.clone(),
        role: proposal.role,
        base_profile_id: proposal.base_profile_id.clone(),
        base_profile_digest: proposal.base_profile_digest.clone(),
        base_profile_json: super::canonical_json(base_profile)?,
        base_config_toml: base_config_toml.clone(),
        base_guidance: base_guidance.clone(),
        learned_guidance_path,
        config_revision: crate::domain::ids::Revision(revision),
        config_digest: current_snapshot.digest.clone(),
        topic_key: topic_key.clone(),
        repository_ids: repository_scope,
        source_finding_ids: proposal.source_finding_ids.clone(),
        source_ticket_run_ids: source_runs,
        expected_prior_digest: proposal.expected_prior_digest.clone(),
        evaluation_criterion: proposal.evaluation_criterion.clone(),
        description: proposal.description.clone(),
        learned_guidance: proposal.learned_guidance.clone(),
        external_sources,
    };
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(|error| error.to_string())?;
    if files
        .insert(
            crate::learning::PROFILE_CANDIDATE_METADATA_PATH.into(),
            metadata_bytes,
        )
        .is_some()
    {
        return Err("base profile collides with the reserved candidate metadata path".into());
    }
    let total_bytes = files.values().map(Vec::len).sum::<usize>();
    if files.len() > crate::learning::MAX_PROFILE_PACKAGE_FILES
        || total_bytes > crate::learning::MAX_PROFILE_PACKAGE_BYTES
    {
        return Err("candidate package exceeds the existing profile package limits".into());
    }
    let package_manifest_digest =
        crate::learning::manifest_digest(&files).map_err(|error| error.to_string())?;
    let package_rows = files
        .iter()
        .map(|(path, bytes)| {
            (
                path,
                Digest::parse(format!("{:x}", Sha256::digest(bytes)))
                    .expect("SHA-256 digest is valid"),
            )
        })
        .collect::<Vec<_>>();
    let package_json = serde_json::to_string(&package_rows).map_err(|error| error.to_string())?;
    let package_files_json = serde_json::to_string(&files).map_err(|error| error.to_string())?;
    let revision_digest =
        crate::learning::candidate_revision_digest(&files).map_err(|error| error.to_string())?;
    let created_at =
        crate::learning::unix_seconds_to_utc(now_unix as u64).map_err(|error| error.to_string())?;
    let expires_at =
        crate::learning::unix_seconds_to_utc((now_unix as u64).saturating_add(14 * 24 * 3600))
            .map_err(|error| error.to_string())?;
    let record = LearningCandidateRecord {
        revision: CandidateRevision {
            candidate_id,
            project_id: project.clone(),
            role: proposal.role,
            digest: revision_digest,
            created_at,
            expires_at,
            status: CandidateStatus::Proposed,
        },
        profile_id,
        package_manifest_digest,
        package_files_json,
        package_json,
        expected_pairs: crate::learning::MAX_TRIAL_PAIRS_PER_REVISION,
    };
    if record.package_json.len() > MAX_RECORD_BYTES
        || record.package_files_json.len() > MAX_RECORD_BYTES
    {
        return Err("candidate package exceeds durable storage bounds".into());
    }
    let same_existing = if let Some((_, _, files_json, _)) = active.first() {
        let old_files: BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        let old_metadata: crate::learning::ProfileCandidateMetadata =
            crate::protocol::parse_unique(
                old_files
                    .get(crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
                    .ok_or("active candidate metadata is missing")?,
            )?;
        let old_non_metadata = old_files
            .iter()
            .filter(|(path, _)| path.as_str() != crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
            .collect::<Vec<_>>();
        let new_non_metadata = files
            .iter()
            .filter(|(path, _)| path.as_str() != crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
            .collect::<Vec<_>>();
        old_non_metadata == new_non_metadata
            && old_metadata.base_profile_digest == proposal.base_profile_digest
            && old_metadata.base_profile_json == super::canonical_json(base_profile)?
            && old_metadata.base_config_toml == base_config_toml
            && old_metadata.base_guidance == base_guidance
            && old_metadata.topic_key == topic_key
            && old_metadata.repository_ids == metadata.repository_ids
            && old_metadata.description == proposal.description
            && old_metadata.learned_guidance == proposal.learned_guidance
            && old_metadata.evaluation_criterion == proposal.evaluation_criterion
    } else {
        false
    };
    let supersedes = current_prior;
    if same_existing {
        return Ok(PreparedLearningCandidate {
            record: None,
            supersedes,
        });
    }
    projected.candidates = current_supervisor_candidate_entries(tx, project)?;
    projected
        .candidates
        .retain(|candidate| candidate.revision.candidate_id != record.revision.candidate_id);
    projected.candidates.push(SupervisorCandidateEntry {
        revision: record.revision.clone(),
        profile_id: record.profile_id.clone(),
        package_manifest_digest: record.package_manifest_digest.clone(),
        expected_pairs: record.expected_pairs,
        evidence: None,
        metadata: Some(crate::learning::ProfileCandidateSummary::from(&metadata)),
    });
    trim_supervisor_snapshot(&mut projected).map_err(|error| {
        format!("candidate would make the next Supervisor learning input unissuable: {error}")
    })?;
    if let Some(prior) = &supersedes
        && candidate_revision_is_pinned(tx, project, &record.revision.candidate_id, prior)?
    {
        return Err("candidate slot is pinned by an unfinished trial or promotion".into());
    }
    let mut ledger = CandidateLedger::default();
    {
        let mut statement = tx
            .prepare("SELECT revision_json FROM learning_candidates WHERE project_id=?1")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([project.as_str()], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        for row in rows {
            ledger.revisions.push(crate::protocol::parse_unique(
                row.map_err(|error| error.to_string())?.as_bytes(),
            )?);
        }
    }
    if let Some(prior) = &supersedes {
        ledger.supersede_slot(
            project,
            &record.revision.candidate_id,
            &record.revision.digest,
        );
        if !ledger.revisions.iter().any(|old| {
            old.project_id == *project
                && old.candidate_id == record.revision.candidate_id
                && old.digest == *prior
                && old.status == CandidateStatus::Superseded
        }) {
            return Err("candidate predecessor is not available for replacement".into());
        }
    }
    ledger
        .register(record.revision.clone())
        .map_err(|error| error.to_string())?;
    Ok(PreparedLearningCandidate {
        record: Some(record),
        supersedes,
    })
}

fn captured_skill_sources(
    snapshot: &crate::config::AppliedConfig,
    profile: &crate::config::Profile,
    canonical_profile_root: &std::path::Path,
) -> Result<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>), String> {
    let mut roots = Vec::new();
    let mut files = Vec::new();
    for skill in &profile.skill_paths {
        let configured = std::path::PathBuf::from(skill);
        let configured = if configured.is_absolute() {
            configured
        } else {
            canonical_profile_root.join(configured)
        };
        if let Some(directory) = snapshot.source_files.iter().find(|source| {
            matches!(source.kind, crate::config::SourceKind::Directory)
                && std::path::Path::new(&source.path) == configured
        }) {
            roots.push(std::path::PathBuf::from(&directory.canonical_path));
            continue;
        }
        if let Some(file) = snapshot.source_files.iter().find(|source| {
            matches!(source.kind, crate::config::SourceKind::File)
                && std::path::Path::new(&source.path) == configured
        }) {
            files.push(std::path::PathBuf::from(&file.canonical_path));
            continue;
        }
        if snapshot.source_files.iter().any(|source| {
            matches!(source.kind, crate::config::SourceKind::File)
                && std::path::Path::new(&source.path).starts_with(&configured)
        }) {
            roots.push(configured);
            continue;
        }
        return Err(format!(
            "captured source manifest cannot resolve configured skill path `{skill}`; reapply the Project config"
        ));
    }
    Ok((roots, files))
}

fn candidate_revision_is_pinned(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    candidate_id: &str,
    digest: &Digest,
) -> Result<bool, String> {
    let pinned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM profile_trial_authorizations a WHERE a.project_id=?1 AND a.candidate_id=?2 AND a.candidate_digest=?3 AND a.lifecycle IN ('pending','authorized')) OR EXISTS(SELECT 1 FROM profile_trial_launches l JOIN profile_trial_authorizations a USING(authorization_id) WHERE a.project_id=?1 AND a.candidate_id=?2 AND a.candidate_digest=?3 AND l.lifecycle IN ('prepared','running','uncertain')) OR EXISTS(SELECT 1 FROM profile_promotions p WHERE p.project_id=?1 AND p.candidate_id=?2 AND p.candidate_digest=?3 AND p.state IN ('approved','publication_pending','published','activation_pending','active')) OR EXISTS(SELECT 1 FROM profile_promotions p JOIN effects e USING(operation_id) WHERE p.project_id=?1 AND p.candidate_id=?2 AND p.candidate_digest=?3 AND e.kind='publish_profile' AND e.status IN ('pending','claimed','uncertain')) OR EXISTS(SELECT 1 FROM provider_qualification_candidate_targets t JOIN provider_qualification_jobs q USING(request_id) WHERE t.project_id=?1 AND t.candidate_id=?2 AND t.candidate_digest=?3 AND q.status IN ('queued','running','unknown'))",
        params![project.as_str(), candidate_id, digest.as_str()],
        |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    Ok(pinned)
}

fn register_learning_candidate_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    generation: u64,
    record: &LearningCandidateRecord,
) -> Result<CandidateRegistration, String> {
    if !(5..=MAX_TRIALS).contains(&record.expected_pairs)
        || record.package_json.len() > MAX_RECORD_BYTES
        || record.package_files_json.len() > MAX_RECORD_BYTES
        || record.revision.status != CandidateStatus::Proposed
    {
        return Err("candidate package, identity, or trial count exceeds bounds".into());
    }
    verify_digest(&record.package_json, &record.package_manifest_digest)?;
    let files: BTreeMap<String, Vec<u8>> =
        crate::protocol::parse_unique(record.package_files_json.as_bytes())?;
    if serde_json::to_string(&files).map_err(|e| e.to_string())? != record.package_files_json
        || crate::learning::manifest_digest(&files).map_err(|e| e.to_string())?
            != record.package_manifest_digest
    {
        return Err("candidate file bytes do not match their immutable manifest".into());
    }
    validate_active_generation(tx, generation)?;
    let revision_json = serde_json::to_string(&record.revision).map_err(|e| e.to_string())?;
    let role = serde_json::to_value(record.revision.role)
        .map_err(|e| e.to_string())?
        .as_str()
        .ok_or("invalid role")?
        .to_owned();
    let status = serde_json::to_value(record.revision.status)
        .map_err(|e| e.to_string())?
        .as_str()
        .ok_or("invalid candidate status")?
        .to_owned();
    let prior: Option<(String,String,String,String,usize)> = tx.query_row(
        "SELECT revision_json,package_manifest_digest,package_files_json,package_json,expected_pairs FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
        params![record.revision.project_id.as_str(),record.revision.candidate_id,record.revision.digest.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).optional().map_err(|error| error.to_string())?;
    if let Some(found) = prior {
        if found
            != (
                revision_json,
                record.package_manifest_digest.to_string(),
                record.package_files_json.clone(),
                record.package_json.clone(),
                record.expected_pairs,
            )
        {
            return Err("candidate identity has different immutable content".into());
        }
        return Ok(CandidateRegistration::AlreadyRegistered);
    }
    let mut ledger = CandidateLedger::default();
    {
        let mut statement = tx
            .prepare("SELECT revision_json FROM learning_candidates WHERE project_id=?1")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([record.revision.project_id.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        for row in rows {
            ledger.revisions.push(crate::protocol::parse_unique(
                row.map_err(|error| error.to_string())?.as_bytes(),
            )?);
        }
    }
    ledger
        .register(record.revision.clone())
        .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO learning_candidates(project_id,candidate_id,role,digest,profile_id,revision_json,package_manifest_digest,package_files_json,package_json,expected_pairs,status,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![record.revision.project_id.as_str(),record.revision.candidate_id,role,record.revision.digest.as_str(),record.profile_id.as_str(),revision_json,record.package_manifest_digest.as_str(),record.package_files_json,record.package_json,record.expected_pairs,status,super::now_unix()?],
    ).map_err(|error| error.to_string())?;
    Ok(CandidateRegistration::Registered)
}

/// Install v10 over a v9 database as part of the caller's backed-up migration transaction.
pub(crate) fn migrate_v10(connection: &Connection) -> Result<(), String> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != 9 {
        return Err(format!(
            "learning migration requires schema v9, found v{version}"
        ));
    }
    tx.execute_batch(
        "ALTER TABLE controller_owners ADD COLUMN rex_endpoint TEXT;
        CREATE TABLE knowledge_publications (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            ticket_run_id TEXT NOT NULL UNIQUE REFERENCES ticket_runs(ticket_run_id),
            request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
            request_json TEXT NOT NULL CHECK(length(request_json)<=4194304),
            state TEXT NOT NULL CHECK(state IN ('prepared','published','failed','uncertain')),
            manifest_json TEXT,
            manifest_digest TEXT,
            created_at_unix INTEGER NOT NULL,
            published_at_unix INTEGER,
            CHECK((state='published' AND manifest_json IS NOT NULL AND manifest_digest IS NOT NULL)
               OR (state!='published' AND manifest_json IS NULL AND manifest_digest IS NULL))
        );
        CREATE INDEX knowledge_publication_project ON knowledge_publications(project_id,created_at_unix);
        CREATE TABLE learning_candidates (
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            role TEXT NOT NULL,
            digest TEXT NOT NULL CHECK(length(digest)=64),
            profile_id TEXT NOT NULL,
            revision_json TEXT NOT NULL CHECK(length(revision_json)<=65536),
            package_manifest_digest TEXT NOT NULL CHECK(length(package_manifest_digest)=64),
            package_files_json TEXT NOT NULL CHECK(length(package_files_json)<=4194304),
            package_json TEXT NOT NULL CHECK(length(package_json)<=4194304),
            expected_pairs INTEGER NOT NULL CHECK(expected_pairs BETWEEN 5 AND 10),
            status TEXT NOT NULL CHECK(status IN ('proposed','trialing','awaiting_approval','promoted','superseded','expired','rejected')),
            evidence_json TEXT,
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,candidate_id,digest)
        );
        CREATE INDEX learning_candidates_slots ON learning_candidates(project_id,role,status,created_at_unix);
        CREATE TABLE supervisor_learning_schedule (
            project_id TEXT PRIMARY KEY REFERENCES projects(project_id) ON DELETE CASCADE,
            next_due_at_unix INTEGER NOT NULL,
            last_run_at_unix INTEGER,
            last_snapshot_digest TEXT CHECK(last_snapshot_digest IS NULL OR length(last_snapshot_digest)=64)
        );
        CREATE TABLE learning_trial_pairs (
            project_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
            observation_json TEXT NOT NULL CHECK(length(observation_json)<=16384),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(project_id,candidate_id,candidate_digest,pair_index),
            FOREIGN KEY(project_id,candidate_id,candidate_digest)
                REFERENCES learning_candidates(project_id,candidate_id,digest) ON DELETE CASCADE
        );
        CREATE TABLE profile_promotions (
            operation_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
            profile_id TEXT NOT NULL,
            role TEXT NOT NULL,
            evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
            manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64),
            config_source TEXT NOT NULL,
            config_file TEXT NOT NULL,
            expected_config_revision TEXT NOT NULL CHECK(length(expected_config_revision)=64),
            human_request_id TEXT NOT NULL,
            human_response_digest TEXT NOT NULL CHECK(length(human_response_digest)=64),
            approval_subject_digest TEXT NOT NULL CHECK(length(approval_subject_digest)=64),
            profile_material_digest TEXT NOT NULL CHECK(length(profile_material_digest)=64),
            approval_configuration_digest TEXT NOT NULL CHECK(length(approval_configuration_digest)=64),
            approval_policy_digest TEXT NOT NULL CHECK(length(approval_policy_digest)=64),
            approved_package_json TEXT NOT NULL CHECK(length(approved_package_json)<=4194304),
            state TEXT NOT NULL CHECK(state IN ('approved','publication_pending','published','activation_pending','active','stale','rejected')),
            publication_receipt_json TEXT,
            activation_from_revision INTEGER,
            activation_to_revision INTEGER,
            activation_config_digest TEXT,
            applied_config_revision INTEGER,
            applied_config_digest TEXT,
            created_at_unix INTEGER NOT NULL,
            UNIQUE(project_id,role,profile_id,candidate_digest)
        );
        CREATE INDEX profile_promotions_pending ON profile_promotions(project_id,state,created_at_unix);
        INSERT INTO schema_migrations(version,applied_at_unix) VALUES (10,unixepoch());
        PRAGMA user_version=10;"
    ).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

/// Install learning-owned additions in the shared v12 migration transaction.
/// The caller owns the single schema-version bump and invokes this before commit.
pub(crate) fn migrate_v12_learning_tables(tx: &rusqlite::Transaction<'_>) -> Result<(), String> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS profile_trial_authorizations (
            authorization_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            candidate_id TEXT NOT NULL,
            candidate_digest TEXT NOT NULL CHECK(length(candidate_digest)=64),
            human_request_id TEXT NOT NULL UNIQUE,
            request_json TEXT NOT NULL CHECK(length(request_json)<=1048576),
            rex_view_id TEXT NOT NULL CHECK(length(rex_view_id)=64),
            artifact_path TEXT NOT NULL CHECK(length(artifact_path)<=4096),
            authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64),
            authorization_json TEXT NOT NULL CHECK(length(authorization_json)<=4194304),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('pending','authorized','refused','expired','completed')),
            created_at_unix INTEGER NOT NULL,
            authorized_at_unix INTEGER,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS profile_trial_authorizations_pending
            ON profile_trial_authorizations(project_id,lifecycle,created_at_unix);
        CREATE TABLE IF NOT EXISTS profile_trial_launches (
            authorization_id TEXT NOT NULL REFERENCES profile_trial_authorizations(authorization_id) ON DELETE CASCADE,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            side TEXT NOT NULL CHECK(side IN ('baseline','candidate')),
            operation_id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL UNIQUE,
            attempt_id TEXT NOT NULL UNIQUE,
            capsule_digest TEXT NOT NULL CHECK(length(capsule_digest)=64),
            capsule_json TEXT NOT NULL CHECK(length(capsule_json)<=2097152),
            lifecycle TEXT NOT NULL CHECK(lifecycle IN ('prepared','running','uncertain','completed','failed')),
            created_at_unix INTEGER NOT NULL,
            completed_at_unix INTEGER,
            PRIMARY KEY(authorization_id,pair_index,side)
        );
        CREATE INDEX IF NOT EXISTS profile_trial_launches_pending
            ON profile_trial_launches(lifecycle,created_at_unix);
        CREATE TABLE IF NOT EXISTS profile_trial_run_receipts (
            authorization_id TEXT NOT NULL,
            pair_index INTEGER NOT NULL,
            side TEXT NOT NULL,
            run_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64),
            receipt_json TEXT NOT NULL CHECK(length(receipt_json)<=65536),
            received_at_unix INTEGER NOT NULL,
            PRIMARY KEY(authorization_id,pair_index,side),
            FOREIGN KEY(authorization_id,pair_index,side)
                REFERENCES profile_trial_launches(authorization_id,pair_index,side) ON DELETE CASCADE,
            UNIQUE(run_id)
        );
        CREATE TABLE IF NOT EXISTS profile_trial_pairs (
            authorization_id TEXT NOT NULL REFERENCES profile_trial_authorizations(authorization_id) ON DELETE CASCADE,
            pair_index INTEGER NOT NULL CHECK(pair_index BETWEEN 0 AND 9),
            input_digest TEXT NOT NULL CHECK(length(input_digest)=64),
            observation_json TEXT NOT NULL CHECK(length(observation_json)<=16384),
            created_at_unix INTEGER NOT NULL,
            PRIMARY KEY(authorization_id,pair_index)
        );"
    ).map_err(|e| e.to_string())
}

/// Refuse databases that claim v10 but do not contain this exact unreleased
/// learning layout before WAL or other connection PRAGMAs can mutate them.
pub(crate) fn validate_v10_schema(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version < 10 {
        return Err(format!(
            "learning layout validation requires schema v10 or later, found v{version}"
        ));
    }
    for (table, expected) in [
        (
            "knowledge_publications",
            &["operation_id", "request_json", "manifest_json"][..],
        ),
        (
            "learning_candidates",
            &[
                "package_files_json",
                "package_manifest_digest",
                "evidence_json",
            ][..],
        ),
        (
            "learning_trial_pairs",
            &["pair_index", "observation_json"][..],
        ),
        (
            "profile_promotions",
            &[
                "config_source",
                "config_file",
                "approval_subject_digest",
                "profile_material_digest",
                "approved_package_json",
            ][..],
        ),
        (
            "supervisor_learning_schedule",
            &[
                "next_due_at_unix",
                "last_run_at_unix",
                "last_snapshot_digest",
            ][..],
        ),
    ] {
        let mut statement = connection
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .map_err(|e| e.to_string())?;
        let actual = statement
            .query_map([table], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        if expected.iter().any(|column| !actual.contains(*column)) {
            let missing = expected
                .iter()
                .filter(|column| !actual.contains(**column))
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "database claims schema v10 but {table} is missing required columns: {missing}"
            ));
        }
    }
    Ok(())
}

impl ConfigStore {
    /// Read the committed publications for one Project through the typed store API.
    pub fn published_knowledge(
        &self,
        project: &ProjectId,
        ticket_run: Option<&TicketRunId>,
        limit: usize,
    ) -> Result<Vec<PublishedKnowledgeRecord>, String> {
        const MAX_ITEMS: usize = 100;
        if limit == 0 || limit > MAX_ITEMS {
            return Err(format!(
                "knowledge result limit must be between 1 and {MAX_ITEMS}"
            ));
        }
        let ticket_run_filter = ticket_run.map(TicketRunId::as_str);
        let mut statement = self.connection.prepare(
            "SELECT ticket_run_id,request_digest,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE project_id=?1 AND state='published' AND (?2 IS NULL OR ticket_run_id=?2) ORDER BY created_at_unix DESC,ticket_run_id DESC LIMIT ?3",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![project.as_str(), ticket_run_filter, limit as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        let mut publications = Vec::new();
        for row in rows {
            let (ticket_run_id, request_digest, request_json, manifest_json, manifest_digest) =
                row.map_err(|error| error.to_string())?;
            verify_digest(&request_json, &Digest::parse(request_digest)?)?;
            let input: PostmortemInput = crate::protocol::parse_unique(request_json.as_bytes())?;
            validate_postmortem_input(&input).map_err(|error| error.to_string())?;
            let manifest: PublicationManifest =
                crate::protocol::parse_unique(manifest_json.as_bytes())?;
            let manifest_digest = Digest::parse(manifest_digest)?;
            let canonical_manifest = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
            if input.project_id != *project
                || input.ticket_run_id.as_str() != ticket_run_id
                || manifest.project_id != *project
                || manifest.ticket_run_id.as_str() != ticket_run_id
                || manifest.operation_id != input.operation_id
                || format!("{:x}", Sha256::digest(&canonical_manifest)) != manifest_digest.as_str()
            {
                return Err("stored knowledge publication has invalid provenance".into());
            }
            publications.push(PublishedKnowledgeRecord {
                input,
                manifest,
                manifest_digest,
            });
        }
        Ok(publications)
    }

    /// Resolve the exact immutable profile-trial authorization for a pending human request.
    /// The table is created by the coordinated v12 learning migration.
    /// Persist the exact bounded trial batch before making its human request visible.
    /// A crash between these writes leaves a harmless pending batch that can be retried.
    pub fn prepare_profile_trial_authorization(
        &mut self,
        generation: u64,
        authorization: &ProfileTrialAuthorization,
        request: &HumanRuntimeRequest,
        rex_view_id: &Digest,
        artifact_path: &std::path::Path,
        now_unix: u64,
    ) -> Result<bool, String> {
        let mut bound = authorization.clone();
        bind_profile_trial_human_request(&mut bound, request)?;
        if bound
            .human_response_receipt_digest
            .as_str()
            .bytes()
            .all(|b| b == b'0')
        {
            // Pending requests must not carry an approval receipt supplied by their caller.
            if authorization
                .human_response_receipt_digest
                .as_str()
                .bytes()
                .any(|b| b != b'0')
            {
                return Err("pending profile trial cannot contain an approval receipt".into());
            }
        }
        let digest = bound.digest()?;
        let json = super::canonical_json(&bound)?;
        let request_json = super::canonical_json(request)?;
        let artifact_path_text = artifact_path.to_string_lossy().into_owned();
        if json.len() > 4 * 1024 * 1024
            || request_json.len() > crate::human_runtime::MAX_HUMAN_REQUEST_BYTES
            || artifact_path_text.len() > 4096
        {
            return Err("profile trial authorization exceeds its durable size limit".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let candidate: Option<(String, String, String, String, String)> = tx.query_row(
            "SELECT role,profile_id,status,package_manifest_digest,package_files_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![bound.project_id.as_str(),bound.candidate_id,bound.candidate_digest.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((role, profile_id, status, manifest_raw, files_json)) = candidate else {
            return Err(
                "profile trial candidate is not present in the durable learning ledger".into(),
            );
        };
        let expected_role = serde_json::to_value(bound.role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        if role != expected_role
            || profile_id != bound.candidate.profile_id.as_str()
            || !matches!(status.as_str(), "proposed" | "trialing")
        {
            return Err("profile trial candidate scope or lifecycle is stale".into());
        }
        let current_config: Option<(u64, String)> = tx
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [bound.project_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((revision, config_digest)) = current_config else {
            return Err("profile trial Project no longer exists".into());
        };
        if revision != bound.config_revision.0 || config_digest != bound.config_digest.as_str() {
            return Err("profile trial config snapshot is stale".into());
        }
        let candidate_files: std::collections::BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        let manifest = Digest::parse(manifest_raw)?;
        if crate::learning::manifest_digest(&candidate_files).map_err(|e| e.to_string())?
            != manifest
        {
            return Err("durable candidate package manifest is invalid".into());
        }
        let candidate_config: serde_json::Value =
            crate::protocol::parse_unique(bound.candidate.profile_config_json.as_bytes())?;
        let guidance_path = candidate_config
            .get("learned_guidance")
            .and_then(|value| value.get("file"))
            .and_then(serde_json::Value::as_str)
            .ok_or("candidate profile must bind its learned-guidance file")?;
        let stored_guidance = candidate_files
            .get(guidance_path)
            .ok_or("candidate package does not contain its declared learned-guidance file")?;
        let frozen_guidance = bound
            .candidate
            .instruction_files
            .get(guidance_path)
            .ok_or("trial snapshot omits the candidate learned-guidance file")?;
        if stored_guidance != frozen_guidance {
            return Err(
                "trial snapshot learned-guidance bytes differ from the immutable candidate package"
                    .into(),
            );
        }
        let existing: Option<(String,String,String,String,String)> = tx.query_row(
            "SELECT authorization_digest,authorization_json,request_json,rex_view_id,artifact_path FROM profile_trial_authorizations WHERE authorization_id=?1",
            [bound.authorization_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let inserted = if let Some((
            old_digest,
            old_json,
            old_request_json,
            old_view_id,
            old_artifact_path,
        )) = existing
        {
            if old_digest != digest.as_str()
                || old_json != json
                || old_request_json != request_json
                || old_view_id != rex_view_id.as_str()
                || old_artifact_path != artifact_path_text
            {
                return Err(
                    "profile trial authorization ID was reused with different content".into(),
                );
            }
            false
        } else {
            tx.execute(
                "INSERT INTO profile_trial_authorizations(authorization_id,project_id,candidate_id,candidate_digest,human_request_id,request_json,rex_view_id,artifact_path,authorization_digest,authorization_json,lifecycle,created_at_unix,updated_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending',?11,?11)",
                params![bound.authorization_id,bound.project_id.as_str(),bound.candidate_id,bound.candidate_digest.as_str(),bound.human_request_id.as_str(),request_json,rex_view_id.as_str(),artifact_path_text,digest.as_str(),json,now_unix],
            ).map_err(|e| e.to_string())?;
            set_candidate_revision_status(
                &tx,
                &bound.project_id,
                &bound.candidate_id,
                &bound.candidate_digest,
                CandidateStatus::Trialing,
            )?;
            true
        };
        tx.commit().map_err(|e| e.to_string())?;
        self.register_human_request(generation, request, rex_view_id, artifact_path, now_unix)?;
        Ok(inserted)
    }

    /// Turn a pending frozen batch into an authorized batch only from the opaque
    /// receipt minted by the durable human decision store.
    pub fn accept_profile_trial_approval(
        &mut self,
        generation: u64,
        authorization_id: &str,
        now_unix: u64,
    ) -> Result<bool, String> {
        let row: Option<(String,String,String)> = self.connection.query_row(
            "SELECT authorization_json,lifecycle,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((json, lifecycle, stored_digest)) = row else {
            return Err("unknown profile trial authorization".into());
        };
        let pending_json = json.clone();
        let mut authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.digest()?.as_str() != stored_digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        if lifecycle == "authorized" {
            return Ok(false);
        }
        if lifecycle != "pending" {
            return Err(format!("profile trial authorization is {lifecycle}"));
        }
        let receipt = self
            .accepted_human_approval(
                &authorization.human_request_id,
                &authorization.human_subject_digest,
                &authorization.human_configuration_digest,
                &authorization.human_policy_digest,
                now_unix,
            )?
            .ok_or("no current accepted human approval exists for this profile trial")?;
        authorization = accept_profile_trial_approval(authorization, &receipt, now_unix)?;
        let json = super::canonical_json(&authorization)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let current: Option<(String,String)> = tx.query_row("SELECT authorization_json,lifecycle FROM profile_trial_authorizations WHERE authorization_id=?1",[authorization_id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        if current
            .as_ref()
            .is_none_or(|(old_json, state)| old_json != &pending_json || state != "pending")
        {
            return Err(
                "profile trial authorization changed while approval was being checked".into(),
            );
        }
        tx.execute("UPDATE profile_trial_authorizations SET authorization_json=?2,lifecycle='authorized',authorized_at_unix=?3,updated_at_unix=?3 WHERE authorization_id=?1 AND lifecycle='pending'",params![authorization_id,json,now_unix]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Atomically persist the immutable launch capsule and the Rex start effect.
    /// Existing capsules are returned verbatim for reconciliation after restart.
    pub fn next_profile_trial_launch(
        &mut self,
        generation: u64,
        authorization_id: &str,
        now_unix: u64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String,String,String)> = tx.query_row(
            "SELECT authorization_json,lifecycle,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((auth_json, lifecycle, auth_digest)) = row else {
            return Err("unknown profile trial authorization".into());
        };
        if lifecycle != "authorized" {
            return Err("profile trial batch is not human-authorized".into());
        }
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(auth_json.as_bytes())?;
        if authorization.digest()?.as_str() != auth_digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        let existing: Option<(String,String)> = tx.query_row(
            "SELECT capsule_json,capsule_digest FROM profile_trial_launches WHERE authorization_id=?1 AND lifecycle IN ('prepared','running','uncertain') ORDER BY pair_index,CASE side WHEN 'baseline' THEN 0 ELSE 1 END LIMIT 1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some((json, digest)) = existing {
            if super::content_digest(&json) != digest {
                return Err("stored profile trial capsule digest is invalid".into());
            }
            let capsule: ProfileTrialLaunchCapsule =
                crate::protocol::parse_unique(json.as_bytes())?;
            capsule.validate()?;
            if capsule.authorization_id != authorization_id
                || capsule.authorization_digest != authorization.digest()?
            {
                return Err("stored trial capsule belongs to a different authorization".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(capsule));
        }
        if now_unix >= authorization.expires_at_unix {
            tx.execute("UPDATE profile_trial_authorizations SET lifecycle='expired',updated_at_unix=?2 WHERE authorization_id=?1 AND lifecycle='authorized'",params![authorization_id,now_unix]).map_err(|e|e.to_string())?;
            set_candidate_revision_status(
                &tx,
                &authorization.project_id,
                &authorization.candidate_id,
                &authorization.candidate_digest,
                CandidateStatus::Expired,
            )?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        }
        if max_agent_slots == 0 || max_project_slots == 0 {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(None);
        }
        for pair in &authorization.pairs {
            let baseline: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='baseline')",
                params![authorization_id,pair.pair_index], |r| r.get(0),
            ).map_err(|e| e.to_string())?;
            let candidate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='candidate')",
                params![authorization_id,pair.pair_index], |r| r.get(0),
            ).map_err(|e| e.to_string())?;
            let side = if !baseline {
                TrialSide::Baseline
            } else if !candidate {
                TrialSide::Candidate
            } else {
                continue;
            };
            let capsule = ProfileTrialLaunchCapsule::from_authorized_matrix(
                &authorization,
                pair.pair_index,
                side,
            )?;
            let global_used: u32 = tx.query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE pool='agent' AND disposition!='released'",
                [], |r| r.get(0),
            ).map_err(|e|e.to_string())?;
            let project_used: u32 = tx.query_row(
                "SELECT COUNT(*) FROM execution_slots WHERE project_id=?1 AND disposition!='released'",
                [authorization.project_id.as_str()], |r| r.get(0),
            ).map_err(|e|e.to_string())?;
            if global_used >= max_agent_slots || project_used >= max_project_slots {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(None);
            }
            let mut slot_index = None;
            for slot in 0..max_agent_slots {
                let occupied: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM execution_slots WHERE pool='agent' AND slot_index=?1 AND disposition!='released')",
                    [slot], |r| r.get(0),
                ).map_err(|e|e.to_string())?;
                if !occupied {
                    slot_index = Some(slot);
                    break;
                }
            }
            let Some(slot_index) = slot_index else {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(None);
            };
            let project_epoch: u64 = tx
                .query_row(
                    "SELECT project_epoch FROM project_runtimes WHERE project_id=?1",
                    [authorization.project_id.as_str()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .ok_or("profile trial Project has no runtime epoch")?;
            let reserved = tx.execute(
                "INSERT INTO execution_slots(pool,slot_index,project_id,ticket_run_id,owner_kind,owner_id,reservation_epoch,controller_generation,disposition) VALUES ('agent',?1,?2,NULL,'profile_trial',?3,?4,?5,'launch_pending') ON CONFLICT(pool,slot_index) DO UPDATE SET project_id=excluded.project_id,ticket_run_id=NULL,owner_kind=excluded.owner_kind,owner_id=excluded.owner_id,reservation_epoch=excluded.reservation_epoch,controller_generation=excluded.controller_generation,process_identity_json=NULL,disposition='launch_pending' WHERE execution_slots.disposition='released'",
                params![slot_index,authorization.project_id.as_str(),capsule.operation_id().as_str(),project_epoch,generation],
            ).map_err(|e|e.to_string())?;
            if reserved != 1 {
                return Err("profile trial execution slot was concurrently reserved".into());
            }
            let capsule_json = super::canonical_json(&capsule)?;
            let capsule_digest = super::content_digest(&capsule_json);
            let side_name = if side == TrialSide::Baseline {
                "baseline"
            } else {
                "candidate"
            };
            let request_json = super::canonical_json(
                &serde_json::json!({"authorization_id":authorization_id,"capsule_digest":capsule_digest,"pair_index":pair.pair_index,"run_id":capsule.run_id.as_str(),"side":side_name}),
            )?;
            let effect = super::EffectIntent {
                project_id: authorization.project_id.clone(),
                subject_type: "project".into(),
                subject_id: authorization.project_id.to_string(),
                operation_id: capsule.operation_id.to_string(),
                logical_key: format!(
                    "profile-trial-{}-{}-{side_name}",
                    authorization_id, pair.pair_index
                ),
                kind: "start_profile_trial".into(),
                request_digest: super::content_digest(&request_json),
                request_json,
                expected_revision: None,
            };
            tx.execute("INSERT INTO profile_trial_launches(authorization_id,pair_index,side,operation_id,run_id,attempt_id,capsule_digest,capsule_json,lifecycle,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared',?9)",params![authorization_id,pair.pair_index,side_name,capsule.operation_id.as_str(),capsule.run_id.as_str(),capsule.attempt_id,capsule_digest,capsule_json,now_unix]).map_err(|e|e.to_string())?;
            super::insert_effect(&tx, &effect, now_unix as i64)?;
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(capsule));
        }
        tx.execute("UPDATE profile_trial_authorizations SET lifecycle='completed',updated_at_unix=?2 WHERE authorization_id=?1",params![authorization_id,now_unix]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(None)
    }

    /// Accept only host-minted run evidence; pair results become learning evidence
    /// once both sides have durable terminal receipts.
    pub(crate) fn acknowledge_profile_trial_start(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        process: &crate::process::ProcessIdentity,
        _now_unix: u64,
    ) -> Result<(), String> {
        if process.pid == 0
            || process.start_identity.trim().is_empty()
            || process.command.trim().is_empty()
        {
            return Err("profile trial start requires a pinned host process identity".into());
        }
        let identity_json = serde_json::to_string(&serde_json::json!({
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "process_group_id": process.process_group_id,
            "start_identity": process.start_identity,
            "command": process.command,
        }))
        .map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let launch: Option<(String, String, String)> = tx.query_row(
            "SELECT l.lifecycle,a.project_id,l.capsule_digest FROM profile_trial_launches l JOIN profile_trial_authorizations a USING(authorization_id) WHERE l.operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((lifecycle, project_id, _capsule_digest)) = launch else {
            return Err("profile trial start has no durable launch row".into());
        };
        if !matches!(lifecycle.as_str(), "prepared" | "uncertain" | "running") {
            return Err("profile trial launch is not startable".into());
        }
        let slot: Option<(String, String, Option<String>, u64)> = tx.query_row(
            "SELECT project_id,disposition,process_identity_json,controller_generation FROM execution_slots WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((slot_project, disposition, previous_identity, slot_generation)) = slot else {
            return Err("profile trial execution slot is missing".into());
        };
        if slot_project != project_id || slot_generation > generation {
            return Err("profile trial execution slot changed ownership".into());
        }
        if lifecycle == "running" {
            if disposition != "running" || previous_identity.as_deref() != Some(&identity_json) {
                return Err("profile trial start retry has a different process identity".into());
            }
            if slot_generation < generation {
                tx.execute(
                    "UPDATE execution_slots SET controller_generation=?3 WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1 AND project_id=?2 AND controller_generation=?4 AND disposition='running'",
                    params![operation_id.as_str(), project_id, generation, slot_generation],
                ).map_err(|e| e.to_string())?;
            }
        } else {
            let changed = tx.execute(
                "UPDATE execution_slots SET process_identity_json=?3,disposition='running',controller_generation=?4 WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1 AND project_id=?2 AND controller_generation=?5 AND disposition!='released'",
                params![operation_id.as_str(), project_id, identity_json, generation, slot_generation],
            ).map_err(|e| e.to_string())?;
            if changed != 1 {
                return Err(
                    "profile trial execution slot changed before start acknowledgement".into(),
                );
            }
            tx.execute(
                "UPDATE profile_trial_launches SET lifecycle='running' WHERE operation_id=?1 AND lifecycle IN ('prepared','uncertain')",
                [operation_id.as_str()],
            ).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub(crate) fn record_profile_trial_run_receipt(
        &mut self,
        generation: u64,
        receipt: &ProfileTrialRunReceipt,
        now_unix: u64,
    ) -> Result<TrialProgress, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String,String)> = tx.query_row(
            "SELECT authorization_json,lifecycle FROM profile_trial_authorizations WHERE authorization_id=?1",
            [receipt.authorization_id()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((auth_json, lifecycle)) = row else {
            return Err("trial receipt has no durable authorization".into());
        };
        if lifecycle != "authorized" && lifecycle != "completed" {
            return Err("trial receipt authorization is not active".into());
        }
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(auth_json.as_bytes())?;
        receipt.validate_against(&authorization)?;
        let side = if receipt.side() == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        let capsule_row: Option<(String,String,String,String)> = tx.query_row(
            "SELECT capsule_json,capsule_digest,run_id,attempt_id FROM profile_trial_launches WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",
            params![receipt.authorization_id(),receipt.pair_index(),side], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((capsule_json, capsule_digest, run_id, attempt_id)) = capsule_row else {
            return Err("trial receipt has no prepared durable launch".into());
        };
        if run_id != receipt.run_id().as_str()
            || attempt_id != receipt.attempt_id()
            || super::content_digest(&capsule_json) != capsule_digest
        {
            return Err("trial receipt does not match its persisted launch identity".into());
        }
        let capsule: ProfileTrialLaunchCapsule =
            crate::protocol::parse_unique(capsule_json.as_bytes())?;
        capsule.validate()?;
        if capsule.authorization_id != authorization.authorization_id
            || capsule.authorization_digest != authorization.digest()?
            || capsule.pair_index != receipt.pair_index()
            || capsule.side != receipt.side()
            || capsule.run_id != *receipt.run_id()
            || capsule.attempt_id != receipt.attempt_id()
        {
            return Err("trial receipt differs from the immutable persisted capsule".into());
        }
        let receipt_json = super::canonical_json(receipt)?;
        if receipt_json.len() > 65536 {
            return Err("profile trial receipt exceeds size limit".into());
        }
        let receipt_digest = super::content_digest(&receipt_json);
        let old: Option<(String,String)> = tx.query_row(
            "SELECT receipt_digest,receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",
            params![receipt.authorization_id(),receipt.pair_index(),side], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        if let Some((digest, json)) = old {
            if digest != receipt_digest || json != receipt_json {
                return Err("conflicting terminal trial receipt".into());
            }
        } else {
            tx.execute("INSERT INTO profile_trial_run_receipts(authorization_id,pair_index,side,run_id,attempt_id,receipt_digest,receipt_json,received_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![receipt.authorization_id(),receipt.pair_index(),side,receipt.run_id().as_str(),receipt.attempt_id(),receipt_digest,receipt_json,now_unix]).map_err(|e|e.to_string())?;
            tx.execute("UPDATE profile_trial_launches SET lifecycle='completed',completed_at_unix=?4 WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",params![receipt.authorization_id(),receipt.pair_index(),side,now_unix]).map_err(|e|e.to_string())?;
        }
        let slot: Option<(u32,String)> = tx.query_row(
            "SELECT slot_index,disposition FROM execution_slots WHERE pool='agent' AND owner_kind='profile_trial' AND owner_id=?1",
            [capsule.operation_id().as_str()], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((slot_index, disposition)) = slot else {
            return Err("terminal profile trial receipt has no reserved execution slot".into());
        };
        if disposition != "released" {
            tx.execute("UPDATE execution_slots SET disposition='released',controller_generation=?3 WHERE pool='agent' AND slot_index=?1 AND owner_kind='profile_trial' AND owner_id=?2",params![slot_index,capsule.operation_id().as_str(),generation]).map_err(|e|e.to_string())?;
        }
        let baseline_json: Option<String> = tx.query_row("SELECT receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='baseline'",params![receipt.authorization_id(),receipt.pair_index()],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        let candidate_json: Option<String> = tx.query_row("SELECT receipt_json FROM profile_trial_run_receipts WHERE authorization_id=?1 AND pair_index=?2 AND side='candidate'",params![receipt.authorization_id(),receipt.pair_index()],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        if let (Some(baseline_json), Some(candidate_json)) = (baseline_json, candidate_json) {
            let baseline: ProfileTrialRunReceipt =
                crate::protocol::parse_unique(baseline_json.as_bytes())?;
            let candidate: ProfileTrialRunReceipt =
                crate::protocol::parse_unique(candidate_json.as_bytes())?;
            let observation = TrialObservation {
                input_digest: baseline.input_digest().clone(),
                baseline: baseline.status(),
                candidate: candidate.status(),
            };
            let observation_json = super::canonical_json(&observation)?;
            tx.execute("INSERT INTO profile_trial_pairs(authorization_id,pair_index,input_digest,observation_json,created_at_unix) VALUES (?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",params![authorization.authorization_id,receipt.pair_index(),observation.input_digest.as_str(),observation_json,now_unix]).map_err(|e|e.to_string())?;
        }
        let mut stmt = tx.prepare("SELECT pair_index,observation_json FROM profile_trial_pairs WHERE authorization_id=?1 ORDER BY pair_index").map_err(|e|e.to_string())?;
        let rows = stmt
            .query_map([authorization.authorization_id.as_str()], |r| {
                Ok((r.get::<_, usize>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut trials = Vec::new();
        for row in rows {
            let (pair_index, json) = row.map_err(|e| e.to_string())?;
            trials.push(StoredTrial {
                pair_index,
                observation: crate::protocol::parse_unique(json.as_bytes())?,
            });
        }
        drop(stmt);
        let evidence = evaluate_trials(
            &trials
                .iter()
                .map(|t| t.observation.clone())
                .collect::<Vec<_>>(),
            authorization.pairs.len(),
        )
        .map_err(|e| e.to_string())?;
        let evidence_json = super::canonical_json(&evidence)?;
        let expected = authorization.pairs.len();
        let new_status = if trials.len() >= expected {
            "awaiting_approval"
        } else {
            "trialing"
        };
        tx.execute("UPDATE learning_candidates SET evidence_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![authorization.project_id.as_str(),authorization.candidate_id,authorization.candidate_digest.as_str(),evidence_json]).map_err(|e|e.to_string())?;
        set_candidate_revision_status(
            &tx,
            &authorization.project_id,
            &authorization.candidate_id,
            &authorization.candidate_digest,
            if new_status == "awaiting_approval" {
                CandidateStatus::AwaitingApproval
            } else {
                CandidateStatus::Trialing
            },
        )?;
        if trials.len() >= expected {
            tx.execute("UPDATE profile_trial_authorizations SET lifecycle='completed',updated_at_unix=?2 WHERE authorization_id=?1",params![authorization.authorization_id,now_unix]).map_err(|e|e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(TrialProgress { trials, evidence })
    }

    pub fn profile_trial_launch_capsule(
        &self,
        authorization_id: &str,
        pair_index: u8,
        side: TrialSide,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let side = if side == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        let row: Option<(String,String)> = self.connection.query_row("SELECT capsule_json,capsule_digest FROM profile_trial_launches WHERE authorization_id=?1 AND pair_index=?2 AND side=?3",params![authorization_id,pair_index,side],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        if super::content_digest(&json) != digest {
            return Err("stored profile trial capsule digest is invalid".into());
        }
        let capsule: ProfileTrialLaunchCapsule = crate::protocol::parse_unique(json.as_bytes())?;
        capsule.validate()?;
        Ok(Some(capsule))
    }

    pub fn profile_trial_authorization(
        &self,
        authorization_id: &str,
    ) -> Result<Option<ProfileTrialAuthorization>, String> {
        let row: Option<(String,String)> = self.connection.query_row(
            "SELECT authorization_json,authorization_digest FROM profile_trial_authorizations WHERE authorization_id=?1",
            [authorization_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.digest()?.as_str() != digest {
            return Err("stored profile trial authorization digest is invalid".into());
        }
        authorization.validate()?;
        Ok(Some(authorization))
    }

    /// Resolve only a still-pending batch authorization for the persisted
    /// human request. Host observers use this to reconstitute the exact
    /// subject before accepting a response; approved or terminal batches are
    /// not returned by this lookup.
    pub(crate) fn pending_profile_trial_authorization_for_request(
        &self,
        request_id: &HumanRequestId,
    ) -> Result<Option<ProfileTrialAuthorization>, String> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT authorization_json,authorization_digest FROM profile_trial_authorizations WHERE human_request_id=?1 AND lifecycle='pending'",
                [request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((json, digest)) = row else {
            return Ok(None);
        };
        let authorization: ProfileTrialAuthorization =
            crate::protocol::parse_unique(json.as_bytes())?;
        if authorization.human_request_id != *request_id
            || authorization.digest()?.as_str() != digest
        {
            return Err("stored pending profile trial authorization is invalid".into());
        }
        authorization.validate()?;
        Ok(Some(authorization))
    }

    /// A dispatcher retry after the Store commit but before outbox acknowledgement
    /// must replay this exact host receipt instead of starting the Agent again.
    pub(crate) fn profile_trial_terminal_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfileTrialRunReceipt>, String> {
        let row: Option<(String,u8,String,String)> = self.connection.query_row(
            "SELECT r.receipt_json,r.pair_index,r.side,r.receipt_digest FROM profile_trial_run_receipts r JOIN profile_trial_launches l USING(authorization_id,pair_index,side) WHERE l.operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((json, pair_index, side, digest)) = row else {
            return Ok(None);
        };
        if super::content_digest(&json) != digest {
            return Err("stored profile trial terminal receipt digest is invalid".into());
        }
        let receipt: ProfileTrialRunReceipt = crate::protocol::parse_unique(json.as_bytes())?;
        let authorization = self
            .profile_trial_authorization(receipt.authorization_id())?
            .ok_or("trial receipt authorization is missing")?;
        receipt.validate_against(&authorization)?;
        let expected_side = if receipt.side() == TrialSide::Baseline {
            "baseline"
        } else {
            "candidate"
        };
        if receipt.pair_index() != pair_index || expected_side != side {
            return Err("stored profile trial receipt has a mismatched launch scope".into());
        }
        Ok(Some(receipt))
    }

    /// Bounded controller cadence: accept at most one newly decided batch and
    /// materialize at most one next side-effect intent in this tick.
    pub fn tick_profile_trials(
        &mut self,
        generation: u64,
        now_unix: u64,
        max_agent_slots: u32,
        max_project_slots: u32,
    ) -> Result<Option<ProfileTrialLaunchCapsule>, String> {
        let pending: Vec<(String, String, String, String, String)> = {
            let mut stmt = self.connection.prepare(
                "SELECT authorization_id,authorization_json,request_json,rex_view_id,artifact_path FROM profile_trial_authorizations WHERE lifecycle='pending' ORDER BY created_at_unix,authorization_id LIMIT 32",
            ).map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        for (id, json, request_json, rex_view_id, artifact_path) in pending {
            let auth: ProfileTrialAuthorization = crate::protocol::parse_unique(json.as_bytes())?;
            if now_unix >= auth.expires_at_unix {
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|e| e.to_string())?;
                validate_active_generation(&tx, generation)?;
                tx.execute("UPDATE profile_trial_authorizations SET lifecycle='expired',updated_at_unix=?2 WHERE authorization_id=?1 AND lifecycle='pending'",params![id,now_unix]).map_err(|e|e.to_string())?;
                set_candidate_revision_status(
                    &tx,
                    &auth.project_id,
                    &auth.candidate_id,
                    &auth.candidate_digest,
                    CandidateStatus::Expired,
                )?;
                tx.commit().map_err(|e| e.to_string())?;
                continue;
            }
            let request_exists: bool = self
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM human_requests WHERE request_id=?1)",
                    [auth.human_request_id.as_str()],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if !request_exists {
                let request: HumanRuntimeRequest =
                    crate::protocol::parse_unique(request_json.as_bytes())?;
                self.register_human_request(
                    generation,
                    &request,
                    &Digest::parse(rex_view_id)?,
                    std::path::Path::new(&artifact_path),
                    now_unix,
                )?;
            }
            if self
                .accepted_human_approval(
                    &auth.human_request_id,
                    &auth.human_subject_digest,
                    &auth.human_configuration_digest,
                    &auth.human_policy_digest,
                    now_unix,
                )?
                .is_some()
            {
                self.accept_profile_trial_approval(generation, &id, now_unix)?;
                return self.next_profile_trial_launch(
                    generation,
                    &id,
                    now_unix,
                    max_agent_slots,
                    max_project_slots,
                );
            }
        }
        let authorized: Option<String> = self.connection.query_row(
            "SELECT authorization_id FROM profile_trial_authorizations WHERE lifecycle='authorized' ORDER BY authorized_at_unix,authorization_id LIMIT 1",
            [], |r| r.get(0),
        ).optional().map_err(|e|e.to_string())?;
        match authorized {
            Some(id) => self.next_profile_trial_launch(
                generation,
                &id,
                now_unix,
                max_agent_slots,
                max_project_slots,
            ),
            None => Ok(None),
        }
    }

    pub(crate) fn ensure_postmortem_published(
        &self,
        ticket_run_id: &TicketRunId,
    ) -> Result<(), String> {
        let operation: Option<String> = self.connection.query_row(
            "SELECT operation_id FROM knowledge_publications WHERE ticket_run_id=?1 AND state='published'",
            [ticket_run_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(|e| e.to_string())?;
        let Some(operation) = operation else {
            return Err("ticket cannot become Done before durable knowledge publication".into());
        };
        let operation_id = OperationId::parse(operation)?;
        if self.knowledge_publication_receipt(&operation_id)?.is_none() {
            return Err(
                "ticket cannot become Done before a valid knowledge publication receipt".into(),
            );
        }
        Ok(())
    }

    /// Read the immutable package and approval tuple required to replay a profile
    /// publication effect. The caller must still reload the opaque human receipt.
    pub fn profile_promotion_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfilePromotionIntent>, String> {
        type Row = (
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
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        );
        let row: Option<Row> = self.connection.query_row(
            "SELECT project_id,candidate_id,candidate_digest,evidence_digest,profile_id,role,manifest_digest,expected_config_revision,config_source,config_file,human_request_id,approval_subject_digest,profile_material_digest,approval_configuration_digest,approval_policy_digest,human_response_digest,approved_package_json,state FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?,r.get(17)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((
            project_id,
            candidate_id,
            candidate_digest,
            evidence_digest,
            profile_id,
            role,
            manifest,
            config_revision,
            source,
            config_file,
            request_id,
            subject,
            profile_material,
            configuration,
            policy,
            response,
            package_json,
            state,
        )) = row
        else {
            return Ok(None);
        };
        if !matches!(
            state.as_str(),
            "approved" | "publication_pending" | "published" | "activation_pending" | "active"
        ) {
            return Err(format!("profile promotion is terminally {state}"));
        }
        let project_id = ProjectId::parse(project_id)?;
        let candidate_digest = Digest::parse(candidate_digest)?;
        let evidence_digest = Digest::parse(evidence_digest)?;
        let profile_id = ProfileId::parse(profile_id)?;
        let manifest_digest = Digest::parse(manifest)?;
        let expected_config_revision = Digest::parse(config_revision)?;
        let human_request_id = HumanRequestId::parse(request_id)?;
        let approval_subject_digest = Digest::parse(subject)?;
        let profile_material_digest = Digest::parse(profile_material)?;
        let approval_configuration_digest = Digest::parse(configuration)?;
        let approval_policy_digest = Digest::parse(policy)?;
        let response_receipt_digest = Digest::parse(response)?;
        let role: crate::domain::types::Role = serde_json::from_str(&format!("\"{role}\""))
            .map_err(|e| format!("stored profile role is invalid: {e}"))?;
        if package_json.len() > MAX_RECORD_BYTES {
            return Err("stored approved profile package exceeds its limit".into());
        }
        let package: StoredApprovedProfilePackage = serde_json::from_str(&package_json)
            .map_err(|e| format!("stored approved profile package is invalid: {e}"))?;
        if package.project_id != project_id
            || package.profile_id != profile_id
            || package.role != role
            || package.candidate_digest != candidate_digest
            || package.human_request_id != human_request_id
            || package.approval_subject_digest != approval_subject_digest
            || package.profile_material_digest != profile_material_digest
            || package.approval_configuration_digest != approval_configuration_digest
            || package.approval_policy_digest != approval_policy_digest
            || package.response_receipt_digest != response_receipt_digest
            || package.config_revision != expected_config_revision
            || package.candidate_digest.as_str().is_empty()
            || crate::learning::manifest_digest(&package.files).map_err(|e| e.to_string())?
                != manifest_digest
        {
            return Err(
                "stored profile package does not match its immutable promotion identity".into(),
            );
        }
        let subject = crate::learning::profile_approval_subject_digest(
            &project_id,
            role,
            &profile_id,
            &package.candidate_digest,
            &package.files,
            &package.evidence,
            &expected_config_revision,
        )
        .map_err(|e| e.to_string())?;
        if subject != profile_material_digest
            || crate::learning::evidence_digest(&package.evidence).map_err(|e| e.to_string())?
                != evidence_digest
        {
            return Err("stored promotion subject or evidence digest is invalid".into());
        }
        Ok(Some(ProfilePromotionIntent {
            operation_id: operation_id.clone(),
            project_id,
            candidate_id,
            profile_id,
            role,
            manifest_digest,
            profile_material_digest,
            expected_config_revision,
            config_source: source,
            config_file,
            human_request_id,
            approval_subject_digest,
            approval_configuration_digest,
            approval_policy_digest,
            response_receipt_digest,
            package,
        }))
    }

    pub(crate) fn load_approved_profile_package(
        &self,
        intent: &ProfilePromotionIntent,
        now_unix: u64,
    ) -> Result<ProfilePackage, String> {
        let current = self
            .profile_promotion_intent(&intent.operation_id)?
            .ok_or("profile promotion intent disappeared")?;
        if current != *intent {
            return Err("profile promotion intent changed during dispatch".into());
        }
        let request_json: String = self
            .connection
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [intent.human_request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "profile promotion human request is missing".to_owned())?;
        let request: crate::human_runtime::HumanRuntimeRequest =
            crate::protocol::parse_unique(request_json.as_bytes())?;
        if request.purpose != crate::human_runtime::HumanPurpose::ProfilePromotion
            || request.subject.kind != crate::human_runtime::HumanSubjectKind::Profile
            || request.subject.project_id != intent.project_id
            || request.subject.subject_id != intent.candidate_id
            || request.subject.material_digest != intent.profile_material_digest
            || request.subject.configuration_digest != intent.approval_configuration_digest
            || request.subject.policy_digest != intent.approval_policy_digest
            || request.subject.digest().map_err(|e| e.to_string())?
                != intent.approval_subject_digest
        {
            return Err(
                "durable profile approval request no longer matches the approved package".into(),
            );
        }
        let receipt = self
            .accepted_human_approval(
                &intent.human_request_id,
                &intent.approval_subject_digest,
                &intent.approval_configuration_digest,
                &intent.approval_policy_digest,
                now_unix,
            )?
            .ok_or("profile promotion human approval is missing, stale, or expired")?;
        let stored = &intent.package;
        let package = crate::learning::profile_package_from_accepted_approval(
            &receipt,
            stored.project_id.clone(),
            stored.role,
            stored.profile_id.clone(),
            stored.candidate_digest.clone(),
            stored.evidence.clone(),
            stored.files.clone(),
            intent.approval_subject_digest.clone(),
            intent.profile_material_digest.clone(),
            stored.config_revision.clone(),
            stored.approval_configuration_digest.clone(),
            stored.approval_policy_digest.clone(),
            now_unix,
        )
        .map_err(|e| e.to_string())?;
        let claims = validated_promotion_claims(&package).map_err(|e| e.to_string())?;
        if claims.human_request_id != stored.human_request_id
            || claims.approval_subject_digest != stored.approval_subject_digest
            || claims.approval_configuration_digest != stored.approval_configuration_digest
            || claims.approval_policy_digest != stored.approval_policy_digest
            || claims.response_receipt_digest != stored.response_receipt_digest
            || claims.rationale != stored.rationale
            || claims.authorized_at != stored.authorized_at
        {
            return Err("current human receipt differs from the immutable approved package".into());
        }
        Ok(package)
    }

    pub fn profile_publication_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<ProfilePublicationReceipt>, String> {
        let row: Option<(String, Option<String>, String)> = self.connection.query_row(
            "SELECT state,publication_receipt_json,manifest_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((state, json, expected_manifest)) = row else {
            return Ok(None);
        };
        if !matches!(
            state.as_str(),
            "published" | "activation_pending" | "active"
        ) {
            return Ok(None);
        }
        let stored: StoredProfilePublicationReceipt = serde_json::from_str(
            json.as_deref()
                .ok_or("published profile has no durable receipt")?,
        )
        .map_err(|e| format!("stored profile receipt is invalid: {e}"))?;
        if stored.manifest_digest.as_str() != expected_manifest {
            return Err("stored profile receipt manifest differs from approved intent".into());
        }
        let response: String = self
            .connection
            .query_row(
                "SELECT human_response_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if stored.human_response_receipt_digest.as_str() != response {
            return Err("stored profile receipt belongs to a different human response".into());
        }
        Ok(Some(ProfilePublicationReceipt {
            profile_path: std::path::PathBuf::from(stored.profile_path),
            profile_manifest_digest: stored.manifest_digest,
            human_response_receipt_digest: stored.human_response_receipt_digest,
            status: if stored.already_published {
                ProfilePublicationStatus::AlreadyPublished
            } else {
                ProfilePublicationStatus::Published
            },
        }))
    }

    /// Load the exact durable request for an outbox effect. The effect runner
    /// must use this stored input rather than any Agent-supplied replay payload.
    pub fn knowledge_publication_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<KnowledgePublicationIntent>, String> {
        let row: Option<(String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT project_id,ticket_run_id,request_digest,request_json,state FROM knowledge_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((project_id, ticket_run_id, request_digest, request_json, state)) = row else {
            return Ok(None);
        };
        if !matches!(state.as_str(), "prepared" | "published" | "uncertain") {
            return Err(format!("knowledge publication is terminally {state}"));
        }
        let request_digest = Digest::parse(request_digest)?;
        verify_digest(&request_json, &request_digest)?;
        let request: PostmortemInput = serde_json::from_str(&request_json)
            .map_err(|error| format!("stored postmortem request is invalid: {error}"))?;
        let project_id = ProjectId::parse(project_id)?;
        let ticket_run_id = TicketRunId::parse(ticket_run_id)?;
        if request.operation_id != *operation_id
            || request.project_id != project_id
            || request.ticket_run_id != ticket_run_id
        {
            return Err("stored knowledge request does not match its durable identity".into());
        }
        validate_postmortem_input(&request).map_err(|error| error.to_string())?;
        Ok(Some(KnowledgePublicationIntent {
            operation_id: operation_id.clone(),
            project_id,
            ticket_run_id,
            request_digest,
            request_json,
        }))
    }

    /// Return the committed terminal receipt, if publication completed before
    /// the generic dispatcher recorded its outbox receipt.
    pub fn knowledge_publication_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<KnowledgePublicationReceipt>, String> {
        let row: Option<(String, Option<String>, Option<String>)> = self
            .connection
            .query_row(
                "SELECT state,manifest_json,manifest_digest FROM knowledge_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((state, manifest_json, manifest_digest)) = row else {
            return Ok(None);
        };
        if state != "published" {
            return Ok(None);
        }
        let manifest: PublicationManifest = serde_json::from_str(
            manifest_json
                .as_deref()
                .ok_or("published knowledge row has no manifest")?,
        )
        .map_err(|error| format!("stored publication manifest is invalid: {error}"))?;
        let manifest_digest =
            Digest::parse(manifest_digest.ok_or("published knowledge row has no digest")?)?;
        let canonical = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&canonical)) != manifest_digest.as_str() {
            return Err("stored publication receipt digest is invalid".into());
        }
        if manifest.operation_id != *operation_id {
            return Err("stored publication receipt has a different operation ID".into());
        }
        Ok(Some(KnowledgePublicationReceipt {
            manifest,
            manifest_digest,
        }))
    }

    pub(crate) fn supervisor_topic_intent(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<crate::topic::TopicIntent>, String> {
        let row: Option<(String, String, String, String, i64, Option<String>)> = self.connection.query_row(
            "SELECT intent_json,intent_digest,project_id,destination_root,revision,prior_content_digest FROM supervisor_topic_publications WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((
            intent_json,
            intent_digest,
            project_id,
            destination_root,
            revision,
            prior_digest,
        )) = row
        else {
            return Ok(None);
        };
        verify_digest(&intent_json, &Digest::parse(intent_digest)?)?;
        let intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(intent_json.as_bytes())?;
        if intent.operation_id != operation_id.as_str()
            || crate::topic::expected_operation_id(&intent)? != intent.operation_id
            || intent.project_id.as_str() != project_id
            || intent.destination_root.to_string_lossy() != destination_root
            || i64::try_from(intent.revision).ok() != Some(revision)
            || intent.expected_prior_digest.as_ref().map(Digest::as_str) != prior_digest.as_deref()
            || crate::topic::validate_version_identity(&intent).is_err()
            || !intent.destination_root.is_absolute()
            || intent.content_digest != crate::topic::content_digest(&intent.content)
        {
            return Err(
                "stored Supervisor Topic intent does not match its immutable identity".into(),
            );
        }
        Ok(Some(intent))
    }

    pub(crate) fn supervisor_topic_conflict_reason(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<String>, String> {
        let conflict_json: Option<String> = self
            .connection
            .query_row(
                "SELECT conflict_json FROM supervisor_topic_publications WHERE operation_id=?1 AND state='conflict'",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(conflict_json) = conflict_json else {
            return Ok(None);
        };
        let conflict: serde_json::Value = crate::protocol::parse_unique(conflict_json.as_bytes())?;
        let reason = conflict
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .filter(|reason| !reason.trim().is_empty())
            .ok_or("stored Topic conflict has no reason")?;
        if conflict
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            != Some(operation_id.as_str())
            || conflict.get("state").and_then(serde_json::Value::as_str) != Some("conflict")
        {
            return Err("stored Topic conflict does not match its operation".into());
        }
        Ok(Some(reason.to_owned()))
    }

    pub(crate) fn supervisor_topic_intent_digest(
        &self,
        operation_id: &OperationId,
    ) -> Result<String, String> {
        let digest: String = self
            .connection
            .query_row(
                "SELECT intent_digest FROM supervisor_topic_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        Ok(Digest::parse(digest)?.to_string())
    }

    pub(crate) fn supervisor_topic_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<crate::topic::TopicReceipt>, String> {
        let row: Option<(String, Option<String>, Option<String>)> = self.connection.query_row(
            "SELECT state,receipt_json,receipt_digest FROM supervisor_topic_publications WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((state, json, digest)) = row else {
            return Ok(None);
        };
        if state != "published" {
            return Ok(None);
        }
        let json = json.ok_or("published Topic row has no receipt")?;
        let digest = Digest::parse(digest.ok_or("published Topic row has no receipt digest")?)?;
        verify_digest(&json, &digest)?;
        let receipt: crate::topic::TopicReceipt = crate::protocol::parse_unique(json.as_bytes())?;
        let intent = self
            .supervisor_topic_intent(operation_id)?
            .ok_or("published Topic receipt has no durable intent")?;
        if receipt.manifest.operation_id != operation_id.as_str()
            || receipt.manifest.project_id != intent.project_id
            || receipt.manifest.topic_key != intent.key
            || receipt.manifest.format != "okf-0.2"
            || receipt.manifest.relative_path != crate::topic::publication_relative_path(&intent)?
            || receipt.manifest.content_sha256 != intent.content_digest
            || receipt.manifest.byte_count != intent.content.len()
            || receipt.manifest.source_finding_ids != sorted_source_ids(&intent.sources)
            || receipt.manifest.source_publication_digests
                != sorted_source_publication_digests(&intent.sources)
            || Digest::parse(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&receipt.manifest).map_err(|e| e.to_string())?)
            ))? != receipt.manifest_digest
        {
            return Err("stored Topic receipt has invalid identity".into());
        }
        Ok(Some(receipt))
    }

    pub(crate) fn record_supervisor_topic_conflict(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        reason: &str,
    ) -> Result<(), String> {
        let conflict_json = super::canonical_json(&serde_json::json!({
            "operation_id": operation_id.as_str(),
            "state": "conflict",
            "reason": reason,
        }))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let changed = tx.execute(
            "UPDATE supervisor_topic_publications SET state='conflict',conflict_json=?2 WHERE operation_id=?1 AND state='pending'",
            params![operation_id.as_str(), conflict_json],
        ).map_err(|e| e.to_string())?;
        if changed != 1 {
            let existing: Option<String> = tx.query_row(
                "SELECT conflict_json FROM supervisor_topic_publications WHERE operation_id=?1 AND state='conflict'",
                [operation_id.as_str()],
                |row| row.get(0),
            ).optional().map_err(|e| e.to_string())?;
            if existing.as_deref() != Some(conflict_json.as_str()) {
                return Err(
                    "Topic publication conflict lacks a pending intent or changed on replay".into(),
                );
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub(crate) fn record_supervisor_topic_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        receipt: &crate::topic::TopicReceipt,
    ) -> Result<bool, String> {
        let receipt_json = super::canonical_json(receipt)?;
        let receipt_digest = Digest::parse(super::content_digest(&receipt_json))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(SupervisorTopicPublicationDbRow, i64, Option<String>)> = tx.query_row(
            "SELECT project_id,topic_key,destination_root,intent_json,receipt_json,receipt_digest,revision,prior_content_digest FROM supervisor_topic_publications WHERE operation_id=?1 AND state IN ('pending','published')",
            [operation_id.as_str()],
            |row| Ok((SupervisorTopicPublicationDbRow { project_id: row.get(0)?, topic_key: row.get(1)?, destination_root: row.get(2)?, intent_json: row.get(3)?, receipt_json: row.get(4)?, receipt_digest: row.get(5)? }, row.get(6)?, row.get(7)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((row, ledger_revision, ledger_prior_digest)) = row else {
            return Err("Topic receipt has no durable pending intent".into());
        };
        let SupervisorTopicPublicationDbRow {
            project_id: project,
            topic_key: key,
            destination_root: root,
            intent_json,
            receipt_json: old_json,
            receipt_digest: old_digest,
        } = row;
        let intent_digest: String = tx
            .query_row(
                "SELECT intent_digest FROM supervisor_topic_publications WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        verify_digest(&intent_json, &Digest::parse(intent_digest)?)?;
        let intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(intent_json.as_bytes())?;
        let expected_path = crate::topic::publication_relative_path(&intent)?;
        if intent.project_id.as_str() != project
            || intent.key.as_str() != key
            || intent.destination_root.to_string_lossy() != root
            || intent.operation_id != operation_id.as_str()
            || i64::try_from(intent.revision).ok() != Some(ledger_revision)
            || intent.expected_prior_digest.as_ref().map(Digest::as_str)
                != ledger_prior_digest.as_deref()
            || crate::topic::expected_operation_id(&intent)? != intent.operation_id
            || intent.content_digest != crate::topic::content_digest(&intent.content)
            || receipt.manifest.project_id != intent.project_id
            || receipt.manifest.topic_key != intent.key
            || receipt.manifest.operation_id != operation_id.as_str()
            || receipt.manifest.relative_path != expected_path
            || receipt.manifest.format != "okf-0.2"
            || receipt.manifest.content_sha256 != intent.content_digest
            || receipt.manifest.byte_count != intent.content.len()
            || receipt.manifest.source_finding_ids != sorted_source_ids(&intent.sources)
            || receipt.manifest.source_publication_digests
                != sorted_source_publication_digests(&intent.sources)
            || receipt.manifest_digest
                != Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&receipt.manifest).map_err(|e| e.to_string())?
                    )
                ))?
        {
            return Err("Topic receipt does not match its exact durable intent".into());
        }
        if old_json.is_some() {
            if old_json.as_deref() != Some(receipt_json.as_str())
                || old_digest.as_deref() != Some(receipt_digest.as_str())
            {
                return Err("Topic publication receipt changed on replay".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        tx.execute("UPDATE supervisor_topic_publications SET state='published',receipt_json=?2,receipt_digest=?3,published_at_unix=?4 WHERE operation_id=?1 AND state='pending'", params![operation_id.as_str(),receipt_json,receipt_digest.as_str(),receipt.published_at_unix]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Persist the immutable postmortem request before filesystem publication.
    pub fn prepare_knowledge_publication(
        &mut self,
        generation: u64,
        intent: &KnowledgePublicationIntent,
    ) -> Result<bool, String> {
        verify_digest(&intent.request_json, &intent.request_digest)?;
        if intent.request_json.len() > MAX_RECORD_BYTES {
            return Err("knowledge request exceeds size limit".into());
        }
        let request: PostmortemInput = serde_json::from_str(&intent.request_json)
            .map_err(|error| format!("invalid postmortem request: {error}"))?;
        validate_postmortem_input(&request).map_err(|error| error.to_string())?;
        if request.operation_id != intent.operation_id
            || request.project_id != intent.project_id
            || request.ticket_run_id != intent.ticket_run_id
        {
            return Err("postmortem request does not match durable operation subject".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let old: Option<(String,String)> = tx.query_row("SELECT request_digest,request_json FROM knowledge_publications WHERE operation_id=?1",[intent.operation_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        if let Some((digest, json)) = old {
            if digest != intent.request_digest.as_str() || json != intent.request_json {
                return Err("knowledge operation ID reused with different content".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        let current_run: Option<(u64, String)> = tx.query_row(
            "SELECT revision,internal_phase FROM ticket_runs WHERE ticket_run_id=?1 AND project_id=?2",
            params![intent.ticket_run_id.as_str(), intent.project_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        let (revision, phase) = current_run.ok_or("knowledge ticket run no longer exists")?;
        if phase != "postmortem" {
            return Err("knowledge publication can only begin during the Postmortem phase".into());
        }
        tx.execute("INSERT INTO knowledge_publications(operation_id,project_id,ticket_run_id,request_digest,request_json,state,created_at_unix) VALUES (?1,?2,?3,?4,?5,'prepared',?6)",params![intent.operation_id.as_str(),intent.project_id.as_str(),intent.ticket_run_id.as_str(),intent.request_digest.as_str(),intent.request_json,super::now_unix()?]).map_err(|e|e.to_string())?;
        let request_json = super::canonical_json(&serde_json::json!({
            "operation_id": intent.operation_id.as_str(),
            "request_digest": intent.request_digest.as_str(),
        }))?;
        let effect = super::EffectIntent {
            project_id: intent.project_id.clone(),
            subject_type: "ticket_run".into(),
            subject_id: intent.ticket_run_id.to_string(),
            operation_id: intent.operation_id.to_string(),
            logical_key: format!("publish-knowledge-{}", intent.ticket_run_id),
            kind: "publish_knowledge".into(),
            request_digest: super::content_digest(&request_json),
            request_json,
            expected_revision: Some(revision),
        };
        super::insert_effect(&tx, &effect, super::now_unix()?)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Persist an immutable publication receipt. Replays must match its exact manifest.
    pub fn record_knowledge_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        manifest: &PublicationManifest,
        manifest_digest: &Digest,
    ) -> Result<bool, String> {
        let json = serde_json::to_string(manifest).map_err(|e| e.to_string())?;
        verify_digest(&json, manifest_digest)?;
        if manifest.operation_id != *operation_id {
            return Err("publication operation ID mismatch".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<PublicationDbRow> = tx.query_row("SELECT project_id,ticket_run_id,state,request_json,manifest_json,manifest_digest FROM knowledge_publications WHERE operation_id=?1",[operation_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|e|e.to_string())?;
        let Some((project, run, state, request_json, old_json, old_digest)) = row else {
            return Err("publication receipt has no durable intent".into());
        };
        if project != manifest.project_id.as_str() || run != manifest.ticket_run_id.as_str() {
            return Err("publication receipt subject mismatch".into());
        }
        let request: PostmortemInput = serde_json::from_str(&request_json)
            .map_err(|error| format!("stored postmortem request is invalid: {error}"))?;
        let mut expected_sources = request
            .sources
            .iter()
            .map(|source| source.digest.clone())
            .collect::<Vec<_>>();
        expected_sources.sort();
        let key = format!(
            "{:x}",
            Sha256::digest(request.ticket_run_id.as_str().as_bytes())
        );
        let expected_path = format!(
            "projects/{}/postmortems/{key}.md",
            request.project_id.as_str()
        );
        if manifest.operation_id != request.operation_id
            || manifest.project_id != request.project_id
            || manifest.ticket_run_id != request.ticket_run_id
            || manifest.format != "okf-0.2"
            || manifest.relative_path != expected_path
            || manifest.byte_count > DEFAULT_MAX_ARTICLE_BYTES
            || manifest.source_digests != expected_sources
        {
            return Err(
                "publication manifest does not match the durable postmortem request".into(),
            );
        }
        if state == "published" {
            if old_json.as_deref() == Some(json.as_str())
                && old_digest.as_deref() == Some(manifest_digest.as_str())
            {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err("immutable publication receipt conflict".into());
        }
        if state != "prepared" {
            return Err(format!("knowledge operation is {state}, not prepared"));
        }
        tx.execute("UPDATE knowledge_publications SET state='published',manifest_json=?2,manifest_digest=?3,published_at_unix=?4 WHERE operation_id=?1 AND state='prepared'",params![operation_id.as_str(),json,manifest_digest.as_str(),super::now_unix()?]).map_err(|e|e.to_string())?;
        let source_digests_json =
            serde_json::to_string(&manifest.source_digests).map_err(|e| e.to_string())?;
        for (ordinal, text) in request.findings.iter().enumerate() {
            let ordinal =
                u32::try_from(ordinal).map_err(|_| "Finding ordinal exceeds supported range")?;
            let finding_id = learning_finding_id(manifest_digest, ordinal, text)?;
            tx.execute("INSERT INTO learning_findings(finding_id,project_id,ticket_run_id,publication_digest,ordinal,finding_text,source_digests_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![finding_id.as_str(), request.project_id.as_str(), request.ticket_run_id.as_str(), manifest_digest.as_str(), ordinal, text, source_digests_json, super::now_unix()?]).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Reconstruct exact candidate bytes from the immutable bounded manifest.
    /// The digest is revalidated before host review code can observe them.
    pub fn learning_candidate_package(
        &self,
        project: &ProjectId,
        candidate_id: &str,
        candidate_digest: &Digest,
    ) -> Result<Option<LearningCandidatePackage>, String> {
        let row: Option<(String, String, String, String, Option<String>)> = self.connection.query_row(
            "SELECT revision_json,profile_id,package_manifest_digest,package_files_json,evidence_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![project.as_str(),candidate_id,candidate_digest.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((revision_json, profile_id, manifest_raw, files_json, evidence_json)) = row else {
            return Ok(None);
        };
        let revision: CandidateRevision = crate::protocol::parse_unique(revision_json.as_bytes())?;
        let profile_id = ProfileId::parse(profile_id)?;
        let manifest_digest = Digest::parse(manifest_raw)?;
        let files: std::collections::BTreeMap<String, Vec<u8>> =
            crate::protocol::parse_unique(files_json.as_bytes())?;
        if revision.project_id != *project
            || revision.candidate_id != candidate_id
            || revision.digest != *candidate_digest
            || serde_json::to_string(&files).map_err(|e| e.to_string())? != files_json
            || crate::learning::manifest_digest(&files).map_err(|e| e.to_string())?
                != manifest_digest
        {
            return Err(
                "stored candidate files do not match the immutable candidate identity".into(),
            );
        }
        let evidence = evidence_json
            .map(|json| crate::protocol::parse_unique(json.as_bytes()))
            .transpose()?;
        Ok(Some(LearningCandidatePackage {
            revision,
            profile_id,
            manifest_digest,
            files,
            evidence,
        }))
    }

    pub(crate) fn resolve_provider_qualification_candidate(
        &self,
        request: &crate::store::provider_qualification_runtime::ProviderQualificationRequest,
        applied: &crate::config::AppliedConfig,
    ) -> Result<crate::config::Profile, String> {
        use crate::store::provider_qualification_runtime::ProviderQualificationTarget;
        let ProviderQualificationTarget::Candidate {
            candidate_id,
            candidate_digest,
        } = &request.target
        else {
            return Err("provider qualification request does not target a candidate".into());
        };
        if applied.digest != request.config_digest {
            return Err("candidate qualification config changed after request".into());
        }
        let current: Option<(u64, String)> = self
            .connection
            .query_row(
                "SELECT config_revision,config_digest FROM projects WHERE project_id=?1",
                [request.project_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if current != Some((request.config_revision, request.config_digest.to_string())) {
            return Err(
                "candidate qualification request is stale for the current Project config".into(),
            );
        }
        let status: Option<String> = self.connection.query_row(
            "SELECT status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![request.project_id.as_str(), candidate_id, candidate_digest.as_str()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if status.as_deref() != Some("proposed") {
            return Err("candidate is no longer eligible for provider qualification".into());
        }
        let package = self
            .learning_candidate_package(&request.project_id, candidate_id, candidate_digest)?
            .ok_or("exact candidate package is missing")?;
        if package.revision.status != CandidateStatus::Proposed
            || package.revision.digest != *candidate_digest
        {
            return Err("candidate revision is not the exact proposed target".into());
        }
        let metadata: crate::learning::ProfileCandidateMetadata = crate::protocol::parse_unique(
            package
                .files
                .get(crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
                .ok_or("candidate metadata is missing")?,
        )?;
        let rows = package
            .files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    Digest::parse(format!("{:x}", Sha256::digest(bytes)))
                        .expect("SHA-256 digest is valid"),
                )
            })
            .collect::<Vec<_>>();
        let package_json = serde_json::to_string(&rows).map_err(|error| error.to_string())?;
        validate_profile_candidate_metadata(
            &request.project_id,
            &package.revision,
            &package.profile_id,
            &package.manifest_digest,
            &package.files,
            &package_json,
            &metadata,
        )?;
        let projects = &applied.config.projects;
        let project = projects
            .get(&request.project_id)
            .ok_or("candidate Project is absent from applied config")?;
        let mut bindings = crate::config::effective_project_roles(&request.project_id, projects)?
            .into_iter()
            .collect::<Vec<_>>();
        for matched in &project.operation_matches {
            if let Some(recipe) = applied.config.operation_recipes.get(&matched.recipe) {
                bindings.extend(
                    recipe
                        .roles
                        .iter()
                        .map(|(role, profile)| (*role, profile.clone())),
                );
            }
        }
        if !bindings
            .iter()
            .any(|(role, profile)| *role == request.role && *profile == metadata.base_profile_id)
        {
            return Err("candidate base profile is not bound to this role by the current Project or selected recipe".into());
        }
        let base = applied
            .profiles
            .get(&metadata.base_profile_id)
            .ok_or("candidate base profile is absent from applied config")?;
        if crate::store::agent_profile_digest(base)? != metadata.base_profile_digest
            || metadata.project_id != request.project_id
            || metadata.role != request.role
            || metadata.profile_id != package.profile_id
            || metadata.config_revision.0 != request.config_revision
            || metadata.config_digest != request.config_digest
            || package.revision.project_id != request.project_id
            || package.revision.role != request.role
            || package.profile_id != request.profile_id
        {
            return Err("candidate package metadata does not match the qualification request and current config".into());
        }
        let profile: crate::config::Profile = toml::from_str(
            std::str::from_utf8(
                package
                    .files
                    .get("config.toml")
                    .ok_or("candidate config.toml is missing")?,
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("candidate config.toml is invalid: {error}"))?;
        if crate::store::agent_profile_digest(&profile)? != request.profile_digest {
            return Err("candidate profile digest differs from the qualification request".into());
        }
        Ok(profile)
    }

    /// Resolve the single currently approval-eligible revision by its stable
    /// candidate ID. Ambiguous IDs fail closed instead of choosing by recency.
    pub fn current_learning_candidate_package(
        &self,
        project: &ProjectId,
        candidate_id: &str,
    ) -> Result<Option<LearningCandidatePackage>, String> {
        let mut statement = self.connection.prepare(
            "SELECT digest FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND status='awaiting_approval' ORDER BY digest",
        ).map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(params![project.as_str(), candidate_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| e.to_string())?;
        let digests = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(statement);
        match digests.as_slice() {
            [] => Ok(None),
            [digest] => self.learning_candidate_package(
                project,
                candidate_id,
                &Digest::parse(digest.clone())?,
            ),
            _ => Err("candidate ID has multiple approval-eligible revisions".into()),
        }
    }

    pub fn register_learning_candidate(
        &mut self,
        generation: u64,
        record: &LearningCandidateRecord,
    ) -> Result<CandidateRegistration, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let registration = register_learning_candidate_in_transaction(&tx, generation, record)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(registration)
    }

    /// One bounded per-project maintenance snapshot for a Supervisor tick.
    /// Expiration is persisted before the snapshot is returned so a crash/retry
    /// sees the same terminal candidate revisions and cannot extend their TTL.
    pub fn maintain_project_supervisor_learning(
        &mut self,
        generation: u64,
        project: &ProjectId,
        now_utc: &str,
        knowledge_limit: usize,
        topic_destination_root: Option<&std::path::Path>,
    ) -> Result<ProjectSupervisorMaintenance, String> {
        if knowledge_limit == 0 || knowledge_limit > MAX_SUPERVISOR_KNOWLEDGE_ITEMS {
            return Err("Supervisor knowledge batch size is outside the configured bound".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let project_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=?1)",
                [project.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !project_exists {
            return Err("Supervisor learning tick references an unknown project".into());
        }
        let snapshot = supervisor_learning_snapshot_in_transaction(
            &tx,
            project,
            now_utc,
            knowledge_limit,
            topic_destination_root,
        )?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(snapshot)
    }

    /// At most one due Project per controller tick gets a bounded learning
    /// snapshot and a durable Supervisor wake. The wake and next due time commit
    /// together; a crash cannot lose a completed maintenance batch.
    pub fn queue_due_supervisor_learning(
        &mut self,
        generation: u64,
        configured_projects: &[ProjectId],
        now_unix: i64,
        interval_seconds: u64,
        topic_destination_root: Option<&std::path::Path>,
    ) -> Result<Option<ProjectId>, String> {
        if now_unix < 0 || interval_seconds == 0 {
            return Err("Supervisor learning schedule requires positive bounded timing".into());
        }
        let configured = configured_projects
            .iter()
            .map(ProjectId::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let now_utc =
            crate::learning::unix_seconds_to_utc(now_unix as u64).map_err(|e| e.to_string())?;
        let next_due = now_unix
            .checked_add(
                i64::try_from(interval_seconds)
                    .map_err(|_| "learning interval exceeds supported range")?,
            )
            .ok_or("Supervisor learning due time overflow")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let mut projects = tx.prepare("SELECT p.project_id,p.config_revision,p.config_digest,COALESCE(s.next_due_at_unix,0) FROM projects p JOIN project_runtimes r USING(project_id) LEFT JOIN supervisor_learning_schedule s USING(project_id) WHERE p.desired_lifecycle='running' AND r.observed_lifecycle='running' AND r.controller_generation=?1 ORDER BY COALESCE(s.next_due_at_unix,0),p.project_id").map_err(|e|e.to_string())?;
        let candidates = projects
            .query_map(params![generation], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        drop(projects);
        for (project_raw, config_revision, config_digest, due) in candidates {
            if !configured.contains(project_raw.as_str()) {
                continue;
            }
            let already_issued: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM learning_batches WHERE project_id=?1 AND status='issued')", [&project_raw], |r| r.get(0)).map_err(|e|e.to_string())?;
            if already_issued {
                continue;
            }
            let legacy_pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM role_wake_inputs WHERE project_id=?1 AND source_type='learning_maintenance' AND lifecycle IN ('pending','assigned','claimed'))", [&project_raw], |r| r.get(0)).map_err(|e|e.to_string())?;
            if legacy_pending {
                continue;
            }
            let unconsumed: i64 = tx.query_row("SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id IS NULL", [&project_raw], |r| r.get(0)).map_err(|e|e.to_string())?;
            let periodic_due = due <= now_unix;
            if usize::try_from(unconsumed).unwrap_or(0) < LEARNING_BATCH_TRIGGER_FINDINGS
                && !periodic_due
            {
                continue;
            }
            let project = ProjectId::parse(project_raw.clone())?;
            let mut stmt = tx.prepare("SELECT finding_id,ticket_run_id,publication_digest,ordinal,finding_text,source_digests_json FROM learning_findings WHERE project_id=?1 AND consumed_batch_id IS NULL ORDER BY created_at_unix,ticket_run_id,ordinal LIMIT ?2").map_err(|e|e.to_string())?;
            let findings = stmt
                .query_map(
                    params![project.as_str(), LEARNING_BATCH_MAX_FINDINGS as i64],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, u32>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, String>(5)?,
                        ))
                    },
                )
                .map_err(|e| e.to_string())?
                .map(|row| {
                    row.map_err(|e| e.to_string()).and_then(
                        |(id, run, pub_digest, ordinal, text, source_digests_json)| {
                            Ok(LearningFinding {
                                id: Digest::parse(id)?,
                                ticket_run_id: TicketRunId::parse(run)?,
                                publication_digest: Digest::parse(pub_digest)?,
                                ordinal,
                                text,
                                source_digests: crate::protocol::parse_unique(
                                    source_digests_json.as_bytes(),
                                )?,
                            })
                        },
                    )
                })
                .collect::<Result<Vec<_>, String>>()?;
            drop(stmt);
            let checkpoint = latest_supervisor_checkpoint(&tx, &project_raw)?;
            let maintenance = supervisor_learning_snapshot_in_transaction(
                &tx,
                &project,
                &now_utc,
                0,
                topic_destination_root,
            )?;
            let mut findings = findings;
            let (base_snapshot, base_snapshot_json) = loop {
                let snapshot = serde_json::json!({"type":"supervisor_learning_batch","project_id":project.as_str(),"config_revision":config_revision,"config_digest":config_digest,"issued_at_unix":now_unix,"prior_checkpoint":&checkpoint,"maintenance":&maintenance,"findings":&findings});
                let json = super::canonical_json(&snapshot)?;
                if json.len() <= MAX_SUPERVISOR_BATCH_BYTES {
                    break (snapshot, json);
                }
                if findings.len() <= 1 {
                    return Err("Supervisor learning batch exceeds its aggregate byte limit".into());
                }
                findings.pop();
            };
            let digest = Digest::parse(format!("{:x}", Sha256::digest(&base_snapshot_json)))?;
            let batch_id = format!("learning-{}", digest.as_str());
            let mut payload_value = base_snapshot;
            payload_value["batch_id"] = serde_json::Value::String(batch_id.clone());
            payload_value["batch_digest"] = serde_json::Value::String(digest.to_string());
            let payload_json = super::canonical_json(&payload_value)?;
            let source_revision = due.max(1) as u64;
            tx.execute("INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'learning_batch',?3,?4,1,?5,'pending',?6)",params![project.as_str(),format!("project:{}:supervisor",project.as_str()),batch_id,source_revision,payload_json,now_unix]).map_err(|e|e.to_string())?;
            let wake_id = tx.last_insert_rowid();
            let findings_json = serde_json::to_string(&findings).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO learning_batches(batch_id,project_id,batch_digest,config_revision,config_digest,owner_generation,wake_input_id,findings_json,snapshot_json,status,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'issued',?10)",params![batch_id,project.as_str(),digest.as_str(),config_revision,config_digest,generation,wake_id,findings_json,payload_json,now_unix]).map_err(|e|e.to_string())?;
            if periodic_due {
                tx.execute("INSERT INTO supervisor_learning_schedule(project_id,next_due_at_unix,last_run_at_unix,last_snapshot_digest) VALUES (?1,?2,?3,?4) ON CONFLICT(project_id) DO UPDATE SET next_due_at_unix=excluded.next_due_at_unix,last_run_at_unix=excluded.last_run_at_unix,last_snapshot_digest=excluded.last_snapshot_digest",params![project.as_str(),next_due,now_unix,digest.as_str()]).map_err(|e|e.to_string())?;
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(Some(project));
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(None)
    }

    pub fn consume_supervisor_learning_decision(
        &mut self,
        owner_generation: u64,
        result: &crate::store::agent_results::IngestedAgentResult,
        now_unix: i64,
        topic_destination_root: Option<&std::path::Path>,
    ) -> Result<(), String> {
        use crate::engine::orchestration::{AgentAssertion, RoleOutputKind, RoleResultPayload};
        if result.validated.kind != RoleOutputKind::LearningDecision
            || result.validated.binding.role != crate::domain::types::Role::Supervisor
            || result.validated.binding.ticket_run_id.is_some()
        {
            return Err("learning batch consumer received another result kind or authority".into());
        }
        let payload = match &result.validated.typed_payload {
            RoleResultPayload::LearningDecision(payload) => Some(payload),
            _ => None,
        };
        let binding = &result.validated.binding;
        if now_unix < 0 {
            return Err("learning decision belongs to another controller generation".into());
        }
        let terminal = crate::store::agent_results::verify_agent_terminal(
            self,
            owner_generation,
            &binding.agent_run_id,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let authority = validate_learning_run_owner(&tx, binding, &terminal)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT batch_id,result_digest FROM learning_decisions WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some((batch_id, digest)) = existing {
            if payload.is_none_or(|payload| batch_id != payload.batch_id)
                || digest != result.validated.result_digest.as_str()
            {
                return Err("learning result evidence was replayed with changed content".into());
            }
            let ack: Option<(u64,String)>=tx.query_row("SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",[result.receipt.evidence_id()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
            if ack != Some((binding.config_revision.0, "applied".into())) {
                return Err(
                    "accepted learning decision has no matching applied result acknowledgement"
                        .into(),
                );
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(());
        }
        let evidence: Option<(String,String,u64,String,String)>=tx.query_row("SELECT e.agent_run_id,e.project_id,e.run_epoch,e.role,e.result_digest FROM agent_result_evidence e WHERE e.evidence_id=?1 AND e.outcome='completed'",[result.receipt.evidence_id()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
        if !matches!(evidence,Some((ref run,ref p,epoch,ref role,ref result_digest)) if run==binding.agent_run_id.as_str() && p==binding.project_id.as_str() && epoch==binding.run_epoch && role=="supervisor" && result_digest==result.validated.result_digest.as_str())
        {
            return Err("learning result evidence is outside its Supervisor run authority".into());
        }
        let reservation_json: String = tx
            .query_row(
                "SELECT reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
                [binding.agent_run_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let reservation: crate::launch::AgentLaunchReservation =
            crate::protocol::parse_unique(reservation_json.as_bytes())?;
        reservation.validate()?;
        if reservation.project_id != binding.project_id
            || reservation.role != crate::domain::types::Role::Supervisor
            || reservation.config_revision != binding.config_revision
            || reservation.config_digest != binding.config_digest
            || reservation.run_epoch != binding.run_epoch
            || reservation.controller_generation != authority.controller_generation
            || reservation.wake_snapshot.content_digest()? != authority.wake_snapshot_digest
        {
            return Err(
                "learning result launch reservation does not match its batch authority".into(),
            );
        }
        let mut learning_wakes = reservation
            .wake_snapshot
            .inputs
            .iter()
            .filter(|wake| wake.source_type == "learning_batch");
        let wake = learning_wakes
            .next()
            .ok_or("Supervisor launch has no learning batch wake")?;
        if learning_wakes.next().is_some() {
            return Err("Supervisor launch has multiple learning batch wakes".into());
        }
        let batch: Option<LearningBatchDbRow>=tx.query_row(
            "SELECT project_id,batch_digest,config_revision,config_digest,wake_input_id,findings_json,snapshot_json,status FROM learning_batches WHERE batch_id=?1",
            [&wake.source_id], |r| Ok(LearningBatchDbRow { project: r.get(0)?, digest: r.get(1)?, config_revision: r.get(2)?, config_digest: r.get(3)?, wake_id: r.get(4)?, findings_json: r.get(5)?, snapshot_json: r.get(6)?, status: r.get(7)? }),
        ).optional().map_err(|error| error.to_string())?;
        let Some(LearningBatchDbRow {
            project,
            digest,
            config_revision,
            config_digest,
            wake_id,
            findings_json,
            snapshot_json,
            status,
        }) = batch
        else {
            return Err("immutable learning wake references a missing batch".into());
        };
        let snapshot_value: serde_json::Value =
            crate::protocol::parse_unique(snapshot_json.as_bytes())?;
        let mut digest_input = snapshot_value.clone();
        let object = digest_input
            .as_object_mut()
            .ok_or("stored learning batch snapshot is not an object")?;
        let stored_batch_id = object
            .remove("batch_id")
            .and_then(|value| value.as_str().map(str::to_owned));
        let stored_batch_digest = object
            .remove("batch_digest")
            .and_then(|value| value.as_str().map(str::to_owned));
        let calculated_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(super::canonical_json(&digest_input)?.as_bytes())
        ))?;
        if project != binding.project_id.as_str()
            || wake_id
                != i64::try_from(wake.wake_input_id).map_err(|_| "learning wake ID overflow")?
            || wake.source_id != format!("learning-{digest}")
            || stored_batch_id.as_deref() != Some(wake.source_id.as_str())
            || stored_batch_digest.as_deref() != Some(digest.as_str())
            || calculated_digest.as_str() != digest
            || wake.payload_json != snapshot_value
        {
            return Err("immutable learning wake or stored batch snapshot is invalid".into());
        }
        let stored_wake: Option<(String,String,String,String,String)>=tx.query_row("SELECT project_id,role_session_id,source_type,source_id,payload_json FROM role_wake_inputs WHERE wake_input_id=?1 AND consuming_agent_run_id=?2 AND lifecycle IN ('assigned','consumed')",params![wake_id,binding.agent_run_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
        let Some((wake_project, session, source_type, source_id, wake_payload)) = stored_wake
        else {
            return Err("learning batch wake was not assigned to the producing Agent run".into());
        };
        if wake_project != project
            || session != binding.role_session_id.as_str()
            || source_type != "learning_batch"
            || source_id != wake.source_id
            || wake_payload != snapshot_json
            || serde_json::to_string(&wake.payload_json).map_err(|e| e.to_string())? != wake_payload
        {
            return Err("learning batch wake differs from the exact issued snapshot".into());
        }
        let findings: Vec<LearningFinding> =
            crate::protocol::parse_unique(findings_json.as_bytes())?;
        let snapshot_findings: Vec<LearningFinding> = serde_json::from_value(
            snapshot_value
                .get("findings")
                .cloned()
                .ok_or("issued learning snapshot has no findings")?,
        )
        .map_err(|e| format!("issued learning snapshot findings are invalid: {e}"))?;
        if findings != snapshot_findings {
            return Err(
                "issued learning Finding ledger differs from the digest-bound snapshot".into(),
            );
        }
        let current: Option<(u64,String,String,String)>=tx.query_row("SELECT p.config_revision,p.config_digest,p.desired_lifecycle,r.observed_lifecycle FROM projects p JOIN project_runtimes r USING(project_id) WHERE p.project_id=?1",[&project],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|e|e.to_string())?;
        let mut rejection = match &result.validated.assertion {
            AgentAssertion::Failed { reason } => Some(format!(
                "Supervisor learning turn failed: {}",
                reason.chars().take(1024).collect::<String>()
            )),
            AgentAssertion::Blocked { reason } => Some(format!(
                "Supervisor learning turn was blocked: {}",
                reason.chars().take(1024).collect::<String>()
            )),
            AgentAssertion::Cancelled { reason } => Some(format!(
                "Supervisor learning turn was cancelled{}",
                reason
                    .as_deref()
                    .map(|reason| format!(": {}", reason.chars().take(1024).collect::<String>()))
                    .unwrap_or_default()
            )),
            AgentAssertion::Succeeded if payload.is_none() => {
                Some("Supervisor learning result has no supported decision payload".into())
            }
            AgentAssertion::Succeeded => None,
        };
        let mut topic_intents = Vec::new();
        let mut prepared_candidate = None;
        let mut rendered_topic_bytes = 0usize;
        if let Some(payload) = payload {
            let topic_changes_valid =
                crate::topic::validate_changes(&payload.topic_changes).is_ok();
            if !topic_changes_valid
                || !payload.improvements.is_empty()
                || payload.observations.is_empty()
                || payload.observations.len() > 20
                || payload
                    .observations
                    .iter()
                    .any(|value| value.trim().is_empty() || value.len() > 4096)
                || payload.checkpoint.len() > 32
                || payload
                    .checkpoint
                    .iter()
                    .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 1024)
            {
                rejection.get_or_insert_with(|| {
                    "Supervisor learning decision is unsupported or exceeds host bounds".into()
                });
            }
            if rejection.is_none() && payload.candidate_change.is_some() {
                match prepare_learning_candidate(
                    &tx,
                    &binding.project_id,
                    payload,
                    &snapshot_value,
                    &findings,
                    now_unix,
                ) {
                    Ok(candidate) => prepared_candidate = Some(candidate),
                    Err(error) => {
                        rejection
                            .get_or_insert_with(|| format!("candidate proposal rejected: {error}"));
                    }
                }
            }
            if !payload.topic_changes.is_empty() && topic_changes_valid {
                match topic_destination_root {
                    Some(root) if root.is_absolute() => {
                        for change in &payload.topic_changes {
                            let mut sources = Vec::new();
                            for source_id in &change.source_finding_ids {
                                match resolve_topic_source(&tx, &binding.project_id, source_id)? {
                                    Some(source) => sources.push(source),
                                    None => {
                                        rejection.get_or_insert_with(|| format!(
                                            "Topic source Finding `{source_id}` is not a published Finding in this Project"
                                        ));
                                    }
                                }
                            }
                            if sources.len() == change.source_finding_ids.len() {
                                let key = crate::topic::TopicKey::parse(&change.topic_key)?;
                                let history: Option<(Option<i64>, bool)> = Some(tx.query_row(
                                    "SELECT MAX(revision),EXISTS(SELECT 1 FROM supervisor_topic_publications p WHERE p.project_id=?1 AND p.topic_key=?2 AND p.state='pending') FROM supervisor_topic_publications WHERE project_id=?1 AND topic_key=?2",
                                    params![binding.project_id.as_str(), key.as_str()],
                                    |row| Ok((row.get(0)?, row.get(1)?)),
                                ).map_err(|error| error.to_string())?);
                                let max_revision = history
                                    .as_ref()
                                    .and_then(|(revision, _)| *revision)
                                    .map(|revision| {
                                        u64::try_from(revision)
                                            .map_err(|_| "stored Topic revision ordinal is invalid")
                                    })
                                    .transpose()?;
                                let prior_published: Option<PublishedTopicVersionDbRow> = tx.query_row(
                                    "SELECT operation_id,intent_json,intent_digest,receipt_json,receipt_digest,destination_root,revision,prior_content_digest FROM supervisor_topic_publications WHERE project_id=?1 AND topic_key=?2 AND state='published' ORDER BY revision DESC LIMIT 1",
                                    params![binding.project_id.as_str(), key.as_str()],
                                    |row| Ok(PublishedTopicVersionDbRow {
                                        operation_id: row.get(0)?,
                                        intent_json: row.get(1)?,
                                        intent_digest: row.get(2)?,
                                        receipt_json: row.get(3)?,
                                        receipt_digest: row.get(4)?,
                                        destination_root: row.get(5)?,
                                        revision: row.get(6)?,
                                        prior_content_digest: row.get(7)?,
                                    }),
                                ).optional().map_err(|error| error.to_string())?;
                                let issued_topics = snapshot_value
                                    .get("maintenance")
                                    .and_then(|value| value.get("topics"))
                                    .and_then(serde_json::Value::as_array);
                                let issued_prior = issued_topics.and_then(|topics| {
                                    topics.iter().find_map(|topic| {
                                        (topic.get("topic_key").and_then(serde_json::Value::as_str)
                                            == Some(key.as_str()))
                                        .then(|| {
                                            topic
                                                .get("content_digest")
                                                .and_then(serde_json::Value::as_str)
                                        })
                                        .flatten()
                                    })
                                });
                                let root_string = root.to_string_lossy().into_owned();
                                let prior_digest = match (
                                    &change.expected_prior_digest,
                                    &history,
                                    &prior_published,
                                ) {
                                    (_, Some((_, true)), _) => {
                                        rejection.get_or_insert_with(|| {
                                            format!(
                                                "Topic `{}` has a pending publication",
                                                key.as_str()
                                            )
                                        });
                                        None
                                    }
                                    (None, Some((None, false)), None) => None,
                                    (
                                        Some(expected),
                                        Some((Some(_), false)),
                                        Some(PublishedTopicVersionDbRow {
                                            operation_id: prior_operation_id,
                                            intent_json,
                                            intent_digest,
                                            receipt_json,
                                            receipt_digest,
                                            destination_root: prior_root,
                                            revision: prior_revision,
                                            prior_content_digest: prior_ledger_digest,
                                        }),
                                    ) => {
                                        verify_digest(
                                            intent_json,
                                            &Digest::parse(intent_digest.clone())?,
                                        )?;
                                        verify_digest(
                                            receipt_json,
                                            &Digest::parse(receipt_digest.clone())?,
                                        )?;
                                        let prior_intent: crate::topic::TopicIntent =
                                            crate::protocol::parse_unique(intent_json.as_bytes())?;
                                        let prior_receipt: crate::topic::TopicReceipt =
                                            crate::protocol::parse_unique(receipt_json.as_bytes())?;
                                        if prior_root != &root_string
                                            || prior_intent.operation_id != *prior_operation_id
                                            || prior_intent.destination_root.to_string_lossy()
                                                != root_string
                                            || i64::try_from(prior_intent.revision).ok()
                                                != Some(*prior_revision)
                                            || prior_intent
                                                .expected_prior_digest
                                                .as_ref()
                                                .map(Digest::as_str)
                                                != prior_ledger_digest.as_deref()
                                            || crate::topic::validate_version_identity(
                                                &prior_intent,
                                            )
                                            .is_err()
                                            || crate::topic::expected_operation_id(&prior_intent)?
                                                != prior_intent.operation_id
                                            || prior_intent.content_digest
                                                != crate::topic::content_digest(
                                                    &prior_intent.content,
                                                )
                                            || prior_receipt.manifest.operation_id
                                                != prior_intent.operation_id
                                            || prior_receipt.manifest.project_id
                                                != binding.project_id
                                            || prior_receipt.manifest.topic_key != key
                                            || prior_receipt.manifest.content_sha256
                                                != prior_intent.content_digest
                                            || prior_receipt.manifest.byte_count
                                                != prior_intent.content.len()
                                            || prior_receipt.manifest.format != "okf-0.2"
                                            || prior_receipt.manifest.relative_path
                                                != crate::topic::publication_relative_path(
                                                    &prior_intent,
                                                )?
                                            || prior_receipt.manifest.source_finding_ids
                                                != sorted_source_ids(&prior_intent.sources)
                                            || prior_receipt.manifest.source_publication_digests
                                                != sorted_source_publication_digests(
                                                    &prior_intent.sources,
                                                )
                                            || prior_receipt.manifest_digest
                                                != Digest::parse(format!(
                                                    "{:x}",
                                                    Sha256::digest(
                                                        serde_json::to_vec(
                                                            &prior_receipt.manifest,
                                                        )
                                                        .map_err(|e| e.to_string())?
                                                    )
                                                ))?
                                            || prior_intent.content_digest != *expected
                                            || issued_prior != Some(expected.as_str())
                                        {
                                            rejection.get_or_insert_with(|| format!("Topic `{}` prior digest is stale or was not present in the issued learning batch", key.as_str()));
                                            None
                                        } else {
                                            Some(expected.clone())
                                        }
                                    }
                                    (None, _, _) => {
                                        rejection.get_or_insert_with(|| {
                                            format!(
                                                "Topic `{}` already has publication history",
                                                key.as_str()
                                            )
                                        });
                                        None
                                    }
                                    (Some(_), _, _) => {
                                        rejection.get_or_insert_with(|| format!("Topic `{}` prior digest does not match a published version", key.as_str()));
                                        None
                                    }
                                };
                                if rejection.is_some() {
                                    continue;
                                }
                                let revision = match max_revision {
                                    Some(revision) => match revision.checked_add(1) {
                                        Some(revision) if prior_digest.is_some() => revision,
                                        _ => {
                                            rejection.get_or_insert_with(|| format!("Topic `{}` revision ordinal overflow or missing prior version", key.as_str()));
                                            continue;
                                        }
                                    },
                                    None if prior_digest.is_none() => 0,
                                    None => {
                                        rejection.get_or_insert_with(|| {
                                            format!(
                                                "Topic `{}` has no prior publication",
                                                key.as_str()
                                            )
                                        });
                                        continue;
                                    }
                                };
                                let mut sources = sources;
                                sources
                                    .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
                                match crate::topic::render(&binding.project_id, change, &sources) {
                                    Ok(content) => {
                                        rendered_topic_bytes = rendered_topic_bytes
                                            .checked_add(content.len())
                                            .ok_or("Topic batch rendered byte count overflow")?;
                                        if rendered_topic_bytes
                                            > crate::topic::MAX_TOPIC_BATCH_DOCUMENT_BYTES
                                        {
                                            rejection.get_or_insert_with(|| "Supervisor Topic batch exceeds its rendered byte limit".into());
                                        }
                                        let content_digest = crate::topic::content_digest(&content);
                                        let mut intent = crate::topic::TopicIntent {
                                            operation_id: String::new(),
                                            project_id: binding.project_id.clone(),
                                            key,
                                            revision,
                                            expected_prior_digest: prior_digest,
                                            destination_root: root.to_path_buf(),
                                            content_digest,
                                            content,
                                            sources,
                                        };
                                        intent.operation_id =
                                            crate::topic::expected_operation_id(&intent)?;
                                        topic_intents.push(intent);
                                    }
                                    Err(error) => {
                                        rejection.get_or_insert(error);
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        rejection.get_or_insert_with(|| {
                            "Topic publication requires an absolute host-configured knowledge root".into()
                        });
                    }
                }
            }
            if payload.batch_id != wake.source_id
                || payload.batch_digest.as_str() != digest
                || payload.config_revision.0 != config_revision
            {
                rejection.get_or_insert_with(|| {
                    "Supervisor learning decision does not match its issued batch".into()
                });
            }
        }
        if status != "issued"
            || config_revision != binding.config_revision.0
            || config_digest != binding.config_digest.as_str()
            || !matches!(current, Some((revision, ref current_digest, ref desired, ref observed)) if revision == config_revision && current_digest == &config_digest && desired == "running" && observed == "running")
        {
            rejection.get_or_insert_with(|| {
                "Supervisor learning result uses an obsolete Project configuration or batch".into()
            });
        }
        if let Some(reason) = rejection {
            let current_revision: u64 = tx
                .query_row(
                    "SELECT config_revision FROM projects WHERE project_id=?1",
                    [&project],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let ack: Option<(u64,String)> = tx.query_row("SELECT reducer_revision,disposition FROM agent_result_reducer_ack WHERE evidence_id=?1", [result.receipt.evidence_id()], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|error| error.to_string())?;
            if let Some((revision, disposition)) = ack {
                if revision != current_revision || disposition != "rejected_by_host" {
                    return Err("learning result already has another reducer disposition".into());
                }
            } else {
                tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'rejected_by_host',?3)",params![result.receipt.evidence_id(),current_revision,now_unix]).map_err(|error| error.to_string())?;
            }
            tx.execute("UPDATE project_runtimes SET last_error=COALESCE(last_error,?2) WHERE project_id=?1",params![project,reason]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        if let Some(prepared) = prepared_candidate {
            if let (Some(prior), Some(record)) = (&prepared.supersedes, &prepared.record) {
                let changed = tx.execute(
                    "UPDATE learning_candidates SET status='superseded',revision_json=json_set(revision_json,'$.status','superseded') WHERE project_id=?1 AND candidate_id=?2 AND digest=?3 AND status IN ('proposed','trialing','awaiting_approval')",
                    params![binding.project_id.as_str(),record.revision.candidate_id,prior.as_str()],
                ).map_err(|error| error.to_string())?;
                if changed != 1 {
                    return Err("candidate predecessor changed after validation".into());
                }
            }
            if let Some(record) = &prepared.record {
                register_learning_candidate_in_transaction(&tx, owner_generation, record)?;
            }
        }
        let payload =
            payload.ok_or("validated Supervisor result has no typed learning decision")?;
        let canonical = serde_json::to_string(payload).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO learning_decisions(batch_id,evidence_id,result_digest,decision_json,accepted_at_unix) VALUES (?1,?2,?3,?4,?5)",params![payload.batch_id,result.receipt.evidence_id(),result.validated.result_digest.as_str(),canonical,now_unix]).map_err(|e|e.to_string())?;
        if topic_intents.len() != payload.topic_changes.len() {
            return Err("validated Topic proposal count changed before persistence".into());
        }
        for intent in topic_intents {
            let intent_json = super::canonical_json(&intent)?;
            if intent_json.len() > 1_048_576 || !intent.destination_root.is_absolute() {
                return Err(
                    "Supervisor Topic intent exceeds storage bounds or has a relative root".into(),
                );
            }
            let intent_digest = Digest::parse(super::content_digest(&intent_json))?;
            tx.execute(
                "INSERT INTO supervisor_topic_publications(operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,created_at_unix,revision,prior_content_digest) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9)",
                params![intent.operation_id,intent.project_id.as_str(),intent.key.as_str(),intent.destination_root.to_string_lossy(),intent_json,intent_digest.as_str(),now_unix,i64::try_from(intent.revision).map_err(|_| "Topic revision ordinal exceeds SQLite range")?,intent.expected_prior_digest.as_ref().map(Digest::as_str)],
            ).map_err(|error| error.to_string())?;
            let request_json = super::canonical_json(&serde_json::json!({
                "operation_id": intent.operation_id,
                "intent_digest": intent_digest.as_str(),
            }))?;
            let effect = super::EffectIntent {
                project_id: intent.project_id.clone(),
                subject_type: "project".into(),
                subject_id: intent.project_id.to_string(),
                operation_id: intent.operation_id.clone(),
                logical_key: if intent.revision == 0 {
                    format!("topic-create:{}:{}", intent.project_id, intent.key.as_str())
                } else {
                    format!(
                        "topic-revision:{}:{}:{}",
                        intent.project_id,
                        intent.key.as_str(),
                        intent.revision
                    )
                },
                kind: crate::engine::reducer::effect_name(
                    &crate::engine::reducer::EffectKind::PublishTopic,
                )
                .into(),
                request_digest: super::content_digest(&request_json),
                request_json,
                expected_revision: None,
            };
            super::insert_effect(&tx, &effect, now_unix)?;
        }
        tx.execute("UPDATE learning_batches SET status='completed',completed_at_unix=?2 WHERE batch_id=?1 AND status='issued'",params![payload.batch_id,now_unix]).map_err(|e|e.to_string())?;
        for finding in findings {
            let changed=tx.execute("UPDATE learning_findings SET consumed_batch_id=?2 WHERE finding_id=?1 AND project_id=?3 AND publication_digest=?4 AND ordinal=?5 AND consumed_batch_id IS NULL",params![finding.id.as_str(),payload.batch_id,project,finding.publication_digest.as_str(),finding.ordinal]).map_err(|e|e.to_string())?;
            if changed != 1 {
                return Err(
                    "issued learning batch no longer matches its eligible Finding set".into(),
                );
            }
        }
        tx.execute("INSERT INTO agent_result_reducer_ack(evidence_id,reducer_revision,disposition,acknowledged_at_unix) VALUES (?1,?2,'applied',?3)",params![result.receipt.evidence_id(),binding.config_revision.0,now_unix]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Return an issued batch wake after a completed Supervisor turn that did not return its
    /// LearningDecision. This preserves the immutable batch across mixed wake snapshots.
    pub fn reoffer_unhandled_learning_batch(
        &mut self,
        owner_generation: u64,
        result: &crate::store::agent_results::IngestedAgentResult,
    ) -> Result<(), String> {
        let binding = &result.validated.binding;
        if binding.role != crate::domain::types::Role::Supervisor {
            return Ok(());
        }
        let has_assigned_batch: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM learning_batches b JOIN role_wake_inputs w ON w.wake_input_id=b.wake_input_id WHERE b.project_id=?1 AND b.status='issued' AND w.consuming_agent_run_id=?2 AND w.lifecycle IN ('assigned','consumed'))",
            params![binding.project_id.as_str(), binding.agent_run_id.as_str()],
            |row| row.get(0),
        ).map_err(|e| e.to_string())?;
        if !has_assigned_batch {
            return Ok(());
        }
        let terminal = crate::store::agent_results::verify_agent_terminal(
            self,
            owner_generation,
            &binding.agent_run_id,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, owner_generation)?;
        let authority = validate_learning_run_owner(&tx, binding, &terminal)?;
        let reservation_json: Option<String> = tx
            .query_row(
                "SELECT reservation_json FROM agent_launch_reservations WHERE agent_run_id=?1",
                [binding.agent_run_id.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(reservation_json) = reservation_json else {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(());
        };
        let reservation: crate::launch::AgentLaunchReservation =
            crate::protocol::parse_unique(reservation_json.as_bytes())?;
        if reservation.role != crate::domain::types::Role::Supervisor
            || reservation.project_id != binding.project_id
            || reservation.run_epoch != binding.run_epoch
            || reservation.controller_generation != authority.controller_generation
        {
            return Err("cannot reoffer a learning wake from a different Supervisor launch".into());
        }
        let mut issued_wakes = Vec::new();
        for wake in reservation
            .wake_snapshot
            .inputs
            .iter()
            .filter(|w| w.source_type == "learning_batch")
        {
            let batch_exists: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM learning_batches WHERE batch_id=?1 AND wake_input_id=?2 AND status='issued')",params![wake.source_id,i64::try_from(wake.wake_input_id).map_err(|_|"learning wake ID overflow")?],|r|r.get(0)).map_err(|e|e.to_string())?;
            if !batch_exists {
                continue;
            }
            issued_wakes.push(wake);
        }
        if issued_wakes.is_empty() {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(());
        }
        for wake in issued_wakes {
            let source_id = wake.source_id.clone();
            let row: Option<(String,String,String)>=tx.query_row("SELECT project_id,role_session_id,payload_json FROM role_wake_inputs WHERE wake_input_id=?1 AND consuming_agent_run_id=?2 AND lifecycle IN ('assigned','consumed')",params![wake.wake_input_id,binding.agent_run_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|e|e.to_string())?;
            if let Some((project, session, payload)) = row {
                if project != binding.project_id.as_str()
                    || session != binding.role_session_id.as_str()
                    || serde_json::to_string(&wake.payload_json).map_err(|e| e.to_string())?
                        != payload
                {
                    return Err(
                        "learning batch wake differs from its original launch snapshot".into(),
                    );
                }
                let max_revision: u64 = tx.query_row(
                    "SELECT COALESCE(MAX(source_revision),0) FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='learning_batch' AND source_id=?2",
                    params![session, source_id],
                    |row| row.get(0),
                ).map_err(|error| error.to_string())?;
                let next_revision = max_revision
                    .checked_add(1)
                    .ok_or("learning batch delivery revision overflow")?;
                let next_revision_sql = i64::try_from(next_revision)
                    .map_err(|_| "learning batch delivery revision exceeds SQLite range")?;
                tx.execute(
                    "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'learning_batch',?3,?4,1,?5,'pending',?6)",
                    params![project, session, source_id, next_revision_sql, payload, super::now_unix()?],
                ).map_err(|error| error.to_string())?;
                let new_wake_id = tx.last_insert_rowid();
                let changed = tx.execute(
                    "UPDATE learning_batches SET wake_input_id=?2 WHERE batch_id=?1 AND wake_input_id=?3 AND status='issued'",
                    params![source_id, new_wake_id, i64::try_from(wake.wake_input_id).map_err(|_| "learning wake ID overflow")?],
                ).map_err(|error| error.to_string())?;
                if changed != 1 {
                    return Err(
                        "issued learning batch delivery pointer changed during reoffer".into(),
                    );
                }
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_learning_trial(
        &mut self,
        generation: u64,
        project: &ProjectId,
        candidate_id: &str,
        digest: &Digest,
        pair_index: usize,
        observation: &TrialObservation,
    ) -> Result<TrialProgress, String> {
        if pair_index >= MAX_TRIALS {
            return Err("trial pair index exceeds maximum".into());
        }
        let json = serde_json::to_string(observation).map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let (expected,status):(usize,String)=tx.query_row("SELECT expected_pairs,status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![project.as_str(),candidate_id,digest.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
        if !matches!(
            status.as_str(),
            "proposed" | "trialing" | "awaiting_approval"
        ) || pair_index >= expected
        {
            return Err("candidate does not accept this trial pair".into());
        }
        let old:Option<String>=tx.query_row("SELECT observation_json FROM learning_trial_pairs WHERE project_id=?1 AND candidate_id=?2 AND candidate_digest=?3 AND pair_index=?4",params![project.as_str(),candidate_id,digest.as_str(),pair_index],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
        if let Some(old) = old {
            if old != json {
                return Err("trial pair retry conflicts with stored observation".into());
            }
        } else {
            if status == "awaiting_approval" {
                return Err("completed candidate cannot accept another trial pair".into());
            }
            tx.execute("INSERT INTO learning_trial_pairs(project_id,candidate_id,candidate_digest,pair_index,input_digest,observation_json,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![project.as_str(),candidate_id,digest.as_str(),pair_index,observation.input_digest.as_str(),json,super::now_unix()?]).map_err(|e|e.to_string())?;
        }
        let mut stmt=tx.prepare("SELECT pair_index,observation_json FROM learning_trial_pairs WHERE project_id=?1 AND candidate_id=?2 AND candidate_digest=?3 ORDER BY pair_index").map_err(|e|e.to_string())?;
        let rows = stmt
            .query_map(
                params![project.as_str(), candidate_id, digest.as_str()],
                |r| Ok((r.get::<_, usize>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(|e| e.to_string())?;
        let mut trials = Vec::new();
        for row in rows {
            let (index, json) = row.map_err(|e| e.to_string())?;
            trials.push(StoredTrial {
                pair_index: index,
                observation: serde_json::from_str(&json).map_err(|e| e.to_string())?,
            })
        }
        drop(stmt);
        let observations = trials
            .iter()
            .map(|t| t.observation.clone())
            .collect::<Vec<_>>();
        let evidence = evaluate_trials(&observations, expected).map_err(|e| e.to_string())?;
        let evidence_json = serde_json::to_string(&evidence).map_err(|e| e.to_string())?;
        let new_status = if trials.len() < expected {
            "trialing"
        } else {
            "awaiting_approval"
        };
        let candidate_status = if new_status == "trialing" {
            CandidateStatus::Trialing
        } else {
            CandidateStatus::AwaitingApproval
        };
        set_candidate_revision_status(&tx, project, candidate_id, digest, candidate_status)?;
        tx.execute("UPDATE learning_candidates SET evidence_json=?4 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",params![project.as_str(),candidate_id,digest.as_str(),evidence_json]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(TrialProgress { trials, evidence })
    }

    /// Record promotion eligibility from a package carrying a crate-private,
    /// controller-validated human receipt. This API is crate-private so CLI or
    /// Agent supplied approver strings can never act as authorization.
    #[allow(dead_code)]
    pub(crate) fn register_profile_promotion(
        &mut self,
        generation: u64,
        request: &ProfilePromotionRequest,
        package: &ProfilePackage,
    ) -> Result<(), String> {
        let claims = validated_promotion_claims(package).map_err(|e| e.to_string())?;
        if claims
            .response_receipt_digest
            .as_str()
            .bytes()
            .all(|byte| byte == b'0')
            || request.config_source.is_empty()
            || request.config_source.chars().any(char::is_control)
            || !std::path::Path::new(&request.config_file).is_absolute()
            || request.human_request_id.as_str().is_empty()
            || request.human_request_id != claims.human_request_id
        {
            return Err(
                "profile promotion needs a validated human response and config source".into(),
            );
        }
        // The human API's receipt digest covers a HumanSubjectBinding envelope. The
        // profile-specific digest lives in that envelope's material_digest; verify
        // both layers against the durable original request before accepting a package.
        let request_json: String = self
            .connection
            .query_row(
                "SELECT request_json FROM human_requests WHERE request_id=?1",
                [claims.human_request_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| "profile promotion has no durable human request".to_owned())?;
        let human_request: crate::human_runtime::HumanRuntimeRequest =
            crate::protocol::parse_unique(request_json.as_bytes())?;
        let material_digest = crate::learning::profile_approval_subject_digest(
            &claims.project_id,
            claims.role,
            &claims.profile_id,
            &claims.candidate_digest,
            &package.files,
            &package.evidence,
            &claims.config_revision,
        )
        .map_err(|e| e.to_string())?;
        if human_request.purpose != crate::human_runtime::HumanPurpose::ProfilePromotion
            || human_request.subject.kind != crate::human_runtime::HumanSubjectKind::Profile
            || human_request.subject.project_id != claims.project_id
            || human_request.subject.subject_id != request.candidate_id
            || human_request.subject.material_digest != material_digest
            || human_request.subject.configuration_digest != claims.approval_configuration_digest
            || human_request.subject.policy_digest != claims.approval_policy_digest
            || human_request.subject.digest().map_err(|e| e.to_string())?
                != claims.approval_subject_digest
        {
            return Err(
                "profile approval request does not bind the complete approved package".into(),
            );
        }
        let now_unix: u64 = super::now_unix()?
            .try_into()
            .map_err(|_| "system clock is before the Unix epoch")?;
        let accepted = self
            .accepted_human_approval(
                &claims.human_request_id,
                &claims.approval_subject_digest,
                &claims.approval_configuration_digest,
                &claims.approval_policy_digest,
                now_unix,
            )?
            .ok_or("profile promotion has no current accepted human approval")?;
        let regenerated = crate::learning::profile_package_from_accepted_approval(
            &accepted,
            claims.project_id.clone(),
            claims.role,
            claims.profile_id.clone(),
            claims.candidate_digest.clone(),
            package.evidence.clone(),
            package.files.clone(),
            claims.approval_subject_digest.clone(),
            material_digest.clone(),
            claims.config_revision.clone(),
            claims.approval_configuration_digest.clone(),
            claims.approval_policy_digest.clone(),
            now_unix,
        )
        .map_err(|e| e.to_string())?;
        if validated_promotion_claims(&regenerated).map_err(|e| e.to_string())? != claims {
            return Err("profile package differs from the authoritative human approval".into());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let candidate: Option<(String, String, Option<String>, String, String)> = tx.query_row(
            "SELECT role,status,evidence_json,profile_id,package_manifest_digest FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            params![claims.project_id.as_str(), request.candidate_id, claims.candidate_digest.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((role, status, evidence_json, candidate_profile_id, candidate_manifest_digest)) =
            candidate
        else {
            return Err("approved profile candidate does not exist".into());
        };
        if role
            != serde_json::to_value(claims.role)
                .map_err(|e| e.to_string())?
                .as_str()
                .ok_or("invalid role")?
            || status != "awaiting_approval"
        {
            return Err("profile candidate is not awaiting approval for the approved role".into());
        }
        if candidate_profile_id != claims.profile_id.as_str()
            || candidate_manifest_digest != claims.manifest_digest.as_str()
        {
            return Err(
                "human approval does not match the candidate's complete profile manifest".into(),
            );
        }
        let evidence_json = evidence_json.ok_or("candidate has no completed trial evidence")?;
        let evidence: TrialEvidence =
            serde_json::from_str(&evidence_json).map_err(|e| e.to_string())?;
        if crate::learning::evidence_digest(&evidence).map_err(|e| e.to_string())?
            != claims.evidence_digest
        {
            return Err("human approval does not match the stored trial evidence".into());
        }
        let role_name = serde_json::to_value(claims.role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        let approved_package_json = serde_json::to_string(&StoredApprovedProfilePackage {
            project_id: claims.project_id.clone(),
            role: claims.role,
            profile_id: claims.profile_id.clone(),
            candidate_digest: claims.candidate_digest.clone(),
            evidence: package.evidence.clone(),
            files: package.files.clone(),
            approver: format!("human request {}", claims.human_request_id),
            rationale: claims.rationale.clone(),
            authorized_at: claims.authorized_at.clone(),
            human_request_id: claims.human_request_id.clone(),
            approval_subject_digest: claims.approval_subject_digest.clone(),
            approval_configuration_digest: claims.approval_configuration_digest.clone(),
            approval_policy_digest: claims.approval_policy_digest.clone(),
            response_receipt_digest: claims.response_receipt_digest.clone(),
            config_revision: claims.config_revision.clone(),
            profile_material_digest: material_digest.clone(),
        })
        .map_err(|e| e.to_string())?;
        if approved_package_json.len() > MAX_RECORD_BYTES {
            return Err("approved profile package exceeds the durable intent limit".into());
        }
        let prior: Option<PromotionIntentRow> = tx.query_row(
            "SELECT project_id,candidate_digest,profile_id,role,evidence_digest,manifest_digest,config_source,config_file,expected_config_revision,human_request_id,human_response_digest FROM profile_promotions WHERE operation_id=?1",
            [request.operation_id.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
        ).optional().map_err(|e| e.to_string())?;
        if let Some(existing) = prior {
            let expected = (
                claims.project_id.to_string(),
                claims.candidate_digest.to_string(),
                claims.profile_id.to_string(),
                role_name.clone(),
                claims.evidence_digest.to_string(),
                claims.manifest_digest.to_string(),
                request.config_source.clone(),
                request.config_file.clone(),
                claims.config_revision.to_string(),
                request.human_request_id.to_string(),
                claims.response_receipt_digest.to_string(),
            );
            if existing != expected {
                return Err(
                    "profile promotion operation ID was reused with different approval".into(),
                );
            }
            let prior_package: String = tx
                .query_row(
                    "SELECT approved_package_json FROM profile_promotions WHERE operation_id=?1",
                    [request.operation_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if prior_package != approved_package_json {
                return Err(
                    "profile promotion operation was retried with a different package or rationale"
                        .into(),
                );
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO profile_promotions(operation_id,project_id,candidate_id,candidate_digest,profile_id,role,evidence_digest,manifest_digest,config_source,config_file,expected_config_revision,human_request_id,human_response_digest,approval_subject_digest,profile_material_digest,approval_configuration_digest,approval_policy_digest,approved_package_json,state,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,'approved',?19)",
            params![request.operation_id.as_str(), claims.project_id.as_str(), request.candidate_id,
                claims.candidate_digest.as_str(), claims.profile_id.as_str(),
                role_name,
                claims.evidence_digest.as_str(), claims.manifest_digest.as_str(), request.config_source, request.config_file,
                claims.config_revision.as_str(), request.human_request_id.as_str(),
                claims.response_receipt_digest.as_str(), claims.approval_subject_digest.as_str(), material_digest.as_str(),
                claims.approval_configuration_digest.as_str(), claims.approval_policy_digest.as_str(),
                approved_package_json, super::now_unix()?],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn begin_profile_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let promotion: Option<(String, String)> = tx
            .query_row(
                "SELECT project_id,manifest_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((project_id, manifest_digest)) = promotion else {
            return Err("profile promotion does not exist".into());
        };
        let changed = tx.execute(
            "UPDATE profile_promotions SET state='publication_pending' WHERE operation_id=?1 AND state='approved'",
            [operation_id.as_str()],
        ).map_err(|e| e.to_string())? == 1;
        if changed {
            let project_revision: u64 = tx
                .query_row(
                    "SELECT state_revision FROM projects WHERE project_id=?1",
                    [&project_id],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            let request_json = super::canonical_json(&serde_json::json!({
                "operation_id": operation_id.as_str(),
                "manifest_digest": manifest_digest,
            }))?;
            let effect = super::EffectIntent {
                project_id: ProjectId::parse(project_id.clone())?,
                subject_type: "project".into(),
                subject_id: project_id,
                operation_id: operation_id.to_string(),
                logical_key: format!("publish-profile-{}", operation_id),
                kind: "publish_profile".into(),
                request_digest: super::content_digest(&request_json),
                request_json,
                expected_revision: Some(project_revision),
            };
            super::insert_effect(&tx, &effect, super::now_unix()?)?;
        }
        if !changed {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM profile_promotions WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if state.as_deref() != Some("publication_pending")
                && state.as_deref() != Some("published")
                && state.as_deref() != Some("activation_pending")
                && state.as_deref() != Some("active")
            {
                return Err("profile promotion is not approved for publication".into());
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    #[allow(dead_code)]
    pub(crate) fn record_profile_publication(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        receipt: &ProfilePublicationReceipt,
    ) -> Result<bool, String> {
        let receipt_json = serde_json::to_string(&StoredProfilePublicationReceipt {
            profile_path: receipt.profile_path.display().to_string(),
            manifest_digest: receipt.profile_manifest_digest.clone(),
            human_response_receipt_digest: receipt.human_response_receipt_digest.clone(),
            already_published: receipt.status == ProfilePublicationStatus::AlreadyPublished,
        })
        .map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String, String, Option<String>)> = tx.query_row(
            "SELECT state,manifest_digest,publication_receipt_json FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((state, expected_manifest, prior)) = row else {
            return Err("profile publication has no approved intent".into());
        };
        if expected_manifest != receipt.profile_manifest_digest.as_str() {
            return Err("profile publication manifest differs from human-approved package".into());
        }
        let expected_response: String = tx
            .query_row(
                "SELECT human_response_digest FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if expected_response != receipt.human_response_receipt_digest.as_str() {
            return Err("profile publication receipt is bound to another human response".into());
        }
        if matches!(
            state.as_str(),
            "published" | "activation_pending" | "active"
        ) {
            let old: StoredProfilePublicationReceipt = serde_json::from_str(
                prior
                    .as_deref()
                    .ok_or("published profile is missing its receipt")?,
            )
            .map_err(|e| format!("stored profile receipt is invalid: {e}"))?;
            let new: StoredProfilePublicationReceipt =
                serde_json::from_str(&receipt_json).map_err(|e| e.to_string())?;
            if old.profile_path == new.profile_path
                && old.manifest_digest == new.manifest_digest
                && old.human_response_receipt_digest == new.human_response_receipt_digest
            {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err(
                "profile publication receipt conflicts with immutable stored receipt".into(),
            );
        }
        if state != "publication_pending" {
            return Err("profile publication was not prepared".into());
        }
        tx.execute("UPDATE profile_promotions SET state='published',publication_receipt_json=?2 WHERE operation_id=?1", params![operation_id.as_str(), receipt_json]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Mark a candidate active only after ConfigStore has accepted the exact
    /// applied snapshot and it binds this project/role to the approved profile.
    /// The caller writes an activation intent first; if the process stops after
    /// `apply_snapshot`, the same target revision and digest can be reconciled.
    #[allow(dead_code)]
    pub(crate) fn prepare_profile_activation(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        expected_current_revision: crate::domain::ids::Revision,
        target_config_digest: &Digest,
    ) -> Result<bool, String> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let row: Option<(String, String, Option<u64>, Option<String>)> = tx.query_row(
            "SELECT state,config_source,activation_to_revision,activation_config_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((state, source, prior_target_revision, prior_target_digest)) = row else {
            return Err("profile activation has no promotion intent".into());
        };
        if state == "active" {
            if prior_target_digest.as_deref() == Some(target_config_digest.as_str()) {
                tx.commit().map_err(|e| e.to_string())?;
                return Ok(false);
            }
            return Err("profile promotion is already active at another config revision".into());
        }
        if state == "activation_pending" {
            if prior_target_digest.as_deref() != Some(target_config_digest.as_str()) {
                return Err("profile activation retry changed its target config digest".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        if state != "published" {
            return Err("profile package must be published before config activation".into());
        }
        let current: Option<(u64, String)> = tx.query_row(
            "SELECT current.revision,snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity,revision) WHERE current.source_identity=?1",
            [&source],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        let Some((current_revision, current_digest)) = current else {
            return Err("profile config source has no applied snapshot".into());
        };
        if current_revision != expected_current_revision.0 {
            return Err("profile config source changed before activation intent".into());
        }
        let target_revision = current_revision
            .checked_add(1)
            .ok_or("profile config revision is exhausted")?;
        tx.execute(
            "UPDATE profile_promotions SET state='activation_pending',activation_from_revision=?2,activation_to_revision=?3,activation_config_digest=?4 WHERE operation_id=?1 AND state='published'",
            params![operation_id.as_str(),current_revision,target_revision,target_config_digest.as_str()],
        ).map_err(|e|e.to_string())?;
        // Make sure a pending target cannot be confused with an already applied revision.
        if current_digest == target_config_digest.as_str() {
            return Err("target profile config is already applied; reconcile it before starting a new activation".into());
        }
        if prior_target_revision.is_some() {
            return Err("published profile unexpectedly has a prior activation target".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    #[allow(dead_code)]
    pub(crate) fn confirm_profile_activation(
        &mut self,
        generation: u64,
        operation_id: &OperationId,
        applied: &super::AppliedRevision,
    ) -> Result<bool, String> {
        let row: Option<PromotionDbRow> = self.connection.query_row(
            "SELECT project_id,profile_id,role,config_source,state,candidate_digest,applied_config_revision,applied_config_digest,activation_to_revision,activation_config_digest FROM profile_promotions WHERE operation_id=?1",
            [operation_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)),
        ).optional().map_err(|e| e.to_string())?;
        let Some((
            project_id,
            profile_id,
            role,
            source,
            state,
            candidate_digest,
            old_revision,
            old_digest,
            activation_target_revision,
            activation_target_digest,
        )) = row
        else {
            return Err("profile activation has no promotion intent".into());
        };
        if !matches!(state.as_str(), "activation_pending" | "active") {
            return Err("profile package is not durably published".into());
        }
        let snapshot = self
            .load_snapshot(&source)?
            .ok_or("applied declarative config snapshot is missing")?;
        if snapshot.revision != applied.revision || snapshot.config.digest != applied.digest {
            return Err(
                "promotion activation does not match the current ConfigStore CAS snapshot".into(),
            );
        }
        if activation_target_revision != Some(applied.revision.0)
            || activation_target_digest.as_deref() != Some(applied.digest.as_str())
        {
            return Err(
                "applied config snapshot does not match the durable profile activation intent"
                    .into(),
            );
        }
        let project = ProjectId::parse(project_id.clone())?;
        let profile = crate::domain::ids::ProfileId::parse(profile_id.clone())?;
        let role: crate::domain::types::Role = serde_json::from_str(&format!("\"{role}\""))
            .map_err(|e| format!("stored promotion role is invalid: {e}"))?;
        let project_config = snapshot
            .config
            .config
            .projects
            .get(&project)
            .ok_or("applied config does not contain the approved project")?;
        if project_config.roles.get(&role) != Some(&profile)
            || !snapshot.config.profiles.contains_key(&profile)
        {
            return Err(
                "applied config does not bind the approved profile to the approved role".into(),
            );
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        validate_active_generation(&tx, generation)?;
        let current: Option<(u64, String)> = tx.query_row(
            "SELECT current.revision,snapshots.digest FROM config_current current JOIN config_snapshots snapshots USING(source_identity,revision) WHERE current.source_identity=?1",
            [&source], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|e| e.to_string())?;
        if current != Some((applied.revision.0, applied.digest.to_string())) {
            return Err("config source advanced before profile activation was recorded".into());
        }
        if state == "active" {
            if old_revision != Some(applied.revision.0)
                || old_digest.as_deref() != Some(applied.digest.as_str())
            {
                return Err("profile promotion is active at a different config revision".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        tx.execute("UPDATE profile_promotions SET state='active',applied_config_revision=?2,applied_config_digest=?3 WHERE operation_id=?1", params![operation_id.as_str(),applied.revision.0,applied.digest.as_str()]).map_err(|e| e.to_string())?;
        let role_name = serde_json::to_value(role)
            .map_err(|e| e.to_string())?
            .as_str()
            .ok_or("invalid role")?
            .to_owned();
        let mut prior_stmt = tx.prepare("SELECT candidate_id,digest FROM learning_candidates WHERE project_id=?1 AND role=?2 AND status='promoted'").map_err(|e|e.to_string())?;
        let prior_rows = prior_stmt
            .query_map(params![project.as_str(), role_name], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut prior_candidates = Vec::new();
        for row in prior_rows {
            prior_candidates.push(row.map_err(|e| e.to_string())?);
        }
        drop(prior_stmt);
        for (old_id, old_digest) in prior_candidates {
            set_candidate_revision_status(
                &tx,
                &project,
                &old_id,
                &Digest::parse(old_digest)?,
                CandidateStatus::Superseded,
            )?;
        }
        let changed = tx.execute("UPDATE learning_candidates SET status='promoted' WHERE project_id=?1 AND digest=?2 AND candidate_id=(SELECT candidate_id FROM profile_promotions WHERE operation_id=?3) AND status='awaiting_approval'", params![project.as_str(),candidate_digest,operation_id.as_str()]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("approved profile candidate disappeared before activation".into());
        }
        let promoted_id: String = tx
            .query_row(
                "SELECT candidate_id FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        set_candidate_revision_status(
            &tx,
            &project,
            &promoted_id,
            &Digest::parse(candidate_digest)?,
            CandidateStatus::Promoted,
        )?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }
}

fn set_candidate_revision_status(
    tx: &rusqlite::Transaction<'_>,
    project: &ProjectId,
    candidate_id: &str,
    digest: &Digest,
    status: CandidateStatus,
) -> Result<(), String> {
    let revision_json: String = tx.query_row(
        "SELECT revision_json FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
        params![project.as_str(),candidate_id,digest.as_str()],
        |row| row.get(0),
    ).map_err(|e| e.to_string())?;
    let mut revision: CandidateRevision = serde_json::from_str(&revision_json)
        .map_err(|e| format!("stored candidate revision is invalid: {e}"))?;
    revision.status = status;
    let revision_json = serde_json::to_string(&revision).map_err(|e| e.to_string())?;
    let status = serde_json::to_value(status)
        .map_err(|e| e.to_string())?
        .as_str()
        .ok_or("invalid candidate status")?
        .to_owned();
    tx.execute(
        "UPDATE learning_candidates SET status=?4,revision_json=?5 WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
        params![project.as_str(),candidate_id,digest.as_str(),status,revision_json],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

fn verify_digest(json: &str, digest: &Digest) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(json.as_bytes()));
    if actual != digest.as_str() {
        Err("serialized value digest mismatch".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use rusqlite::{Connection, params};
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    use super::{
        CandidateRegistration, KnowledgePublicationIntent, LEARNING_BATCH_MAX_FINDINGS,
        LearningCandidateRecord, LearningFinding, ProjectSupervisorMaintenance, StoredTrial,
        SupervisorTopicEntry, applied_config_in_transaction, captured_skill_sources,
        learning_finding_id, migrate_v10, prepare_learning_candidate,
        register_learning_candidate_in_transaction, resolve_topic_source,
        supervisor_learning_snapshot_in_transaction, trim_supervisor_snapshot,
    };
    use crate::config::{AppliedConfig, SourceFile, SourceKind};
    use crate::domain::ids::{
        Digest, OperationId, ProfileId, ProjectId, Revision, TicketId, TicketNamespace, TicketRunId,
    };
    use crate::domain::types::Role;
    use crate::human_runtime::{
        HumanDecisionChoice, HumanDecisionIntent, HumanPurpose, HumanRuntimeRequest,
        HumanSubjectBinding, HumanSubjectKind, write_runtime_review_artifact,
    };
    use crate::knowledge::PostmortemInput;
    use crate::knowledge_effect::KnowledgeEffectHandler;
    use crate::launch::{RexView, RexViewKind};
    use crate::learning::{
        CandidateRevision, CandidateStatus, TrialObservation, TrialOutcome, TrialRunStatus,
    };
    use crate::learning::{ProfilePackage, profile_approval_subject_digest};
    use crate::learning_trials::{
        FrozenTrialInput, HostTrialOutcome, HostTrialRunObservation, ProfileTrialAuthorization,
        TrialPairSpec, TrialProfileSnapshot, TrialSide, profile_trial_human_request,
        profile_trial_review_bundle,
    };
    use crate::store::human::HumanDecisionResult;
    use crate::store::learning_store::candidate_revision_is_pinned;
    use crate::store::{
        ConfigStore, DurableInput, EffectIntent, ExpectedRevision, OwnerMetadata, ProjectRecord,
        content_digest, durable_input_digest,
    };

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn oversized_supervisor_topic_context_omits_oldest_with_count() {
        let mut snapshot = ProjectSupervisorMaintenance {
            project_id: ProjectId::parse("sample").unwrap(),
            expired_candidates: 0,
            knowledge: Vec::new(),
            topics: (0..5)
                .map(|index| SupervisorTopicEntry {
                    topic_key: crate::topic::TopicKey::parse(&format!("topic-{index}")).unwrap(),
                    content: "x".repeat(60_000),
                    content_digest: digest('a'),
                })
                .collect(),
            omitted_topics: 0,
            candidates: Vec::new(),
            candidate_targets: Vec::new(),
            omitted_candidate_targets: 0,
        };
        trim_supervisor_snapshot(&mut snapshot).unwrap();
        assert_eq!(snapshot.topics.len(), 4);
        assert_eq!(snapshot.omitted_topics, 1);
        assert!(
            serde_json::to_vec(&snapshot).unwrap().len() <= super::MAX_SUPERVISOR_CONTEXT_BYTES
        );
    }

    #[test]
    fn v21_topic_validator_rejects_partial_revision_unique_key() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE supervisor_topic_publications (
                operation_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                topic_key TEXT NOT NULL,
                destination_root TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                receipt_json TEXT,
                receipt_digest TEXT,
                conflict_json TEXT,
                created_at_unix INTEGER NOT NULL,
                published_at_unix INTEGER,
                revision INTEGER NOT NULL DEFAULT 0,
                prior_content_digest TEXT
             );",
            )
            .unwrap();
        connection.execute_batch(
            "CREATE UNIQUE INDEX topic_partial_revision ON supervisor_topic_publications(project_id,topic_key,revision) WHERE state='published';",
        ).unwrap();
        let error = super::validate_v21_topic_publications(&connection).unwrap_err();
        assert!(error.contains("revision uniqueness is invalid"), "{error}");
    }

    #[test]
    fn v21_topic_validator_rejects_missing_state_and_revision_checks() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE supervisor_topic_publications (
                operation_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                topic_key TEXT NOT NULL,
                destination_root TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                receipt_json TEXT,
                receipt_digest TEXT,
                conflict_json TEXT,
                created_at_unix INTEGER NOT NULL,
                published_at_unix INTEGER,
                revision INTEGER NOT NULL DEFAULT 0,
                prior_content_digest TEXT,
                UNIQUE(project_id,topic_key,revision)
             );",
            )
            .unwrap();
        let error = super::validate_v21_topic_publications(&connection).unwrap_err();
        assert!(
            error.contains("ledger constraints are incomplete"),
            "{error}"
        );
    }

    #[test]
    fn topic_snapshot_selects_current_distinct_keys_before_its_limit() {
        let (_temp, mut store, project, _generation, _run) = running_store();
        let root = std::env::temp_dir().join("rex-projects-topic-snapshot-fixture");
        let root_string = root.to_string_lossy().into_owned();
        let insert = |store: &mut ConfigStore,
                      key: &str,
                      revision: u64,
                      prior: Option<Digest>,
                      content: &str,
                      state: &str,
                      published_at: Option<i64>| {
            let mut intent = crate::topic::TopicIntent {
                operation_id: String::new(),
                project_id: project.clone(),
                key: crate::topic::TopicKey::parse(key).unwrap(),
                revision,
                expected_prior_digest: prior.clone(),
                destination_root: std::path::PathBuf::from(&root_string),
                content: content.to_owned(),
                content_digest: crate::topic::content_digest(content),
                sources: Vec::new(),
            };
            intent.operation_id = crate::topic::expected_operation_id(&intent).unwrap();
            let mut receipt_json = None;
            let mut receipt_digest = None;
            if state == "published" {
                let manifest = crate::topic::TopicManifest {
                    operation_id: intent.operation_id.clone(),
                    project_id: project.clone(),
                    topic_key: intent.key.clone(),
                    relative_path: crate::topic::publication_relative_path(&intent).unwrap(),
                    format: "okf-0.2".into(),
                    content_sha256: intent.content_digest.clone(),
                    source_finding_ids: Vec::new(),
                    source_publication_digests: Vec::new(),
                    byte_count: content.len(),
                };
                let manifest_digest = Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&manifest).unwrap())
                ))
                .unwrap();
                let receipt = crate::topic::TopicReceipt {
                    manifest,
                    manifest_digest,
                    published_at_unix: published_at.unwrap(),
                };
                let json = serde_json::to_string(&receipt).unwrap();
                receipt_digest = Some(crate::store::content_digest(&json));
                receipt_json = Some(json);
            }
            let intent_json = crate::store::canonical_json(&intent).unwrap();
            let intent_digest = crate::store::content_digest(&intent_json);
            let conflict_json = (state == "conflict").then(|| {
                serde_json::json!({"operation_id":intent.operation_id,"state":"conflict","reason":"fixture mismatch"}).to_string()
            });
            store.connection.execute(
                "INSERT INTO supervisor_topic_publications(operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,receipt_json,receipt_digest,conflict_json,created_at_unix,published_at_unix,revision,prior_content_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?13)",
                params![intent.operation_id, project.as_str(), key, root_string, intent_json, intent_digest, state, receipt_json, receipt_digest, conflict_json, published_at, i64::try_from(revision).unwrap(), prior.as_ref().map(Digest::as_str)],
            ).unwrap();
            intent
        };

        let first = insert(
            &mut store,
            "topic-0",
            0,
            None,
            "topic zero genesis",
            "published",
            Some(10),
        );
        let second = insert(
            &mut store,
            "topic-0",
            1,
            Some(first.content_digest.clone()),
            "topic zero revision one",
            "published",
            Some(20),
        );
        let current = insert(
            &mut store,
            "topic-0",
            2,
            Some(second.content_digest.clone()),
            "topic zero revision two",
            "published",
            Some(100),
        );
        for index in 1..=5 {
            insert(
                &mut store,
                &format!("topic-{index}"),
                0,
                None,
                &format!("topic {index}"),
                "published",
                Some(10 + index),
            );
        }
        insert(
            &mut store,
            "topic-0",
            3,
            Some(current.content_digest.clone()),
            "conflicted next version",
            "conflict",
            None,
        );
        insert(
            &mut store,
            "unpublished",
            0,
            None,
            "pending only",
            "pending",
            None,
        );

        let tx = store.connection.transaction().unwrap();
        let snapshot = super::supervisor_learning_snapshot_in_transaction(
            &tx,
            &project,
            "2026-11-13T00:00:00Z",
            0,
            Some(std::path::Path::new(&root_string)),
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(snapshot.topics.len(), 5);
        assert_eq!(snapshot.omitted_topics, 1);
        let current_entry = snapshot
            .topics
            .iter()
            .find(|topic| topic.topic_key.as_str() == "topic-0")
            .unwrap();
        assert_eq!(current_entry.content, current.content);
        assert_eq!(current_entry.content_digest, current.content_digest);
        assert_eq!(
            snapshot
                .topics
                .iter()
                .map(|topic| topic.topic_key.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
    }

    #[test]
    fn conflicting_revision_is_durably_rejected_and_keeps_last_published_topic_current() {
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            result,
            config,
            config_digest,
            ..
        } = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
            Some(root.clone()),
        )
        .unwrap();
        let genesis: String = store
            .connection
            .query_row(
                "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let genesis_operation = OperationId::parse(genesis).unwrap();
        let genesis_intent = store
            .supervisor_topic_intent(&genesis_operation)
            .unwrap()
            .unwrap();
        let handler = crate::topic_effect::TopicEffectHandler::new(root.clone());
        let limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(3600),
            retry_base: std::time::Duration::from_secs(1),
            retry_max: std::time::Duration::from_secs(8),
        };
        crate::effects::EffectDispatcher::tick(&mut store, generation, 102, &[&handler], limits)
            .unwrap();
        let change = crate::topic::TopicChange {
            topic_key: genesis_intent.key.as_str().into(),
            title: "A revised title that conflicts on disk".into(),
            summary: "The host must preserve bytes at a digest-derived revision path.".into(),
            claims: vec!["A mismatching file is never overwritten.".into()],
            applicability: "Used to test a revision destination conflict.".into(),
            proposed_check: "Keep the last successfully published version current.".into(),
            counterexamples: Vec::new(),
            source_finding_ids: genesis_intent
                .sources
                .iter()
                .map(|source| source.finding_id.clone())
                .collect(),
            expected_prior_digest: Some(genesis_intent.content_digest.clone()),
        };
        let content = crate::topic::render(&project, &change, &genesis_intent.sources).unwrap();
        let mut revision = crate::topic::TopicIntent {
            operation_id: String::new(),
            project_id: project.clone(),
            key: genesis_intent.key.clone(),
            revision: 1,
            expected_prior_digest: Some(genesis_intent.content_digest.clone()),
            destination_root: root.clone(),
            content_digest: crate::topic::content_digest(&content),
            content,
            sources: genesis_intent.sources.clone(),
        };
        revision.operation_id = crate::topic::expected_operation_id(&revision).unwrap();
        let intent_json = crate::store::canonical_json(&revision).unwrap();
        let intent_digest = crate::store::content_digest(&intent_json);
        store.connection.execute(
            "INSERT INTO supervisor_topic_publications(operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,created_at_unix,revision,prior_content_digest) VALUES (?1,?2,?3,?4,?5,?6,'pending',103,1,?7)",
            params![revision.operation_id, project.as_str(), revision.key.as_str(), root.to_string_lossy(), intent_json, intent_digest, revision.expected_prior_digest.as_ref().unwrap().as_str()],
        ).unwrap();
        let request_json = crate::store::canonical_json(&serde_json::json!({
            "operation_id": revision.operation_id,
            "intent_digest": intent_digest,
        }))
        .unwrap();
        let effect = crate::store::EffectIntent {
            project_id: project.clone(),
            subject_type: "project".into(),
            subject_id: project.to_string(),
            operation_id: revision.operation_id.clone(),
            logical_key: format!("topic-revision:{}:{}:1", project, revision.key.as_str()),
            kind: "publish_topic".into(),
            request_digest: crate::store::content_digest(&request_json),
            request_json,
            expected_revision: None,
        };
        let tx = store.connection.transaction().unwrap();
        super::super::insert_effect(&tx, &effect, 103).unwrap();
        tx.commit().unwrap();
        let tx = store.connection.transaction().unwrap();
        let pending_snapshot = super::supervisor_learning_snapshot_in_transaction(
            &tx,
            &project,
            "2026-11-13T00:00:00Z",
            0,
            Some(&root),
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(pending_snapshot.topics.len(), 1);
        assert_eq!(pending_snapshot.topics[0].content, genesis_intent.content);
        assert_eq!(
            pending_snapshot.topics[0].content_digest,
            genesis_intent.content_digest
        );
        let target = root.join(crate::topic::publication_relative_path(&revision).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let unexpected = b"preserve this unrecognized revision artifact";
        std::fs::write(&target, unexpected).unwrap();
        assert!(matches!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                generation,
                104,
                &[&handler],
                limits,
            )
            .unwrap(),
            crate::effects::DispatchTick::Completed { .. }
        ));
        assert_eq!(std::fs::read(&target).unwrap(), unexpected);
        let (state, conflict_json): (String, String) = store.connection.query_row(
            "SELECT state,conflict_json FROM supervisor_topic_publications WHERE operation_id=?1",
            [revision.operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(state, "conflict");
        assert!(conflict_json.contains("different bytes"));
        let tx = store.connection.transaction().unwrap();
        let snapshot = super::supervisor_learning_snapshot_in_transaction(
            &tx,
            &project,
            "2026-11-13T00:00:00Z",
            0,
            Some(&root),
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(snapshot.topics.len(), 1);
        assert_eq!(snapshot.topics[0].content, genesis_intent.content);
        assert_eq!(
            snapshot.topics[0].content_digest,
            genesis_intent.content_digest
        );
        assert!(matches!(
            handler.execute(&mut store, generation, &effect),
            Err(crate::topic::TopicPublicationError::Conflict(_))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), unexpected);
        std::fs::remove_file(&target).unwrap();
        store.stop_owner(generation).unwrap();
        drop(store);
        let mut store = ConfigStore::open_test(_temp.path()).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "topic-conflict-replay-owner".into(),
                state_root: _temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "topic-conflict-replay-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert!(matches!(
            handler.execute(&mut store, generation, &effect),
            Err(crate::topic::TopicPublicationError::Conflict(_))
        ));
        assert!(!target.exists());
    }

    fn digest_serialized<T: serde::Serialize>(value: &T) -> Digest {
        Digest::parse(format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap())).as_str())
            .unwrap()
    }

    fn v9_fixture() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at_unix INTEGER NOT NULL);
             CREATE TABLE projects(project_id TEXT PRIMARY KEY);
             CREATE TABLE ticket_runs(ticket_run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(project_id));
             CREATE TABLE controller_owners(singleton INTEGER PRIMARY KEY);
             PRAGMA user_version=9;",
        ).unwrap();
        connection
    }

    #[test]
    fn migration_requires_v9_and_installs_all_durable_ledgers_atomically() {
        let wrong = Connection::open_in_memory().unwrap();
        wrong.pragma_update(None, "user_version", 8).unwrap();
        assert!(migrate_v10(&wrong).is_err());
        let fixture = v9_fixture();
        migrate_v10(&fixture).unwrap();
        let version: i64 = fixture
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 10);
        let has_rex_endpoint: bool = fixture
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('controller_owners') WHERE name='rex_endpoint')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_rex_endpoint);
        for table in [
            "knowledge_publications",
            "learning_candidates",
            "learning_trial_pairs",
            "profile_promotions",
            "supervisor_learning_schedule",
        ] {
            let exists: bool = fixture
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
        super::validate_v10_schema(&fixture).unwrap();
    }

    #[test]
    fn v12_learning_trial_tables_install_inside_the_shared_migration_transaction() {
        let mut fixture = v9_fixture();
        migrate_v10(&fixture).unwrap();
        let tx = fixture
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
        for table in [
            "profile_trial_authorizations",
            "profile_trial_launches",
            "profile_trial_run_receipts",
            "profile_trial_pairs",
        ] {
            let exists: bool = fixture
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing {table}");
        }
        let tx = fixture
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn approved_profile_trial_persists_capsule_slot_receipt_and_replays_after_restart() {
        let (temp, mut store, project, generation, _) = running_store();
        let project_record = store.project(&project).unwrap().unwrap();
        let tx = store.connection.transaction().unwrap();
        super::migrate_v12_learning_tables(&tx).unwrap();
        tx.commit().unwrap();
        let candidate_id = "worker-learned-v1";
        let candidate_digest = digest('d');
        let profile_id = ProfileId::parse("worker-learned").unwrap();
        let guidance = b"Keep acceptance checks.".to_vec();
        let files = BTreeMap::from([("learned.md".to_owned(), guidance.clone())]);
        let manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let manifest_rows: Vec<_> = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes)).as_str()).unwrap(),
                )
            })
            .collect();
        let candidate_record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: candidate_id.into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2027-11-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: profile_id.clone(),
            package_manifest_digest: manifest_digest,
            package_files_json: serde_json::to_string(&files).unwrap(),
            package_json: serde_json::to_string(&manifest_rows).unwrap(),
            expected_pairs: 10,
        };
        store
            .register_learning_candidate(generation, &candidate_record)
            .unwrap();

        let make_snapshot = |learned: bool, description: &str| {
            let mut config = serde_json::json!({"adapter":"codex","command":["agent"],"description":description,"model":"fixture-model","effort":"low","turn_timeout_seconds":30,"instruction_files":[],"skill_paths":[],"commit_mode":"auto","learned_guidance":null,"options":null});
            let snapshot_files = if learned {
                config["learned_guidance"] = serde_json::json!({"file":"learned.md","project_id":project.as_str(),"role":"worker","repository_ids":["repo-a"]});
                files.clone()
            } else {
                BTreeMap::new()
            };
            let profile: crate::config::Profile = serde_json::from_value(config).unwrap();
            let profile_config_json = crate::store::canonical_json(&profile).unwrap();
            TrialProfileSnapshot {
                profile_id: if learned {
                    profile_id.clone()
                } else {
                    ProfileId::parse("worker").unwrap()
                },
                profile_digest: crate::store::agent_profile_digest(&profile).unwrap(),
                instruction_digest: digest_serialized(&snapshot_files),
                profile_config_json,
                instruction_files: snapshot_files,
            }
        };
        let baseline = make_snapshot(false, "base");
        let candidate = make_snapshot(true, "candidate");
        let inputs: Vec<_> = (0..5)
            .map(|i| {
                let input_json = format!("{{\"case\":{i}}}");
                let evaluator = crate::learning_trials::TrialEvaluator::StructuredAssertionsV1 {
                    assertions: vec![],
                };
                let fixture_seed = crate::learning_trials::InlineFixtureV1::empty();
                FrozenTrialInput {
                    input_id: format!("input-{i}"),
                    input_digest: Digest::parse(
                        format!("{:x}", Sha256::digest(input_json.as_bytes())).as_str(),
                    )
                    .unwrap(),
                    input_json,
                    fixture_id: crate::learning_trials::INLINE_FIXTURE_ID.into(),
                    fixture_revision: Digest::parse(format!(
                        "{:x}",
                        Sha256::digest(b"inline_fixture_v1")
                    ))
                    .unwrap(),
                    workspace_seed_digest: fixture_seed.digest().unwrap(),
                    fixture_seed,
                    evaluator_id: evaluator.implementation_id().into(),
                    evaluator_revision: evaluator.digest().unwrap(),
                    evaluator,
                }
            })
            .collect();
        let pairs = (0..10)
            .map(|pair_index| TrialPairSpec {
                pair_index,
                input_id: format!("input-{}", pair_index / 2),
            })
            .collect();
        let authorization = ProfileTrialAuthorization {
            schema_version: 1,
            authorization_id: "profile-trial-1".into(),
            project_id: project.clone(),
            role: Role::Worker,
            candidate_id: candidate_id.into(),
            candidate_digest: candidate_digest.clone(),
            base_profile_id: ProfileId::parse("worker").unwrap(),
            base_profile_digest: baseline.profile_digest.clone(),
            config_revision: project_record.config_revision,
            config_digest: project_record.config_digest.clone(),
            baseline_qualification_digest: digest('1'),
            candidate_qualification_digest: digest('2'),
            trial_policy_digest: digest('3'),
            baseline,
            candidate,
            inputs,
            pairs,
            scoped_exception: None,
            human_request_id: crate::domain::ids::HumanRequestId::parse("human-trial-1").unwrap(),
            human_subject_digest: digest('4'),
            human_configuration_digest: project_record.config_digest,
            human_policy_digest: digest('3'),
            human_response_receipt_digest: digest('0'),
            authorized_at_unix: 10,
            max_attempts_per_side: 1,
            expires_at_unix: 4_102_444_800,
        };
        let bundle = profile_trial_review_bundle(&authorization).unwrap();
        let request = profile_trial_human_request(
            authorization.human_request_id.clone(),
            &authorization,
            bundle,
            "Approve this exact bounded fixture batch?".into(),
            authorization.expires_at_unix,
        )
        .unwrap();
        let view = RexView {
            view_id: RexView::derive_id(&project, RexViewKind::Supervisor, None, None, 1).unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "supervisor-window".into(),
        };
        store.register_rex_view(generation, &view).unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        assert!(
            store
                .prepare_profile_trial_authorization(
                    generation,
                    &authorization,
                    &request,
                    &view.view_id,
                    &artifact,
                    100
                )
                .unwrap()
        );
        assert_eq!(
            store
                .pending_profile_trial_authorization_for_request(&request.request_id)
                .unwrap()
                .unwrap()
                .authorization_id,
            authorization.authorization_id
        );
        // Simulate a crash after the authorization transaction committed but
        // before the human request was registered. The controller cadence
        // must reconstruct the request from its durable authorization row.
        store
            .connection
            .execute(
                "DELETE FROM human_requests WHERE request_id=?1",
                [request.request_id.as_str()],
            )
            .unwrap();
        assert!(
            !store
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM human_requests WHERE request_id=?1)",
                    [request.request_id.as_str()],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        assert!(
            store
                .tick_profile_trials(generation, 100, 2, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            ConfigStore::read_human_request(temp.path(), &request.request_id)
                .unwrap()
                .is_some()
        );
        let now = 101;
        let response = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "trial-response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some(
                "Run only the exact isolated fixture matrix for this candidate.".into(),
            ),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &response, now).unwrap();
        assert!(matches!(
            store
                .process_human_decision(generation, &response.response_id, &request.subject, now)
                .unwrap(),
            HumanDecisionResult::Applied
        ));
        assert!(
            store
                .accept_profile_trial_approval(generation, &authorization.authorization_id, now + 1)
                .unwrap()
        );
        assert!(
            store
                .pending_profile_trial_authorization_for_request(&request.request_id)
                .unwrap()
                .is_none()
        );
        let capsule = store
            .next_profile_trial_launch(generation, &authorization.authorization_id, now + 2, 2, 1)
            .unwrap()
            .unwrap();
        assert_eq!(capsule.side, TrialSide::Baseline);
        assert_eq!(
            store
                .next_profile_trial_launch(
                    generation,
                    &authorization.authorization_id,
                    now + 3,
                    2,
                    1
                )
                .unwrap()
                .unwrap(),
            capsule
        );
        let active_slots:usize=store.connection.query_row("SELECT count(*) FROM execution_slots WHERE owner_kind='profile_trial' AND disposition!='released'",[],|r|r.get(0)).unwrap();
        assert_eq!(active_slots, 1);
        let observation = HostTrialRunObservation {
            run_id: capsule.run_id.clone(),
            attempt_id: capsule.attempt_id.clone(),
            qualification_receipt_digest: capsule.provider_qualification_digest.clone(),
            config_revision: capsule.config_revision,
            config_digest: capsule.config_digest.clone(),
            profile_digest: capsule.profile.profile_digest.clone(),
            instruction_digest: capsule.profile.instruction_digest.clone(),
            input_digest: capsule.input_digest.clone(),
            fixture_id: capsule.fixture_id.clone(),
            fixture_revision: capsule.fixture_revision.clone(),
            evaluator_id: capsule.evaluator_id.clone(),
            evaluator_revision: capsule.evaluator_revision.clone(),
            workspace_seed_digest: capsule.workspace_seed_digest.clone(),
            no_effects_receipt_digest: digest('e'),
            outcome: HostTrialOutcome::Equivalent,
            result_receipt_digest: digest('f'),
            completed_at_unix: now + 4,
        };
        let receipt = capsule.mint_terminal_receipt(observation).unwrap();
        store
            .record_profile_trial_run_receipt(generation, &receipt, now + 4)
            .unwrap();
        assert_eq!(
            store
                .profile_trial_terminal_receipt(capsule.operation_id())
                .unwrap(),
            Some(receipt.clone())
        );
        store
            .record_profile_trial_run_receipt(generation, &receipt, now + 5)
            .unwrap();
        let active_slots:usize=store.connection.query_row("SELECT count(*) FROM execution_slots WHERE owner_kind='profile_trial' AND disposition!='released'",[],|r|r.get(0)).unwrap();
        assert_eq!(active_slots, 0);
        let next = store
            .tick_profile_trials(generation, now + 6, 2, 1)
            .unwrap()
            .unwrap();
        assert_eq!(next.pair_index, capsule.pair_index);
        assert_eq!(next.side, TrialSide::Candidate);
        let effect_count: usize = store
            .connection
            .query_row(
                "SELECT count(*) FROM effects WHERE kind='start_profile_trial'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 2);
        drop(store);
        let restored = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            restored
                .profile_trial_launch_capsule(
                    &authorization.authorization_id,
                    capsule.pair_index,
                    TrialSide::Baseline
                )
                .unwrap(),
            Some(capsule)
        );
    }

    #[test]
    fn startup_refuses_a_v10_database_with_an_incomplete_learning_layout_without_migration() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("state.sqlite3");
        let connection = Connection::open(&database).unwrap();
        connection.pragma_update(None, "user_version", 10).unwrap();
        drop(connection);
        let before = fs::read(&database).unwrap();
        let error = match ConfigStore::open_test(temp.path()) {
            Ok(_) => panic!("incomplete schema v10 unexpectedly opened"),
            Err(error) => error,
        };
        assert!(error.contains("database claims schema v10"));
        assert_eq!(fs::read(&database).unwrap(), before);
    }

    #[test]
    fn startup_refuses_a_v19_database_with_an_incomplete_learning_batch_layout() {
        let (temp, store, _, _, _) = running_store();
        store
            .connection
            .execute("DROP TABLE learning_decisions", [])
            .unwrap();
        drop(store);
        let error = match ConfigStore::open_test(temp.path()) {
            Ok(_) => panic!("incomplete schema v19 unexpectedly opened"),
            Err(error) => error,
        };
        assert!(error.contains("database claims schema v19 but learning_decisions is incomplete"));
    }

    fn test_snapshot() -> AppliedConfig {
        let mut snapshot = AppliedConfig {
            config: serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "adapters": {"tickets": {"kind":"command","command":["test"]}},
                "repositories": {"fixture-repo": {
                    "clone_url":"https://example.invalid/fixture/repo.git",
                    "base_branch":"main", "forge":"github"
                }},
                "projects": {
                    "sample": {"mode":"goal","ticket_adapter":"tickets","goal":{"revision":1,"statement":"Fixture goal","acceptance":["Published findings remain available"]}},
                    "sample-b": {"mode":"goal","ticket_adapter":"tickets","goal":{"revision":1,"statement":"Independent fixture goal","acceptance":["Maintain an independent learning cadence"]}},
                    "sample-after-learning-rejection": {"mode":"goal","ticket_adapter":"tickets","goal":{"revision":1,"statement":"Continue after a rejected result","acceptance":["Another Project can still be maintained"]}}
                }
            }))
            .unwrap(),
            profiles: BTreeMap::new(),
            source_root: "/tmp/rex-projects-test-config".into(),
            source_files: vec![SourceFile {
                kind: SourceKind::File,
                path: "/tmp/rex-projects-test-config/config.toml".into(),
                canonical_path: "/tmp/rex-projects-test-config/config.toml".into(),
                sha256: Digest::parse(format!("{:x}", Sha256::digest(b"x"))).unwrap(),
                bytes: 1,
                contents: "x".into(),
            }],
            digest: Digest::parse("a".repeat(64)).unwrap(),
        };
        for project in snapshot.config.projects.values_mut() {
            project.repositories =
                vec![crate::domain::ids::RepositoryId::parse("fixture-repo").unwrap()];
            project.roles = Role::ALL
                .into_iter()
                .map(|role| (role, ProfileId::parse("fixture-profile").unwrap()))
                .collect();
        }
        snapshot.profiles.insert(
            ProfileId::parse("fixture-profile").unwrap(),
            serde_json::from_value(serde_json::json!({
                "adapter":"codex", "command":["/bin/codex"], "model":"fixture",
                "commit_mode":"native", "turn_timeout_seconds":60
            }))
            .unwrap(),
        );
        let contents = toml::to_string(&snapshot.config).unwrap();
        snapshot.source_files[0].bytes = contents.len() as u64;
        snapshot.source_files[0].sha256 =
            Digest::parse(format!("{:x}", Sha256::digest(contents.as_bytes()))).unwrap();
        snapshot.source_files[0].contents = contents;
        snapshot.digest = Digest::parse(
            crate::config::digest_manifest(
                &snapshot.config,
                &snapshot.profiles,
                &snapshot.source_files,
            )
            .unwrap(),
        )
        .unwrap();
        snapshot
    }

    fn running_store() -> (TempDir, ConfigStore, ProjectId, u64, TicketRunId) {
        running_store_with_snapshot(&test_snapshot())
    }

    fn running_store_with_snapshot(
        snapshot: &AppliedConfig,
    ) -> (TempDir, ConfigStore, ProjectId, u64, TicketRunId) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let mut snapshot = snapshot.clone();
        for source in &mut snapshot.source_files {
            if matches!(source.kind, SourceKind::File) {
                source.bytes = source.contents.len() as u64;
                source.sha256 =
                    Digest::parse(format!("{:x}", Sha256::digest(source.contents.as_bytes())))
                        .unwrap();
            }
        }
        for (profile_id, profile) in &snapshot.profiles {
            let profile_root = std::path::Path::new(&snapshot.source_root)
                .join("profiles")
                .join(profile_id.as_str());
            let profile_root_string = profile_root.to_string_lossy().into_owned();
            if !snapshot.source_files.iter().any(|source| {
                matches!(source.kind, SourceKind::Directory) && source.path == profile_root_string
            }) {
                snapshot.source_files.push(SourceFile {
                    kind: SourceKind::Directory,
                    path: profile_root_string.clone(),
                    canonical_path: profile_root_string.clone(),
                    sha256: Digest::parse(format!(
                        "{:x}",
                        Sha256::digest(profile_root_string.as_bytes())
                    ))
                    .unwrap(),
                    bytes: 0,
                    contents: String::new(),
                });
            }
            let contents = toml::to_string(profile).unwrap();
            let path = profile_root
                .join("config.toml")
                .to_string_lossy()
                .into_owned();
            snapshot.source_files.push(SourceFile {
                kind: SourceKind::File,
                path: path.clone(),
                canonical_path: path,
                sha256: Digest::parse(format!("{:x}", Sha256::digest(contents.as_bytes())))
                    .unwrap(),
                bytes: contents.len() as u64,
                contents,
            });
        }
        snapshot.digest = Digest::parse(
            crate::config::digest_manifest(
                &snapshot.config,
                &snapshot.profiles,
                &snapshot.source_files,
            )
            .unwrap(),
        )
        .unwrap();
        let applied = store
            .apply_snapshot("factory", &snapshot, ExpectedRevision::Bootstrap)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='running' WHERE project_id='sample'",
                [],
            )
            .unwrap();
        let project_id = ProjectId::parse("sample").unwrap();
        store
            .insert_project(&ProjectRecord {
                id: project_id.clone(),
                config_source: "factory".into(),
                config_revision: applied.revision,
                config_digest: applied.digest,
                mode: "goal".into(),
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "test-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let run = TicketRunId::parse("sample-1-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &project_id,
                &TicketNamespace::parse("github:org/repo").unwrap(),
                &TicketId::parse("1").unwrap(),
                &run,
                1,
                "postmortem",
                "In Progress",
            )
            .unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, crate::store::SCHEMA_VERSION);
        (temp, store, project_id, generation, run)
    }

    fn load_symlinked_candidate_fixture(
        mut snapshot: AppliedConfig,
        base_guidance: &str,
    ) -> AppliedConfig {
        let temp = tempfile::tempdir().unwrap();
        let config_root = temp.path().join("config");
        let source_profile = temp.path().join("source-profiles/candidate-worker");
        fs::create_dir_all(config_root.join("profiles")).unwrap();
        fs::create_dir_all(source_profile.join("aliases")).unwrap();
        let skill_a = temp.path().join("skills-a");
        let skill_a_target = temp.path().join("skills-a-target");
        let skill_b = temp.path().join("skills-b");
        let skill_file = temp.path().join("skill-file-target.md");
        let skill_file_alias = temp.path().join("skill-file-alias.md");
        fs::create_dir_all(&skill_a_target).unwrap();
        symlink(&skill_a_target, &skill_a).unwrap();
        fs::create_dir_all(&skill_b).unwrap();
        fs::write(skill_a.join("README.md"), "shared skill guidance").unwrap();
        fs::write(skill_b.join("README.md"), "shared skill guidance").unwrap();
        fs::write(&skill_file, "captured absolute skill file").unwrap();
        symlink(&skill_file, &skill_file_alias).unwrap();
        fs::write(
            source_profile.join("instruction-target.md"),
            "captured instruction alias",
        )
        .unwrap();
        fs::write(source_profile.join("guidance-target.md"), base_guidance).unwrap();
        symlink(
            source_profile.join("instruction-target.md"),
            source_profile.join("aliases/instruction.md"),
        )
        .unwrap();
        symlink(
            source_profile.join("guidance-target.md"),
            source_profile.join("aliases/guidance.md"),
        )
        .unwrap();

        let candidate_id = ProfileId::parse("candidate-worker").unwrap();
        let candidate_profile = snapshot.profiles.get_mut(&candidate_id).unwrap();
        candidate_profile.instruction_files = vec!["aliases/instruction.md".into()];
        candidate_profile.skill_paths = vec![
            skill_a.to_string_lossy().into_owned(),
            skill_b.to_string_lossy().into_owned(),
            skill_file_alias.to_string_lossy().into_owned(),
        ];
        candidate_profile.learned_guidance = Some(crate::config::LearnedGuidance {
            file: "aliases/guidance.md".into(),
            project_id: ProjectId::parse("sample").unwrap(),
            role: Role::Worker,
            repository_ids: [crate::domain::ids::RepositoryId::parse("fixture-repo").unwrap()]
                .into_iter()
                .collect(),
        });
        fs::write(
            source_profile.join("config.toml"),
            toml::to_string(candidate_profile).unwrap(),
        )
        .unwrap();

        for (profile_id, profile) in &snapshot.profiles {
            if profile_id.as_str() == "candidate-worker" {
                continue;
            }
            let profile_root = config_root.join("profiles").join(profile_id.as_str());
            fs::create_dir_all(&profile_root).unwrap();
            fs::write(
                profile_root.join("config.toml"),
                toml::to_string(profile).unwrap(),
            )
            .unwrap();
        }
        symlink(
            &source_profile,
            config_root.join("profiles/candidate-worker"),
        )
        .unwrap();
        fs::write(
            config_root.join("config.toml"),
            toml::to_string(&snapshot.config).unwrap(),
        )
        .unwrap();
        crate::config::load(&config_root.join("config.toml")).unwrap()
    }

    #[test]
    fn publication_intent_and_receipt_are_durable_idempotent_and_subject_bound() {
        let (temp, mut store, project, generation, run) = running_store();
        let input = PostmortemInput {
            operation_id: OperationId::parse("postmortem-op-1").unwrap(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            title: "Learning".into(),
            summary: "A concise summary.".into(),
            findings: vec![format!(
                "The terminal receipt survives a restart.{}",
                "x".repeat(16_385)
            )],
            sources: vec![],
            generated_at: "2026-11-07T00:00:00Z".into(),
            max_source_bytes: 1024,
        };
        let request_json = serde_json::to_string(&input).unwrap();
        let request_digest =
            Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes()))).unwrap();
        let intent = KnowledgePublicationIntent {
            operation_id: input.operation_id.clone(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            request_digest,
            request_json,
        };
        assert!(
            store
                .prepare_knowledge_publication(generation, &intent)
                .unwrap()
        );
        assert_eq!(
            store
                .knowledge_publication_intent(&input.operation_id)
                .unwrap(),
            Some(intent.clone())
        );
        assert!(
            !store
                .prepare_knowledge_publication(generation, &intent)
                .unwrap()
        );
        let effect_count: usize = store
            .connection
            .query_row(
                "SELECT count(*) FROM effects WHERE operation_id=?1 AND kind='publish_knowledge'",
                [input.operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effect_count, 1);
        let transition_input = DurableInput {
            producer_id: "postmortem-agent".into(),
            message_id: "knowledge-published-1".into(),
            content_digest: durable_input_digest(
                "ticket_run",
                "{\"input\":\"knowledge_published\"}",
            ),
            recipient: "ticket_run".into(),
            payload: "{\"input\":\"knowledge_published\"}".into(),
        };
        let complete_effect = EffectIntent {
            project_id: project.clone(),
            subject_type: "ticket_run".into(),
            subject_id: run.to_string(),
            operation_id: "complete-ticket-1".into(),
            logical_key: "complete-ticket-r1".into(),
            kind: "complete_ticket".into(),
            request_json: "{}".into(),
            request_digest: content_digest("{}"),
            expected_revision: Some(1),
        };
        assert!(
            store
                .commit_ticket_transition(
                    generation,
                    &run,
                    Revision(0),
                    &transition_input,
                    crate::engine::reducer::Input::KnowledgePublished,
                    "Postmortem receipt is required before completion.",
                    "{}",
                    std::slice::from_ref(&complete_effect),
                )
                .err()
                .unwrap()
                .contains("durable knowledge publication")
        );
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let knowledge_root = temp.path().join("knowledge");
        let handler = KnowledgeEffectHandler::new(knowledge_root.clone());
        let receipt = handler.execute(&mut store, generation, &effect).unwrap();
        let moved_root = temp.path().join("knowledge-published-before-crash");
        fs::rename(&knowledge_root, &moved_root).unwrap();
        let replay = handler.execute(&mut store, generation, &effect).unwrap();
        assert_eq!(replay, receipt);
        assert!(
            !knowledge_root.exists(),
            "terminal receipt replay reran filesystem publication"
        );
        let transition = store
            .commit_ticket_transition(
                generation,
                &run,
                Revision(0),
                &transition_input,
                crate::engine::reducer::Input::KnowledgePublished,
                "Postmortem receipt is required before completion.",
                "{}",
                std::slice::from_ref(&complete_effect),
            )
            .unwrap();
        assert_eq!(transition.receipt["revision"], 1);
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM knowledge_publications WHERE operation_id=?1",
                [input.operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "published");
        let indexed: (String, String) = store
            .connection
            .query_row(
                "SELECT finding_text,publication_digest FROM learning_findings WHERE project_id=?1",
                [project.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(indexed.0, input.findings[0]);
        assert_eq!(indexed.1, receipt.manifest_digest.as_str());
        store.connection.execute_batch("DROP TABLE provider_qualification_candidate_targets; DELETE FROM schema_migrations WHERE version=22; DROP TABLE supervisor_topic_publications; DELETE FROM schema_migrations WHERE version=21; DELETE FROM schema_migrations WHERE version=20; DROP TABLE learning_decisions; DROP TABLE learning_findings; DROP TABLE learning_batches; DELETE FROM schema_migrations WHERE version=19; PRAGMA user_version=18;").unwrap();
        drop(store);
        let migrated = ConfigStore::open_test(temp.path()).unwrap();
        let backfilled: String = migrated
            .connection
            .query_row(
                "SELECT finding_text FROM learning_findings WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(backfilled, input.findings[0]);
    }

    #[test]
    fn candidates_and_trial_pairs_survive_database_round_trips_and_reject_conflicts() {
        let (_temp, mut store, project, generation, _) = running_store();
        let candidate_files = BTreeMap::from([(
            "instructions.md".to_owned(),
            b"Keep changes focused.".to_vec(),
        )]);
        let package_files_json = serde_json::to_string(&candidate_files).unwrap();
        let package_digest = crate::learning::manifest_digest(&candidate_files).unwrap();
        let manifest_rows: Vec<_> = candidate_files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect();
        let package_json = serde_json::to_string(&manifest_rows).unwrap();
        let candidate_digest = Digest::parse("b".repeat(64)).unwrap();
        let record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: "worker-profile-v2".into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2026-12-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: ProfileId::parse("worker-profile").unwrap(),
            package_manifest_digest: package_digest,
            package_files_json,
            package_json,
            expected_pairs: 5,
        };
        assert_eq!(
            store
                .register_learning_candidate(generation, &record)
                .unwrap(),
            CandidateRegistration::Registered
        );
        assert_eq!(
            store
                .register_learning_candidate(generation, &record)
                .unwrap(),
            CandidateRegistration::AlreadyRegistered
        );
        let candidate_package = store
            .learning_candidate_package(&project, &record.revision.candidate_id, &candidate_digest)
            .unwrap()
            .unwrap();
        assert_eq!(candidate_package.files, candidate_files);
        for pair_index in 0usize..5 {
            let observation = TrialObservation {
                input_digest: Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(pair_index.to_be_bytes())
                ))
                .unwrap(),
                baseline: TrialRunStatus::Equivalent,
                candidate: TrialRunStatus::Improved,
            };
            let progress = store
                .record_learning_trial(
                    generation,
                    &project,
                    &record.revision.candidate_id,
                    &candidate_digest,
                    pair_index,
                    &observation,
                )
                .unwrap();
            if pair_index == 4 {
                assert_eq!(progress.evidence.outcome, TrialOutcome::Improved);
            }
            assert_eq!(
                progress.trials.last().unwrap(),
                &StoredTrial {
                    pair_index,
                    observation
                }
            );
        }
        let conflict = TrialObservation {
            input_digest: Digest::parse("c".repeat(64)).unwrap(),
            baseline: TrialRunStatus::Equivalent,
            candidate: TrialRunStatus::Failed,
        };
        assert!(
            store
                .record_learning_trial(
                    generation,
                    &project,
                    &record.revision.candidate_id,
                    &candidate_digest,
                    0,
                    &conflict
                )
                .is_err()
        );
        let count: usize = store
            .connection
            .query_row("SELECT count(*) FROM learning_trial_pairs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 5);
        let supervisor = store
            .maintain_project_supervisor_learning(
                generation,
                &project,
                "2026-11-08T00:00:00Z",
                12,
                None,
            )
            .unwrap();
        assert_eq!(supervisor.project_id, project);
        assert_eq!(supervisor.expired_candidates, 0);
        assert_eq!(supervisor.knowledge.len(), 0);
        assert_eq!(supervisor.candidates.len(), 1);
        assert_eq!(
            supervisor.candidates[0].evidence.as_ref().unwrap().outcome,
            TrialOutcome::Improved
        );
        let _ = ProfileId::parse("worker-profile").unwrap();
    }

    #[test]
    fn supervisor_learning_runs_on_durable_per_project_cadence_and_wakes_supervisor() {
        let (temp, mut store, project, generation, _) = running_store();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project.as_str(),generation],
        ).unwrap();
        let second_project = ProjectId::parse("sample-b").unwrap();
        let first_record = store.project(&project).unwrap().unwrap();
        store
            .insert_project(&ProjectRecord {
                id: second_project.clone(),
                config_source: first_record.config_source,
                config_revision: first_record.config_revision,
                config_digest: first_record.config_digest,
                mode: first_record.mode,
                goal_revision: 1,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        store
            .set_project_lifecycle(generation, &second_project, "running")
            .unwrap();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![second_project.as_str(),generation],
        ).unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    &[project.clone(), second_project.clone()],
                    100,
                    3600,
                    None
                )
                .unwrap(),
            Some(project.clone())
        );
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    &[project.clone(), second_project.clone()],
                    101,
                    3600,
                    None
                )
                .unwrap(),
            Some(second_project.clone())
        );
        let supervisor_session = format!("project:{}:supervisor", project.as_str());
        store
            .connection
            .execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'ticket_observation','ticket-1:ready',1,30,'{}','pending',101)",
                rusqlite::params![project.as_str(), supervisor_session],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO role_wake_inputs(project_id,role_session_id,source_type,source_id,source_revision,priority,payload_json,lifecycle,created_at_unix) VALUES (?1,?2,'periodic_supervisor_review','low-priority',1,0,'{}','pending',101)",
                rusqlite::params![project.as_str(), supervisor_session],
            )
            .unwrap();
        let pending = store
            .pending_role_wake_inputs(&project, &supervisor_session, 2)
            .unwrap();
        assert_eq!(
            pending
                .iter()
                .map(|wake| wake.source_type.as_str())
                .collect::<Vec<_>>(),
            vec!["learning_batch", "ticket_observation"]
        );
        assert_eq!(
            pending.iter().map(|wake| wake.priority).collect::<Vec<_>>(),
            vec![1, 30]
        );
        assert!(pending[0].source_id.starts_with("learning-"));
        assert_eq!(pending[0].source_revision, 1);
        assert!(pending.iter().all(|wake| wake.source_revision > 0));
        let mut inbox = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: supervisor_session,
            agent_run_id: "agent-supervisor-test".into(),
            digest: crate::domain::ids::Digest::parse("0".repeat(64)).unwrap(),
            inputs: pending
                .into_iter()
                .map(|wake| crate::agent_api::AgentWakeItem {
                    wake_input_id: wake.wake_input_id,
                    source_type: wake.source_type,
                    source_id: wake.source_id,
                    source_revision: wake.source_revision,
                    priority: wake.priority,
                    payload_json: wake.payload_json,
                    host_artifact_source_evidence_ids: Vec::new(),
                    host_artifacts: Vec::new(),
                    host_completion_context: None,
                })
                .collect(),

            worker_correction_context: None,
        };
        inbox.digest = inbox.content_digest().unwrap();
        inbox.validate().unwrap();
        let wake: (String,String,String,String) = store.connection.query_row(
            "SELECT role_session_id,source_type,source_id,payload_json FROM role_wake_inputs WHERE project_id=?1 AND source_type='learning_batch'",
            [project.as_str()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(wake.0, format!("project:{}:supervisor", project.as_str()));
        assert_eq!(wake.1, "learning_batch");
        let payload: serde_json::Value = serde_json::from_str(&wake.3).unwrap();
        assert_eq!(payload["type"], "supervisor_learning_batch");
        assert_eq!(payload["project_id"], project.as_str());
        assert_eq!(payload["batch_id"], wake.2);
        let stored_digest: String = store
            .connection
            .query_row(
                "SELECT batch_digest FROM learning_batches WHERE batch_id=?1",
                [&wake.2],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(payload["batch_digest"], stored_digest);
        assert_eq!(payload["findings"].as_array().unwrap().len(), 0);
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    &[project.clone(), second_project.clone()],
                    3700,
                    3600,
                    None
                )
                .unwrap(),
            None
        );
        let wake_count: usize = store.connection.query_row(
            "SELECT count(*) FROM role_wake_inputs WHERE project_id=?1 AND source_type='learning_batch'",
            [project.as_str()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(wake_count, 1);
        let prior_snapshot: (String, String) = store.connection.query_row(
            "SELECT batch_id,snapshot_json FROM learning_batches WHERE project_id=?1 AND status='issued'",
            [project.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        drop(store);
        let mut reopened = ConfigStore::open_test(temp.path()).unwrap();
        assert_eq!(
            reopened.connection.query_row::<String,_,_>(
                "SELECT snapshot_json FROM learning_batches WHERE batch_id=?1 AND status='issued'",
                [&prior_snapshot.0],
                |row| row.get(0),
            ).unwrap(),
            prior_snapshot.1
        );
        assert_eq!(
            reopened
                .queue_due_supervisor_learning(
                    generation,
                    &[project.clone(), second_project.clone()],
                    3701,
                    3600,
                    None
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn config_sync_supersedes_only_pending_old_batch_and_allows_new_revision_batch() {
        let (_temp, mut store, project, generation, _) = running_store();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project.as_str(), generation],
        ).unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    100,
                    3600,
                    None
                )
                .unwrap(),
            Some(project.clone())
        );
        let old_wake: (String, i64) = store.connection.query_row(
            "SELECT batch_id,wake_input_id FROM learning_batches WHERE project_id=?1 AND status='issued'",
            [project.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        let old_wake_lifecycle: String = store
            .connection
            .query_row(
                "SELECT lifecycle FROM role_wake_inputs WHERE wake_input_id=?1",
                [old_wake.1],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_wake_lifecycle, "pending");

        let mut revised = test_snapshot();
        revised.config.projects.insert(
            project.clone(),
            serde_json::from_value(
                serde_json::json!({"mode":"operations","ticket_adapter":"tickets"}),
            )
            .unwrap(),
        );
        revised.digest = Digest::parse(
            crate::config::digest_manifest(
                &revised.config,
                &revised.profiles,
                &revised.source_files,
            )
            .unwrap(),
        )
        .unwrap();
        let applied = store
            .apply_snapshot("factory", &revised, ExpectedRevision::Current(Revision(1)))
            .unwrap();
        assert_eq!(applied.revision, Revision(2));
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [&old_wake.0],
                    |row| row.get(0)
                )
                .unwrap(),
            "superseded"
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT lifecycle FROM role_wake_inputs WHERE wake_input_id=?1",
                    [old_wake.1],
                    |row| row.get(0)
                )
                .unwrap(),
            "superseded"
        );

        store
            .connection
            .execute(
                "UPDATE supervisor_learning_schedule SET next_due_at_unix=0 WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    101,
                    3600,
                    None
                )
                .unwrap(),
            Some(project.clone())
        );
        let issued: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM learning_batches WHERE project_id=?1 AND status='issued'",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(issued, 1);
    }

    #[test]
    fn latest_learning_checkpoint_uses_insertion_order_when_acceptance_seconds_tie() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE learning_batches(batch_id TEXT PRIMARY KEY,project_id TEXT NOT NULL);
             CREATE TABLE learning_decisions(decision_sequence INTEGER PRIMARY KEY AUTOINCREMENT,batch_id TEXT NOT NULL UNIQUE,decision_json TEXT NOT NULL,accepted_at_unix INTEGER NOT NULL);
             INSERT INTO learning_batches VALUES ('learning-z-older','sample'),('learning-a-newer','sample');
             INSERT INTO learning_decisions(batch_id,decision_json,accepted_at_unix) VALUES ('learning-z-older','{\"checkpoint\":{\"step\":\"older\"}}',100);
             INSERT INTO learning_decisions(batch_id,decision_json,accepted_at_unix) VALUES ('learning-a-newer','{\"checkpoint\":{\"step\":\"newer\"}}',100);",
        ).unwrap();
        assert_eq!(
            super::latest_supervisor_checkpoint(&connection, "sample").unwrap(),
            BTreeMap::from([("step".into(), "newer".into())]),
        );
        connection.execute_batch("VACUUM").unwrap();
        assert_eq!(
            super::latest_supervisor_checkpoint(&connection, "sample").unwrap(),
            BTreeMap::from([("step".into(), "newer".into())]),
        );
    }

    #[test]
    fn five_individual_findings_trigger_one_fifo_batch_capped_at_twenty() {
        let (_temp, mut store, project, generation, run) = running_store();
        store.connection.execute("UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",rusqlite::params![project.as_str(),generation]).unwrap();
        store.connection.execute("INSERT INTO supervisor_learning_schedule(project_id,next_due_at_unix) VALUES (?1,1000)", [project.as_str()]).unwrap();
        let publication = Digest::parse("a".repeat(64)).unwrap();
        for ordinal in 0..4u32 {
            let text = format!("finding-{ordinal}");
            let id = learning_finding_id(&publication, ordinal, &text).unwrap();
            store.connection.execute("INSERT INTO learning_findings(finding_id,project_id,ticket_run_id,publication_digest,ordinal,finding_text,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,10)",params![id.as_str(),project.as_str(),run.as_str(),publication.as_str(),ordinal,text]).unwrap();
        }
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    100,
                    3600,
                    None
                )
                .unwrap(),
            None
        );
        for ordinal in 4..25u32 {
            let publication = Digest::parse(format!("{:064x}", ordinal + 1)).unwrap();
            let text = format!("finding-{ordinal}");
            let id = learning_finding_id(&publication, ordinal, &text).unwrap();
            store.connection.execute("INSERT INTO learning_findings(finding_id,project_id,ticket_run_id,publication_digest,ordinal,finding_text,created_at_unix) VALUES (?1,?2,?3,?4,?5,?6,10)",params![id.as_str(),project.as_str(),run.as_str(),publication.as_str(),ordinal,text]).unwrap();
        }
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    101,
                    3600,
                    None
                )
                .unwrap(),
            Some(project.clone())
        );
        let (batch_id,findings_json):(String,String)=store.connection.query_row("SELECT batch_id,findings_json FROM learning_batches WHERE project_id=?1 AND status='issued'",[project.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        let selected: Vec<LearningFinding> = serde_json::from_str(&findings_json).unwrap();
        assert_eq!(selected.len(), LEARNING_BATCH_MAX_FINDINGS);
        assert_eq!(selected[0].text, "finding-0");
        assert_eq!(selected[19].text, "finding-19");
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    102,
                    3600,
                    None
                )
                .unwrap(),
            None
        );
        let issued: usize = store
            .connection
            .query_row(
                "SELECT count(*) FROM learning_batches WHERE project_id=?1 AND status='issued'",
                [project.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(issued, 1);
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT batch_id FROM learning_batches WHERE project_id=?1 AND status='issued'",
                    [project.as_str()],
                    |r| r.get(0)
                )
                .unwrap(),
            batch_id
        );
    }

    struct LearningDispatchFixture {
        _temp: TempDir,
        store: ConfigStore,
        project: ProjectId,
        generation: u64,
        batch_id: String,
        result: crate::store::agent_results::IngestedAgentResult,
        config: crate::config::Config,
        config_digest: Digest,
        checkpoint: BTreeMap<String, String>,
    }

    enum CandidateFixture {
        Omitted,
        Proposed,
        StalePrior,
        OversizedContext,
        OversizedGuidance,
    }

    fn learning_dispatch_fixture(
        assertion: crate::engine::orchestration::AgentAssertion,
        unsupported_proposal: bool,
        maximum_finding: bool,
        claim_override: Option<(bool, bool)>,
    ) -> LearningDispatchFixture {
        learning_dispatch_fixture_with_topic(
            assertion,
            unsupported_proposal,
            maximum_finding,
            claim_override,
            false,
            None,
        )
    }

    fn learning_dispatch_fixture_with_topic(
        assertion: crate::engine::orchestration::AgentAssertion,
        unsupported_proposal: bool,
        maximum_finding: bool,
        claim_override: Option<(bool, bool)>,
        create_topic: bool,
        topic_source_override: Option<Digest>,
    ) -> LearningDispatchFixture {
        learning_dispatch_fixture_with_options(
            assertion,
            unsupported_proposal,
            maximum_finding,
            claim_override,
            create_topic,
            topic_source_override,
            CandidateFixture::Omitted,
        )
    }

    fn learning_dispatch_fixture_with_options(
        assertion: crate::engine::orchestration::AgentAssertion,
        unsupported_proposal: bool,
        maximum_finding: bool,
        claim_override: Option<(bool, bool)>,
        create_topic: bool,
        topic_source_override: Option<Digest>,
        candidate: CandidateFixture,
    ) -> LearningDispatchFixture {
        let include_candidate = !matches!(candidate, CandidateFixture::Omitted);
        let stale_candidate_prior = matches!(candidate, CandidateFixture::StalePrior);
        let large_candidate_context = matches!(candidate, CandidateFixture::OversizedContext);
        let oversized_guidance = matches!(candidate, CandidateFixture::OversizedGuidance);
        let mut config = test_snapshot();
        let profile_id = ProfileId::parse("fixture-profile").unwrap();
        config.config.projects.insert(
            ProjectId::parse("sample").unwrap(),
            serde_json::from_value(serde_json::json!({
                "mode": "goal",
                "ticket_adapter": "tickets",
                "goal":{"revision":1,"statement":"Fixture objective","acceptance":["Candidate dispatch is accepted."]},
                "roles": if include_candidate { serde_json::json!({"supervisor":"fixture-profile","coordinator":"fixture-profile","planner":"fixture-profile","worker":"candidate-worker","reviewer":"fixture-profile","merge_decision":"fixture-profile","operator":"fixture-profile","postmortem":"fixture-profile"}) } else { serde_json::json!({"supervisor":"fixture-profile"}) },
                "repositories": if include_candidate { vec!["fixture-repo".to_string()] } else { Vec::<String>::new() }
            }))
            .unwrap(),
        );
        config.profiles.insert(
            profile_id.clone(),
            serde_json::from_value(serde_json::json!({
                "adapter": "codex",
                "command": ["/bin/codex"],
                "model": "fixture",
                "commit_mode": "native",
                "turn_timeout_seconds": 60
            }))
            .unwrap(),
        );
        if oversized_guidance {
            config.profiles.get_mut(&profile_id).unwrap().description = Some("d".repeat(20_000));
        }
        if include_candidate {
            config.profiles.insert(
                ProfileId::parse("candidate-worker").unwrap(),
                serde_json::from_value(serde_json::json!({
                    "adapter":"codex","command":["/bin/codex"],"model":"worker-model",
                    "description":"Worker profile",
                    "instruction_files":[],"skill_paths":["/fixture/skills-a","/fixture/skills-b"],
                    "commit_mode":"native","turn_timeout_seconds":73
                }))
                .unwrap(),
            );
            config.config.repositories.insert(
                crate::domain::ids::RepositoryId::parse("fixture-repo").unwrap(),
                serde_json::from_value(serde_json::json!({
                    "clone_url":"https://example.invalid/fixture/repo.git",
                    "base_branch":"main","forge":"github"
                }))
                .unwrap(),
            );
            config = load_symlinked_candidate_fixture(
                config,
                &if oversized_guidance {
                    "g".repeat(super::MAX_SUPERVISOR_CONTEXT_BYTES + 1)
                } else {
                    "captured base guidance".into()
                },
            );
        }
        let (temp, mut store, project, generation, run) = running_store_with_snapshot(&config);
        if create_topic {
            config.config.knowledge = Some(crate::config::KnowledgeConfig {
                format: "okf-0.2".into(),
                root: temp
                    .path()
                    .join("topic-knowledge")
                    .to_string_lossy()
                    .into_owned(),
                max_source_bytes: 1024,
            });
        }
        store
            .connection
            .execute(
                "UPDATE projects SET desired_lifecycle='running' WHERE project_id=?1",
                [project.as_str()],
            )
            .unwrap();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![project.as_str(), generation],
        ).unwrap();
        let summary = "Published evidence for the Supervisor learning flow.";
        let generated_at = "2026-11-07T00:00:00Z";
        let finding = if maximum_finding {
            "x".repeat(
                crate::knowledge::DEFAULT_MAX_ARTICLE_BYTES
                    - 1024
                    - "Learning fixture".len()
                    - summary.len()
                    - generated_at.len()
                    - 64,
            )
        } else {
            "A published Finding reaches a durable Supervisor decision.".into()
        };
        let input = PostmortemInput {
            operation_id: OperationId::parse("learning-flow-publication").unwrap(),
            project_id: project.clone(),
            ticket_run_id: run.clone(),
            title: "Learning fixture".into(),
            summary: summary.into(),
            findings: vec![finding],
            sources: vec![],
            generated_at: generated_at.into(),
            max_source_bytes: 1024,
        };
        crate::knowledge::validate_postmortem_input(&input).unwrap();
        let request_json = serde_json::to_string(&input).unwrap();
        let intent = KnowledgePublicationIntent {
            operation_id: input.operation_id.clone(),
            project_id: project.clone(),
            ticket_run_id: run,
            request_digest: Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes())))
                .unwrap(),
            request_json,
        };
        store
            .prepare_knowledge_publication(generation, &intent)
            .unwrap();
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let knowledge_root = if create_topic {
            std::path::PathBuf::from(&config.config.knowledge.as_ref().unwrap().root)
        } else {
            temp.path().join("learning-flow-knowledge")
        };
        KnowledgeEffectHandler::new(knowledge_root.clone())
            .execute(&mut store, generation, &effect)
            .unwrap();
        if include_candidate {
            let second_run = TicketRunId::parse("sample-2-g1").unwrap();
            store
                .create_ticket_run(
                    generation,
                    &project,
                    &TicketNamespace::parse("github:org/repo").unwrap(),
                    &TicketId::parse("2").unwrap(),
                    &second_run,
                    1,
                    "postmortem",
                    "In Progress",
                )
                .unwrap();
            let second_input = PostmortemInput {
                operation_id: OperationId::parse("learning-flow-publication-second").unwrap(),
                project_id: project.clone(),
                ticket_run_id: second_run.clone(),
                title: "Second learning fixture".into(),
                summary: summary.into(),
                findings: vec![
                    "A distinct TicketRun contributes independent published evidence.".into(),
                ],
                sources: vec![],
                generated_at: "2026-11-07T00:01:00Z".into(),
                max_source_bytes: 1024,
            };
            let request_json = serde_json::to_string(&second_input).unwrap();
            let second_intent = KnowledgePublicationIntent {
                operation_id: second_input.operation_id.clone(),
                project_id: project.clone(),
                ticket_run_id: second_run,
                request_digest: Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(request_json.as_bytes())
                ))
                .unwrap(),
                request_json,
            };
            store
                .prepare_knowledge_publication(generation, &second_intent)
                .unwrap();
            let second_effect = store
                .next_due_effect(generation, i64::MAX)
                .unwrap()
                .unwrap();
            KnowledgeEffectHandler::new(knowledge_root.clone())
                .execute(&mut store, generation, &second_effect)
                .unwrap();
        }
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    100,
                    3600,
                    if create_topic {
                        Some(knowledge_root.as_path())
                    } else {
                        None
                    }
                )
                .unwrap(),
            Some(project.clone())
        );
        let wake_session = format!("project:{}:supervisor", project.as_str());
        let pending = store
            .pending_role_wake_inputs(&project, &wake_session, 16)
            .unwrap();
        let batch_payload = pending
            .iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap()
            .payload_json
            .clone();
        if include_candidate {
            let worker_target = batch_payload["maintenance"]["candidate_targets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|target| target["profile_id"] == "candidate-worker")
                .unwrap();
            if oversized_guidance {
                assert!(worker_target["learned_guidance"].is_null());
                assert_eq!(
                    worker_target["omitted_learned_guidance_bytes"],
                    super::MAX_SUPERVISOR_CONTEXT_BYTES + 1
                );
            } else {
                assert_eq!(worker_target["learned_guidance"], "captured base guidance");
            }
        }
        let batch_id = batch_payload["batch_id"].as_str().unwrap().to_owned();
        let batch_digest = Digest::parse(batch_payload["batch_digest"].as_str().unwrap()).unwrap();
        assert_eq!(
            batch_payload["findings"].as_array().unwrap().len(),
            if include_candidate { 2 } else { 1 }
        );
        let wake_inputs: Vec<crate::agent_api::AgentWakeItem> = pending
            .into_iter()
            .map(|wake| crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type,
                source_id: wake.source_id,
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            })
            .collect();
        let config_revision = store.project(&project).unwrap().unwrap().config_revision;
        let checkpoint = BTreeMap::from([("last_batch".into(), batch_id.clone())]);
        let (wrong_batch_id, wrong_digest) = claim_override.unwrap_or((false, false));
        let claimed_batch_id = if wrong_batch_id {
            "learning-typo".to_owned()
        } else {
            batch_id.clone()
        };
        let claimed_batch_digest = if wrong_digest {
            Digest::parse("f".repeat(64)).unwrap()
        } else {
            batch_digest
        };
        let topic_changes = if create_topic {
            let finding_id = topic_source_override.unwrap_or(
                Digest::parse(
                    batch_payload["findings"][0]["id"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
                .unwrap(),
            );
            vec![crate::topic::TopicChange {
                topic_key: "safe-replay".into(),
                title: "Replay only the accepted bytes".into(),
                summary: "An effect retry may publish only the exact immutable Topic document."
                    .into(),
                claims: vec![
                    "Create-only publication preserves an unexpected existing target.".into(),
                ],
                applicability: "Use when retrying generated knowledge publication.".into(),
                proposed_check: "Compare the saved content digest and preserve any mismatch."
                    .into(),
                counterexamples: vec![
                    "A manual edit at the same path must remain unchanged.".into(),
                ],
                source_finding_ids: vec![finding_id],
                expected_prior_digest: None,
            }]
        } else if unsupported_proposal {
            vec![crate::topic::TopicChange {
                topic_key: "topic-update".into(),
                title: "Updated topic".into(),
                summary: "Unsupported revision fixture.".into(),
                claims: vec!["A revision is not yet supported.".into()],
                applicability: "Fixture only.".into(),
                proposed_check: "Remain rejected.".into(),
                counterexamples: Vec::new(),
                source_finding_ids: vec![Digest::parse("c".repeat(64)).unwrap()],
                expected_prior_digest: Some(Digest::parse("d".repeat(64)).unwrap()),
            }]
        } else {
            Vec::new()
        };
        let candidate_change = if include_candidate {
            let base_profile_id = ProfileId::parse("candidate-worker").unwrap();
            Some(crate::learning::ProfileCandidateProposal {
                role: crate::domain::types::Role::Worker,
                base_profile_id: base_profile_id.clone(),
                base_profile_digest: crate::store::agent_profile_digest(
                    config.profiles.get(&base_profile_id).unwrap(),
                )
                .unwrap(),
                topic_key: "reliable-test-commands".into(),
                repository_ids: vec![
                    crate::domain::ids::RepositoryId::parse("fixture-repo").unwrap(),
                ],
                source_finding_ids: batch_payload["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|finding| Digest::parse(finding["id"].as_str().unwrap()).unwrap())
                    .collect(),
                expected_prior_digest: stale_candidate_prior
                    .then(|| Digest::parse("f".repeat(64)).unwrap()),
                description: if large_candidate_context {
                    "\u{1}".repeat(crate::learning::MAX_CANDIDATE_TEXT_BYTES)
                } else {
                    "Run focused acceptance checks first".into()
                },
                learned_guidance: if large_candidate_context {
                    "\u{1}".repeat(crate::learning::MAX_CANDIDATE_GUIDANCE_BYTES)
                } else {
                    "Run the smallest relevant test before the full suite.".into()
                },
                evaluation_criterion: if large_candidate_context {
                    "\u{1}".repeat(crate::learning::MAX_CANDIDATE_TEXT_BYTES)
                } else {
                    "Paired runs reduce avoidable full-suite retries without adding regressions."
                        .into()
                },
            })
        } else {
            None
        };
        let decision_payload = crate::engine::orchestration::LearningDecisionPayload {
            batch_id: claimed_batch_id,
            batch_digest: claimed_batch_digest,
            config_revision,
            observations: vec!["The Finding is stable and reproducible.".into()],
            topic_changes,
            checkpoint: checkpoint.clone(),
            improvements: Vec::new(),
            candidate_change,
        };
        let message = crate::roles::RoleResultMessage {
            schema_version: 1,
            message_id: "learning-flow-result".into(),
            kind: crate::engine::orchestration::RoleOutputKind::LearningDecision,
            assertion,
            structured_result: serde_json::to_value(&decision_payload).unwrap(),
            result_digest: None,
            artifact_refs: Vec::new(),
        };
        let message = if create_topic || include_candidate {
            let schema = crate::roles::result_schema(crate::domain::types::Role::Supervisor);
            let encoded_message = serde_json::to_string(&message).unwrap();
            let final_response = [
                serde_json::json!({"type":"thread.started","thread_id":"topic-thread-1"}),
                serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":serde_json::to_string(&serde_json::json!({"result": encoded_message})).unwrap()}}),
                serde_json::json!({"type":"turn.completed"}),
            ].iter().map(serde_json::Value::to_string).collect::<Vec<_>>().join("\n");
            let (_, parsed) = crate::providers::parse_result(
                crate::domain::types::AgentAdapter::Codex,
                final_response.as_bytes(),
                &schema,
            )
            .unwrap();
            serde_json::from_value(parsed).unwrap()
        } else {
            message
        };
        if create_topic || include_candidate {
            let inbox_root = temp.path().join("topic-inbox");
            fs::create_dir(&inbox_root).unwrap();
            let mut snapshot = crate::agent_api::AgentWakeSnapshot {
                schema_version: 1,
                project_id: project.clone(),
                role_session_id: format!("project:{}:supervisor", project.as_str()),
                agent_run_id: "learning-flow-agent".into(),
                digest: Digest::parse("0".repeat(64)).unwrap(),
                inputs: wake_inputs.clone(),
                worker_correction_context: None,
            };
            crate::agent_api::publish_wake_snapshot(&inbox_root, snapshot.clone()).unwrap();
            let read = crate::agent_api::read_inbox(&inbox_root, "learning-flow-agent", 0).unwrap();
            assert_eq!(read, wake_inputs);
            assert!(snapshot.serialized_bytes().unwrap().len() < crate::agent_api::MAX_INBOX_BYTES);
        }
        let canonical_root = fs::canonicalize(temp.path()).unwrap();
        let result = crate::store::agent_results::host_validation_fixture::host_validated_supervisor_result_in_with_wake_inputs(
            &mut store,
            &canonical_root,
            generation,
            project.clone(),
            message,
            crate::domain::ids::AgentRunId::parse("learning-flow-agent").unwrap(),
            wake_inputs,
        ).unwrap().ingested;
        store.connection.execute(
            "UPDATE role_wake_inputs SET lifecycle='consumed' WHERE consuming_agent_run_id=?1 AND source_type='learning_batch'",
            [result.validated.binding.agent_run_id.as_str()],
        ).unwrap();
        let config_digest = store.project(&project).unwrap().unwrap().config_digest;
        LearningDispatchFixture {
            _temp: temp,
            store,
            project,
            generation,
            batch_id,
            result,
            config: config.config,
            config_digest,
            checkpoint,
        }
    }

    #[test]
    fn supervisor_candidate_dispatch_persists_and_reissues_verified_learning_input() {
        let fixture = learning_dispatch_fixture_with_options(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            false,
            None,
            CandidateFixture::Proposed,
        );
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            ..
        } = fixture;
        let config_revision = store.project(&project).unwrap().unwrap().config_revision;
        let tx = store.connection.transaction().unwrap();
        let applied_config =
            applied_config_in_transaction(&tx, &project, config_revision.0, config_digest.as_str())
                .unwrap();
        tx.rollback().unwrap();
        let base_profile = &applied_config.profiles[&ProfileId::parse("candidate-worker").unwrap()];
        let profile_root =
            std::path::Path::new(&applied_config.source_root).join("profiles/candidate-worker");
        let canonical_profile_root = applied_config
            .source_files
            .iter()
            .find(|source| {
                matches!(source.kind, crate::config::SourceKind::Directory)
                    && std::path::Path::new(&source.path) == profile_root
            })
            .map(|source| std::path::PathBuf::from(&source.canonical_path))
            .unwrap();
        let (skill_roots, skill_files) =
            captured_skill_sources(&applied_config, base_profile, &canonical_profile_root).unwrap();
        assert_eq!(skill_roots.len(), 2);
        assert_eq!(skill_files.len(), 1);
        let mut old_captured_manifest = applied_config.clone();
        old_captured_manifest.source_files.retain(|source| {
            !matches!(source.kind, crate::config::SourceKind::Directory)
                || !base_profile
                    .skill_paths
                    .iter()
                    .any(|skill| std::path::Path::new(skill) == std::path::Path::new(&source.path))
        });
        assert!(
            captured_skill_sources(
                &old_captured_manifest,
                base_profile,
                &canonical_profile_root
            )
            .is_err()
        );
        let mut other_slot = match &result.validated.typed_payload {
            crate::engine::orchestration::RoleResultPayload::LearningDecision(payload) => {
                payload.clone()
            }
            other => panic!("expected parsed learning decision, got {other:?}"),
        };
        other_slot.candidate_change.as_mut().unwrap().topic_key = "reliable-incident-checks".into();
        let (snapshot_json, findings_json): (String, String) = store
            .connection
            .query_row(
                "SELECT snapshot_json,findings_json FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let issued_snapshot: serde_json::Value = serde_json::from_str(&snapshot_json).unwrap();
        let findings: Vec<LearningFinding> = serde_json::from_str(&findings_json).unwrap();
        let tx = store.connection.transaction().unwrap();
        let other_record = prepare_learning_candidate(
            &tx,
            &project,
            &other_slot,
            &issued_snapshot,
            &findings,
            1_800_000_000,
        )
        .unwrap()
        .record
        .unwrap();
        let other_candidate_id = other_record.revision.candidate_id.clone();
        let other_candidate_digest = other_record.revision.digest.clone();
        register_learning_candidate_in_transaction(&tx, generation, &other_record).unwrap();
        tx.commit().unwrap();
        crate::engine::factory_runtime::tests::apply_agent_result_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest.clone(),
            &result,
        )
        .unwrap();
        let rejection: Option<String> = store
            .connection
            .query_row(
                "SELECT last_error FROM project_runtimes WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            rejection.is_none(),
            "candidate dispatch rejected: {rejection:?}"
        );
        assert_eq!(
            store.connection.query_row::<String, _, _>(
                "SELECT status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
                rusqlite::params![project.as_str(), other_candidate_id, other_candidate_digest.as_str()],
                |row| row.get(0),
            ).unwrap(),
            "proposed",
            "accepting another same-role Topic slot must preserve the existing candidate"
        );
        let (candidate_id, profile_id) = crate::learning::candidate_slot_id(
            &project,
            crate::domain::types::Role::Worker,
            &ProfileId::parse("candidate-worker").unwrap(),
            &crate::topic::TopicKey::parse("reliable-test-commands").unwrap(),
        );
        let (candidate_digest, profile_id_raw): (String,String) = store.connection.query_row(
            "SELECT digest,profile_id FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND status='proposed'",
            rusqlite::params![project.as_str(),candidate_id],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(ProfileId::parse(profile_id_raw).unwrap(), profile_id);
        let payload = match &result.validated.typed_payload {
            crate::engine::orchestration::RoleResultPayload::LearningDecision(payload) => {
                payload.clone()
            }
            other => panic!("expected parsed learning decision, got {other:?}"),
        };
        let (snapshot_json, findings_json): (String, String) = store
            .connection
            .query_row(
                "SELECT snapshot_json,findings_json FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let issued_snapshot: serde_json::Value = serde_json::from_str(&snapshot_json).unwrap();
        let findings: Vec<LearningFinding> = serde_json::from_str(&findings_json).unwrap();
        let mut no_op = payload.clone();
        no_op
            .candidate_change
            .as_mut()
            .unwrap()
            .expected_prior_digest = Some(Digest::parse(candidate_digest.clone()).unwrap());
        let tx = store.connection.transaction().unwrap();
        let prepared = prepare_learning_candidate(
            &tx,
            &project,
            &no_op,
            &issued_snapshot,
            &findings,
            1_800_000_000,
        )
        .unwrap();
        assert!(
            prepared.record.is_none(),
            "a semantic no-op must reuse the current revision"
        );
        tx.rollback().unwrap();

        let expires_at: String = store.connection.query_row(
            "SELECT json_extract(revision_json,'$.expires_at') FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            rusqlite::params![project.as_str(), candidate_id, candidate_digest],
            |row| row.get(0),
        ).unwrap();
        store.connection.execute(
            "INSERT INTO profile_trial_authorizations(authorization_id,project_id,candidate_id,candidate_digest,human_request_id,request_json,rex_view_id,artifact_path,authorization_digest,authorization_json,lifecycle,created_at_unix,updated_at_unix) VALUES ('pending-pin',?1,?2,?3,'pending-pin-request','{}',?4,'/tmp/pin',?5,'{}','pending',1,1)",
            rusqlite::params![project.as_str(),candidate_id,candidate_digest,"a".repeat(64),"b".repeat(64)],
        ).unwrap();
        let mut replacement = payload;
        replacement
            .candidate_change
            .as_mut()
            .unwrap()
            .expected_prior_digest = Some(Digest::parse(candidate_digest.clone()).unwrap());
        replacement
            .candidate_change
            .as_mut()
            .unwrap()
            .description
            .push_str(" revised");
        let tx = store.connection.transaction().unwrap();
        assert!(
            prepare_learning_candidate(
                &tx,
                &project,
                &replacement,
                &issued_snapshot,
                &findings,
                1_800_000_000,
            )
            .err()
            .unwrap()
            .contains("pinned")
        );
        let maintenance =
            supervisor_learning_snapshot_in_transaction(&tx, &project, &expires_at, 50, None)
                .unwrap();
        assert!(maintenance.candidates.iter().any(|candidate| {
            candidate.revision.candidate_id == candidate_id
                && candidate.revision.digest.as_str() == candidate_digest
                && candidate.revision.status == CandidateStatus::Proposed
        }));
        tx.rollback().unwrap();
        let package = store
            .learning_candidate_package(
                &project,
                &candidate_id,
                &Digest::parse(candidate_digest.clone()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let candidate_profile: crate::config::Profile =
            toml::from_str(std::str::from_utf8(package.files.get("config.toml").unwrap()).unwrap())
                .unwrap();
        let qualification_request =
            crate::store::provider_qualification_runtime::ProviderQualificationRequest {
                request_id: "candidate-resolver-fixture".into(),
                project_id: project.clone(),
                role: package.revision.role,
                profile_id: package.profile_id.clone(),
                profile_digest: crate::store::agent_profile_digest(&candidate_profile).unwrap(),
                config_revision: config_revision.0,
                config_digest: config_digest.clone(),
                target: crate::store::provider_qualification_runtime::ProviderQualificationTarget::Candidate {
                    candidate_id: candidate_id.clone(),
                    candidate_digest: Digest::parse(candidate_digest.clone()).unwrap(),
                },
            };
        let resolved_profile = store
            .resolve_provider_qualification_candidate(&qualification_request, &applied_config)
            .unwrap();
        assert_eq!(
            crate::store::agent_profile_digest(&resolved_profile).unwrap(),
            qualification_request.profile_digest
        );
        let metadata: crate::learning::ProfileCandidateMetadata = crate::protocol::parse_unique(
            package
                .files
                .get(crate::learning::PROFILE_CANDIDATE_METADATA_PATH)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata.source_ticket_run_ids.len(), 2);
        assert_eq!(
            metadata.base_guidance.as_deref(),
            Some("captured base guidance")
        );
        assert_eq!(
            package.files.get("aliases/instruction.md").unwrap(),
            b"captured instruction alias"
        );
        assert_eq!(metadata.external_sources.len(), 3);
        assert_eq!(
            metadata
                .external_sources
                .values()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        assert!(metadata.external_sources.values().any(|path| {
            package
                .files
                .get(path)
                .is_some_and(|bytes| bytes.as_slice() == b"captured absolute skill file")
        }));
        assert!(metadata.external_sources.values().any(|path| {
            package
                .files
                .get(path)
                .is_some_and(|bytes| bytes.as_slice() == b"shared skill guidance")
        }));
        let base_profile: crate::config::Profile =
            crate::protocol::parse_unique(metadata.base_profile_json.as_bytes()).unwrap();
        assert_eq!(base_profile.model.as_deref(), Some("worker-model"));
        let candidate_profile: crate::config::Profile =
            toml::from_str(std::str::from_utf8(package.files.get("config.toml").unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            candidate_profile.description.as_deref(),
            Some("Run focused acceptance checks first")
        );
        assert_eq!(candidate_profile.command, vec!["/bin/codex"]);
        assert_eq!(candidate_profile.model.as_deref(), Some("worker-model"));
        assert_eq!(candidate_profile.turn_timeout_seconds, 73);
        assert_eq!(
            candidate_profile.commit_mode,
            crate::domain::types::CommitMode::Native
        );
        assert_eq!(
            candidate_profile.learned_guidance.as_ref().unwrap().role,
            crate::domain::types::Role::Worker
        );
        assert_eq!(
            package.manifest_digest,
            crate::learning::manifest_digest(&package.files).unwrap()
        );
        assert_ne!(package.manifest_digest, package.revision.digest);
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [batch_id],
                    |row| row.get(0)
                )
                .unwrap(),
            "completed"
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0)
                )
                .unwrap(),
            "applied"
        );
        drop(store);
        let mut reopened = ConfigStore::open_test(_temp.path()).unwrap();
        assert_eq!(
            reopened
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    10_000,
                    3_600,
                    None,
                )
                .unwrap(),
            Some(project.clone())
        );
        let session = format!("project:{}:supervisor", project.as_str());
        let next_batch = reopened
            .pending_role_wake_inputs(&project, &session, 16)
            .unwrap()
            .into_iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let card = next_batch.payload_json["maintenance"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["revision"]["digest"] == candidate_digest)
            .unwrap();
        assert_eq!(card["profile_id"], profile_id.as_str());
        assert_eq!(
            card["metadata"]["learned_guidance"],
            "Run the smallest relevant test before the full suite."
        );
        assert_eq!(
            card["metadata"]["source_ticket_run_ids"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(card["metadata"]["base_profile_json"].is_null());
        assert!(card["metadata"]["base_config_toml"].is_null());
        assert!(card["metadata"]["external_sources"].is_null());
        let inbox_root = _temp.path().join("next-batch-control");
        fs::create_dir(&inbox_root).unwrap();
        let next_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: session,
            agent_run_id: "candidate-next-batch".into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![crate::agent_api::AgentWakeItem {
                wake_input_id: next_batch.wake_input_id,
                source_type: next_batch.source_type,
                source_id: next_batch.source_id,
                source_revision: next_batch.source_revision,
                priority: next_batch.priority,
                payload_json: next_batch.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            }],
            worker_correction_context: None,
        };
        crate::agent_api::publish_wake_snapshot(&inbox_root, next_snapshot.clone()).unwrap();
        let issued_input =
            crate::agent_api::read_inbox(&inbox_root, "candidate-next-batch", 0).unwrap();
        assert_eq!(issued_input, next_snapshot.inputs);
        let issued_cards = issued_input[0].payload_json["maintenance"]["candidates"]
            .as_array()
            .unwrap();
        let issued_card = issued_cards
            .iter()
            .find(|candidate| candidate["revision"]["digest"] == candidate_digest)
            .unwrap();
        assert_eq!(issued_card["profile_id"], profile_id.as_str());
        assert!(issued_cards.iter().any(|candidate| {
            candidate["revision"]["candidate_id"] == other_candidate_id
                && candidate["revision"]["digest"] == other_candidate_digest.as_str()
        }));
    }

    #[test]
    fn nonterminal_provider_qualification_pins_only_its_exact_candidate() {
        use crate::store::provider_qualification_runtime::{
            ProviderQualificationJobStatus as JobStatus, ProviderQualificationRequest,
            ProviderQualificationTarget, QualificationClaim,
        };

        let (_temp, mut store, project, generation, _) = running_store();
        let files = BTreeMap::from([("config.toml".to_owned(), b"fixture".to_vec())]);
        let manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let rows = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let candidate_digest = crate::learning::candidate_revision_digest(&files).unwrap();
        let record = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: "qualification-pinned-candidate".into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-12T00:00:00Z".into(),
                expires_at: "2026-11-13T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: ProfileId::parse("qualification-pinned-profile").unwrap(),
            package_manifest_digest: manifest_digest,
            package_files_json: serde_json::to_string(&files).unwrap(),
            package_json: serde_json::to_string(&rows).unwrap(),
            expected_pairs: 5,
        };
        store
            .register_learning_candidate(generation, &record)
            .unwrap();
        let project_record = store.project(&project).unwrap().unwrap();
        let request = ProviderQualificationRequest {
            request_id: "qualification-candidate-pin".into(),
            project_id: project.clone(),
            role: Role::Worker,
            profile_id: record.profile_id.clone(),
            profile_digest: Digest::parse("a".repeat(64)).unwrap(),
            config_revision: project_record.config_revision.0,
            config_digest: project_record.config_digest,
            target: ProviderQualificationTarget::Candidate {
                candidate_id: record.revision.candidate_id.clone(),
                candidate_digest: candidate_digest.clone(),
            },
        };
        store
            .enqueue_provider_qualification(generation, &request)
            .unwrap();
        let tx = store.connection.transaction().unwrap();
        assert!(
            candidate_revision_is_pinned(
                &tx,
                &project,
                &record.revision.candidate_id,
                &candidate_digest,
            )
            .unwrap()
        );
        tx.rollback().unwrap();
        let QualificationClaim::Claimed { .. } = store
            .claim_provider_qualification(generation, 4, 4)
            .unwrap()
        else {
            panic!("queued candidate qualification must be claimable");
        };
        store
            .mark_provider_qualification_unknown(generation, &request.request_id)
            .unwrap();
        let tx = store.connection.transaction().unwrap();
        assert!(
            candidate_revision_is_pinned(
                &tx,
                &project,
                &record.revision.candidate_id,
                &candidate_digest,
            )
            .unwrap()
        );
        tx.rollback().unwrap();
        let failed_result = "{}";
        store
            .finish_provider_qualification_job(
                generation,
                &request.request_id,
                JobStatus::Failed,
                failed_result,
                &Digest::parse(format!("{:x}", Sha256::digest(failed_result.as_bytes()))).unwrap(),
                true,
            )
            .unwrap();
        let tx = store.connection.transaction().unwrap();
        assert!(
            !candidate_revision_is_pinned(
                &tx,
                &project,
                &record.revision.candidate_id,
                &candidate_digest,
            )
            .unwrap()
        );
        tx.rollback().unwrap();
    }

    #[test]
    fn invalid_supervisor_candidate_is_rejected_without_partial_learning_writes() {
        let fixture = learning_dispatch_fixture_with_options(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            false,
            None,
            CandidateFixture::StalePrior,
        );
        let LearningDispatchFixture {
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            ..
        } = fixture;
        crate::engine::factory_runtime::tests::apply_agent_result_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
        )
        .unwrap();
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_candidates WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0)
                )
                .unwrap(),
            "rejected_by_host"
        );
        assert!(
            store
                .connection
                .query_row::<Option<String>, _, _>(
                    "SELECT last_error FROM project_runtimes WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0)
                )
                .unwrap()
                .unwrap()
                .contains("candidate predecessor digest is stale")
        );
    }

    #[test]
    fn oversized_configured_guidance_still_issues_supervisor_batch() {
        let fixture = learning_dispatch_fixture_with_options(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            false,
            None,
            CandidateFixture::OversizedGuidance,
        );
        let mut store = fixture.store;
        let input_json: String = store
            .connection
            .query_row(
                "SELECT snapshot_json FROM learning_batches WHERE batch_id=?1",
                [&fixture.batch_id],
                |row| row.get(0),
            )
            .unwrap();
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        let targets = &input["maintenance"]["candidate_targets"];
        assert!(serde_json::to_vec(targets).unwrap().len() <= super::MAX_SUPERVISOR_TARGET_BYTES);
        assert!(targets.as_array().unwrap().iter().any(|target| {
            target["omitted_description_bytes"].as_u64().unwrap() > 0
                && target["description"].is_null()
        }));
        assert!(input_json.len() <= super::MAX_SUPERVISOR_BATCH_BYTES);
        let snapshot = store.load_snapshot("factory").unwrap().unwrap();
        assert_eq!(
            snapshot.config.profiles[&ProfileId::parse("fixture-profile").unwrap()]
                .description
                .as_ref()
                .unwrap()
                .len(),
            20_000
        );
        let source = snapshot
            .config
            .source_files
            .iter()
            .find(|source| source.path.ends_with("aliases/guidance.md"))
            .unwrap();
        assert_eq!(
            source.contents.len(),
            super::MAX_SUPERVISOR_CONTEXT_BYTES + 1
        );
        assert_eq!(
            source.sha256.as_str(),
            format!("{:x}", Sha256::digest(source.contents.as_bytes()))
        );
        let next_project = ProjectId::parse("sample-b").unwrap();
        store
            .set_project_lifecycle(fixture.generation, &next_project, "running")
            .unwrap();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            params![next_project.as_str(), fixture.generation],
        ).unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    fixture.generation,
                    &[fixture.project.clone(), next_project.clone()],
                    101,
                    3600,
                    None,
                )
                .unwrap(),
            Some(next_project)
        );
        crate::engine::factory_runtime::tests::apply_agent_result_for_test(
            &mut store,
            fixture.generation,
            102,
            &fixture.config,
            fixture.config_digest,
            &fixture.result,
        )
        .unwrap();
        let rejection: String = store
            .connection
            .query_row(
                "SELECT last_error FROM project_runtimes WHERE project_id=?1",
                [fixture.project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(rejection.contains("candidate target guidance was omitted"));
        assert_eq!(
            store
                .connection
                .query_row::<usize, _, _>(
                    "SELECT count(*) FROM learning_candidates WHERE project_id=?1",
                    [fixture.project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn candidate_that_would_overflow_next_learning_input_is_rejected_before_consumption() {
        let fixture = learning_dispatch_fixture_with_options(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            false,
            None,
            CandidateFixture::OversizedContext,
        );
        let LearningDispatchFixture {
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            ..
        } = fixture;
        let mut existing_proposal = match &result.validated.typed_payload {
            crate::engine::orchestration::RoleResultPayload::LearningDecision(payload) => {
                payload.clone()
            }
            other => panic!("expected learning decision, got {other:?}"),
        };
        existing_proposal
            .candidate_change
            .as_mut()
            .unwrap()
            .topic_key = "existing-escaped-guidance".into();
        let (snapshot_json, findings_json): (String, String) = store
            .connection
            .query_row(
                "SELECT snapshot_json,findings_json FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let tx = store.connection.transaction().unwrap();
        let existing = prepare_learning_candidate(
            &tx,
            &project,
            &existing_proposal,
            &serde_json::from_str(&snapshot_json).unwrap(),
            &serde_json::from_str::<Vec<LearningFinding>>(&findings_json).unwrap(),
            100,
        )
        .unwrap()
        .record
        .unwrap();
        let existing_revision = existing.revision.clone();
        register_learning_candidate_in_transaction(&tx, generation, &existing).unwrap();
        tx.commit().unwrap();
        crate::engine::factory_runtime::tests::apply_agent_result_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
        )
        .unwrap();
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_candidates WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .learning_candidate_package(
                    &project,
                    &existing_revision.candidate_id,
                    &existing_revision.digest,
                )
                .unwrap()
                .unwrap()
                .revision,
            existing_revision
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id=?2",
            rusqlite::params![project.as_str(), batch_id], |row| row.get(0)
        ).unwrap(), 0);
        let rejection: String = store
            .connection
            .query_row(
                "SELECT last_error FROM project_runtimes WHERE project_id=?1",
                [project.as_str()],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .unwrap();
        assert!(
            rejection.contains("next Supervisor learning input unissuable"),
            "{rejection}"
        );
    }

    #[test]
    fn candidate_registration_rolls_back_when_result_ack_fails() {
        let fixture = learning_dispatch_fixture_with_options(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            false,
            None,
            CandidateFixture::Proposed,
        );
        let LearningDispatchFixture {
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            ..
        } = fixture;
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_candidate_ack BEFORE INSERT ON agent_result_reducer_ack
             BEGIN SELECT RAISE(ABORT, 'fixture rejects result ACK'); END;",
            )
            .unwrap();
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest,
                &result
            )
            .is_err()
        );
        for (table, query) in [
            (
                "candidate",
                "SELECT count(*) FROM learning_candidates WHERE project_id=?1",
            ),
            (
                "decision",
                "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
            ),
            (
                "finding consumption",
                "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id IS NOT NULL",
            ),
            (
                "ACK",
                "SELECT count(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
            ),
        ] {
            let key = if table == "decision" {
                batch_id.as_str()
            } else if table == "ACK" {
                result.receipt.evidence_id()
            } else {
                project.as_str()
            };
            assert_eq!(
                store
                    .connection
                    .query_row::<i64, _, _>(query, [key], |row| row.get(0))
                    .unwrap(),
                0,
                "{table} write must roll back"
            );
        }
    }

    #[test]
    fn published_finding_flows_through_supervisor_result_dispatch_and_atomic_ack() {
        let fixture = learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp,
            mut store,
            project: _project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            checkpoint,
        } = fixture;

        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_learning_ack BEFORE INSERT ON agent_result_reducer_ack
             BEGIN SELECT RAISE(ABORT, 'fixture rejects result ACK'); END;",
            )
            .unwrap();
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest.clone(),
                &result,
            )
            .is_err()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_findings WHERE consumed_batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            "issued"
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_learning_ack")
            .unwrap();
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation + 1,
                102,
                &config,
                config_digest.clone(),
                &result
            )
            .is_err()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                103,
                &config,
                config_digest.clone(),
                &result
            )
            .unwrap()
        );

        let consumed: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM learning_findings WHERE consumed_batch_id=?1",
                [&batch_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            "completed"
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |r| r.get(0)
                )
                .unwrap(),
            "applied"
        );
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                105,
                &config,
                config_digest,
                &result
            )
            .unwrap()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            1
        );
        let checkpoint_json: String = store.connection.query_row(
            "SELECT json_extract(decision_json,'$.checkpoint') FROM learning_decisions WHERE batch_id=?1", [&batch_id], |r| r.get(0)
        ).unwrap();
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, String>>(&checkpoint_json).unwrap(),
            checkpoint
        );
    }

    #[test]
    fn typed_topic_runs_from_provider_result_through_effect_into_next_batch() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            batch_id: _,
            result,
            config,
            config_digest,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);

        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest,
                &result,
                Some(root.clone()),
            )
            .unwrap()
        );
        let operation_id: String = store
            .connection
            .query_row(
                "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let effect: String = store
            .connection
            .query_row(
                "SELECT kind FROM effects WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(effect, "publish_topic");
        let operation = OperationId::parse(operation_id.clone()).unwrap();
        let intent = store.supervisor_topic_intent(&operation).unwrap().unwrap();
        crate::topic::publish_immutable(&intent).unwrap();
        assert!(
            store
                .supervisor_topic_receipt(&operation)
                .unwrap()
                .is_none()
        );
        let handler = crate::topic_effect::TopicEffectHandler::new(root.clone());
        let limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(3600),
            retry_base: std::time::Duration::from_secs(1),
            retry_max: std::time::Duration::from_secs(8),
        };
        let tick = crate::effects::EffectDispatcher::tick(
            &mut store,
            generation,
            102,
            &[&handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            tick,
            crate::effects::DispatchTick::Completed { .. }
        ));
        let (state, content, content_digest): (String, String, String) = store.connection.query_row(
            "SELECT state,intent_json,intent_digest FROM supervisor_topic_publications WHERE operation_id=?1",
            [&operation_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(state, "published");
        let intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(content.as_bytes()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(content.as_bytes())),
            content_digest
        );
        let effect = store
            .effect_by_logical_key(&format!("topic-create:{}:{}", project, intent.key.as_str()))
            .unwrap()
            .unwrap();
        let durable_effect_receipt: String = store
            .connection
            .query_row(
                "SELECT receipt_json FROM effects WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        let replayed_receipt = handler.execute(&mut store, generation, &effect).unwrap();
        let durable_receipt: crate::topic::TopicReceipt =
            crate::protocol::parse_unique(durable_effect_receipt.as_bytes()).unwrap();
        assert_eq!(replayed_receipt, durable_receipt);
        let file = root.join(format!(
            "projects/{}/topics/{}.md",
            project,
            intent.key.as_str()
        ));
        assert_eq!(std::fs::read(&file).unwrap(), intent.content.as_bytes());
        let run_hash = format!(
            "{:x}",
            Sha256::digest(intent.sources[0].ticket_run_id.as_bytes())
        );
        let source_file = root.join(format!("projects/{}/postmortems/{run_hash}.md", project));
        let source_bytes = std::fs::read(&source_file).unwrap();
        assert!(
            intent
                .content
                .contains(&format!("../postmortems/{run_hash}.md")),
            "rendered Topic omitted its source resource link: {}",
            intent.content
        );
        assert_eq!(
            file.parent()
                .unwrap()
                .join(format!("../postmortems/{run_hash}.md"))
                .canonicalize()
                .unwrap(),
            source_file.canonicalize().unwrap()
        );
        assert!(
            intent
                .content
                .contains(intent.sources[0].finding_id.as_str())
        );
        assert!(
            intent
                .content
                .contains(intent.sources[0].publication_digest.as_str())
        );
        assert!(
            String::from_utf8_lossy(&source_bytes)
                .contains("A published Finding reaches a durable Supervisor decision\\.")
        );
        let ack: String = store
            .connection
            .query_row(
                "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ack, "applied");
        let tx = store.connection.transaction().unwrap();
        let consumed_source =
            resolve_topic_source(&tx, &project, &intent.sources[0].finding_id).unwrap();
        assert!(
            consumed_source.is_some(),
            "published Finding provenance remains usable after its learning batch is consumed"
        );
        tx.commit().unwrap();

        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    4000,
                    3600,
                    Some(root.as_path())
                )
                .unwrap(),
            Some(project.clone())
        );
        let wakes = store
            .pending_role_wake_inputs(
                &project,
                &format!("project:{}:supervisor", project.as_str()),
                16,
            )
            .unwrap();
        let next = wakes
            .iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let topics = next.payload_json["maintenance"]["topics"]
            .as_array()
            .unwrap();
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0]["content"], intent.content);
        assert_eq!(topics[0]["content_digest"], intent.content_digest.as_str());
        let changed_root = _temp.path().join("changed-knowledge-root");
        let changed_destination = store
            .maintain_project_supervisor_learning(
                generation,
                &project,
                "2026-11-08T00:00:00Z",
                12,
                Some(&changed_root),
            )
            .unwrap();
        assert!(
            changed_destination.topics.is_empty(),
            "a snapshot for a new knowledge root must exclude Topics published under the old root"
        );
        assert_eq!(changed_destination.omitted_topics, 0);
        store
            .connection
            .execute(
                "UPDATE supervisor_topic_publications SET destination_root=?2 WHERE project_id=?1",
                params![project.as_str(), changed_root.to_string_lossy().as_ref()],
            )
            .unwrap();
        assert!(
            store
                .maintain_project_supervisor_learning(
                    generation,
                    &project,
                    "2026-11-08T00:00:00Z",
                    12,
                    Some(&changed_root),
                )
                .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE supervisor_topic_publications SET destination_root=?2 WHERE project_id=?1",
                params![project.as_str(), root.to_string_lossy().as_ref()],
            )
            .unwrap();

        let mut wrong_format = durable_receipt.clone();
        wrong_format.manifest.format = "unsupported-format".into();
        wrong_format.manifest_digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&wrong_format.manifest).unwrap())
        ))
        .unwrap();
        let wrong_format_json = crate::store::canonical_json(&wrong_format).unwrap();
        store.connection.execute(
            "UPDATE supervisor_topic_publications SET receipt_json=?2,receipt_digest=?3 WHERE operation_id=?1",
            params![operation.as_str(), wrong_format_json, crate::store::content_digest(&wrong_format_json)],
        ).unwrap();
        assert!(
            store
                .maintain_project_supervisor_learning(
                    generation,
                    &project,
                    "2026-11-08T00:00:00Z",
                    12,
                    Some(&root),
                )
                .is_err(),
            "a matching receipt digest must not authorize an unsupported Topic format"
        );
        assert!(store.supervisor_topic_receipt(&operation).is_err());
        let valid_receipt_json = crate::store::canonical_json(&durable_receipt).unwrap();
        store.connection.execute(
            "UPDATE supervisor_topic_publications SET receipt_json=?2,receipt_digest=?3 WHERE operation_id=?1",
            params![operation.as_str(), valid_receipt_json, crate::store::content_digest(&valid_receipt_json)],
        ).unwrap();

        drop(store);
        let reopened = ConfigStore::open_test(_temp.path()).unwrap();
        assert!(
            reopened
                .supervisor_topic_receipt(&operation)
                .unwrap()
                .is_some()
        );
        let mut legacy_intent_value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&intent).unwrap()).unwrap();
        legacy_intent_value
            .as_object_mut()
            .unwrap()
            .remove("revision");
        legacy_intent_value
            .as_object_mut()
            .unwrap()
            .remove("expected_prior_digest");
        let legacy_intent_json = crate::store::canonical_json(&legacy_intent_value).unwrap();
        let legacy_intent_digest = crate::store::content_digest(&legacy_intent_json);
        reopened.connection.execute(
            "UPDATE supervisor_topic_publications SET intent_json=?2,intent_digest=?3 WHERE operation_id=?1",
            params![operation.as_str(), legacy_intent_json, legacy_intent_digest],
        ).unwrap();
        reopened.connection.execute_batch(
            "ALTER TABLE supervisor_topic_publications RENAME TO supervisor_topic_publications_v21;
             CREATE TABLE supervisor_topic_publications (
                operation_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(project_id),
                topic_key TEXT NOT NULL,
                destination_root TEXT NOT NULL,
                intent_json TEXT NOT NULL CHECK(length(intent_json)<=1048576),
                intent_digest TEXT NOT NULL CHECK(length(intent_digest)=64),
                state TEXT NOT NULL CHECK(state IN ('pending','published','conflict')),
                receipt_json TEXT,
                receipt_digest TEXT CHECK(receipt_digest IS NULL OR length(receipt_digest)=64),
                conflict_json TEXT,
                created_at_unix INTEGER NOT NULL,
                published_at_unix INTEGER,
                UNIQUE(project_id,topic_key),
                CHECK((state='published' AND receipt_json IS NOT NULL AND receipt_digest IS NOT NULL AND published_at_unix IS NOT NULL AND conflict_json IS NULL)
                   OR (state='pending' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NULL)
                   OR (state='conflict' AND receipt_json IS NULL AND receipt_digest IS NULL AND published_at_unix IS NULL AND conflict_json IS NOT NULL))
             );
             INSERT INTO supervisor_topic_publications(operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,receipt_json,receipt_digest,conflict_json,created_at_unix,published_at_unix)
               SELECT operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,receipt_json,receipt_digest,conflict_json,created_at_unix,published_at_unix FROM supervisor_topic_publications_v21;
             DROP TABLE supervisor_topic_publications_v21;
             CREATE INDEX supervisor_topic_publications_project ON supervisor_topic_publications(project_id,state,created_at_unix DESC,topic_key);
             DROP TABLE provider_qualification_candidate_targets;
             DELETE FROM schema_migrations WHERE version=22;
             DELETE FROM schema_migrations WHERE version=21;
             PRAGMA user_version=20;"
        ).unwrap();
        drop(reopened);
        let migrated = ConfigStore::open_test(_temp.path()).unwrap();
        assert_eq!(
            migrated
                .connection
                .query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            22
        );
        let migrated_json: String = migrated
            .connection
            .query_row(
                "SELECT intent_json FROM supervisor_topic_publications WHERE operation_id=?1",
                [operation.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migrated_json, legacy_intent_json);
        let migrated_intent = migrated
            .supervisor_topic_intent(&operation)
            .unwrap()
            .unwrap();
        assert_eq!(migrated_intent.revision, 0);
        assert_eq!(migrated_intent.expected_prior_digest, None);
        assert_eq!(
            migrated
                .supervisor_topic_receipt(&operation)
                .unwrap()
                .unwrap()
                .manifest
                .relative_path,
            format!("projects/{}/topics/{}.md", project, intent.key.as_str())
        );
    }

    #[test]
    fn consumed_finding_can_source_a_later_accepted_topic_decision() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            batch_id: first_batch_id,
            result: first_result,
            config,
            config_digest,
            ..
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest.clone(),
            &first_result,
            Some(root.clone()),
        )
        .unwrap();
        let topic_handler = crate::topic_effect::TopicEffectHandler::new(root.clone());
        let effect_limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(3600),
            retry_base: std::time::Duration::from_secs(1),
            retry_max: std::time::Duration::from_secs(8),
        };
        assert!(matches!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                generation,
                102,
                &[&topic_handler],
                effect_limits,
            )
            .unwrap(),
            crate::effects::DispatchTick::Completed { .. }
        ));
        let first_intent_json: String = store
            .connection
            .query_row(
                "SELECT intent_json FROM supervisor_topic_publications WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let first_intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(first_intent_json.as_bytes()).unwrap();
        let consumed_source = first_intent.sources[0].finding_id.clone();
        let old_consumed: Option<String> = store
            .connection
            .query_row(
                "SELECT consumed_batch_id FROM learning_findings WHERE finding_id=?1",
                [consumed_source.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_consumed.as_deref(), Some(first_batch_id.as_str()));

        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    4000,
                    3600,
                    Some(root.as_path())
                )
                .unwrap(),
            Some(project.clone())
        );
        let session = format!("project:{}:supervisor", project.as_str());
        let pending = store
            .pending_role_wake_inputs(&project, &session, 16)
            .unwrap();
        let batch_wake = pending
            .iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let batch_payload = batch_wake.payload_json.clone();
        let second_batch_id = batch_payload["batch_id"].as_str().unwrap().to_owned();
        assert_ne!(second_batch_id, first_batch_id);
        let second_wakes = pending
            .into_iter()
            .map(|wake| crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type,
                source_id: wake.source_id,
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            })
            .collect();
        let project_state = store.project(&project).unwrap().unwrap();
        let second_payload = crate::engine::orchestration::LearningDecisionPayload {
            batch_id: second_batch_id.clone(),
            batch_digest: Digest::parse(batch_payload["batch_digest"].as_str().unwrap()).unwrap(),
            config_revision: project_state.config_revision,
            observations: vec![
                "A previously consumed Finding remains valid source evidence.".into(),
            ],
            topic_changes: vec![crate::topic::TopicChange {
                topic_key: first_intent.key.as_str().into(),
                title: "Revise the durable consumed evidence guidance".into(),
                summary: "A later batch revises the Topic using its exact published digest.".into(),
                claims: vec!["Published Topic history is immutable.".into()],
                applicability: "Use when existing guidance needs an evidence-backed revision."
                    .into(),
                proposed_check: "Compare the issued digest and preserve all prior versions.".into(),
                counterexamples: Vec::new(),
                source_finding_ids: vec![consumed_source.clone()],
                expected_prior_digest: Some(first_intent.content_digest.clone()),
            }],
            checkpoint: BTreeMap::new(),
            improvements: Vec::new(),
            candidate_change: None,
        };
        let message = crate::roles::RoleResultMessage {
            schema_version: 1,
            message_id: "later-consumed-source-result".into(),
            kind: crate::engine::orchestration::RoleOutputKind::LearningDecision,
            assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
            structured_result: serde_json::to_value(second_payload).unwrap(),
            result_digest: None,
            artifact_refs: Vec::new(),
        };
        let schema = crate::roles::result_schema(crate::domain::types::Role::Supervisor);
        let encoded_message = serde_json::to_string(&message).unwrap();
        let final_response = [
            serde_json::json!({"type":"thread.started","thread_id":"topic-revision-thread"}),
            serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":serde_json::to_string(&serde_json::json!({"result": encoded_message})).unwrap()}}),
            serde_json::json!({"type":"turn.completed"}),
        ].iter().map(serde_json::Value::to_string).collect::<Vec<_>>().join("\n");
        let (_, parsed) = crate::providers::parse_result(
            crate::domain::types::AgentAdapter::Codex,
            final_response.as_bytes(),
            &schema,
        )
        .unwrap();
        let message = serde_json::from_value(parsed).unwrap();
        let second_result = crate::store::agent_results::host_validation_fixture::host_validated_supervisor_result_in_with_wake_inputs(
            &mut store,
            &std::fs::canonicalize(_temp.path()).unwrap(),
            generation,
            project.clone(),
            message,
            crate::domain::ids::AgentRunId::parse("later-consumed-source-agent").unwrap(),
            second_wakes,
        ).unwrap().ingested;
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            4001,
            &config,
            config_digest.clone(),
            &second_result,
            Some(root.clone()),
        )
        .unwrap();

        let second_operation_id: String = store.connection.query_row(
            "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1 AND revision=1",
            [project.as_str()],
            |row| row.get(0),
        ).unwrap();
        let second_operation = OperationId::parse(second_operation_id.clone()).unwrap();
        let second_intent = store
            .supervisor_topic_intent(&second_operation)
            .unwrap()
            .unwrap();
        assert_eq!(second_intent.revision, 1);
        assert_eq!(
            second_intent.expected_prior_digest,
            Some(first_intent.content_digest.clone())
        );
        assert_ne!(second_intent.content_digest, first_intent.content_digest);
        assert_eq!(
            std::fs::read(
                root.join(crate::topic::publication_relative_path(&first_intent).unwrap())
            )
            .unwrap(),
            first_intent.content.as_bytes()
        );
        crate::topic::publish_immutable(&second_intent).unwrap();
        assert!(
            store
                .supervisor_topic_receipt(&second_operation)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read(
                root.join(crate::topic::publication_relative_path(&second_intent).unwrap())
            )
            .unwrap(),
            second_intent.content.as_bytes()
        );
        store.stop_owner(generation).unwrap();
        drop(store);
        let mut store = ConfigStore::open_test(_temp.path()).unwrap();
        let generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "topic-revision-replay-owner".into(),
                state_root: _temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "topic-revision-replay-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert_eq!(store.activate_starting_projects(generation).unwrap(), 1);
        assert!(matches!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                generation,
                4002,
                &[&topic_handler],
                effect_limits,
            )
            .unwrap(),
            crate::effects::DispatchTick::Completed { .. }
        ));
        assert!(
            store
                .supervisor_topic_receipt(&second_operation)
                .unwrap()
                .is_some()
        );
        let second_file =
            root.join(crate::topic::publication_relative_path(&second_intent).unwrap());
        assert_eq!(
            std::fs::read(&second_file).unwrap(),
            second_intent.content.as_bytes()
        );
        assert_eq!(
            std::fs::read(
                root.join(crate::topic::publication_relative_path(&first_intent).unwrap())
            )
            .unwrap(),
            first_intent.content.as_bytes()
        );
        let second_effect = store
            .effect_by_logical_key(&format!(
                "topic-revision:{}:{}:1",
                project,
                second_intent.key.as_str()
            ))
            .unwrap()
            .unwrap();
        assert!(
            topic_handler
                .execute(&mut store, generation, &second_effect)
                .is_ok()
        );
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    8000,
                    3600,
                    Some(root.as_path())
                )
                .unwrap(),
            Some(project.clone())
        );
        let latest_batch = store
            .pending_role_wake_inputs(&project, &session, 16)
            .unwrap()
            .into_iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let latest_topics = latest_batch.payload_json["maintenance"]["topics"]
            .as_array()
            .unwrap();
        assert_eq!(latest_topics.len(), 1);
        assert_eq!(latest_topics[0]["content"], second_intent.content);
        assert_eq!(
            latest_topics[0]["content_digest"],
            second_intent.content_digest.as_str()
        );
        let third_wakes = store
            .pending_role_wake_inputs(&project, &session, 16)
            .unwrap()
            .into_iter()
            .map(|wake| crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type,
                source_id: wake.source_id,
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            })
            .collect::<Vec<_>>();
        let third_batch_wake = third_wakes
            .iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let third_batch = third_batch_wake.payload_json.clone();
        let project_state = store.project(&project).unwrap().unwrap();
        let third_payload = crate::engine::orchestration::LearningDecisionPayload {
            batch_id: third_batch["batch_id"].as_str().unwrap().to_owned(),
            batch_digest: Digest::parse(third_batch["batch_digest"].as_str().unwrap().to_owned())
                .unwrap(),
            config_revision: project_state.config_revision,
            observations: vec!["The second immutable revision is now current.".into()],
            topic_changes: vec![crate::topic::TopicChange {
                topic_key: second_intent.key.as_str().into(),
                title: "Refine the durable consumed evidence guidance".into(),
                summary: "A second revision retains both earlier immutable versions.".into(),
                claims: vec!["Each accepted revision names the preceding digest.".into()],
                applicability: "Use when published guidance needs another evidence-backed change."
                    .into(),
                proposed_check: "Verify the exact latest digest from this batch.".into(),
                counterexamples: Vec::new(),
                source_finding_ids: vec![consumed_source.clone()],
                expected_prior_digest: Some(second_intent.content_digest.clone()),
            }],
            checkpoint: BTreeMap::new(),
            improvements: Vec::new(),
            candidate_change: None,
        };
        let third_message = crate::roles::RoleResultMessage {
            schema_version: 1,
            message_id: "second-topic-revision-result".into(),
            kind: crate::engine::orchestration::RoleOutputKind::LearningDecision,
            assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
            structured_result: serde_json::to_value(third_payload).unwrap(),
            result_digest: None,
            artifact_refs: Vec::new(),
        };
        let encoded_message = serde_json::to_string(&third_message).unwrap();
        let final_response = [
            serde_json::json!({"type":"thread.started","thread_id":"topic-revision-thread-2"}),
            serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":serde_json::to_string(&serde_json::json!({"result": encoded_message})).unwrap()}}),
            serde_json::json!({"type":"turn.completed"}),
        ]
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        let (_, parsed) = crate::providers::parse_result(
            crate::domain::types::AgentAdapter::Codex,
            final_response.as_bytes(),
            &schema,
        )
        .unwrap();
        let third_message = serde_json::from_value(parsed).unwrap();
        let third_result = crate::store::agent_results::host_validation_fixture::host_validated_supervisor_result_in_with_wake_inputs(
            &mut store,
            &std::fs::canonicalize(_temp.path()).unwrap(),
            generation,
            project.clone(),
            third_message,
            crate::domain::ids::AgentRunId::parse("second-topic-revision-agent").unwrap(),
            third_wakes,
        )
        .unwrap()
        .ingested;
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            8001,
            &config,
            config_digest.clone(),
            &third_result,
            Some(root.clone()),
        )
        .unwrap();
        let third_operation_id: String = store
            .connection
            .query_row(
                "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1 AND revision=2",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let third_operation = OperationId::parse(third_operation_id).unwrap();
        let third_intent = store
            .supervisor_topic_intent(&third_operation)
            .unwrap()
            .unwrap();
        assert_eq!(
            third_intent.expected_prior_digest,
            Some(second_intent.content_digest.clone())
        );
        assert!(matches!(
            crate::effects::EffectDispatcher::tick(
                &mut store,
                generation,
                8002,
                &[&topic_handler],
                effect_limits,
            )
            .unwrap(),
            crate::effects::DispatchTick::Completed { .. }
        ));
        for intent in [&first_intent, &second_intent, &third_intent] {
            assert_eq!(
                std::fs::read(root.join(crate::topic::publication_relative_path(intent).unwrap()))
                    .unwrap(),
                intent.content.as_bytes()
            );
        }
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    std::slice::from_ref(&project),
                    12000,
                    3600,
                    Some(root.as_path())
                )
                .unwrap(),
            Some(project.clone())
        );
        let newest_pending = store
            .pending_role_wake_inputs(&project, &session, 16)
            .unwrap();
        let newest_batch = newest_pending
            .iter()
            .find(|wake| wake.source_type == "learning_batch")
            .unwrap();
        let newest_topics = newest_batch.payload_json["maintenance"]["topics"]
            .as_array()
            .unwrap();
        assert_eq!(newest_topics.len(), 1);
        assert_eq!(newest_topics[0]["content"], third_intent.content);
        assert_eq!(
            newest_topics[0]["content_digest"],
            third_intent.content_digest.as_str()
        );
        let newest_batch_id = newest_batch.payload_json["batch_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let stale_payload = crate::engine::orchestration::LearningDecisionPayload {
            batch_id: newest_batch_id.clone(),
            batch_digest: Digest::parse(
                newest_batch.payload_json["batch_digest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
            .unwrap(),
            config_revision: store.project(&project).unwrap().unwrap().config_revision,
            observations: vec!["The old digest must be rejected.".into()],
            topic_changes: vec![crate::topic::TopicChange {
                topic_key: third_intent.key.as_str().into(),
                title: "Stale revision attempt".into(),
                summary: "This proposal names an earlier version.".into(),
                claims: vec!["Stale proposals do not replace the current version.".into()],
                applicability: "Used only for the rejection fixture.".into(),
                proposed_check: "The issued digest must match the current publication.".into(),
                counterexamples: Vec::new(),
                source_finding_ids: vec![consumed_source.clone()],
                expected_prior_digest: Some(first_intent.content_digest.clone()),
            }],
            checkpoint: BTreeMap::new(),
            improvements: Vec::new(),
            candidate_change: None,
        };
        let stale_message = crate::roles::RoleResultMessage {
            schema_version: 1,
            message_id: "stale-topic-revision-result".into(),
            kind: crate::engine::orchestration::RoleOutputKind::LearningDecision,
            assertion: crate::engine::orchestration::AgentAssertion::Succeeded,
            structured_result: serde_json::to_value(stale_payload).unwrap(),
            result_digest: None,
            artifact_refs: Vec::new(),
        };
        let encoded_message = serde_json::to_string(&stale_message).unwrap();
        let final_response = [
            serde_json::json!({"type":"thread.started","thread_id":"stale-topic-thread"}),
            serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":serde_json::to_string(&serde_json::json!({"result": encoded_message})).unwrap()}}),
            serde_json::json!({"type":"turn.completed"}),
        ]
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        let (_, parsed) = crate::providers::parse_result(
            crate::domain::types::AgentAdapter::Codex,
            final_response.as_bytes(),
            &schema,
        )
        .unwrap();
        let stale_message = serde_json::from_value(parsed).unwrap();
        let newest_wakes = newest_pending
            .into_iter()
            .map(|wake| crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type,
                source_id: wake.source_id,
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            })
            .collect();
        let stale_result = crate::store::agent_results::host_validation_fixture::host_validated_supervisor_result_in_with_wake_inputs(
            &mut store,
            &std::fs::canonicalize(_temp.path()).unwrap(),
            generation,
            project.clone(),
            stale_message,
            crate::domain::ids::AgentRunId::parse("stale-topic-revision-agent").unwrap(),
            newest_wakes,
        )
        .unwrap()
        .ingested;
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            12001,
            &config,
            config_digest.clone(),
            &stale_result,
            Some(root.clone()),
        )
        .unwrap();
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [stale_result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            "rejected_by_host"
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [newest_batch_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM supervisor_topic_publications WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            3
        );

        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [second_result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            "applied"
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [&second_batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            "completed"
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT consumed_batch_id FROM learning_findings WHERE finding_id=?1",
                    [consumed_source.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            first_batch_id
        );
        let second_intent_json: String = store.connection.query_row(
            "SELECT intent_json FROM supervisor_topic_publications WHERE project_id=?1 AND topic_key=?2 AND revision=1",
            params![project.as_str(), first_intent.key.as_str()], |row| row.get(0),
        ).unwrap();
        let second_intent: crate::topic::TopicIntent =
            crate::protocol::parse_unique(second_intent_json.as_bytes()).unwrap();
        assert_eq!(second_intent.revision, 1);
        assert_eq!(
            second_intent
                .sources
                .iter()
                .map(|source| source.finding_id.clone())
                .collect::<Vec<_>>(),
            vec![consumed_source]
        );
        assert_eq!(store.connection.query_row::<i64, _, _>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id=?2",
            rusqlite::params![project.as_str(), second_batch_id], |row| row.get(0),
        ).unwrap(), batch_payload["findings"].as_array().unwrap().len() as i64);
    }

    #[test]
    fn foreign_topic_source_is_rejected_without_consuming_findings_or_creating_intent() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            Some(digest('e')),
        );
        let LearningDispatchFixture {
            _temp: _,
            mut store,
            project,
            generation,
            batch_id,
            mut result,
            config,
            config_digest,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        let mut foreign_project = store.project(&project).unwrap().unwrap();
        foreign_project.id = ProjectId::parse("foreign").unwrap();
        foreign_project.desired_lifecycle = "stopped".into();
        store.insert_project(&foreign_project).unwrap();
        let foreign_run = TicketRunId::parse("foreign-1-g1").unwrap();
        store
            .create_ticket_run(
                generation,
                &foreign_project.id,
                &TicketNamespace::parse("github:org/foreign").unwrap(),
                &TicketId::parse("1").unwrap(),
                &foreign_run,
                1,
                "postmortem",
                "In Progress",
            )
            .unwrap();
        let foreign_input = PostmortemInput {
            operation_id: OperationId::parse("foreign-learning-publication").unwrap(),
            project_id: foreign_project.id.clone(),
            ticket_run_id: foreign_run.clone(),
            title: "Foreign learning fixture".into(),
            summary: "A valid published foreign source.".into(),
            findings: vec!["This Finding is published for another Project.".into()],
            sources: vec![],
            generated_at: "2026-11-07T00:00:00Z".into(),
            max_source_bytes: 1024,
        };
        let request_json = serde_json::to_string(&foreign_input).unwrap();
        let foreign_intent = KnowledgePublicationIntent {
            operation_id: foreign_input.operation_id.clone(),
            project_id: foreign_input.project_id.clone(),
            ticket_run_id: foreign_run,
            request_digest: Digest::parse(format!("{:x}", Sha256::digest(request_json.as_bytes())))
                .unwrap(),
            request_json,
        };
        store
            .prepare_knowledge_publication(generation, &foreign_intent)
            .unwrap();
        let foreign_effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        KnowledgeEffectHandler::new(root.clone())
            .execute(&mut store, generation, &foreign_effect)
            .unwrap();
        let foreign_finding: String = store
            .connection
            .query_row(
                "SELECT finding_id FROM learning_findings WHERE project_id=?1",
                [foreign_project.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        let tx = store.connection.transaction().unwrap();
        assert!(
            resolve_topic_source(
                &tx,
                &foreign_project.id,
                &Digest::parse(foreign_finding.clone()).unwrap()
            )
            .unwrap()
            .is_some()
        );
        assert!(
            resolve_topic_source(
                &tx,
                &project,
                &Digest::parse(foreign_finding.clone()).unwrap()
            )
            .unwrap()
            .is_none()
        );
        tx.commit().unwrap();
        let mut decision: crate::engine::orchestration::LearningDecisionPayload =
            serde_json::from_value(result.validated.structured_result.clone()).unwrap();
        decision.topic_changes[0].source_finding_ids =
            vec![Digest::parse(foreign_finding).unwrap()];
        result.validated.structured_result = serde_json::to_value(&decision).unwrap();
        result.validated.typed_payload =
            crate::engine::orchestration::RoleResultPayload::LearningDecision(decision);
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest,
                &result,
                Some(root),
            )
            .unwrap()
        );
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "rejected_by_host");
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM supervisor_topic_publications WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id=?2",
            rusqlite::params![project.as_str(),batch_id], |row| row.get(0),
        ).unwrap(), 0);
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        let tx = store.connection.transaction().unwrap();
        assert!(
            resolve_topic_source(&tx, &project, &digest('c'))
                .unwrap()
                .is_none()
        );
        tx.commit().unwrap();
    }

    #[test]
    fn invalid_topic_changes_skip_source_resolution() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp: _,
            mut store,
            project,
            generation,
            mut result,
            config,
            config_digest,
            batch_id,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        let mut decision: crate::engine::orchestration::LearningDecisionPayload =
            serde_json::from_value(result.validated.structured_result.clone()).unwrap();
        let source_id = decision.topic_changes[0].source_finding_ids[0].clone();
        let ticket_run_id: String = store
            .connection
            .query_row(
                "SELECT ticket_run_id FROM learning_findings WHERE project_id=?1 AND finding_id=?2",
                params![project.as_str(), source_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE knowledge_publications SET request_digest=?3 WHERE project_id=?1 AND ticket_run_id=?2",
                params![project.as_str(), ticket_run_id, "0".repeat(64)],
            )
            .unwrap();

        decision
            .topic_changes
            .push(decision.topic_changes[0].clone());
        result.validated.structured_result = serde_json::to_value(&decision).unwrap();
        result.validated.typed_payload =
            crate::engine::orchestration::RoleResultPayload::LearningDecision(decision);
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest,
                &result,
                Some(root),
            )
            .unwrap()
        );
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "rejected_by_host");
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM supervisor_topic_publications WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn failed_topic_ack_rolls_back_decision_finding_consumption_intent_and_outbox() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp: _,
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_topic_ack BEFORE INSERT ON agent_result_reducer_ack
             BEGIN SELECT RAISE(ABORT, 'fixture rejects Topic result ACK'); END;",
            )
            .unwrap();
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
                &mut store,
                generation,
                101,
                &config,
                config_digest,
                &result,
                Some(root),
            )
            .is_err()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM supervisor_topic_publications WHERE project_id=?1",
                    [project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM effects WHERE kind='publish_topic' AND project_id=?1",
                    [project.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id=?2",
            rusqlite::params![project.as_str(),batch_id], |row| row.get(0),
        ).unwrap(), 0);
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn existing_pending_topic_key_is_reserved_and_new_proposal_rejected() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp: _,
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        store.connection.execute(
            "INSERT INTO supervisor_topic_publications(operation_id,project_id,topic_key,destination_root,intent_json,intent_digest,state,created_at_unix) VALUES ('pending-existing',?1,'safe-replay',?2,'{}',?3,'pending',99)",
            rusqlite::params![project.as_str(),root.to_string_lossy(),"0".repeat(64)],
        ).unwrap();
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
            Some(root),
        )
        .unwrap();
        let disposition: String = store
            .connection
            .query_row(
                "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                [result.receipt.evidence_id()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "rejected_by_host");
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM supervisor_topic_publications WHERE project_id=?1 AND topic_key='safe-replay'",
            [project.as_str()], |row| row.get(0),
        ).unwrap(), 1);
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id=?2",
            rusqlite::params![project.as_str(),batch_id], |row| row.get(0),
        ).unwrap(), 0);
    }

    #[test]
    fn changed_topic_destination_is_a_durable_rejection() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp: _,
            mut store,
            project,
            generation,
            result,
            config,
            config_digest,
            batch_id: _,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
            Some(root.clone()),
        )
        .unwrap();
        let operation_id: String = store
            .connection
            .query_row(
                "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| {
                panic!("Topic intent must be accepted before its effect is dispatched")
            });
        let operation = OperationId::parse(operation_id.clone()).unwrap();
        let handler = crate::topic_effect::TopicEffectHandler::new(root.with_extension("changed"));
        let limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(3600),
            retry_base: std::time::Duration::from_secs(1),
            retry_max: std::time::Duration::from_secs(8),
        };
        let tick = crate::effects::EffectDispatcher::tick(
            &mut store,
            generation,
            102,
            &[&handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            tick,
            crate::effects::DispatchTick::Completed { .. }
        ));
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM supervisor_topic_publications WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "conflict");
        assert!(
            store
                .supervisor_topic_receipt(&operation)
                .unwrap()
                .is_none()
        );
        let status: String = store
            .connection
            .query_row(
                "SELECT status FROM effects WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert!(
            !root
                .join(format!("projects/{}/topics/safe-replay.md", project))
                .exists()
        );
    }

    #[test]
    fn unexpected_existing_topic_file_is_preserved_and_durably_rejected() {
        let fixture = learning_dispatch_fixture_with_topic(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
            true,
            None,
        );
        let LearningDispatchFixture {
            _temp: temp,
            mut store,
            project,
            generation,
            result,
            config,
            config_digest,
            batch_id: _,
            checkpoint: _,
        } = fixture;
        let root = std::path::PathBuf::from(&config.knowledge.as_ref().unwrap().root);
        crate::engine::factory_runtime::tests::apply_agent_result_with_topic_root_for_test(
            &mut store,
            generation,
            101,
            &config,
            config_digest,
            &result,
            Some(root.clone()),
        )
        .unwrap();
        let target = root.join(format!("projects/{}/topics/safe-replay.md", project));
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"human-owned contents").unwrap();
        let operation_id: String = store
            .connection
            .query_row(
                "SELECT operation_id FROM supervisor_topic_publications WHERE project_id=?1",
                [project.as_str()],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| {
                panic!("Topic intent must be accepted before its effect is dispatched")
            });
        let handler = crate::topic_effect::TopicEffectHandler::new(root.clone());
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let request = crate::effects::EffectRequest {
            intent: effect,
            attempt_count: 1,
            created_at_unix: 101,
        };
        let first_observation = {
            let mut context = crate::effects::EffectContext {
                store: &mut store,
                owner_generation: generation,
                now_unix: 102,
            };
            crate::effects::EffectHandler::handle(
                &handler,
                crate::effects::EffectMode::Submit,
                &request,
                &mut context,
            )
            .unwrap()
        };
        let crate::effects::EffectObservation::Rejected {
            receipt: first_receipt,
        } = first_observation
        else {
            panic!("conflicting Topic must be durably rejected");
        };
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM supervisor_topic_publications WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "conflict");
        drop(store);
        fs::remove_file(&target).unwrap();
        let mut store = ConfigStore::open_test(temp.path()).unwrap();
        let generation = store
            .start_owner(&crate::store::OwnerMetadata {
                owner_nonce: "topic-conflict-replay".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test-restart".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        let replayed_observation = {
            let mut context = crate::effects::EffectContext {
                store: &mut store,
                owner_generation: generation,
                now_unix: 103,
            };
            crate::effects::EffectHandler::handle(
                &handler,
                crate::effects::EffectMode::Submit,
                &request,
                &mut context,
            )
            .unwrap()
        };
        assert_eq!(
            replayed_observation,
            crate::effects::EffectObservation::Rejected {
                receipt: first_receipt
            }
        );
        assert!(
            !target.exists(),
            "a saved conflict must not republish after the conflicting file is removed"
        );
        let limits = crate::effects::EffectLimits {
            max_attempts: 3,
            max_age: std::time::Duration::from_secs(3600),
            retry_base: std::time::Duration::from_secs(1),
            retry_max: std::time::Duration::from_secs(8),
        };
        let tick = crate::effects::EffectDispatcher::tick(
            &mut store,
            generation,
            103,
            &[&handler],
            limits,
        )
        .unwrap();
        assert!(matches!(
            tick,
            crate::effects::DispatchTick::Completed { .. }
        ));
        assert!(
            !target.exists(),
            "dispatcher replay must terminally reject without republishing"
        );
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM supervisor_topic_publications WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "conflict");
        let status: String = store
            .connection
            .query_row(
                "SELECT status FROM effects WHERE operation_id=?1",
                [&operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "failed");
    }

    #[test]
    fn completed_learning_result_dispatches_after_controller_restart() {
        let LearningDispatchFixture {
            _temp,
            mut store,
            project: _,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            ..
        } = learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
        );
        let run_id = &result.validated.binding.agent_run_id;
        let old_run_generation: u64 = store
            .connection
            .query_row(
                "SELECT controller_generation FROM agent_runs WHERE agent_run_id=?1",
                [run_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_run_generation, generation);
        assert!(store.connection.query_row::<bool,_,_>(
            "SELECT EXISTS(SELECT 1 FROM agent_result_evidence WHERE evidence_id=?1 AND outcome='completed')",
            [result.receipt.evidence_id()],
            |row| row.get(0),
        ).unwrap());

        store.stop_owner(generation).unwrap();
        let new_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "learning-result-owner-restarted".into(),
                state_root: _temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "learning-result-owner-restarted-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert_ne!(new_generation, old_run_generation);
        assert_eq!(store.activate_starting_projects(new_generation).unwrap(), 1);
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                104,
                &config,
                config_digest.clone(),
                &result,
            )
            .is_err()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );

        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                new_generation,
                105,
                &config,
                config_digest.clone(),
                &result,
            )
            .unwrap()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            "applied"
        );

        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                new_generation,
                106,
                &config,
                config_digest,
                &result,
            )
            .unwrap()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn historical_learning_dispatch_rejects_missing_terminal_proof() {
        let LearningDispatchFixture {
            _temp,
            mut store,
            generation,
            result,
            config,
            config_digest,
            ..
        } = learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
        );
        store.stop_owner(generation).unwrap();
        let new_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "learning-result-invalid-terminal-owner".into(),
                state_root: _temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "learning-result-invalid-terminal-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store.activate_starting_projects(new_generation).unwrap();
        store
            .connection
            .execute_batch("DROP TRIGGER agent_terminal_receipts_immutable_delete")
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM agent_terminal_receipts WHERE agent_run_id=?1",
                [result.validated.binding.agent_run_id.as_str()],
            )
            .unwrap();
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                new_generation,
                107,
                &config,
                config_digest,
                &result,
            )
            .is_err()
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |row| row.get(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn historical_learning_batch_reoffer_accepts_verified_terminal_after_restart() {
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            batch_id,
            result,
            ..
        } = learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            None,
        );
        store.stop_owner(generation).unwrap();
        let new_generation = store
            .start_owner(&OwnerMetadata {
                owner_nonce: "learning-reoffer-owner-restarted".into(),
                state_root: _temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "learning-reoffer-owner-restarted-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "e".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        store.activate_starting_projects(new_generation).unwrap();
        let original_wake_id: i64 = store
            .connection
            .query_row(
                "SELECT wake_input_id FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| row.get(0),
            )
            .unwrap();
        let original_batch: (String, String) = store
            .connection
            .query_row(
                "SELECT snapshot_json,findings_json FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        store
            .reoffer_unhandled_learning_batch(new_generation, &result)
            .unwrap();
        store
            .reoffer_unhandled_learning_batch(new_generation, &result)
            .unwrap();
        let deliveries: Vec<(i64, u64, String, Option<String>)> = store.connection.prepare(
            "SELECT wake_input_id,source_revision,lifecycle,consuming_agent_run_id FROM role_wake_inputs WHERE role_session_id=?1 AND source_type='learning_batch' AND source_id=?2 ORDER BY wake_input_id",
        ).unwrap().query_map(
            rusqlite::params![result.validated.binding.role_session_id.as_str(), batch_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap().collect::<Result<_,_>>().unwrap();
        assert_eq!(
            deliveries.len(),
            2,
            "one reoffer creates exactly one new delivery"
        );
        assert_eq!(deliveries[0].0, original_wake_id);
        assert_eq!(deliveries[0].2, "consumed");
        assert_eq!(
            deliveries[0].3.as_deref(),
            Some(result.validated.binding.agent_run_id.as_str())
        );
        assert_ne!(deliveries[0].1, deliveries[1].1);
        assert_eq!(deliveries[1].2, "pending");
        assert_eq!(deliveries[1].3, None);
        let current_wake_id: i64 = store
            .connection
            .query_row(
                "SELECT wake_input_id FROM learning_batches WHERE batch_id=?1 AND status='issued'",
                [&batch_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_wake_id, deliveries[1].0);
        let current_batch: (String, String) = store
            .connection
            .query_row(
                "SELECT snapshot_json,findings_json FROM learning_batches WHERE batch_id=?1",
                [&batch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(current_batch, original_batch);
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id IS NULL",
            [project.as_str()],
            |row| row.get(0),
        ).unwrap(), 1);

        let base = store
            .agent_launch_reservation_for_run(&result.validated.binding.agent_run_id)
            .unwrap()
            .unwrap();
        let pending = store
            .pending_role_wake_inputs(&project, &base.role_session_id, 256)
            .unwrap();
        let wake = pending
            .into_iter()
            .find(|wake| wake.wake_input_id == u64::try_from(current_wake_id).unwrap())
            .unwrap();
        let mut wake_snapshot = crate::agent_api::AgentWakeSnapshot {
            schema_version: 1,
            project_id: project.clone(),
            role_session_id: base.role_session_id.clone(),
            agent_run_id: base.agent_run_id.as_str().into(),
            digest: Digest::parse("0".repeat(64)).unwrap(),
            inputs: vec![crate::agent_api::AgentWakeItem {
                wake_input_id: wake.wake_input_id,
                source_type: wake.source_type,
                source_id: wake.source_id,
                source_revision: wake.source_revision,
                priority: wake.priority,
                payload_json: wake.payload_json,
                host_artifact_source_evidence_ids: Vec::new(),
                host_artifacts: Vec::new(),
                host_completion_context: None,
            }],
            worker_correction_context: None,
        };
        let seed = serde_json::to_vec(&(
            "rex-projects-agent-run-v1",
            &project,
            &base.role_session_id,
            vec![current_wake_id as u64],
        ))
        .unwrap();
        let seed_digest = crate::runtime_services::digest_bytes(&seed).unwrap();
        let short = &seed_digest.as_str()[..32];
        let next_run_id = crate::domain::ids::AgentRunId::parse(format!("agent-{short}")).unwrap();
        let next_operation_id = OperationId::parse(format!("start-{short}")).unwrap();
        wake_snapshot.agent_run_id = next_run_id.as_str().into();
        wake_snapshot.digest = wake_snapshot.content_digest().unwrap();
        let run_root = _temp.path().join("agents").join(next_run_id.as_str());
        let control_dir = run_root.join("control");
        let mut next = base.clone();
        next.agent_run_id = next_run_id.clone();
        next.run_epoch = base.run_epoch + 1;
        next.controller_generation = new_generation;
        next.operation_id = next_operation_id.clone();
        next.wake_snapshot = wake_snapshot;
        next.descriptor_path = run_root.join("run-step.package.json");
        next.control_dir = control_dir.clone();
        next.mailbox_directory = control_dir.clone();
        next.mailbox_expires_at_unix = base.mailbox_expires_at_unix + 3600;
        next.mailbox_capability_digest = crate::runtime_services::mailbox_capability_digest(
            &next_run_id,
            next.mailbox_expires_at_unix,
            next.mailbox_max_request_bytes,
            next.mailbox_max_pending_requests,
        )
        .unwrap();
        std::fs::create_dir_all(&control_dir).unwrap();
        std::fs::create_dir_all(&next.mailbox_directory).unwrap();
        assert!(matches!(
            store.prepare_role_launch(&next).unwrap(),
            crate::store::agent_runtime::LaunchPreparationOutcome::Prepared { .. }
        ));
        assert_ne!(next_run_id, result.validated.binding.agent_run_id);
        assert_ne!(next_operation_id, base.operation_id);
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM effects WHERE operation_id=?1 AND kind='start_agent'",
                    [next_operation_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
            1
        );
        let reoffered: (String, Option<String>) = store.connection.query_row(
            "SELECT lifecycle,consuming_agent_run_id FROM role_wake_inputs WHERE wake_input_id=?1",
            [current_wake_id],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(reoffered.0, "assigned");
        assert_eq!(reoffered.1.as_deref(), Some(next_run_id.as_str()));
    }

    fn assert_learning_result_is_held(fixture: LearningDispatchFixture) {
        let LearningDispatchFixture {
            _temp,
            mut store,
            project,
            generation,
            batch_id,
            result,
            config,
            config_digest,
            checkpoint: _,
        } = fixture;
        assert!(
            crate::engine::factory_runtime::tests::apply_agent_result_for_test(
                &mut store,
                generation,
                200,
                &config,
                config_digest,
                &result,
            )
            .unwrap()
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT disposition FROM agent_result_reducer_ack WHERE evidence_id=?1",
                    [result.receipt.evidence_id()],
                    |r| r.get(0)
                )
                .unwrap(),
            "rejected_by_host"
        );
        let artifacts =
            crate::artifacts::ArtifactStore::open(&_temp.path().join("artifacts")).unwrap();
        assert!(
            store
                .pending_validated_agent_results(&artifacts, generation, 8)
                .unwrap()
                .iter()
                .all(|pending| pending.receipt.evidence_id() != result.receipt.evidence_id())
        );
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM learning_decisions WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(store.connection.query_row::<i64,_,_>(
            "SELECT count(*) FROM learning_findings WHERE project_id=?1 AND consumed_batch_id IS NOT NULL",
            [project.as_str()], |r| r.get(0)
        ).unwrap(), 0);
        assert!(
            store
                .connection
                .query_row::<Option<String>, _, _>(
                    "SELECT last_error FROM project_runtimes WHERE project_id=?1",
                    [project.as_str()],
                    |r| r.get(0)
                )
                .unwrap()
                .is_some()
        );
        let second_project = ProjectId::parse("sample-after-learning-rejection").unwrap();
        let first_record = store.project(&project).unwrap().unwrap();
        store
            .insert_project(&ProjectRecord {
                id: second_project.clone(),
                config_source: first_record.config_source,
                config_revision: first_record.config_revision,
                config_digest: first_record.config_digest,
                mode: first_record.mode,
                goal_revision: first_record.goal_revision,
                desired_lifecycle: "running".into(),
                state_revision: Revision(0),
            })
            .unwrap();
        store
            .set_project_lifecycle(generation, &second_project, "running")
            .unwrap();
        store.connection.execute(
            "UPDATE project_runtimes SET observed_lifecycle='running',controller_generation=?2 WHERE project_id=?1",
            rusqlite::params![second_project.as_str(), generation],
        ).unwrap();
        assert_eq!(
            store
                .queue_due_supervisor_learning(
                    generation,
                    &[project.clone(), second_project.clone()],
                    201,
                    3600,
                    None
                )
                .unwrap(),
            Some(second_project)
        );
        assert_eq!(
            store
                .connection
                .query_row::<String, _, _>(
                    "SELECT status FROM learning_batches WHERE batch_id=?1",
                    [&batch_id],
                    |r| r.get(0)
                )
                .unwrap(),
            "issued"
        );
    }

    #[test]
    fn learning_dispatch_holds_failed_and_unsupported_results_without_ack_or_consumption() {
        assert_learning_result_is_held(learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Failed {
                reason: "provider reported a failed learning turn".into(),
            },
            false,
            false,
            Some((true, false)),
        ));
        assert_learning_result_is_held(learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            true,
            false,
            Some((true, false)),
        ));
        assert_learning_result_is_held(learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Succeeded,
            false,
            false,
            Some((false, true)),
        ));
    }

    #[test]
    fn learning_dispatch_rejects_blocked_and_cancelled_assertions_without_consumption() {
        assert_learning_result_is_held(learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Blocked {
                reason: "provider blocked the learning turn".into(),
            },
            false,
            false,
            None,
        ));
        assert_learning_result_is_held(learning_dispatch_fixture(
            crate::engine::orchestration::AgentAssertion::Cancelled {
                reason: Some("provider cancelled the learning turn".into()),
            },
            false,
            false,
            None,
        ));
    }

    #[test]
    fn approved_inconclusive_profile_publishes_replays_and_activates_after_config_cas() {
        let (temp, mut store, project, generation, _) = running_store();
        let profile_id = ProfileId::parse("worker-learned").unwrap();
        let candidate_id = "worker-learned-v1";
        let candidate_digest = Digest::parse("d".repeat(64)).unwrap();
        let files = BTreeMap::from([
            (
                "config.toml".to_owned(),
                b"adapter = \"codex\"\ncommand = [\"codex\"]\n".to_vec(),
            ),
            (
                "instructions.md".to_owned(),
                b"Keep changes small and record test results.".to_vec(),
            ),
        ]);
        let manifest_digest = crate::learning::manifest_digest(&files).unwrap();
        let package_rows: Vec<_> = files
            .iter()
            .map(|(path, bytes)| {
                (
                    path,
                    Digest::parse(format!("{:x}", Sha256::digest(bytes))).unwrap(),
                )
            })
            .collect();
        let package_json = serde_json::to_string(&package_rows).unwrap();
        let candidate = LearningCandidateRecord {
            revision: CandidateRevision {
                candidate_id: candidate_id.into(),
                project_id: project.clone(),
                role: Role::Worker,
                digest: candidate_digest.clone(),
                created_at: "2026-11-07T00:00:00Z".into(),
                expires_at: "2027-11-07T00:00:00Z".into(),
                status: CandidateStatus::Proposed,
            },
            profile_id: profile_id.clone(),
            package_manifest_digest: manifest_digest,
            package_files_json: serde_json::to_string(&files).unwrap(),
            package_json,
            expected_pairs: 5,
        };
        store
            .register_learning_candidate(generation, &candidate)
            .unwrap();
        let mut evidence = None;
        for pair_index in 0usize..5 {
            let observation = TrialObservation {
                input_digest: Digest::parse(format!(
                    "{:x}",
                    Sha256::digest(pair_index.to_be_bytes())
                ))
                .unwrap(),
                baseline: TrialRunStatus::Equivalent,
                candidate: TrialRunStatus::Equivalent,
            };
            evidence = Some(
                store
                    .record_learning_trial(
                        generation,
                        &project,
                        candidate_id,
                        &candidate_digest,
                        pair_index,
                        &observation,
                    )
                    .unwrap()
                    .evidence,
            );
        }
        let evidence = evidence.unwrap();
        assert_eq!(evidence.outcome, TrialOutcome::Inconclusive);
        assert_eq!(evidence.distinct_inputs, 5);
        let candidate_package = store
            .learning_candidate_package(&project, candidate_id, &candidate_digest)
            .unwrap()
            .unwrap();
        assert_eq!(candidate_package.files, files);
        assert_eq!(candidate_package.evidence, Some(evidence.clone()));
        assert_eq!(
            store
                .current_learning_candidate_package(&project, candidate_id)
                .unwrap(),
            Some(candidate_package.clone())
        );

        let declarative_root = temp.path().join("declarative");
        fs::create_dir_all(&declarative_root).unwrap();
        let config_file = declarative_root.join("config.toml");
        fs::write(&config_file, "schema_version = 1\n").unwrap();
        let config_revision =
            crate::learning::config_revision(&config_file, &declarative_root.join("profiles"))
                .unwrap();
        let config_digest = store
            .load_snapshot("factory")
            .unwrap()
            .unwrap()
            .config
            .digest;
        let policy_digest = Digest::parse("e".repeat(64)).unwrap();
        let material_digest = profile_approval_subject_digest(
            &project,
            Role::Worker,
            &profile_id,
            &candidate_digest,
            &files,
            &evidence,
            &config_revision,
        )
        .unwrap();
        let bundle = crate::learning::profile_candidate_review_bundle(&candidate_package).unwrap();
        let request = HumanRuntimeRequest {
            request_id: crate::domain::ids::HumanRequestId::parse("profile-approval-1").unwrap(),
            purpose: HumanPurpose::ProfilePromotion,
            subject: HumanSubjectBinding {
                project_id: project.clone(),
                kind: HumanSubjectKind::Profile,
                subject_id: candidate_id.to_owned(),
                ticket_run_id: None,
                revision: crate::learning::profile_candidate_revision(&candidate_digest).unwrap(),
                material_digest: material_digest.clone(),
                configuration_digest: config_digest.clone(),
                policy_digest: policy_digest.clone(),
                bundle_digest: crate::human::review_bundle_digest(&bundle).unwrap(),
            },
            question: "Approve publishing this profile to the declarative staging directory?"
                .into(),
            choices: vec![HumanDecisionChoice::Approve, HumanDecisionChoice::Refuse],
            expires_at_unix: 4_102_444_800,
            review_bundle: bundle,
        };
        let supervisor_view = RexView {
            view_id: RexView::derive_id(&project, RexViewKind::Supervisor, None, None, 1).unwrap(),
            project_id: project.clone(),
            kind: RexViewKind::Supervisor,
            ticket_namespace: None,
            ticket_id: None,
            view_epoch: 1,
            rex_server_identity: "test-server".into(),
            rex_session_id: "test-session".into(),
            rex_window_id: "supervisor-window".into(),
        };
        store
            .register_rex_view(generation, &supervisor_view)
            .unwrap();
        let artifact_root = temp.path().join("human-artifacts");
        fs::create_dir_all(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = write_runtime_review_artifact(&artifact_root, &request).unwrap();
        assert!(
            store
                .register_human_request(
                    generation,
                    &request,
                    &supervisor_view.view_id,
                    &artifact,
                    super::super::now_unix().unwrap() as u64,
                )
                .unwrap()
        );
        let now = super::super::now_unix().unwrap() as u64;
        let response = HumanDecisionIntent {
            request_id: request.request_id.clone(),
            response_id: "profile-approval-response-1".into(),
            expected_subject_digest: request.subject.digest().unwrap(),
            choice: HumanDecisionChoice::Approve,
            explanation: Some("Promote only this worker profile for further evaluation; these trials do not establish efficacy.".into()),
        };
        ConfigStore::enqueue_human_decision(temp.path(), &response, now + 1).unwrap();
        assert!(matches!(
            store
                .process_human_decision(
                    generation,
                    &response.response_id,
                    &request.subject,
                    now + 2
                )
                .unwrap(),
            HumanDecisionResult::Applied
        ));
        let receipt = store
            .accepted_human_approval(
                &request.request_id,
                &request.subject.digest().unwrap(),
                &config_digest,
                &policy_digest,
                now + 3,
            )
            .unwrap()
            .unwrap();
        let package: ProfilePackage = crate::learning::profile_package_from_accepted_approval(
            &receipt,
            project.clone(),
            Role::Worker,
            profile_id.clone(),
            candidate_digest.clone(),
            evidence.clone(),
            files.clone(),
            request.subject.digest().unwrap(),
            material_digest.clone(),
            config_revision.clone(),
            config_digest.clone(),
            policy_digest.clone(),
            now + 3,
        )
        .unwrap();
        let operation_id = OperationId::parse("profile-promotion-op-1").unwrap();
        store
            .register_profile_promotion(
                generation,
                &super::ProfilePromotionRequest {
                    operation_id: operation_id.clone(),
                    candidate_id: candidate_id.into(),
                    config_source: "factory".into(),
                    config_file: config_file.display().to_string(),
                    human_request_id: request.request_id.clone(),
                },
                &package,
            )
            .unwrap();
        assert!(
            store
                .begin_profile_publication(generation, &operation_id)
                .unwrap()
        );
        let effect = store
            .next_due_effect(generation, i64::MAX)
            .unwrap()
            .unwrap();
        let handler = crate::profile_effect::ProfileEffectHandler::new(declarative_root.clone());
        let published = handler.execute(&mut store, generation, &effect).unwrap();
        assert!(published.profile_path.is_dir());
        let replay = handler.execute(&mut store, generation, &effect).unwrap();
        assert_eq!(replay, published);

        let current = store.load_snapshot("factory").unwrap().unwrap();
        let mut target = current.config;
        let mut config_value = serde_json::to_value(&target.config).unwrap();
        config_value["projects"][project.as_str()] = serde_json::json!({
            "mode":"goal", "ticket_adapter":"tickets", "roles":{"worker":profile_id.as_str()}
        });
        target.config = serde_json::from_value(config_value).unwrap();
        let profile: crate::config::Profile = serde_json::from_value(serde_json::json!({
            "adapter":"codex", "command":["codex"], "model":"test"
        }))
        .unwrap();
        target.profiles.insert(profile_id, profile);
        target.digest = Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&target.config).unwrap())
        ))
        .unwrap();
        assert!(
            store
                .prepare_profile_activation(
                    generation,
                    &operation_id,
                    current.revision,
                    &target.digest
                )
                .unwrap()
        );
        let applied = store
            .apply_snapshot(
                "factory",
                &target,
                ExpectedRevision::Current(current.revision),
            )
            .unwrap();
        assert!(
            store
                .confirm_profile_activation(generation, &operation_id, &applied)
                .unwrap()
        );
        let status: String = store.connection.query_row(
            "SELECT status FROM learning_candidates WHERE project_id=?1 AND candidate_id=?2 AND digest=?3",
            rusqlite::params![project.as_str(), candidate_id, candidate_digest.as_str()],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(status, "promoted");
        assert!(
            store
                .current_learning_candidate_package(&project, candidate_id)
                .unwrap()
                .is_none()
        );
        store.stop_owner(generation).unwrap();
        drop(store);
        let mut reopened = ConfigStore::open_test(temp.path()).unwrap();
        let recovered_generation = reopened
            .start_owner(&OwnerMetadata {
                owner_nonce: "recovered-profile-owner".into(),
                state_root: temp.path().display().to_string(),
                config_source: "factory".into(),
                process_start_identity: "test-recovered-start".into(),
                executable_path: "/tmp/rex-projects-test".into(),
                executable_digest: "f".repeat(64),
                rex_endpoint: None,
                rex_server_identity: None,
                rex_session_id: None,
                rex_block_id: None,
            })
            .unwrap();
        assert!(
            !reopened
                .confirm_profile_activation(recovered_generation, &operation_id, &applied)
                .unwrap()
        );
        let recovered_state: String = reopened
            .connection
            .query_row(
                "SELECT state FROM profile_promotions WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recovered_state, "active");
    }
}
