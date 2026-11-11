//! Durable, local-only subset of the GitHub CLI `gh api` contract used by delivery.
//!
//! This is an emulated provider fixture. It stores pull requests and reviews in a private
//! SQLite database and uses only the bare repositories below the selected fixture root.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use rex_projects::process::{ProcessRequest, resolve_executable, run};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const STDERR_LIMIT: usize = 16 * 1024;
const FIXTURE_ACTOR: &str = "fixture-operator";
const REVIEW_THREADS_QUERY: &str = "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100){nodes{id isResolved comments(first:100){nodes{id} pageInfo{hasNextPage}}} pageInfo{hasNextPage}}}}}";

pub fn run_cli(root: &Path, args: &[OsString]) -> Result<(), String> {
    validate_root(root)?;
    let request = parse_args(args)?;
    let body = if request.input {
        let mut body = Vec::new();
        std::io::stdin()
            .read_to_end(&mut body)
            .map_err(|error| format!("read gh api request body: {error}"))?;
        if body.len() > OUTPUT_LIMIT {
            return Err("gh api request body exceeds the fixture limit".into());
        }
        serde_json::from_slice::<Value>(&body)
            .map_err(|_| "gh api request body is not JSON".to_owned())?
    } else {
        Value::Null
    };

    let connection = Connection::open(root.join("state/forge.sqlite"))
        .map_err(|error| format!("open local forge state: {error}"))?;
    initialize_db(&connection)?;
    let (status, response) = dispatch(root, &connection, &request, body)?;
    if status >= 400 {
        eprintln!(
            "gh api fixture: {}",
            response["message"].as_str().unwrap_or("request failed")
        );
        std::process::exit(1);
    }
    serde_json::to_writer(std::io::stdout().lock(), &response)
        .map_err(|error| format!("write gh api fixture response: {error}"))?;
    std::io::stdout()
        .write_all(b"\n")
        .map_err(|error| format!("finish gh api fixture response: {error}"))
}

fn validate_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || !root.is_dir() {
        return Err("fixture root must be an existing absolute directory".into());
    }
    for name in ["state", "git"] {
        if !root.join(name).is_dir() {
            return Err(format!("fixture root is missing its `{name}` directory"));
        }
    }
    Ok(())
}

fn initialize_db(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;
         CREATE TABLE IF NOT EXISTS pull_requests (
             number INTEGER PRIMARY KEY AUTOINCREMENT,
             owner TEXT NOT NULL,
             repo TEXT NOT NULL,
             node_id TEXT NOT NULL UNIQUE,
             state TEXT NOT NULL,
             merged INTEGER NOT NULL DEFAULT 0,
             merge_commit_sha TEXT,
             title TEXT NOT NULL,
             body TEXT NOT NULL,
             head_ref TEXT NOT NULL,
             head_sha TEXT NOT NULL,
             base_ref TEXT NOT NULL,
             base_sha TEXT NOT NULL,
             draft INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS reviews (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             pull_number INTEGER NOT NULL,
             user TEXT NOT NULL,
             state TEXT NOT NULL,
             commit_id TEXT,
             submitted_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS comments (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             pull_number INTEGER NOT NULL,
             kind TEXT NOT NULL,
             user TEXT NOT NULL,
             body TEXT NOT NULL,
             created_at TEXT NOT NULL
         );",
        )
        .map_err(|error| format!("initialize local forge state: {error}"))
}

struct Request {
    method: String,
    endpoint: String,
    input: bool,
}

fn parse_args(args: &[OsString]) -> Result<Request, String> {
    let mut method = None;
    let mut endpoint = None;
    let mut input = false;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str().ok_or("gh argument is not UTF-8")?;
        if arg == "api" {
            index += 1;
            endpoint = Some(
                args.get(index)
                    .and_then(|value| value.to_str())
                    .ok_or("gh api endpoint is missing")?
                    .to_owned(),
            );
        } else if matches!(arg, "-X" | "--method") {
            index += 1;
            method = Some(
                args.get(index)
                    .and_then(|value| value.to_str())
                    .ok_or("gh api method is missing")?
                    .to_ascii_uppercase(),
            );
        } else if arg == "--input" {
            index += 1;
            let value = args.get(index).and_then(|value| value.to_str());
            if value != Some("-") {
                return Err("fixture gh only accepts --input -".into());
            }
            input = true;
        }
        index += 1;
    }
    let endpoint = endpoint.ok_or("expected `gh api <endpoint>`")?;
    let method = method.unwrap_or_else(|| if input { "POST" } else { "GET" }.into());
    if !matches!(method.as_str(), "GET" | "POST" | "PATCH" | "PUT") {
        return Err(format!("unsupported fixture HTTP method `{method}`"));
    }
    Ok(Request {
        method,
        endpoint,
        input,
    })
}

fn dispatch(
    root: &Path,
    connection: &Connection,
    request: &Request,
    body: Value,
) -> Result<(u16, Value), String> {
    if request.endpoint == "user" && request.method == "GET" {
        return Ok((
            200,
            json!({"login":FIXTURE_ACTOR,"id":1,"node_id":"fixture-user"}),
        ));
    }
    if request.endpoint == "graphql" && request.method == "POST" {
        return observe_review_threads(connection, root, body);
    }
    let (path, query) = request
        .endpoint
        .split_once('?')
        .unwrap_or((&request.endpoint, ""));
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.first() != Some(&"repos") || parts.len() < 3 {
        return not_found("unsupported local GitHub endpoint");
    }
    let owner = safe_component(parts[1])?;
    let repo = safe_component(parts[2])?;
    let remote = root.join("git").join(&owner).join(format!("{repo}.git"));
    if !remote.is_dir() {
        return not_found("local bare repository is absent");
    }
    if parts.len() == 3 && request.method == "GET" {
        let default_branch = default_branch(&remote)?;
        return Ok((
            200,
            json!({
                "id": repository_id(&owner, &repo),
                "full_name": format!("{owner}/{repo}"),
                "default_branch": default_branch,
                "allow_merge_commit": true,
                "allow_squash_merge": true,
                "allow_rebase_merge": true
            }),
        ));
    }
    if parts.len() < 4 || parts[3] != "pulls" {
        return dispatch_repository_route(
            connection,
            &remote,
            &owner,
            &repo,
            request,
            &parts[3..],
            body,
        );
    }
    match (parts.len(), request.method.as_str()) {
        (4, "GET") => list_pulls(connection, &owner, &repo, query),
        (4, "POST") => create_pull(connection, &remote, &owner, &repo, body),
        (5, "GET") => get_pull(connection, &owner, &repo, parse_number(parts[4])?),
        (5, "PATCH") => update_pull(
            connection,
            &remote,
            &owner,
            &repo,
            parse_number(parts[4])?,
            body,
        ),
        (6, "PUT") if parts[5] == "merge" => merge_pull(
            connection,
            &remote,
            &owner,
            &repo,
            parse_number(parts[4])?,
            body,
        ),
        (6, "GET") if parts[5] == "reviews" => {
            list_reviews(connection, &owner, &repo, parse_number(parts[4])?)
        }
        (6, "POST") if parts[5] == "reviews" => {
            create_review(connection, &owner, &repo, parse_number(parts[4])?, body)
        }
        (6, "GET") if parts[5] == "comments" => {
            list_comments(connection, &owner, &repo, parse_number(parts[4])?, "review")
        }
        (6, "GET") if parts[5] == "files" => {
            list_files(&remote, connection, &owner, &repo, parse_number(parts[4])?)
        }
        _ => not_found("unsupported local pull request endpoint"),
    }
}

fn observe_review_threads(
    connection: &Connection,
    root: &Path,
    body: Value,
) -> Result<(u16, Value), String> {
    if body.get("query").and_then(Value::as_str) != Some(REVIEW_THREADS_QUERY) {
        return not_found("unsupported local GitHub GraphQL query");
    }
    let Some(variables) = body.get("variables").and_then(Value::as_object) else {
        return not_found("review thread query variables are missing");
    };
    if variables.len() != 3 {
        return not_found("review thread query variables are unsupported");
    }
    let (Some(owner), Some(repo), Some(number)) = (
        variables.get("owner").and_then(Value::as_str),
        variables.get("name").and_then(Value::as_str),
        variables.get("number").and_then(Value::as_u64),
    ) else {
        return not_found("review thread query identity is malformed");
    };
    let owner = safe_component(owner)?;
    let repo = safe_component(repo)?;
    let remote = root.join("git").join(&owner).join(format!("{repo}.git"));
    if !remote.is_dir() || load_pull(connection, &owner, &repo, number)?.is_none() {
        return not_found("local pull request identity is unknown");
    }
    let review_comments: i64 = connection
        .query_row(
            "SELECT count(*) FROM comments WHERE pull_number=?1 AND kind='review'",
            [number],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if review_comments != 0 {
        return not_found("fixture cannot model review comment threads or resolution state");
    }
    Ok((
        200,
        json!({"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}}),
    ))
}

fn dispatch_repository_route(
    connection: &Connection,
    remote: &Path,
    owner: &str,
    repo: &str,
    request: &Request,
    parts: &[&str],
    body: Value,
) -> Result<(u16, Value), String> {
    match parts {
        ["issues", number, "comments"] if request.method == "GET" => {
            list_comments(connection, owner, repo, parse_number(number)?, "issue")
        }
        ["issues", number, "comments"] if request.method == "POST" => create_comment(
            connection,
            owner,
            repo,
            parse_number(number)?,
            "issue",
            body,
        ),
        ["branches", branch, "protection"] if request.method == "GET" => Ok((
            200,
            json!({
                "required_status_checks":{"strict":true,"contexts":["required-tests"]},
                "required_pull_request_reviews":{"required_approving_review_count":1,"dismiss_stale_reviews":true},
                "enforce_admins":{"enabled":true},"allow_force_pushes":{"enabled":false},"allow_deletions":{"enabled":false},"branch":branch
            }),
        )),
        ["rules", "branches", _branch] if request.method == "GET" => Ok((200, json!([]))),
        ["commits", sha, "check-runs"] if request.method == "GET" => {
            let state = check_state(remote, sha)?;
            let (status, conclusion) = match state.as_str() {
                "success" => ("completed", json!("success")),
                "failure" => ("completed", json!("failure")),
                _ => ("queued", Value::Null),
            };
            Ok((
                200,
                json!({"total_count":1,"check_runs":[{"id":1,"name":"required-tests","head_sha":sha,"status":status,"conclusion":conclusion,"app":{"id":1}}]}),
            ))
        }
        ["commits", sha, "statuses"] if request.method == "GET" => {
            let state = check_state(remote, sha)?;
            Ok((
                200,
                json!([{"id":1,"context":"required-tests","state":state,"sha":sha,"creator":{"login":"fixture-ci"},"created_at":"2026-11-11T00:00:00Z"}]),
            ))
        }
        ["commits", sha] if request.method == "GET" => commit_observation(remote, sha),
        ["compare", pair] if request.method == "GET" => compare(remote, pair),
        ["pulls", number, "merge"] if request.method == "PUT" => {
            merge_pull(connection, remote, owner, repo, parse_number(number)?, body)
        }
        _ => not_found("unsupported local GitHub repository endpoint"),
    }
}

fn list_pulls(
    connection: &Connection,
    owner: &str,
    repo: &str,
    query: &str,
) -> Result<(u16, Value), String> {
    let filters = parse_query(query);
    let head = filters.get("head").cloned();
    let base = filters.get("base").cloned();
    let mut statement = connection.prepare("SELECT number,node_id,state,merged,merge_commit_sha,title,body,head_ref,head_sha,base_ref,base_sha,draft FROM pull_requests WHERE owner=?1 AND repo=?2 ORDER BY number")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![owner, repo], row_pull)
        .map_err(|error| error.to_string())?;
    let mut pulls = Vec::new();
    for row in rows {
        let pull = row.map_err(|error| error.to_string())?;
        if head
            .as_deref()
            .is_some_and(|value| !value.ends_with(&format!(":{}", pull.head_ref)))
            || base.as_deref().is_some_and(|value| value != pull.base_ref)
        {
            continue;
        }
        pulls.push(pull.json(owner, repo));
    }
    Ok((200, Value::Array(pulls)))
}

fn create_pull(
    connection: &Connection,
    remote: &Path,
    owner: &str,
    repo: &str,
    body: Value,
) -> Result<(u16, Value), String> {
    let title = required_string(&body, "title")?;
    let head_ref = required_string(&body, "head")?;
    let base_ref = required_string(&body, "base")?;
    let body_text = body.get("body").and_then(Value::as_str).unwrap_or_default();
    let head_sha = git_text(remote, &["rev-parse", &format!("refs/heads/{head_ref}")])?;
    let base_sha = git_text(remote, &["rev-parse", &format!("refs/heads/{base_ref}")])?;
    connection.execute("INSERT INTO pull_requests(owner,repo,node_id,state,merged,title,body,head_ref,head_sha,base_ref,base_sha,draft) VALUES(?1,?2,?3,'open',0,?4,?5,?6,?7,?8,?9,0)", params![owner,repo,format!("PR_{}_{}_{}",owner,repo,now_ms()),title,body_text,head_ref,head_sha,base_ref,base_sha]).map_err(|error| error.to_string())?;
    let number = connection.last_insert_rowid() as u64;
    get_pull(connection, owner, repo, number)
}

fn update_pull(
    connection: &Connection,
    remote: &Path,
    owner: &str,
    repo: &str,
    number: u64,
    body: Value,
) -> Result<(u16, Value), String> {
    let current = load_pull(connection, owner, repo, number)?.ok_or("pull request not found")?;
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(&current.title);
    let body_text = body
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or(&current.body);
    let head_sha = git_text(
        remote,
        &["rev-parse", &format!("refs/heads/{}", current.head_ref)],
    )?;
    let base_sha = git_text(
        remote,
        &["rev-parse", &format!("refs/heads/{}", current.base_ref)],
    )?;
    connection.execute("UPDATE pull_requests SET title=?1,body=?2,head_sha=?3,base_sha=?4 WHERE number=?5 AND owner=?6 AND repo=?7", params![title,body_text,head_sha,base_sha,number,owner,repo]).map_err(|error| error.to_string())?;
    get_pull(connection, owner, repo, number)
}

fn get_pull(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
) -> Result<(u16, Value), String> {
    let Some(pull) = load_pull(connection, owner, repo, number)? else {
        return not_found("pull request not found");
    };
    Ok((200, pull.json(owner, repo)))
}

fn load_pull(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
) -> Result<Option<Pull>, String> {
    connection.query_row("SELECT number,node_id,state,merged,merge_commit_sha,title,body,head_ref,head_sha,base_ref,base_sha,draft FROM pull_requests WHERE owner=?1 AND repo=?2 AND number=?3",params![owner,repo,number],row_pull).optional().map_err(|error| error.to_string())
}

fn row_pull(row: &rusqlite::Row<'_>) -> rusqlite::Result<Pull> {
    Ok(Pull {
        number: row.get(0)?,
        node_id: row.get(1)?,
        state: row.get(2)?,
        merged: row.get::<_, i64>(3)? != 0,
        merge_sha: row.get(4)?,
        title: row.get(5)?,
        body: row.get(6)?,
        head_ref: row.get(7)?,
        head_sha: row.get(8)?,
        base_ref: row.get(9)?,
        base_sha: row.get(10)?,
        draft: row.get::<_, i64>(11)? != 0,
    })
}

struct Pull {
    number: u64,
    node_id: String,
    state: String,
    merged: bool,
    merge_sha: Option<String>,
    title: String,
    body: String,
    head_ref: String,
    head_sha: String,
    base_ref: String,
    base_sha: String,
    draft: bool,
}

impl Pull {
    fn json(&self, owner: &str, repo: &str) -> Value {
        json!({"number":self.number,"node_id":self.node_id,"html_url":format!("https://github.invalid/{owner}/{repo}/pull/{}",self.number),"state":self.state,"merged":self.merged,"merge_commit_sha":self.merge_sha,"title":self.title,"body":self.body,"draft":self.draft,"head":{"ref":self.head_ref,"sha":self.head_sha,"repo":{"id":repository_id(owner,repo),"full_name":format!("{owner}/{repo}")}},"base":{"ref":self.base_ref,"sha":self.base_sha,"repo":{"id":repository_id(owner,repo),"full_name":format!("{owner}/{repo}")}}})
    }
}

fn create_review(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
    body: Value,
) -> Result<(u16, Value), String> {
    if load_pull(connection, owner, repo, number)?.is_none() {
        return not_found("pull request not found");
    }
    let event = body
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("COMMENTED")
        .to_ascii_uppercase();
    let state = match event.as_str() {
        "APPROVE" => "APPROVED",
        "REQUEST_CHANGES" => "CHANGES_REQUESTED",
        "COMMENT" => "COMMENTED",
        other => other,
    };
    let pull = load_pull(connection, owner, repo, number)?.expect("checked above");
    connection.execute("INSERT INTO reviews(pull_number,user,state,commit_id,submitted_at) VALUES(?1,'fixture-human',?2,?3,datetime('now'))",params![number,state,pull.head_sha]).map_err(|error| error.to_string())?;
    let id = connection.last_insert_rowid() as u64;
    Ok((
        201,
        json!({"id":id,"user":{"login":"fixture-human"},"state":state,"commit_id":pull.head_sha,"submitted_at":"2026-11-07T00:00:00Z"}),
    ))
}

fn list_reviews(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
) -> Result<(u16, Value), String> {
    if load_pull(connection, owner, repo, number)?.is_none() {
        return not_found("pull request not found");
    }
    let mut statement=connection.prepare("SELECT id,user,state,commit_id,submitted_at FROM reviews WHERE pull_number=?1 ORDER BY id").map_err(|error|error.to_string())?;
    let rows=statement.query_map([number],|r| Ok(json!({"id":r.get::<_,u64>(0)?,"user":{"login":r.get::<_,String>(1)?},"state":r.get::<_,String>(2)?,"commit_id":r.get::<_,Option<String>>(3)?,"submitted_at":r.get::<_,String>(4)?}))).map_err(|error|error.to_string())?;
    let values = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let _ = (owner, repo);
    Ok((200, Value::Array(values)))
}

fn merge_pull(
    connection: &Connection,
    remote: &Path,
    owner: &str,
    repo: &str,
    number: u64,
    body: Value,
) -> Result<(u16, Value), String> {
    let pull = load_pull(connection, owner, repo, number)?.ok_or("pull request not found")?;
    let requested_head = required_string(&body, "sha")?;
    if pull.merged || pull.state != "open" || requested_head != pull.head_sha {
        return Ok((409, json!({"message":"PR state or expected head is stale"})));
    }
    let live_base_sha = git_text(
        remote,
        &["rev-parse", &format!("refs/heads/{}", pull.base_ref)],
    )?;
    if live_base_sha != pull.base_sha {
        return Ok((
            409,
            json!({"message":"PR base is out of date with the target branch"}),
        ));
    }
    let approvals:i64=connection.query_row("SELECT COUNT(*) FROM reviews WHERE pull_number=?1 AND state='APPROVED' AND commit_id=?2",params![number,pull.head_sha],|r|r.get(0)).map_err(|error|error.to_string())?;
    if approvals < 1 {
        return Ok((
            409,
            json!({"message":"fixture requires an approval for the current head"}),
        ));
    }
    if !check_success(remote, &pull.head_sha)? {
        return Ok((
            409,
            json!({"message":"required check is not successful for the current head"}),
        ));
    }
    let method = body
        .get("merge_method")
        .and_then(Value::as_str)
        .unwrap_or("squash");
    let message = body
        .get("commit_message")
        .and_then(Value::as_str)
        .unwrap_or(&pull.title);
    let tree = git_text(
        remote,
        &["merge-tree", "--write-tree", &pull.base_sha, &pull.head_sha],
    )?;
    let args = if method == "merge" {
        vec![
            "commit-tree".to_owned(),
            tree,
            "-p".to_owned(),
            pull.base_sha.clone(),
            "-p".to_owned(),
            pull.head_sha.clone(),
            "-m".to_owned(),
            message.to_owned(),
        ]
    } else {
        vec![
            "commit-tree".to_owned(),
            tree,
            "-p".to_owned(),
            pull.base_sha.clone(),
            "-m".to_owned(),
            message.to_owned(),
        ]
    };
    let merge_sha = git_text_with_identity(remote, &args)?;
    let refname = format!("refs/heads/{}", pull.base_ref);
    git_text(
        remote,
        &["update-ref", &refname, &merge_sha, &pull.base_sha],
    )?;
    let new_base = git_text(remote, &["rev-parse", &refname])?;
    connection.execute("UPDATE pull_requests SET state='closed',merged=1,merge_commit_sha=?1,base_sha=?2 WHERE number=?3 AND owner=?4 AND repo=?5",params![merge_sha,new_base,number,owner,repo]).map_err(|error|error.to_string())?;
    Ok((
        200,
        json!({"sha":merge_sha,"merged":true,"message":"Pull Request successfully merged"}),
    ))
}

fn check_success(remote: &Path, head: &str) -> Result<bool, String> {
    Ok(check_state(remote, head)? == "success")
}

fn check_state(remote: &Path, head: &str) -> Result<String, String> {
    let checks = remote
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or("invalid bare remote path")?
        .join("state/checks.json");
    let value = match std::fs::read(&checks) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .map_err(|error| format!("parse fixture check state: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(error) => return Err(format!("read fixture check state: {error}")),
    };
    Ok(value
        .get(head)
        .and_then(Value::as_str)
        .unwrap_or("pending")
        .to_owned())
}

fn create_comment(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
    kind: &str,
    body: Value,
) -> Result<(u16, Value), String> {
    if load_pull(connection, owner, repo, number)?.is_none() {
        return not_found("pull request not found");
    }
    let text = required_string(&body, "body")?;
    let created_at: String = connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|error| error.to_string())?;
    connection
        .execute(
            "INSERT INTO comments(pull_number,kind,user,body,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![number, kind, FIXTURE_ACTOR, text, created_at],
        )
        .map_err(|error| error.to_string())?;
    let id = connection.last_insert_rowid() as u64;
    Ok((
        201,
        json!({"id":id,"user":{"login":FIXTURE_ACTOR},"body":text,"created_at":created_at}),
    ))
}

fn list_comments(
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
    kind: &str,
) -> Result<(u16, Value), String> {
    if load_pull(connection, owner, repo, number)?.is_none() {
        return not_found("pull request not found");
    }
    let mut statement=connection.prepare("SELECT id,user,body,created_at FROM comments WHERE pull_number=?1 AND kind=?2 ORDER BY id").map_err(|error|error.to_string())?;
    let rows=statement.query_map(params![number,kind],|r|Ok(json!({"id":r.get::<_,u64>(0)?,"user":{"login":r.get::<_,String>(1)?},"body":r.get::<_,String>(2)?,"created_at":r.get::<_,String>(3)?}))).map_err(|error|error.to_string())?;
    let values = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let _ = (owner, repo);
    Ok((200, Value::Array(values)))
}

fn list_files(
    remote: &Path,
    connection: &Connection,
    owner: &str,
    repo: &str,
    number: u64,
) -> Result<(u16, Value), String> {
    let pull = load_pull(connection, owner, repo, number)?.ok_or("pull request not found")?;
    let names = git_text(
        remote,
        &[
            "diff",
            "--name-only",
            &format!("{}..{}", pull.base_sha, pull.head_sha),
        ],
    )?;
    let files=names.lines().filter(|line|!line.is_empty()).map(|name|json!({"filename":name,"status":"modified","additions":1,"deletions":0,"changes":1,"patch":"@@ fixture @@"})).collect::<Vec<_>>();
    Ok((200, Value::Array(files)))
}

fn commit_observation(remote: &Path, sha: &str) -> Result<(u16, Value), String> {
    let tree = git_text(remote, &["show", "-s", "--format=%T", sha])?;
    let parents = git_text(remote, &["show", "-s", "--format=%P", sha])?;
    let message = git_text(remote, &["show", "-s", "--format=%B", sha])?;
    Ok((
        200,
        json!({"sha":sha,"commit":{"tree":{"sha":tree},"message":message},"parents":parents.split_whitespace().map(|p|json!({"sha":p})).collect::<Vec<_>>()}),
    ))
}

fn compare(remote: &Path, pair: &str) -> Result<(u16, Value), String> {
    let (base, head) = pair.split_once("...").ok_or("invalid compare pair")?;
    let base_sha = git_text(remote, &["rev-parse", base])?;
    let head_sha = git_text(remote, &["rev-parse", head])?;
    let count = git_text(
        remote,
        &["rev-list", "--count", &format!("{base_sha}..{head_sha}")],
    )?
    .parse::<u64>()
    .unwrap_or(0);
    Ok((
        200,
        json!({"status":if count==0{"identical"}else{"ahead"},"ahead_by":count,"behind_by":0,"base_commit":{"sha":base_sha},"head_commit":{"sha":head_sha}}),
    ))
}

fn default_branch(remote: &Path) -> Result<String, String> {
    let value =
        git_text(remote, &["symbolic-ref", "--short", "HEAD"]).unwrap_or_else(|_| "main".into());
    Ok(value.rsplit('/').next().unwrap_or("main").to_owned())
}

fn git_text(remote: &Path, args: &[&str]) -> Result<String, String> {
    git_text_with_env(remote, args, BTreeMap::new())
}
fn git_text_with_identity(remote: &Path, args: &[String]) -> Result<String, String> {
    let env = BTreeMap::from([
        (
            OsString::from("GIT_AUTHOR_NAME"),
            OsString::from("Fixture Merge"),
        ),
        (
            OsString::from("GIT_AUTHOR_EMAIL"),
            OsString::from("fixture@example.invalid"),
        ),
        (
            OsString::from("GIT_COMMITTER_NAME"),
            OsString::from("Fixture Merge"),
        ),
        (
            OsString::from("GIT_COMMITTER_EMAIL"),
            OsString::from("fixture@example.invalid"),
        ),
    ]);
    git_text_with_env(
        remote,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        env,
    )
}
fn git_text_with_env(
    remote: &Path,
    args: &[&str],
    extra: BTreeMap<OsString, OsString>,
) -> Result<String, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::env::split_paths(&path).collect::<Vec<_>>();
    let executable =
        resolve_executable(Path::new("git"), &paths).ok_or("git executable is unavailable")?;
    let output = run(ProcessRequest {
        executable,
        args: args.iter().map(OsString::from).collect(),
        stdin: Vec::new(),
        cwd: None,
        clear_environment: true,
        environment: extra
            .into_iter()
            .chain([
                (OsString::from("GIT_DIR"), remote.as_os_str().to_owned()),
                (OsString::from("PATH"), path),
            ])
            .collect(),
        timeout: Duration::from_secs(10),
        shutdown_grace: Duration::from_secs(2),
        stdout_limit: OUTPUT_LIMIT,
        stderr_tail_limit: STDERR_LIMIT,
    })
    .map_err(|e| format!("run bounded fixture git: {e}"))?;
    if output.timed_out || !output.cleanup_confirmed || !output.status.is_some_and(|s| s.success())
    {
        return Err("fixture git command failed, timed out, or had unknown completion".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "fixture git output is not UTF-8".into())
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.replace("%3A", ":").replace("%3a", ":")))
        .collect()
}
fn safe_component(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("unsafe repository path component".into());
    }
    Ok(value.to_owned())
}
fn parse_number(value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| "pull request number is invalid".into())
}
fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("request requires nonempty `{key}`"))
}
fn not_found(message: &str) -> Result<(u16, Value), String> {
    Ok((404, json!({"message":message})))
}
fn repository_id(owner: &str, repo: &str) -> u64 {
    owner
        .bytes()
        .chain(repo.bytes())
        .fold(0x811c9dc5u64, |h, b| {
            h.wrapping_mul(0x100000001b3) ^ u64::from(b)
        })
}
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_projects::forge::github::{GitHubCliForge, GitHubCommandRunner};
    use rex_projects::forge::{
        CommentIntent, EffectCertainty, Forge, ForgeFailureKind, MergeEffectIntent,
        MergeEffectOperation, Observed, PullRequestRef, Reconciliation, RepositoryRef,
    };
    use rex_projects::process::{ProcessError, ProcessOutput};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct AdapterFixtureRunner {
        root: std::path::PathBuf,
        connection: Mutex<Connection>,
        requests: Mutex<Vec<(String, String, Value, Value)>>,
    }

    impl GitHubCommandRunner for AdapterFixtureRunner {
        fn run(&self, request: ProcessRequest) -> Result<ProcessOutput, ProcessError> {
            let parsed = parse_args(&request.args).map_err(ProcessError::Invalid)?;
            let body = if parsed.input {
                serde_json::from_slice(&request.stdin)
                    .map_err(|error| ProcessError::Invalid(error.to_string()))?
            } else {
                Value::Null
            };
            let (status, response) = dispatch(
                &self.root,
                &self.connection.lock().unwrap(),
                &parsed,
                body.clone(),
            )
            .map_err(ProcessError::Invalid)?;
            self.requests.lock().unwrap().push((
                parsed.method.clone(),
                parsed.endpoint.clone(),
                body,
                response.clone(),
            ));
            use std::os::unix::process::ExitStatusExt;
            Ok(ProcessOutput {
                status: Some(std::process::ExitStatus::from_raw(if status < 400 {
                    0
                } else {
                    1 << 8
                })),
                stdout: serde_json::to_vec(&response).unwrap_or_default(),
                stderr_tail: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
                cleanup_confirmed: true,
            })
        }
    }

    fn git(remote: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(remote)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn fixture_pull() -> (
        tempfile::TempDir,
        Connection,
        std::path::PathBuf,
        u64,
        String,
        String,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let state = root.join("state");
        let remote = root.join("git/fixture/repository.git");
        let work = root.join("work");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(remote.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "-b", "main"]);
        git(&work, &["config", "user.name", "Fixture User"]);
        git(&work, &["config", "user.email", "fixture@example.invalid"]);
        std::fs::write(work.join("README.md"), "base\n").unwrap();
        git(&work, &["add", "README.md"]);
        git(&work, &["commit", "-m", "base"]);
        let base_sha = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["branch", "feature"]);
        git(&work, &["checkout", "feature"]);
        std::fs::write(work.join("feature.txt"), "feature\n").unwrap();
        git(&work, &["add", "feature.txt"]);
        git(&work, &["commit", "-m", "feature"]);
        let head_sha = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["init", "--bare", remote.to_str().unwrap()]);
        git(
            &work,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&work, &["push", "origin", "main", "feature"]);

        let connection = Connection::open_in_memory().unwrap();
        initialize_db(&connection).unwrap();
        let create = Request {
            method: "POST".into(),
            endpoint: "repos/fixture/repository/pulls".into(),
            input: true,
        };
        let (status, pull) = dispatch(
            root,
            &connection,
            &create,
            json!({"title":"Fixture change","head":"feature","base":"main"}),
        )
        .unwrap();
        assert_eq!(status, 200);
        let number = pull["number"].as_u64().unwrap();
        let review = Request {
            method: "POST".into(),
            endpoint: format!("repos/fixture/repository/pulls/{number}/reviews"),
            input: true,
        };
        assert_eq!(
            dispatch(root, &connection, &review, json!({"event":"APPROVE"}))
                .unwrap()
                .0,
            201
        );
        std::fs::write(
            state.join("checks.json"),
            serde_json::to_vec(&json!({(head_sha.clone()):"success"})).unwrap(),
        )
        .unwrap();
        let protection = Request {
            method: "GET".into(),
            endpoint: "repos/fixture/repository/branches/main/protection".into(),
            input: false,
        };
        let (protection_status, protection) =
            dispatch(root, &connection, &protection, Value::Null).unwrap();
        assert_eq!(protection_status, 200);
        assert_eq!(protection["required_status_checks"]["strict"], true);
        assert_eq!(
            protection["required_status_checks"]["contexts"],
            json!(["required-tests"])
        );
        assert_eq!(
            protection["required_pull_request_reviews"]["required_approving_review_count"],
            1
        );
        assert_eq!(
            protection["required_pull_request_reviews"]["dismiss_stale_reviews"],
            true
        );
        assert_eq!(protection["enforce_admins"]["enabled"], true);
        (temporary, connection, remote, number, base_sha, head_sha)
    }

    #[test]
    fn request_comment_reconciles_through_github_adapter_and_fixture_cli_contract() {
        let (temporary, connection, _remote, number, base_sha, head_sha) = fixture_pull();
        let root = temporary.path().to_path_buf();
        let runner = Arc::new(AdapterFixtureRunner {
            root,
            connection: Mutex::new(connection),
            requests: Mutex::new(Vec::new()),
        });
        let forge = GitHubCliForge::new(
            runner.clone(),
            "/fixture/bin/gh".into(),
            "github.test",
            BTreeMap::new(),
            Duration::from_secs(5),
            Duration::from_secs(1),
            OUTPUT_LIMIT,
            STDERR_LIMIT,
            2,
        )
        .unwrap();
        let repository = RepositoryRef {
            host: "github.test".into(),
            owner: "fixture".into(),
            name: "repository".into(),
            expected_id: None,
        };
        let pull = PullRequestRef {
            repository,
            number,
            expected_node_id: None,
        };
        let user_output = runner
            .run(ProcessRequest {
                executable: "/fixture/bin/gh".into(),
                args: [
                    "--hostname",
                    "github.test",
                    "api",
                    "user",
                    "--method",
                    "GET",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
                stdin: Vec::new(),
                cwd: None,
                clear_environment: true,
                environment: BTreeMap::new(),
                timeout: Duration::from_secs(5),
                shutdown_grace: Duration::from_secs(1),
                stdout_limit: OUTPUT_LIMIT,
                stderr_tail_limit: STDERR_LIMIT,
            })
            .unwrap();
        assert!(user_output.status.unwrap().success());
        let actor = serde_json::from_slice::<Value>(&user_output.stdout).unwrap()["login"]
            .as_str()
            .unwrap()
            .to_owned();
        let attempt_started_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let comment = CommentIntent {
            pull: pull.clone(),
            operation_key: "fixture-request-comment".into(),
            expected_head_sha: head_sha,
            expected_base_sha: base_sha,
            exact_body: "/merge".into(),
            authenticated_actor: actor.clone(),
            attempt_started_unix,
        };
        let acknowledgement = forge.post_comment(&comment).unwrap();
        assert_eq!(acknowledgement.certainty, EffectCertainty::Applied);
        let reconciliation = forge
            .reconcile(&MergeEffectIntent {
                pull: pull.clone(),
                operation_key: comment.operation_key.clone(),
                request_digest: acknowledgement.request_digest.clone(),
                operation: MergeEffectOperation::RequestComment(comment),
                attempt_started_unix,
            })
            .unwrap();
        let Reconciliation::Recovered(recovered) = reconciliation else {
            panic!("request comment was not recovered from the fixture observation");
        };
        assert_eq!(recovered.certainty, EffectCertainty::Recovered);

        let requests = runner.requests.lock().unwrap();
        let user = requests
            .iter()
            .find(|(method, endpoint, _, _)| method == "GET" && endpoint == "user")
            .unwrap();
        assert_eq!(user.3["login"], actor);
        let post = requests
            .iter()
            .find(|(method, endpoint, _, _)| {
                method == "POST" && endpoint.ends_with("/issues/1/comments")
            })
            .unwrap();
        let get = requests
            .iter()
            .find(|(method, endpoint, _, _)| {
                method == "GET"
                    && endpoint.starts_with("repos/fixture/repository/issues/1/comments")
            })
            .unwrap();
        let posted_comment_id = post.3["id"].as_u64().unwrap();
        assert_eq!(
            recovered.external_id.as_deref(),
            Some(posted_comment_id.to_string().as_str())
        );
        assert_eq!(post.2["body"], "/merge");
        assert_eq!(post.3["user"]["login"], actor);
        assert_eq!(get.3[0]["user"]["login"], post.3["user"]["login"]);
        assert_eq!(get.3[0]["created_at"], post.3["created_at"]);
        assert_eq!(get.3[0]["id"], posted_comment_id);
        assert!(
            get.3[0]["created_at"]
                .as_str()
                .is_some_and(|value| { value.contains('T') && value.ends_with('Z') })
        );
        let (status, pull_state) = get_pull(
            &runner.connection.lock().unwrap(),
            "fixture",
            "repository",
            number,
        )
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(pull_state["state"], "open");
        assert_eq!(pull_state["merged"], false);
        assert!(pull_state["merge_commit_sha"].is_null());
    }

    #[test]
    fn actual_github_observe_gets_complete_empty_threads_only_for_known_threadless_pull() {
        let (temporary, connection, _remote, number, _, _) = fixture_pull();
        let root = temporary.path().to_path_buf();
        let runner = Arc::new(AdapterFixtureRunner {
            root,
            connection: Mutex::new(connection),
            requests: Mutex::new(Vec::new()),
        });
        let forge = GitHubCliForge::new(
            runner.clone(),
            "/fixture/bin/gh".into(),
            "github.test",
            BTreeMap::new(),
            Duration::from_secs(5),
            Duration::from_secs(1),
            OUTPUT_LIMIT,
            STDERR_LIMIT,
            2,
        )
        .unwrap();
        let pull = PullRequestRef {
            repository: RepositoryRef {
                host: "github.test".into(),
                owner: "fixture".into(),
                name: "repository".into(),
                expected_id: None,
            },
            number,
            expected_node_id: None,
        };

        let observation = forge.observe(&pull).unwrap();
        assert!(matches!(
            observation.review_threads,
            Observed::Complete { ref value, .. } if value.is_empty()
        ));
        assert!(
            runner
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(method, endpoint, body, _)| method == "POST"
                    && endpoint == "graphql"
                    && body["query"] == REVIEW_THREADS_QUERY
                    && body["variables"]["owner"] == "fixture"
                    && body["variables"]["name"] == "repository"
                    && body["variables"]["number"] == number)
        );

        let unknown = PullRequestRef {
            number: number + 100,
            ..pull.clone()
        };
        let graphql_requests = || {
            runner
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, endpoint, _, _)| endpoint == "graphql")
                .count()
        };
        let known_query_count = graphql_requests();
        let unknown_observation = forge.observe(&unknown).unwrap_err();
        assert_eq!(unknown_observation.kind, ForgeFailureKind::Permanent);
        assert_eq!(graphql_requests(), known_query_count);
    }

    #[test]
    fn review_thread_fixture_refuses_to_invent_empty_threads_when_review_comments_exist() {
        let (temporary, connection, _remote, number, _, _) = fixture_pull();
        connection
            .execute(
                "INSERT INTO comments(pull_number,kind,user,body,created_at) VALUES(?1,'review',?2,'unmodeled review comment','2026-11-11T00:00:00Z')",
                params![number, FIXTURE_ACTOR],
            )
            .unwrap();
        let request = Request {
            method: "POST".into(),
            endpoint: "graphql".into(),
            input: true,
        };
        let (status, response) = dispatch(
            temporary.path(),
            &connection,
            &request,
            json!({
                "query":REVIEW_THREADS_QUERY,
                "variables":{"owner":"fixture","name":"repository","number":number}
            }),
        )
        .unwrap();
        assert_eq!(status, 404);
        assert!(
            response["message"]
                .as_str()
                .unwrap()
                .contains("cannot model")
        );
    }

    #[test]
    fn required_status_fixture_includes_freshness_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let state = root.join("state");
        let remote = root.join("git/fixture/repository.git");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&remote).unwrap();
        std::fs::write(
            state.join("checks.json"),
            serde_json::to_vec(&json!({"abc123":"success"})).unwrap(),
        )
        .unwrap();
        let connection = Connection::open_in_memory().unwrap();
        initialize_db(&connection).unwrap();
        let request = Request {
            method: "GET".into(),
            endpoint: "repos/fixture/repository/commits/abc123/statuses".into(),
            input: false,
        };

        let (status, response) = dispatch_repository_route(
            &connection,
            &remote,
            "fixture",
            "repository",
            &request,
            &["commits", "abc123", "statuses"],
            Value::Null,
        )
        .unwrap();

        assert_eq!(status, 200);
        assert_eq!(response[0]["id"], 1);
        assert_eq!(response[0]["context"], "required-tests");
        assert_eq!(response[0]["state"], "success");
        assert_eq!(response[0]["sha"], "abc123");
        assert_eq!(response[0]["created_at"], "2026-11-11T00:00:00Z");
    }

    #[test]
    fn merge_route_rejects_target_base_advance_without_mutation() {
        let (_temporary, connection, remote, number, base_sha, head_sha) = fixture_pull();
        let work = remote
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("work");
        git(&work, &["checkout", "main"]);
        std::fs::write(work.join("README.md"), "advanced base\n").unwrap();
        git(&work, &["add", "README.md"]);
        git(&work, &["commit", "-m", "advance base"]);
        git(&work, &["push", "origin", "main"]);
        let advanced_base = git(&remote, &["rev-parse", "refs/heads/main"]);
        assert_ne!(advanced_base, base_sha);

        let request = Request {
            method: "PUT".into(),
            endpoint: format!("repos/fixture/repository/pulls/{number}/merge"),
            input: true,
        };
        let (status, response) = dispatch(
            remote.parent().unwrap().parent().unwrap().parent().unwrap(),
            &connection,
            &request,
            json!({"sha":head_sha,"merge_method":"squash"}),
        )
        .unwrap();

        assert_eq!(status, 409);
        assert!(response["message"].as_str().unwrap().contains("base"));
        let (pull_status, pull) = get_pull(&connection, "fixture", "repository", number).unwrap();
        assert_eq!(pull_status, 200);
        assert_eq!(pull["state"], "open");
        assert_eq!(pull["merged"], false);
        assert_eq!(pull["base"]["sha"], base_sha);
        assert_eq!(
            git(&remote, &["rev-parse", "refs/heads/main"]),
            advanced_base
        );
    }

    #[test]
    fn merge_route_accepts_current_base_with_current_head_check_and_approval() {
        let (_temporary, connection, remote, number, base_sha, head_sha) = fixture_pull();
        let request = Request {
            method: "PUT".into(),
            endpoint: format!("repos/fixture/repository/pulls/{number}/merge"),
            input: true,
        };
        let root = remote.parent().unwrap().parent().unwrap().parent().unwrap();
        let (status, response) = dispatch(
            root,
            &connection,
            &request,
            json!({"sha":head_sha,"merge_method":"squash"}),
        )
        .unwrap();

        assert_eq!(status, 200);
        assert_eq!(response["merged"], true);
        assert_ne!(response["sha"], base_sha);
        let (pull_status, pull) = get_pull(&connection, "fixture", "repository", number).unwrap();
        assert_eq!(pull_status, 200);
        assert_eq!(pull["state"], "closed");
        assert_eq!(pull["merged"], true);
    }
}
