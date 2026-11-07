//! Regenerate the checked-in, role-specific result schemas from Rust contracts.
use std::path::PathBuf;

use rex_projects::domain::types::Role;
use rex_projects::roles::{result_schema, role_name};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("schemas/agent-results"));
    std::fs::create_dir_all(&output)?;
    for role in Role::ALL {
        let mut contents = serde_json::to_string_pretty(&result_schema(role))?;
        contents.push('\n');
        std::fs::write(
            output.join(format!("{}-v1.json", role_name(role))),
            contents,
        )?;
    }
    Ok(())
}
