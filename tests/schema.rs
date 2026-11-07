use rex_projects::cli::schema_documents;

#[test]
fn checked_in_schemas_match_the_rust_boundary_types() {
    for (name, generated) in schema_documents() {
        let mut generated = serde_json::to_string_pretty(&generated).unwrap();
        generated.push('\n');
        let checked_in = match name {
            "config" => include_str!("../schemas/config.v1.json"),
            "profile" => include_str!("../schemas/profile.v1.json"),
            "request" => include_str!("../schemas/request.v1.json"),
            "response" => include_str!("../schemas/response.v1.json"),
            "version" => include_str!("../schemas/version.v1.json"),
            _ => unreachable!("schema_documents lists known names only"),
        };
        assert_eq!(generated, checked_in, "schema `{name}` is stale");
    }
}
