use std::fs;
use std::path::Path;

use mlua::{Lua, Table};

fn run_lua_test(lua: &Lua, root: &Path, relative_path: &str) -> mlua::Result<()> {
    let package: Table = lua.globals().get("package")?;
    let lua_dir = root.join("lua");
    package.set(
        "path",
        format!(
            "{};{}/init.lua;{}",
            lua_dir.join("?.lua").display(),
            lua_dir.display(),
            package.get::<String>("path")?
        ),
    )?;

    let path = root.join(relative_path);
    let source = fs::read_to_string(&path).map_err(mlua::Error::external)?;
    lua.load(&source)
        .set_name(path.display().to_string())
        .exec()
}

#[test]
fn lua_51_contract_scripts_pass() -> mlua::Result<()> {
    let lua = Lua::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for script in [
        "tests/lua/bootstrap_version_contract.lua",
        "tests/lua/bootstrap_spec.lua",
        "tests/lua/runtime_details_spec.lua",
    ] {
        run_lua_test(&lua, root, script)?;
    }

    Ok(())
}
