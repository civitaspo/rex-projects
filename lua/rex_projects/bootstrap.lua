local M = {}

local function deadline_seconds(budget)
  if type(budget) == "table" then return budget.seconds end
  return budget
end

local function deadline_now(budget)
  if type(budget) == "table" then return budget.now() end
  return os.time()
end

local function run(exec, argv, started, budget, options)
  -- os.time is whole-second resolution. Subtract one extra second so the
  -- timeout remains safe when setup starts near a second boundary. Rex allows
  -- two seconds after SIGTERM for SIGKILL; reserve both inside the deadline.
  local elapsed = deadline_now(budget) - started
  local remaining = deadline_seconds(budget) - elapsed - 3
  if remaining <= 0 then return nil, "bootstrap deadline reached" end
  local result, err = exec(argv, remaining, options)
  if not result then return nil, err or ("could not start " .. argv[1]) end
  if result.timed_out then return nil, (argv[1] .. " exceeded its bootstrap timeout") end
  if result.code ~= 0 then
    local detail = (result.stderr or ""):gsub("%s+$", "")
    return nil, (argv[1] .. " exited " .. tostring(result.code) .. (detail ~= "" and (": " .. detail) or ""))
  end
  return result
end

local function output(exec, argv, started, budget)
  local result, err = run(exec, argv, started, budget)
  if not result then return nil, err end
  local value = result.stdout or ""
  if value:sub(-2) == "\r\n" then return value:sub(1, -3) end
  if value:sub(-1) == "\n" then return value:sub(1, -2) end
  return value
end

local function valid_absolute(path)
  return type(path) == "string" and path:sub(1, 1) == "/" and not path:find("[%z\r\n]")
end

local function safe_token(value) return type(value) == "string" and value ~= "" and not value:find("[%z\r\n]") end

local function resolve_source(cli, env, exec, started, budget)
  local source
  if cli == nil then return nil, "no developer override" end
  if not safe_token(cli) then return nil, "cli must be an absolute executable path or a PATH command name" end
  if cli:sub(1, 1) == "/" then
    source = cli
  elseif cli:find("/", 1, true) then
    return nil, "relative cli paths with directory components are not supported"
  else
    local search = env("PATH")
    if type(search) ~= "string" or search == "" then return nil, "PATH is empty; use an absolute cli path" end
    local paths = {}
    for part in (search .. ":"):gmatch("(.-):") do
      if part == "" then return nil, "PATH contains an empty component" end
      paths[#paths + 1] = part
    end
    for _, directory in ipairs(paths) do
      local candidate = directory .. "/" .. cli
      local exists = run(exec, { "/bin/test", "-f", candidate }, started, budget)
      local executable = exists and run(exec, { "/bin/test", "-x", candidate }, started, budget)
      if executable then
        source = candidate
        break
      end
    end
    if not source then return nil, ("could not find executable `" .. cli .. "` on PATH") end
  end
  local canonical, err = output(exec, { "realpath", source }, started, budget)
  if not canonical then return nil, "cannot resolve cli path: " .. err end
  local regular, regular_error = run(exec, { "/bin/test", "-f", canonical }, started, budget)
  if not regular then return nil, "cli target is not a regular file: " .. (regular_error or canonical) end
  local executable, executable_error = run(exec, { "/bin/test", "-x", canonical }, started, budget)
  if not executable then return nil, "cli target is not executable: " .. (executable_error or canonical) end
  return canonical
end

local function digest(path, exec, started, budget)
  local value, err = output(exec, { "shasum", "-a", "256", path }, started, budget)
  if not value then return nil, err end
  local hash = value:match("^([0-9a-fA-F]+)")
  if not hash or #hash ~= 64 then return nil, "shasum returned an invalid SHA-256 digest" end
  return hash:lower()
end

local function path_exists(path, exec, started, budget)
  if run(exec, { "/bin/test", "-e", path }, started, budget) then return true end
  return run(exec, { "/bin/test", "-L", path }, started, budget) ~= nil
end

local function is_symlink(path, exec, started, budget)
  return run(exec, { "/bin/test", "-L", path }, started, budget) ~= nil
end

local function file_identity(path, exec, started, budget)
  local value, bsd_error = output(exec, { "stat", "-L", "-f", "%d:%i:%z:%m", path }, started, budget)
  if value then return value end
  local linux_value, linux_error = output(exec, { "stat", "-L", "-c", "%d:%i:%s:%Y", path }, started, budget)
  if linux_value then return linux_value end
  return nil, "stat failed with BSD and GNU formats: " .. tostring(bsd_error) .. "; " .. tostring(linux_error)
end

local function inside(root, path)
  local canonical_root = root:gsub("/+$", "")
  if canonical_root == "" or canonical_root == "/" then return path:sub(1, 1) == "/" and path ~= canonical_root end
  return path:sub(1, #canonical_root + 1) == (canonical_root .. "/")
end

local function cache_root(env, exec, started, budget)
  local base = env("XDG_CACHE_HOME")
  if base == nil or base == "" then
    local home = env("HOME")
    if not valid_absolute(home) then return nil, "HOME is unset or not absolute; set XDG_CACHE_HOME" end
    base = home .. "/.cache"
  elseif not valid_absolute(base) then
    return nil, "XDG_CACHE_HOME must be an absolute path"
  end
  local _, base_error = run(exec, { "mkdir", "-p", base }, started, budget)
  if base_error then return nil, base_error end
  local canonical_base, base_realpath_error = output(exec, { "realpath", base }, started, budget)
  if not canonical_base then return nil, "cannot resolve cache base: " .. tostring(base_realpath_error) end
  local root_path = base .. "/rex-projects"
  if is_symlink(root_path, exec, started, budget) then
    return nil, "cache root is a symlink; it was preserved: " .. root_path
  end
  local root_exists = path_exists(root_path, exec, started, budget)
  if not root_exists then
    local _, err = run(exec, { "mkdir", root_path }, started, budget)
    if err and not path_exists(root_path, exec, started, budget) then return nil, err end
  end
  local canonical, canonical_error = output(exec, { "realpath", root_path }, started, budget)
  if not canonical then return nil, "cannot resolve cache root: " .. tostring(canonical_error) end
  if not inside(canonical_base, canonical) then
    return nil, "cache root resolves outside XDG_CACHE_HOME: " .. canonical
  end
  local _, err = run(exec, { "chmod", "700", canonical }, started, budget)
  if err then return nil, err end
  return canonical
end

local function managed_directory(root, path, exec, started, budget)
  if is_symlink(path, exec, started, budget) then
    return nil, "managed cache ancestor is a symlink; it was preserved: " .. path
  end
  if not path_exists(path, exec, started, budget) then
    local _, mkdir_error = run(exec, { "mkdir", path }, started, budget)
    if mkdir_error and not path_exists(path, exec, started, budget) then return nil, mkdir_error end
  end
  local canonical, realpath_error = output(exec, { "realpath", path }, started, budget)
  if not canonical then return nil, realpath_error end
  if not inside(root, canonical) then return nil, "managed cache ancestor escaped its root: " .. canonical end
  local _, chmod_error = run(exec, { "chmod", "700", canonical }, started, budget)
  if chmod_error then return nil, chmod_error end
  return canonical
end

local function cleanup_temporary(directory, path, exec, started, budget)
  local file_error
  if path then
    _, file_error = run(exec, { "rm", "-f", path }, started, budget)
  end
  local _, directory_error = run(exec, { "rmdir", directory }, started, budget)
  return file_error or directory_error
end

local function create_temporary_directory(parent, exec, started, budget)
  local template = parent .. "/.rex-projects.XXXXXXXX"
  local directory, err = output(exec, { "mktemp", "-d", template }, started, budget)
  if not directory then return nil, err end
  local canonical, realpath_error = output(exec, { "realpath", directory }, started, budget)
  if not canonical then return nil, realpath_error end
  if not inside(parent, canonical) then return nil, "temporary directory escaped its cache parent: " .. canonical end
  return canonical
end

local function validate_version_info(value, expected_version, expected_target, protocol)
  if type(value) ~= "table" then return nil, "version --json returned invalid JSON metadata" end
  -- cli_protocol versions the complete version --json shape; there is no second bootstrap-schema counter.
  local allowed = {
    name = true,
    version = true,
    target = true,
    cli_protocol = true,
    database_schema = true,
    source_revision = true,
    dirty = true,
  }
  for key in pairs(value) do
    if not allowed[key] then
      return nil, "version --json contains a field not defined by CLI protocol " .. tostring(protocol)
    end
  end
  if value.name ~= "rex-projects" or type(value.version) ~= "string" or value.version == "" then
    return nil, "version --json returned invalid CLI identity"
  end
  if expected_version ~= nil and value.version ~= expected_version then
    return nil, "CLI version does not match the selected release"
  end
  if
    type(value.target) ~= "string"
    or value.target == ""
    or (expected_target ~= nil and value.target ~= expected_target)
  then
    return nil, "CLI target does not match the selected release"
  end
  if
    type(value.cli_protocol) ~= "number"
    or value.cli_protocol < 1
    or value.cli_protocol ~= math.floor(value.cli_protocol)
    or value.cli_protocol ~= protocol
  then
    return nil, "CLI target or protocol does not match the selected release"
  end
  if
    type(value.database_schema) ~= "number"
    or value.database_schema < 1
    or value.database_schema ~= math.floor(value.database_schema)
    or type(value.dirty) ~= "boolean"
  then
    return nil, "CLI version metadata is missing database schema or build identity"
  end
  if
    value.source_revision ~= nil
    and (
      type(value.source_revision) ~= "string"
      or not value.source_revision:match("^[%da-fA-F]+$")
      or #value.source_revision ~= 40
    )
  then
    return nil, "CLI version metadata has an invalid source revision"
  end
  return value
end

M.validate_version_info = validate_version_info

local function probe(path, expected_version, expected_target, protocol, decode, exec, started, budget)
  local result, err = run(exec, { path, "version", "--json" }, started, budget)
  if not result then return nil, err end
  local value, decode_error = decode(result.stdout or "")
  if type(value) ~= "table" then return nil, "version --json returned invalid JSON: " .. tostring(decode_error) end
  return validate_version_info(value, expected_version, expected_target, protocol)
end

local function publish_verified(
  temporary,
  final_path,
  expected_digest,
  expected_version,
  target,
  protocol,
  decode,
  exec,
  started,
  budget
)
  if is_symlink(final_path, exec, started, budget) then
    return nil, "cache destination is a symlink; it was preserved: " .. final_path
  end
  local linked, link_error = run(exec, { "link", temporary, final_path }, started, budget)
  if not linked and not path_exists(final_path, exec, started, budget) then
    return nil, "atomic cache publication failed: " .. tostring(link_error)
  end
  if is_symlink(final_path, exec, started, budget) then
    return nil, "cache destination became a symlink during publication; it was preserved: " .. final_path
  end
  local published_digest, digest_error = digest(final_path, exec, started, budget)
  if published_digest ~= expected_digest then
    return nil,
      "existing cache winner failed digest verification; it was preserved"
        .. (digest_error and (": " .. digest_error) or "")
  end
  local value, probe_error = probe(final_path, expected_version, target, protocol, decode, exec, started, budget)
  if not value then return nil, probe_error end
  return value
end

local target_info

local function snapshot_developer(cli, protocol, env, decode, exec, budget, started)
  local target, target_error = target_info(exec, started, budget)
  if not target then return nil, target_error end
  local source, source_error = resolve_source(cli, env, exec, started, budget)
  if not source then return nil, source_error end
  local source_digest, digest_error = digest(source, exec, started, budget)
  if not source_digest then return nil, digest_error end
  local before_identity, identity_error = file_identity(source, exec, started, budget)
  if not before_identity then
    return nil, "cannot inspect cli source identity: " .. tostring(identity_error or source)
  end
  local root, root_error = cache_root(env, exec, started, budget)
  if not root then return nil, root_error end
  local dev_directory, dev_error = managed_directory(root, root .. "/dev", exec, started, budget)
  if not dev_directory then return nil, dev_error end
  local canonical_target, dir_error =
    managed_directory(root, dev_directory .. "/" .. source_digest, exec, started, budget)
  if not canonical_target then return nil, dir_error end
  local final_path = canonical_target .. "/rex-projects"
  if is_symlink(final_path, exec, started, budget) then
    return nil, "developer cache entry is a symlink; it was preserved at " .. final_path
  end
  local final_digest = digest(final_path, exec, started, budget)
  if final_digest == source_digest then
    local value, probe_error = probe(final_path, nil, target.triple, protocol, decode, exec, started, budget)
    if not value then return nil, probe_error end
    return { cli_path = final_path, digest = source_digest, version = value, source = "developer" }
  end
  if path_exists(final_path, exec, started, budget) then
    return nil, "an existing developer snapshot failed digest verification; it was preserved at " .. final_path
  end
  local temporary_directory, temporary_error = create_temporary_directory(canonical_target, exec, started, budget)
  if not temporary_directory then return nil, temporary_error end
  local temporary = temporary_directory .. "/rex-projects"
  local before_copy_digest, before_copy_error = digest(source, exec, started, budget)
  local copy_result, copy_error = run(exec, { "cp", "-n", "-L", source, temporary }, started, budget)
  local after_identity = file_identity(source, exec, started, budget)
  local after_digest = digest(source, exec, started, budget)
  local copied_digest = digest(temporary, exec, started, budget)
  if
    not copy_result
    or before_copy_digest ~= source_digest
    or after_identity ~= before_identity
    or after_digest ~= source_digest
    or copied_digest ~= source_digest
  then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, copy_error or before_copy_error or "cli source changed while it was being snapshotted"
  end
  local _, executable_error = run(exec, { "chmod", "700", temporary }, started, budget)
  if executable_error then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, executable_error
  end
  local value, probe_error = probe(temporary, nil, target.triple, protocol, decode, exec, started, budget)
  if not value then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, probe_error
  end
  local published_value, publish_error =
    publish_verified(temporary, final_path, source_digest, nil, target.triple, protocol, decode, exec, started, budget)
  if not published_value then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, publish_error
  end
  cleanup_temporary(temporary_directory, temporary, exec, started, budget)
  return { cli_path = final_path, digest = source_digest, version = published_value, source = "developer" }
end

target_info = function(exec, started, budget)
  local system, system_error = output(exec, { "uname", "-s" }, started, budget)
  local machine, machine_error = output(exec, { "uname", "-m" }, started, budget)
  if not system or not machine then return nil, system_error or machine_error or "cannot identify host platform" end
  local targets = {
    ["Darwin:aarch64"] = { name = "macos-aarch64", triple = "aarch64-apple-darwin" },
    ["Darwin:arm64"] = { name = "macos-aarch64", triple = "aarch64-apple-darwin" },
    ["Darwin:x86_64"] = { name = "macos-x86_64", triple = "x86_64-apple-darwin" },
    ["Linux:aarch64"] = { name = "linux-aarch64", triple = "aarch64-unknown-linux-gnu" },
    ["Linux:arm64"] = { name = "linux-aarch64", triple = "aarch64-unknown-linux-gnu" },
    ["Linux:x86_64"] = { name = "linux-x86_64", triple = "x86_64-unknown-linux-gnu" },
  }
  local target = targets[system .. ":" .. machine]
  if not target then return nil, ("unsupported Rex host target " .. system .. "/" .. machine) end
  return target
end

local function install_release(pin, env, decode, exec, budget, started)
  local target, target_error = target_info(exec, started, budget)
  if not target then return nil, target_error end
  local asset = pin.targets[target.name]
  if not asset then
    return nil,
      "no reviewed release asset is pinned for "
        .. target.name
        .. '; set setup({ cli = "/absolute/path" }) to use a development build'
  end
  if
    type(asset) ~= "table"
    or type(asset.url) ~= "string"
    or asset.url:sub(1, 8) ~= "https://"
    or asset.url:find("[%z\r\n]")
    or type(asset.sha256) ~= "string"
    or not asset.sha256:match("^[0-9a-f]+$")
    or #asset.sha256 ~= 64
  then
    return nil, "release pin for " .. target.name .. " is invalid"
  end
  local root, root_error = cache_root(env, exec, started, budget)
  if not root then return nil, root_error end
  local bin_directory, bin_error = managed_directory(root, root .. "/bin", exec, started, budget)
  if not bin_directory then return nil, bin_error end
  local version_directory, version_error =
    managed_directory(root, bin_directory .. "/" .. pin.version, exec, started, budget)
  if not version_directory then return nil, version_error end
  local canonical_folder, folder_error =
    managed_directory(root, version_directory .. "/" .. target.name, exec, started, budget)
  if not canonical_folder then return nil, folder_error end
  local final_path = canonical_folder .. "/rex-projects"
  if is_symlink(final_path, exec, started, budget) then
    return nil, "release cache entry is a symlink; it was preserved at " .. final_path
  end
  local existing_digest = digest(final_path, exec, started, budget)
  if existing_digest == asset.sha256 then
    local value, probe_error =
      probe(final_path, pin.version, target.triple, pin.protocol, decode, exec, started, budget)
    if not value then return nil, probe_error end
    return { cli_path = final_path, digest = asset.sha256, version = value, source = "release" }
  end
  if path_exists(final_path, exec, started, budget) then
    return nil, "an existing release cache entry failed digest verification; it was preserved at " .. final_path
  end
  local temporary_directory, temporary_error = create_temporary_directory(canonical_folder, exec, started, budget)
  if not temporary_directory then return nil, temporary_error end
  local temporary = temporary_directory .. "/rex-projects"
  local _, download_error = run(exec, {
    "curl",
    "--disable",
    "--fail",
    "--location",
    "--proto",
    "=https",
    "--proto-redir",
    "=https",
    "--connect-timeout",
    "3",
    "--max-time",
    "15",
    "--max-filesize",
    "104857600",
    "--output",
    temporary,
    asset.url,
  }, started, budget)
  if download_error then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, download_error
  end
  local actual_digest, digest_error = digest(temporary, exec, started, budget)
  if actual_digest ~= asset.sha256 then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, digest_error or "downloaded release SHA-256 does not match the reviewed Lua pin"
  end
  local _, chmod_error2 = run(exec, { "chmod", "700", temporary }, started, budget)
  if chmod_error2 then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, chmod_error2
  end
  local value, probe_error = probe(temporary, pin.version, target.triple, pin.protocol, decode, exec, started, budget)
  if not value then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, probe_error
  end
  local published_value, publish_error = publish_verified(
    temporary,
    final_path,
    asset.sha256,
    pin.version,
    target.triple,
    pin.protocol,
    decode,
    exec,
    started,
    budget
  )
  if not published_value then
    cleanup_temporary(temporary_directory, temporary, exec, started, budget)
    return nil, publish_error
  end
  cleanup_temporary(temporary_directory, temporary, exec, started, budget)
  return { cli_path = final_path, digest = asset.sha256, version = published_value, source = "release" }
end

function M.resolve(options, pin, env, decode, exec, budget, clock)
  options = options or {}
  if type(options) ~= "table" or (options.cli ~= nil and type(options.cli) ~= "string") then
    return nil, "setup options must be a table with an optional string cli"
  end
  if type(exec) ~= "function" or type(env) ~= "function" or type(decode) ~= "function" then
    return nil, "bootstrap requires Rex environment, JSON, and process adapters"
  end
  if
    type(pin) ~= "table"
    or type(pin.protocol) ~= "number"
    or pin.protocol < 1
    or pin.protocol ~= math.floor(pin.protocol)
  then
    return nil, "embedded CLI protocol pin is invalid"
  end
  budget = budget or 25
  if budget ~= 4 and budget ~= 25 then
    return nil, "bootstrap budget must be 4 seconds during setup or 25 seconds in the retry Action"
  end
  local deadline = { seconds = budget, now = clock or os.time }
  local started = deadline.now()
  if options.cli ~= nil then
    return snapshot_developer(options.cli, pin.protocol, env, decode, exec, deadline, started)
  end
  if
    type(pin) ~= "table"
    or type(pin.version) ~= "string"
    or not pin.version:match("^[%w%.%-]+$")
    or pin.version:find("..", 1, true)
    or type(pin.protocol) ~= "number"
    or type(pin.targets) ~= "table"
  then
    return nil, "embedded release pin is invalid"
  end
  return install_release(pin, env, decode, exec, deadline, started)
end

return M
