local M = {}
local invocation_sequence = 0

local function run(exec, argv, started, budget, options, cleanup)
  local elapsed = os.time() - started
  local remaining = budget - elapsed
  local reserve = cleanup and 0 or 2
  if remaining <= reserve then return nil, "bootstrap deadline reached" end
  local result, err = exec(argv, remaining - reserve, options)
  if not result then return nil, err or ("could not start " .. argv[1]) end
  if result.timed_out then return nil, (argv[1] .. " exceeded its bootstrap timeout") end
  if result.code ~= 0 then
    local detail = (result.stderr or ""):gsub("%s+$", "")
    return nil, (argv[1] .. " exited " .. tostring(result.code) .. (detail ~= "" and (": " .. detail) or ""))
  end
  return result
end

local function output(exec, argv, started, budget, cleanup)
  local result, err = run(exec, argv, started, budget, nil, cleanup)
  if not result then return nil, err end
  return (result.stdout or ""):gsub("%s+$", "")
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
  local value = output(exec, { "stat", "-L", "-f", "%d:%i:%z:%m", path }, started, budget)
  if not value then value = output(exec, { "stat", "-L", "-c", "%d:%i:%s:%Y", path }, started, budget) end
  return value
end

local function cache_root(env, exec, started, budget)
  local root = env("XDG_CACHE_HOME")
  if root == nil or root == "" then
    local home = env("HOME")
    if not valid_absolute(home) then return nil, "HOME is unset or not absolute; set XDG_CACHE_HOME" end
    root = home .. "/.cache"
  elseif not valid_absolute(root) then
    return nil, "XDG_CACHE_HOME must be an absolute path"
  end
  root = root .. "/rex-projects"
  local _, err = run(exec, { "mkdir", "-p", root }, started, budget)
  if err then return nil, err end
  local canonical, canonical_error = output(exec, { "realpath", root }, started, budget)
  if not canonical then return nil, "cannot resolve cache root: " .. canonical_error end
  local _, chmod_error = run(exec, { "chmod", "700", canonical }, started, budget)
  if chmod_error then return nil, chmod_error end
  return canonical
end

local function inside(root, path) return path:sub(1, #root + 1) == (root .. "/") end

local function invocation_token()
  invocation_sequence = invocation_sequence + 1
  local address = tostring({}):match("0x[%da-fA-F]+") or "address-unknown"
  return table.concat({ os.date("!%Y%m%dT%H%M%SZ"), tostring(os.clock()), address, tostring(invocation_sequence) }, "-")
end

local function encode_owner(owner, encode)
  local payload, err = encode(owner)
  if type(payload) ~= "string" then return nil, "could not encode bootstrap owner receipt: " .. tostring(err) end
  return payload
end

local function write_owner(lock, owner, encode, exec, started, budget)
  local payload, encode_error = encode_owner(owner, encode)
  if not payload then return nil, encode_error end
  local path = lock.path .. "/owner.json"
  local result, err = run(exec, { "tee", path }, started, budget, {
    stdin = payload,
    stdout = false,
    text = true,
  })
  if not result then return nil, err end
  local _, chmod_error = run(exec, { "chmod", "600", path }, started, budget)
  if chmod_error then return nil, chmod_error end
  return true
end

local function acquire_lock(root, key, owner, encode, decode, exec, started, budget)
  local lock_root = root .. "/.locks"
  local _, err = run(exec, { "mkdir", "-p", lock_root }, started, budget)
  if err then return nil, err end
  local canonical, canonical_error = output(exec, { "realpath", lock_root }, started, budget)
  if not canonical or not inside(root, canonical) then
    return nil, "lock path is outside the owned cache root: " .. (canonical_error or canonical)
  end
  local _, chmod_error = run(exec, { "chmod", "700", canonical }, started, budget)
  if chmod_error then return nil, chmod_error end
  local path = canonical .. "/" .. key .. ".lock"
  local _, lock_error = run(exec, { "mkdir", path }, started, budget)
  if lock_error then
    return nil,
      "bootstrap lock is busy or stale at "
        .. path
        .. "; inspect "
        .. path
        .. "/owner.json and verify the recorded Rex process is stopped before manually removing this lock; setup never steals locks by age"
  end
  local _, lock_chmod_error = run(exec, { "chmod", "700", path }, started, budget)
  if lock_chmod_error then
    -- The successful atomic mkdir is ours; rmdir only removes it if still empty.
    run(exec, { "rmdir", path }, started, budget, nil, true)
    return nil, lock_chmod_error
  end
  local lock = { path = path, token = invocation_token() }
  owner.invocation_token = lock.token
  local written, receipt_error = write_owner(lock, owner, encode, exec, started, budget)
  if not written then
    -- Never remove a receipt we cannot prove is ours. An empty lock directory
    -- can still be safely removed after the atomic mkdir above.
    local receipt = output(exec, { "cat", path .. "/owner.json" }, started, budget, true)
    local decoded = receipt and decode(receipt)
    if type(decoded) == "table" and decoded.invocation_token == lock.token then
      run(exec, { "rm", path .. "/owner.json" }, started, budget, nil, true)
    end
    run(exec, { "rmdir", path }, started, budget, nil, true)
    return nil, receipt_error
  end
  return lock
end

local function lock_owner(kind, binary_digest, version, target, protocol, budget, context, started)
  local server = context and context.server
  if type(server) ~= "string" or server == "" then
    server = "unknown: Rex config-load API does not expose server identity"
  end
  return {
    receipt_version = 1,
    source_kind = kind,
    source_digest = binary_digest,
    expected_version = version or "verified development build",
    target = target,
    cli_protocol = protocol,
    created_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    created_epoch = os.time(),
    deadline_at = os.date("!%Y-%m-%dT%H:%M:%SZ", started + budget),
    deadline_epoch = started + budget,
    rex_server_identity = server,
    rex_process_identity = "unknown: documented Rex Lua API does not expose the server process ID",
    process_identity_note = "No PID or process-start identity is inferred from undocumented environment or APIs.",
  }
end

local function release_lock(lock, decode, exec, started, budget)
  local owner_json, read_error = output(exec, { "cat", lock.path .. "/owner.json" }, started, budget, true)
  if not owner_json then
    return "cannot verify bootstrap lock owner receipt at " .. lock.path .. ": " .. tostring(read_error)
  end
  local owner, decode_error = decode(owner_json)
  if type(owner) ~= "table" or owner.invocation_token ~= lock.token then
    return "bootstrap lock owner receipt changed at "
      .. lock.path
      .. "; preserved it for inspection: "
      .. tostring(decode_error)
  end
  local _, receipt_error = run(exec, { "rm", lock.path .. "/owner.json" }, started, budget, nil, true)
  if receipt_error then return receipt_error end
  local _, lock_error = run(exec, { "rmdir", lock.path }, started, budget, nil, true)
  return lock_error
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

local target_info

local function snapshot_developer(cli, protocol, env, decode, encode, exec, budget, owner_context)
  local started = os.time()
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
  local key = "dev-" .. source_digest
  local owner = lock_owner("developer", source_digest, nil, target.triple, protocol, budget, owner_context, started)
  local lock, lock_error = acquire_lock(root, key, owner, encode, decode, exec, started, budget)
  if not lock then return nil, lock_error end
  local cache_directory = root .. "/dev/" .. source_digest
  local _, dir_error = run(exec, { "mkdir", "-p", cache_directory }, started, budget)
  local canonical_target = not dir_error and output(exec, { "realpath", cache_directory }, started, budget)
  if dir_error or not canonical_target or not inside(root, canonical_target) then
    release_lock(lock, decode, exec, started, budget)
    return nil, dir_error or "developer cache path escaped the owned cache root"
  end
  local _, perm_error = run(exec, { "chmod", "700", canonical_target }, started, budget)
  if perm_error then
    release_lock(lock, decode, exec, started, budget)
    return nil, perm_error
  end
  local final_path = canonical_target .. "/rex-projects"
  if is_symlink(final_path, exec, started, budget) then
    release_lock(lock, decode, exec, started, budget)
    return nil, "developer cache entry is a symlink; it was preserved at " .. final_path
  end
  local final_digest = digest(final_path, exec, started, budget)
  if final_digest == source_digest then
    local value, probe_error = probe(final_path, nil, target.triple, protocol, decode, exec, started, budget)
    local release_error = release_lock(lock, decode, exec, started, budget)
    if not value then return nil, probe_error end
    if release_error then return nil, release_error end
    return { cli_path = final_path, digest = source_digest, version = value, source = "developer" }
  end
  if path_exists(final_path, exec, started, budget) then
    release_lock(lock, decode, exec, started, budget)
    return nil, "an existing developer snapshot failed digest verification; it was preserved at " .. final_path
  end
  local temporary = canonical_target
    .. "/.rex-projects-"
    .. tostring(os.time())
    .. "-"
    .. tostring({}):gsub("table: ", "")
  local exists = run(exec, { "/bin/test", "-e", temporary }, started, budget)
  if exists then
    release_lock(lock, decode, exec, started, budget)
    return nil, "temporary developer snapshot name already exists"
  end
  local before_copy_digest, before_copy_error = digest(source, exec, started, budget)
  local copy_result, copy_error = run(exec, { "cp", "-L", source, temporary }, started, budget)
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
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, copy_error or before_copy_error or "cli source changed while it was being snapshotted"
  end
  local _, executable_error = run(exec, { "chmod", "700", temporary }, started, budget)
  if executable_error then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, executable_error
  end
  local value, probe_error = probe(temporary, nil, target.triple, protocol, decode, exec, started, budget)
  if not value then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, probe_error
  end
  local _, publish_error = run(exec, { "mv", "-n", temporary, final_path }, started, budget)
  if publish_error then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, publish_error
  end
  local published_digest = digest(final_path, exec, started, budget)
  local published_value, published_probe_error =
    probe(final_path, nil, target.triple, protocol, decode, exec, started, budget)
  local release_error = release_lock(lock, decode, exec, started, budget)
  if published_digest ~= source_digest or not published_value then
    return nil, published_probe_error or "published developer snapshot failed verification"
  end
  if release_error then return nil, release_error end
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

local function install_release(pin, env, decode, encode, exec, budget, owner_context)
  local started = os.time()
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
    type(asset.url) ~= "string"
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
  local key = "release-" .. pin.version .. "-" .. target.name
  local owner =
    lock_owner("release", asset.sha256, pin.version, target.triple, pin.protocol, budget, owner_context, started)
  local lock, lock_error = acquire_lock(root, key, owner, encode, decode, exec, started, budget)
  if not lock then return nil, lock_error end
  local folder = root .. "/bin/" .. pin.version .. "/" .. target.name
  local _, dir_error = run(exec, { "mkdir", "-p", folder }, started, budget)
  local canonical_folder = not dir_error and output(exec, { "realpath", folder }, started, budget)
  if dir_error or not canonical_folder or not inside(root, canonical_folder) then
    release_lock(lock, decode, exec, started, budget)
    return nil, dir_error or "release cache path escaped the owned cache root"
  end
  local _, chmod_error = run(exec, { "chmod", "700", canonical_folder }, started, budget)
  if chmod_error then
    release_lock(lock, decode, exec, started, budget)
    return nil, chmod_error
  end
  local final_path = canonical_folder .. "/rex-projects"
  if is_symlink(final_path, exec, started, budget) then
    release_lock(lock, decode, exec, started, budget)
    return nil, "release cache entry is a symlink; it was preserved at " .. final_path
  end
  local existing_digest = digest(final_path, exec, started, budget)
  if existing_digest == asset.sha256 then
    local value, probe_error =
      probe(final_path, pin.version, target.triple, pin.protocol, decode, exec, started, budget)
    local release_error = release_lock(lock, decode, exec, started, budget)
    if not value then return nil, probe_error end
    if release_error then return nil, release_error end
    return { cli_path = final_path, digest = asset.sha256, version = value, source = "release" }
  end
  if path_exists(final_path, exec, started, budget) then
    release_lock(lock, decode, exec, started, budget)
    return nil, "an existing release cache entry failed digest verification; it was preserved at " .. final_path
  end
  local temporary = canonical_folder
    .. "/.rex-projects-"
    .. tostring(os.time())
    .. "-"
    .. tostring({}):gsub("table: ", "")
  local exists = run(exec, { "/bin/test", "-e", temporary }, started, budget)
  if exists then
    release_lock(lock, decode, exec, started, budget)
    return nil, "temporary release path already exists"
  end
  local _, download_error = run(exec, {
    "curl",
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
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, download_error
  end
  local actual_digest, digest_error = digest(temporary, exec, started, budget)
  if actual_digest ~= asset.sha256 then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, digest_error or "downloaded release SHA-256 does not match the reviewed Lua pin"
  end
  local _, chmod_error2 = run(exec, { "chmod", "700", temporary }, started, budget)
  if chmod_error2 then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, chmod_error2
  end
  local value, probe_error = probe(temporary, pin.version, target.triple, pin.protocol, decode, exec, started, budget)
  if not value then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, probe_error
  end
  local _, publish_error = run(exec, { "mv", "-n", temporary, final_path }, started, budget)
  if publish_error then
    run(exec, { "rm", "-f", temporary }, started, budget, nil, true)
    release_lock(lock, decode, exec, started, budget)
    return nil, publish_error
  end
  local published_digest = digest(final_path, exec, started, budget)
  local published_value, published_probe_error =
    probe(final_path, pin.version, target.triple, pin.protocol, decode, exec, started, budget)
  local release_error = release_lock(lock, decode, exec, started, budget)
  if published_digest ~= asset.sha256 or not published_value then
    return nil, published_probe_error or "published release cache failed verification"
  end
  if release_error then return nil, release_error end
  return { cli_path = final_path, digest = asset.sha256, version = published_value, source = "release" }
end

function M.resolve(options, pin, env, decode, encode, exec, budget, owner_context)
  options = options or {}
  if type(options) ~= "table" or (options.cli ~= nil and type(options.cli) ~= "string") then
    return nil, "setup options must be a table with an optional string cli"
  end
  if
    type(exec) ~= "function"
    or type(env) ~= "function"
    or type(decode) ~= "function"
    or type(encode) ~= "function"
  then
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
  if options.cli ~= nil then
    return snapshot_developer(options.cli, pin.protocol, env, decode, encode, exec, budget, owner_context)
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
  return install_release(pin, env, decode, encode, exec, budget, owner_context)
end

return M
