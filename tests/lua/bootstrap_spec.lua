package.path = "./lua/?.lua;./lua/?/init.lua;" .. package.path

local Bootstrap = require("rex_projects.bootstrap")
local hash = string.rep("a", 64)
local revision = string.rep("b", 40)

local function check(condition, message) return assert(condition, message or "expected condition to be true") end

local function version_info(overrides)
  local value = {
    name = "rex-projects",
    version = "0.1.0-dev",
    target = "aarch64-apple-darwin",
    cli_protocol = 1,
    database_schema = 1,
    source_revision = revision,
    dirty = false,
  }
  for key, override in pairs(overrides or {}) do
    value[key] = override
  end
  return value
end

local function success(stdout) return { code = 0, stdout = stdout or "", stderr = "", timed_out = false } end

local function failure(stderr) return { code = 1, stdout = "", stderr = stderr or "fixture failure", timed_out = false } end

local function fake_world(options)
  options = options or {}
  local world = {
    files = {
      [options.source_path or ((options.path_dir or "/dev") .. "/rex-projects")] = {
        digest = hash,
        identity = "1:2:3:4",
        binary = true,
        executable = options.source_executable ~= false,
      },
    },
    directories = { ["/cache"] = true, ["/dev"] = true },
    symlinks = {},
    commands = {},
    version = version_info(options.version_overrides),
    encoded_owner = nil,
    source_copy_count = 0,
  }

  local function exists(path)
    return world.files[path] ~= nil or world.directories[path] ~= nil or world.symlinks[path] ~= nil
  end

  local function cli_version(path)
    if options.cli_times_out then return { code = -1, stdout = "", stderr = "", timed_out = true } end
    if world.files[path] and world.files[path].binary then return success("version-json") end
    return failure("not an executable fixture")
  end

  function world.exec(argv, timeout, exec_options)
    local command = argv[1]
    world.commands[#world.commands + 1] = { argv = argv, timeout = timeout, options = exec_options }
    if options.missing_command == command then return nil, "missing helper " .. command end
    if command == "uname" and argv[2] == "-s" then return success("Darwin\n") end
    if command == "uname" and argv[2] == "-m" then return success("arm64\n") end
    if command == "realpath" then
      local path = argv[2]
      if world.symlinks[path] then path = world.symlinks[path] end
      if exists(path) then return success(path .. "\n") end
      return failure("path does not exist")
    end
    if command == "/bin/test" then
      local flag, path = argv[2], argv[3]
      if flag == "-f" then return world.files[path] and success() or failure() end
      if flag == "-x" then
        return world.files[path] and world.files[path].executable ~= false and success() or failure()
      end
      if flag == "-e" then return exists(path) and success() or failure() end
      if flag == "-L" then return world.symlinks[path] and success() or failure() end
      return failure("unsupported test flag")
    end
    if command == "stat" then
      local path = argv[#argv]
      local file = world.files[path]
      return file and success(file.identity .. "\n") or failure("missing file")
    end
    if command == "shasum" then
      local file = world.files[argv[#argv]]
      return file and success(file.digest .. "  " .. argv[#argv] .. "\n") or failure("missing file")
    end
    if command == "mkdir" then
      local path = argv[#argv]
      if argv[2] == "-p" then
        world.directories[path] = true
        return success()
      end
      if world.directories[path] or world.files[path] or world.symlinks[path] then return failure("already exists") end
      world.directories[path] = true
      if options.on_lock_created and path:match("%.lock$") then options.on_lock_created() end
      return success()
    end
    if command == "chmod" then
      local mode, path = argv[2], argv[3]
      if world.files[path] then world.files[path].mode = mode end
      if world.directories[path] then world.directories[path .. "#mode"] = mode end
      return exists(path) and success() or failure("missing path")
    end
    if command == "tee" then
      local path = argv[2]
      world.files[path] = { content = exec_options.stdin, identity = "receipt", digest = "receipt" }
      return success()
    end
    if command == "cat" then
      local file = world.files[argv[2]]
      return file and success(file.content) or failure("missing receipt")
    end
    if command == "cp" then
      local source, destination = argv[3], argv[4]
      local file = world.files[source]
      if not file then return failure("missing source") end
      world.files[destination] = {
        digest = file.digest,
        identity = file.identity,
        binary = file.binary,
        executable = true,
        mode = "644",
      }
      world.source_copy_count = world.source_copy_count + 1
      if options.mutate_source_after_copy then
        world.files[source].digest = string.rep("c", 64)
        world.files[source].identity = "1:2:changed:5"
      end
      return success()
    end
    if command == "mv" then
      local source, destination = argv[3], argv[4]
      if exists(destination) then return success() end
      if not world.files[source] then return failure("missing source") end
      world.files[destination] = world.files[source]
      world.files[source] = nil
      return success()
    end
    if command == "rm" then
      world.files[argv[#argv]] = nil
      return success()
    end
    if command == "rmdir" then
      local path = argv[2]
      for candidate in pairs(world.files) do
        if candidate:sub(1, #path + 1) == path .. "/" then return failure("directory not empty") end
      end
      for candidate in pairs(world.directories) do
        if candidate ~= path and candidate:sub(1, #path + 1) == path .. "/" then
          return failure("directory not empty")
        end
      end
      world.directories[path] = nil
      return success()
    end
    if command == "curl" then
      if options.curl_fails then return failure("network unavailable") end
      local output_path
      for index, argument in ipairs(argv) do
        if argument == "--output" then output_path = argv[index + 1] end
      end
      world.files[output_path] = {
        digest = options.download_digest or hash,
        identity = "download:1:1:1",
        binary = true,
        executable = false,
      }
      return success()
    end
    if command == "/dev/rex-projects" or (world.files[command] and argv[2] == "version") then
      return cli_version(command)
    end
    if command:match("/rex-projects$") and argv[2] == "version" then return cli_version(command) end
    return failure("unexpected fixture command: " .. tostring(command))
  end

  function world.environment(name)
    return ({ XDG_CACHE_HOME = "/cache", HOME = "/home", PATH = options.path_dir or "/dev" })[name]
  end

  function world.decode(text)
    if text == "version-json" then return world.version end
    if text == "owner-json" then return world.encoded_owner end
    for _, file in pairs(world.files) do
      if file.content == text and text == "owner-json" then return world.encoded_owner end
    end
    return nil, "unknown fixture JSON"
  end

  function world.encode(value)
    world.encoded_owner = value
    return "owner-json"
  end

  function world.resolve(options_value, pin, budget)
    return Bootstrap.resolve(
      options_value,
      pin or { version = "0.1.0", protocol = 1, targets = {} },
      world.environment,
      world.decode,
      world.encode,
      world.exec,
      budget or 25,
      {}
    )
  end

  return world
end

local function assert_no_shell(world)
  for _, call in ipairs(world.commands) do
    local command = call.argv[1]
    check(command ~= "sh" and command ~= "bash", "bootstrap must use argv without a shell")
  end
end

local world = fake_world()
local context, err = world.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(context, err)
check(context.source == "developer" and context.digest == hash)
check(world.files[context.cli_path] and world.files[context.cli_path].binary)
check(world.encoded_owner.invocation_token and world.encoded_owner.source_digest == hash)
check(world.encoded_owner.deadline_epoch > world.encoded_owner.created_epoch)
check(world.encoded_owner.rex_process_identity:find("unknown", 1, true))
check(world.encoded_owner.cli_protocol == 1)
check(not world.directories["/cache/rex-projects/.locks/dev-" .. hash .. ".lock"])
local copy_count = world.source_copy_count
local warm = world.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(warm and warm.cli_path == context.cli_path)
check(world.source_copy_count == copy_count, "warm setup must reuse the verified snapshot")
assert_no_shell(world)

local invalid_protocol = fake_world({ version_overrides = { cli_protocol = 2 } })
local bad, protocol_error = invalid_protocol.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not bad and protocol_error:find("protocol", 1, true))

local path_override = fake_world({ path_dir = "/dev/with spaces" })
local from_path, path_error = path_override.resolve({ cli = "rex-projects" }, nil, 25)
check(from_path, path_error)
check(from_path.source == "developer")

local not_executable = fake_world({ source_executable = false })
local rejected_source, executable_error = not_executable.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not rejected_source and executable_error:find("not executable", 1, true))

local changing = fake_world({ mutate_source_after_copy = true })
local changed, changed_error = changing.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not changed and changed_error:find("changed while it was being snapshotted", 1, true))

local missing_helper = fake_world({ missing_command = "tee" })
local no_receipt, receipt_error = missing_helper.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not no_receipt and receipt_error:find("missing helper tee", 1, true))
check(
  not missing_helper.directories["/cache/rex-projects/.locks/dev-" .. hash .. ".lock"],
  "failed owner receipt creation must release only the newly acquired empty lock"
)

local timeout = fake_world({ cli_times_out = true })
local timed_out, timeout_error = timeout.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not timed_out and timeout_error:find("exceeded its bootstrap timeout", 1, true))
check(timeout.source_copy_count == 1, "timed out CLI probe must not publish an unverified snapshot")
check(
  not timeout.directories["/cache/rex-projects/.locks/dev-" .. hash .. ".lock"],
  "timed out CLI probe must release its owned lock"
)

local deadline_started = os.time()
local deadline_world = fake_world({
  on_lock_created = function()
    local expire_at = deadline_started + 3
    while os.time() < expire_at do
      deadline_started = os.time()
    end
  end,
})
local expired, expired_error = deadline_world.resolve({ cli = "/dev/rex-projects" }, nil, 4)
check(not expired and expired_error:find("deadline reached", 1, true))
check(
  not deadline_world.directories["/cache/rex-projects/.locks/dev-" .. hash .. ".lock"],
  "normal deadline must release its own lock using the reserved cleanup budget"
)
local retried, retry_error = deadline_world.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(retried, "25-second retry must recover after a 4-second setup deadline: " .. tostring(retry_error))
check(
  not deadline_world.directories["/cache/rex-projects/.locks/dev-" .. hash .. ".lock"],
  "successful retry must release its own lock"
)

local busy = fake_world()
local lock_path = "/cache/rex-projects/.locks/dev-" .. hash .. ".lock"
busy.directories["/cache/rex-projects"] = true
busy.directories["/cache/rex-projects/.locks"] = true
busy.directories[lock_path] = true
busy.files[lock_path .. "/owner.json"] = { content = "owner-json", digest = "receipt" }
busy.encoded_owner = { invocation_token = "another-owner" }
local busy_context, busy_error = busy.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not busy_context and busy_error:find(lock_path .. "/owner.json", 1, true))
check(busy.files[lock_path .. "/owner.json"].content == "owner-json", "a busy owner receipt must be preserved")

local corrupt_cache = fake_world()
local corrupt_path = "/cache/rex-projects/dev/" .. hash
corrupt_cache.directories["/cache/rex-projects"] = true
corrupt_cache.directories["/cache/rex-projects/dev"] = true
corrupt_cache.directories[corrupt_path] = true
corrupt_cache.files[corrupt_path .. "/rex-projects"] = {
  digest = string.rep("d", 64),
  identity = "bad:cache",
  binary = true,
}
local corrupt, corrupt_error = corrupt_cache.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not corrupt and corrupt_error:find("failed digest verification", 1, true))
check(corrupt_cache.files[corrupt_path .. "/rex-projects"].digest == string.rep("d", 64))

local unreleased = fake_world()
local none, unreleased_error = unreleased.resolve({}, { version = "0.1.0", protocol = 1, targets = {} }, 25)
check(not none and unreleased_error:find("no reviewed release asset", 1, true))

local malformed = fake_world({ version_overrides = { database_schema = "1" } })
local malformed_context, malformed_error = malformed.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not malformed_context and malformed_error:find("database schema", 1, true))

local unknown_field = fake_world({ version_overrides = { bootstrap_schema = 1 } })
local unknown_context, unknown_error = unknown_field.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not unknown_context and unknown_error:find("field not defined", 1, true))

local release = fake_world()
release.version = version_info({ version = "0.1.0", target = "aarch64-apple-darwin" })
local pinned = {
  version = "0.1.0",
  protocol = 1,
  targets = { ["macos-aarch64"] = { url = "https://example.invalid/rex-projects", sha256 = hash } },
}
local installed, install_error = release.resolve({}, pinned, 25)
check(installed, install_error)
check(installed.source == "release" and installed.digest == hash)
assert_no_shell(release)

local bad_digest = fake_world({ download_digest = string.rep("e", 64) })
bad_digest.version = version_info({ version = "0.1.0", target = "aarch64-apple-darwin" })
local rejected, digest_error = bad_digest.resolve({}, pinned, 25)
check(not rejected and digest_error:find("does not match", 1, true))

local network = fake_world({ curl_fails = true })
local offline, network_error = network.resolve({}, pinned, 25)
check(not offline and network_error:find("network unavailable", 1, true))

print("bootstrap fake-exec contract passed")
