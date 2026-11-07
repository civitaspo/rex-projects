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
    source_copy_count = 0,
    temporary_sequence = 0,
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
      if flag == "-d" then return world.directories[path] and success() or failure() end
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
    if command == "mktemp" then
      world.temporary_sequence = world.temporary_sequence + 1
      local template = argv[3]
      local directory = template:gsub("XXXXXXXX", string.format("%08d", world.temporary_sequence))
      world.directories[directory] = true
      world.directories[directory .. "#mode"] = "700"
      if options.on_temp_directory_created then options.on_temp_directory_created(directory, world) end
      return success(directory .. "\n")
    end
    if command == "mkdir" then
      local path = argv[#argv]
      if argv[2] == "-p" then
        world.directories[path] = true
        return success()
      end
      if world.directories[path] or world.files[path] or world.symlinks[path] then return failure("already exists") end
      world.directories[path] = true
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
      local source, destination
      if argv[2] == "-n" then
        source, destination = argv[4], argv[5]
      else
        source, destination = argv[3], argv[4]
      end
      if world.symlinks[destination] and argv[2] == "-n" then return success() end
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
    if command == "link" then
      local source, destination = argv[2], argv[3]
      if options.on_link then options.on_link(destination, world) end
      if exists(destination) then return failure("destination exists") end
      if not world.files[source] then return failure("missing source") end
      world.files[destination] = world.files[source]
      return success()
    end
    if command == "rm" then
      world.files[argv[#argv]] = nil
      world.symlinks[argv[#argv]] = nil
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
    return nil, "unknown fixture JSON"
  end

  function world.resolve(options_value, pin, budget, clock)
    return Bootstrap.resolve(
      options_value,
      pin or { version = "0.1.0", protocol = 1, targets = {} },
      world.environment,
      world.decode,
      world.exec,
      budget or 25,
      clock
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
check(not world.directories["/cache/rex-projects/.locks"], "immutable publication must not create a shared lock tree")
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

local trailing_space_path = "/dev/rex-projects "
local trailing_space = fake_world({ source_path = trailing_space_path })
local trailing_context, trailing_error = trailing_space.resolve({ cli = trailing_space_path }, nil, 25)
check(trailing_context, trailing_error)
check(trailing_context.digest == hash, "realpath output must preserve meaningful trailing spaces in source names")

local not_executable = fake_world({ source_executable = false })
local rejected_source, executable_error = not_executable.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not rejected_source and executable_error:find("not executable", 1, true))

local changing = fake_world({ mutate_source_after_copy = true })
local changed, changed_error = changing.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not changed and changed_error:find("changed while it was being snapshotted", 1, true))

local missing_helper = fake_world({ missing_command = "link" })
local no_publication, publication_error = missing_helper.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not no_publication and publication_error:find("missing helper link", 1, true))
check(not missing_helper.directories["/cache/rex-projects/.locks"], "a failed publish must not strand a lock")

local missing_stat = fake_world({ missing_command = "stat" })
local stat_context, stat_error = missing_stat.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not stat_context and stat_error:find("stat", 1, true),
  "stat prerequisite errors must identify the missing helper"
)

local timeout = fake_world({ cli_times_out = true })
local timed_out, timeout_error = timeout.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not timed_out and timeout_error:find("exceeded its bootstrap timeout", 1, true))
check(timeout.source_copy_count == 1, "timed out CLI probe must not publish an unverified snapshot")
check(not timeout.directories["/cache/rex-projects/.locks"], "timed out setup must not require lock cleanup")

local now = 1000
local function fake_clock() return now end
local deadline_world = fake_world({ on_temp_directory_created = function() now = 1003 end })
local expired, expired_error = deadline_world.resolve({ cli = "/dev/rex-projects" }, nil, 4, fake_clock)
check(not expired and expired_error:find("deadline reached", 1, true))
local setup_timeout
for _, command in ipairs(deadline_world.commands) do
  if command.argv[1] == "mktemp" then setup_timeout = command.timeout end
end
check(setup_timeout == 1, "a 4-second setup retains one second plus Rex's two-second termination grace")
check(
  not deadline_world.directories["/cache/rex-projects/.locks"],
  "deadline exhaustion must not leave shared lock state"
)
now = 1004
local retried, retry_error = deadline_world.resolve({ cli = "/dev/rex-projects" }, nil, 25, fake_clock)
check(retried, "25-second retry must publish despite an abandoned staging directory: " .. tostring(retry_error))
check(
  deadline_world.directories["/cache/rex-projects/dev/" .. hash],
  "a previous abandoned staging directory must not block immutable publication"
)

local simultaneous = fake_world({
  on_temp_directory_created = function(directory, world_value)
    local final_path = directory:gsub("/%.rex%-projects%.%d+$", "/rex-projects")
    world_value.files[final_path] = {
      digest = hash,
      identity = "winner:1:1:1",
      binary = true,
      executable = true,
    }
  end,
})
local concurrent_winner, winner_error = simultaneous.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(concurrent_winner, "a competing publisher's valid immutable winner must be reused: " .. tostring(winner_error))
check(concurrent_winner.digest == hash)
check(
  not simultaneous.directories["/cache/rex-projects/.locks"],
  "simultaneous publishers must not require shared lock state"
)

local invalid_winner = fake_world({
  on_temp_directory_created = function(directory, world_value)
    local final_path = directory:gsub("/%.rex%-projects%.%d+$", "/rex-projects")
    world_value.files[final_path] = {
      digest = string.rep("f", 64),
      identity = "winner:1:1:1",
      binary = true,
      executable = true,
    }
  end,
})
local rejected_winner, rejected_winner_error = invalid_winner.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not rejected_winner and rejected_winner_error:find("winner failed digest verification", 1, true),
  "a concurrent publisher must preserve and reject a winner with the wrong digest"
)
check(
  invalid_winner.files["/cache/rex-projects/dev/" .. hash .. "/rex-projects"].digest == string.rep("f", 64),
  "publication must never replace an existing immutable cache entry"
)

local directory_winner = fake_world({
  on_temp_directory_created = function(directory, world_value)
    local final_path = directory:gsub("/%.rex%-projects%.%d+$", "/rex-projects")
    world_value.directories[final_path] = true
  end,
})
local rejected_directory, directory_error = directory_winner.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not rejected_directory and directory_error:find("winner failed digest verification", 1, true),
  "publication must reject and preserve a directory at the immutable file path"
)
check(
  directory_winner.directories["/cache/rex-projects/dev/" .. hash .. "/rex-projects"],
  "publication must never replace a directory at the cache file path"
)

local symlink_winner = fake_world({
  on_link = function(final_path, world_value)
    world_value.symlinks[final_path] = "/outside/marker"
    world_value.files["/outside/marker"] = { digest = "outside", identity = "outside" }
  end,
})
local rejected_symlink, symlink_error = symlink_winner.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not rejected_symlink and symlink_error:find("became a symlink", 1, true),
  "publication must reject a symlink introduced between initial validation and atomic link"
)
check(
  symlink_winner.files["/outside/marker"].digest == "outside",
  "atomic publication must not follow a competing symlink to overwrite its target"
)

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

local escaped_dev = fake_world()
escaped_dev.symlinks["/cache/rex-projects/dev"] = "/outside/dev"
local escaped, escaped_error = escaped_dev.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not escaped and escaped_error:find("symlink", 1, true))
check(
  not escaped_dev.directories["/outside/dev/" .. hash],
  "developer setup must validate existing ancestors before creating digest descendants"
)

local escaped_cache = fake_world()
escaped_cache.symlinks["/cache/rex-projects"] = "/outside/rex-projects"
local cache_escape, cache_escape_error = escaped_cache.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not cache_escape and cache_escape_error:find("symlink", 1, true))
check(
  not escaped_cache.directories["/outside/rex-projects/dev"],
  "setup must reject a symlinked managed cache root before creating descendants"
)

local file_cache_root = fake_world()
file_cache_root.directories["/cache/rex-projects"] = nil
file_cache_root.files["/cache/rex-projects"] = {
  digest = "unchanged-cache-root-file",
  identity = "file:root",
  binary = false,
  executable = false,
  mode = "644",
}
local root_file_result, root_file_error = file_cache_root.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not root_file_result and root_file_error:find("cache root is not a directory", 1, true),
  "an ordinary file at the cache root must fail with an actionable error"
)
check(
  file_cache_root.files["/cache/rex-projects"].mode == "644",
  "setup must not chmod an ordinary file where the cache root should be"
)

local file_managed_ancestor = fake_world()
file_managed_ancestor.files["/cache/rex-projects/dev"] = {
  digest = "unchanged-managed-file",
  identity = "file:dev",
  binary = false,
  executable = false,
  mode = "644",
}
local ancestor_file_result, ancestor_file_error = file_managed_ancestor.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(
  not ancestor_file_result and ancestor_file_error:find("managed cache ancestor is not a directory", 1, true),
  "an ordinary file at a managed cache ancestor must fail clearly"
)
check(
  file_managed_ancestor.files["/cache/rex-projects/dev"].mode == "644",
  "setup must not change permissions on an ordinary file at a managed ancestor"
)

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
local curl_call
for _, call in ipairs(release.commands) do
  if call.argv[1] == "curl" then
    curl_call = call
    break
  end
end
check(
  curl_call and curl_call.argv[2] == "--disable",
  "curl must ignore user configuration before downloading pinned bytes"
)

local invalid_asset = fake_world()
local invalid_asset_pin = {
  version = "0.1.0",
  protocol = 1,
  targets = { ["macos-aarch64"] = true },
}
local bad_asset, bad_asset_error = invalid_asset.resolve({}, invalid_asset_pin, 25)
check(
  not bad_asset and bad_asset_error:find("invalid", 1, true),
  "non-table release assets must fail as normal setup errors"
)

local bad_digest = fake_world({ download_digest = string.rep("e", 64) })
bad_digest.version = version_info({ version = "0.1.0", target = "aarch64-apple-darwin" })
local rejected, digest_error = bad_digest.resolve({}, pinned, 25)
check(not rejected and digest_error:find("does not match", 1, true))

local network = fake_world({ curl_fails = true })
local offline, network_error = network.resolve({}, pinned, 25)
check(not offline and network_error:find("network unavailable", 1, true))

local symlinked_temp = fake_world({
  on_temp_directory_created = function(directory, world_value)
    world_value.symlinks[directory .. "/rex-projects"] = "/outside/marker"
    world_value.files["/outside/marker"] = { digest = "unchanged", identity = "outside" }
  end,
})
local symlinked_result, symlinked_error = symlinked_temp.resolve({ cli = "/dev/rex-projects" }, nil, 25)
check(not symlinked_result and symlinked_error:find("source", 1, true))
check(
  symlinked_temp.files["/outside/marker"].digest == "unchanged",
  "snapshot copying must not overwrite a preexisting symlink target in its exclusive temp directory"
)
local temp_mkdir
for _, call in ipairs(symlinked_temp.commands) do
  if call.argv[1] == "mktemp" then
    temp_mkdir = call
    break
  end
end
check(
  temp_mkdir
    and temp_mkdir.argv[2] == "-d"
    and symlinked_temp.directories[temp_mkdir.argv[3]:gsub("XXXXXXXX", "00000001") .. "#mode"] == "700",
  "temporary directories must be created exclusively with the platform mktemp utility"
)

print("bootstrap fake-exec contract passed")
