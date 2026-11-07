package.path = "./lua/?.lua;./lua/?/init.lua;" .. package.path

local RuntimeDetails = require("rex_projects.runtime_details")
local Integration = require("rex_projects.init")

local pin = { status = "unreleased", version = "0.1.0", protocol = 1, targets = {} }
local options = { cli = "/work/tree with spaces/target/debug/rex-projects" }
local failure = RuntimeDetails.describe(options, pin, nil, "source executable is unavailable")
assert(failure.ready == false, "failed bootstrap must be reported as not ready")
assert(failure.source_kind == "developer override", "failed details must retain the selected source kind")
assert(failure.configured_selection == options.cli, "failed details must retain configured CLI selection")
assert(failure.pinned_release_version == pin.version, "failed details must report the release pin")
assert(failure.expected_version == nil, "developer override details must not imply an exact release version")
assert(failure.expected_cli_protocol == 1, "failed details must report expected CLI protocol")
assert(failure.cache_state == "not verified", "failed details must describe cache verification state")
assert(failure.error == "source executable is unavailable", "failed details must retain the setup error")
assert(failure.cli_path == nil and failure.digest == nil, "failure must not claim a resolved binary")

local success = RuntimeDetails.describe({}, pin, {
  source = "release",
  cli_path = "/cache/rex-projects/bin/0.1.0/macos-aarch64/rex-projects",
  digest = string.rep("a", 64),
  version = {
    version = "0.1.0",
    target = "aarch64-apple-darwin",
    cli_protocol = 1,
    database_schema = 4,
  },
})
assert(success.ready == true, "verified bootstrap must be reported as ready")
assert(success.source_kind == "release", "success details must report resolved source kind")
assert(success.configured_selection == "embedded release pin", "default pin selection must be explicit")
assert(success.pinned_release_version == pin.version, "success details must report the release pin")
assert(success.expected_version == pin.version, "release mode must report its exact expected version")
assert(
  success.expected_cli_protocol == 1 and success.cli_protocol == 1,
  "success must report expected and observed protocol"
)
assert(success.cache_state == "verified", "success details must identify verified cache state")
assert(success.cli_path ~= nil and success.digest ~= nil, "success details must include resolved binary identity")
assert(success.database_schema == 4, "success details must report the observed database schema")
assert(success.error == nil, "successful details must omit stale failure information")

local development = RuntimeDetails.describe(options, pin, {
  source = "developer",
  cli_path = "/cache/rex-projects/dev/build-digest/rex-projects",
  digest = string.rep("b", 64),
  version = {
    version = "0.1.0-dev.42",
    target = "aarch64-apple-darwin",
    cli_protocol = 1,
    database_schema = 4,
  },
})
assert(development.version == "0.1.0-dev.42", "developer details must report the actual build version")
assert(development.pinned_release_version == pin.version, "developer details must keep the release pin visible")
assert(development.expected_version == nil, "developer mode must not require the pinned release version")

local secret_env = RuntimeDetails.describe({}, pin, nil, "bootstrap failed")
for _, key in ipairs({ "PATH", "HOME", "TOKEN", "environment" }) do
  assert(secret_env[key] == nil, "runtime details must not expose environment values")
end

local actions = {}
local failed_setup, setup_error = Integration.setup({}, {
  action = function(action) actions[action.name] = action end,
  exec = function(argv)
    if argv[1] == "uname" and argv[2] == "-s" then
      return { code = 0, stdout = "Darwin\n", stderr = "", timed_out = false }
    end
    if argv[1] == "uname" and argv[2] == "-m" then
      return { code = 0, stdout = "arm64\n", stderr = "", timed_out = false }
    end
    error("unexpected bootstrap command: " .. table.concat(argv, " "))
  end,
  json = { decode = function() return nil end, encode = function() return "" end },
})
assert(failed_setup and failed_setup.ready == false, "unreleased setup must fail without hiding its details")
assert(setup_error == nil, "setup returns its details object as one value")
assert(failed_setup.error ~= nil, "failed setup details must include an actionable error")
assert(actions.rex_projects_runtime_details ~= nil, "runtime details Action must exist after setup failure")
local action_result = actions.rex_projects_runtime_details.run({}, {})
assert(action_result.cache_state == "not verified", "runtime details Action must expose failed cache state")
assert(action_result.expected_cli_protocol == 1, "runtime details Action must expose expected protocol after failure")
assert(action_result.error == failed_setup.error, "runtime details Action must expose the setup failure")

print("runtime details contract passed")
