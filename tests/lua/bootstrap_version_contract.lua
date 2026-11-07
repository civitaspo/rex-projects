package.path = "./lua/?.lua;./lua/?/init.lua;" .. package.path

local validate = require("rex_projects.bootstrap").validate_version_info

local valid = {
  name = "rex-projects",
  version = "0.1.0-dev",
  target = "aarch64-apple-darwin",
  cli_protocol = 1,
  database_schema = 1,
  source_revision = string.rep("a", 40),
  dirty = false,
}

local newer_database_schema = {}
for key, value in pairs(valid) do
  newer_database_schema[key] = value
end
newer_database_schema.database_schema = 4

local function accepted(info, version, target, protocol)
  local result, err = validate(info, version, target, protocol)
  assert(result, err)
end

local function rejected(info, version, target, protocol, message)
  local result, err = validate(info, version, target, protocol)
  assert(not result, "expected invalid metadata to be rejected")
  assert(err:find(message, 1, true), "unexpected validation error: " .. tostring(err))
end

accepted(valid, nil, "aarch64-apple-darwin", 1)
accepted(newer_database_schema, nil, "aarch64-apple-darwin", 1)
accepted({
  name = valid.name,
  version = valid.version,
  target = valid.target,
  cli_protocol = valid.cli_protocol,
  database_schema = valid.database_schema,
  dirty = valid.dirty,
}, nil, valid.target, 1)
accepted(valid, "0.1.0-dev", valid.target, 1)

local cases = {
  { omit = "name", message = "invalid CLI identity" },
  { field = "version", value = 4, message = "invalid CLI identity" },
  { omit = "target", message = "target does not match" },
  { field = "cli_protocol", value = 2, message = "protocol does not match" },
  { field = "cli_protocol", value = 1.5, message = "protocol does not match" },
  { field = "database_schema", value = 0, message = "missing database schema" },
  { field = "database_schema", value = 1.5, message = "missing database schema" },
  { field = "dirty", value = "false", message = "missing database schema" },
  { field = "source_revision", value = "not-a-revision", message = "invalid source revision" },
  { field = "extra_field", value = true, message = "field not defined by CLI protocol" },
}

for _, case in ipairs(cases) do
  local info = {}
  for key, value in pairs(valid) do
    info[key] = value
  end
  if case.omit then
    info[case.omit] = nil
  else
    info[case.field] = case.value
  end
  rejected(info, nil, valid.target, 1, case.message)
end

rejected(valid, "0.2.0", valid.target, 1, "selected release")
rejected(valid, nil, "x86_64-apple-darwin", 1, "target does not match")

print("version metadata contract passed")
