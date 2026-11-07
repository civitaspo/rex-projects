local M = {}

function M.describe(options, pin, context, error_message)
  local developer_cli = options and options.cli
  local details = {
    ready = context ~= nil,
    source_kind = context and context.source or (developer_cli and "developer override" or "pinned release"),
    configured_selection = developer_cli or "embedded release pin",
    pinned_release_version = pin.version,
    expected_cli_protocol = pin.protocol,
    cache_state = context and "verified" or "not verified",
  }
  if not developer_cli then details.expected_version = pin.version end
  if context then
    details.version = context.version.version
    details.target = context.version.target
    details.cli_protocol = context.version.cli_protocol
    details.database_schema = context.version.database_schema
    details.digest = context.digest
    details.cli_path = context.cli_path
  end
  if error_message ~= nil then details.error = error_message end
  return details
end

return M
