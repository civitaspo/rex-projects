local Bootstrap = require("rex_projects.bootstrap")
local Pin = require("rex_projects.runtime_version")

local M = {}

local function environment(name) return os.getenv(name) end

local function public_context(context)
  if not context then return { ready = false, error = M.error } end
  return {
    ready = true,
    source = context.source,
    version = context.version.version,
    target = context.version.target,
    cli_protocol = context.version.cli_protocol,
    database_schema = context.version.database_schema,
    digest = context.digest,
    cli_path = context.cli_path,
  }
end

local function register_actions(rex_api)
  rex_api.action({
    name = "rex_projects_retry_setup",
    title = "Retry rex-projects Setup",
    category = "rex-projects",
    run = function(ctx)
      local context, err = Bootstrap.resolve(
        M.options,
        Pin,
        environment,
        function(text) return rex_api.json.decode(text) end,
        function(value) return rex_api.json.encode(value) end,
        function(argv, timeout, extra_options)
          local exec_options = { timeout = timeout, text = true }
          for key, value in pairs(extra_options or {}) do
            exec_options[key] = value
          end
          return rex_api.exec(argv, exec_options)
        end,
        25,
        { server = ctx and ctx.server }
      )
      M.context = context
      M.error = err
      return public_context(context)
    end,
  })
  rex_api.action({
    name = "rex_projects_runtime_details",
    title = "Show rex-projects Runtime Details",
    category = "rex-projects",
    run = function() return public_context(M.context) end,
  })
end

function M.setup(options, rex_api)
  options = options or {}
  if type(options) ~= "table" then return nil, "setup options must be a table" end
  rex_api = rex_api or rex
  if type(rex_api) ~= "table" or type(rex_api.action) ~= "function" or type(rex_api.exec) == "nil" then
    return nil, "Rex exec and action APIs are required"
  end
  M.options = options
  M.context, M.error = Bootstrap.resolve(
    options,
    Pin,
    environment,
    function(text) return rex_api.json.decode(text) end,
    function(value) return rex_api.json.encode(value) end,
    function(argv, timeout, extra_options)
      local exec_options = { timeout = timeout, text = true }
      for key, value in pairs(extra_options or {}) do
        exec_options[key] = value
      end
      return rex_api.exec(argv, exec_options)
    end,
    4,
    {}
  )
  register_actions(rex_api)
  return public_context(M.context)
end

return M
