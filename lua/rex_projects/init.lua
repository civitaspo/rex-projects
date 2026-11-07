local Bootstrap = require("rex_projects.bootstrap")
local Pin = require("rex_projects.runtime_version")
local RuntimeDetails = require("rex_projects.runtime_details")

local M = {}

local function environment(name) return os.getenv(name) end

local function register_actions(rex_api)
  rex_api.action({
    name = "rex_projects_retry_setup",
    title = "Retry rex-projects Setup",
    category = "rex-projects",
    run = function()
      local context, err = Bootstrap.resolve(
        M.options,
        Pin,
        environment,
        function(text) return rex_api.json.decode(text) end,
        function(argv, timeout, extra_options)
          local exec_options = { timeout = timeout, text = true }
          for key, value in pairs(extra_options or {}) do
            exec_options[key] = value
          end
          return rex_api.exec(argv, exec_options)
        end,
        25
      )
      M.context = context
      M.error = err
      return RuntimeDetails.describe(M.options, Pin, context, err)
    end,
  })
  rex_api.action({
    name = "rex_projects_runtime_details",
    title = "Show rex-projects Runtime Details",
    category = "rex-projects",
    run = function() return RuntimeDetails.describe(M.options, Pin, M.context, M.error) end,
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
    function(argv, timeout, extra_options)
      local exec_options = { timeout = timeout, text = true }
      for key, value in pairs(extra_options or {}) do
        exec_options[key] = value
      end
      return rex_api.exec(argv, exec_options)
    end,
    4
  )
  register_actions(rex_api)
  if M.context then return M.context.cli_path end
  return RuntimeDetails.describe(M.options, Pin, M.context, M.error)
end

return M
