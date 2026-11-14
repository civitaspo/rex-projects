-- Rex integration for rex-projects. Load it from ~/.config/rex/init.lua:
--
--   require("rex_projects").setup({ keys = { dashboard = "ctrl+a>p", serve = "ctrl+a>shift+p" } })
--
-- It only launches the `rex-projects` binary; all logic lives there.
local M = {}

local TERMINAL = "com.superlogical.terminal.shell"

local function terminal(command, label)
  return { block = { flavor = TERMINAL, label = label, options = { command = command } } }
end

-- Returns the ID of the first session with `label`, or nil.
local function find_session(label)
  local result, err = rex.call("session.list")
  if result == nil then error("cannot list sessions: " .. tostring(err), 0) end
  for _, session in ipairs(result.sessions or {}) do
    if session.label == label then return session.session_id end
  end
  return nil
end

-- Opens the dashboard as a floating layer in the current session.
local function open_dashboard(opts, ctx)
  local _, err = rex.session.new_layer({
    session_id = ctx.session_id,
    bounds = { 0.05, 0.05, 0.9, 0.9 },
    focus = true,
    layout = terminal({ opts.bin, "ui", "--popup" }, "rex-projects"),
  })
  if err ~= nil then error("cannot open the dashboard: " .. tostring(err), 0) end
end

-- Shows the control session, creating it with `<bin> serve` when missing.
local function open_serve(opts)
  local session_id = find_session(opts.session)
  if session_id == nil then
    local created, err = rex.call("session.create", {
      label = opts.session,
      initial_windows = { { window_label = "serve", layout = terminal({ opts.bin, "serve" }, "serve") } },
    })
    if created == nil then error("cannot create session " .. opts.session .. ": " .. tostring(err), 0) end
    session_id = created.session_id
  end
  -- Showing the session needs an app client; without one, still report the session.
  local shown = pcall(rex.client.queue, "session.select", { session_id = session_id })
  return { session_id = session_id, shown = shown }
end

-- Registers the `rex_projects_dashboard` and `rex_projects_serve` actions.
-- Options: `bin` (default "rex-projects"), `session` (the control session's
-- label, default "rxp"), and `keys.dashboard` / `keys.serve` to bind keys.
function M.setup(opts)
  opts = opts or {}
  local o = {
    bin = opts.bin or "rex-projects",
    session = opts.session or "rxp",
  }
  local keys = opts.keys or {}

  rex.action({
    name = "rex_projects_dashboard",
    title = "rex-projects: Dashboard",
    description = "Open the rex-projects Ticket dashboard as a floating layer",
    category = "rex-projects",
    run = function(ctx) open_dashboard(o, ctx) end,
  })
  rex.action({
    name = "rex_projects_serve",
    title = "rex-projects: Controller",
    description = "Start or show the rex-projects controller session",
    category = "rex-projects",
    run = function() return open_serve(o) end,
  })

  if keys.dashboard then rex.bind(keys.dashboard, "rex_projects_dashboard") end
  if keys.serve then rex.bind(keys.serve, "rex_projects_serve") end
end

return M
