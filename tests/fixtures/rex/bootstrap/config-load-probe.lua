-- Disposable PR0 probe only. This runs at config load under `rex config check`.
-- All executable paths are explicit; argv is never interpreted by a shell.
local fixture_root = os.getenv("REX_PR0_FIXTURE_ROOT")
if not fixture_root or fixture_root:sub(1, 1) ~= "/" then error("REX_PR0_FIXTURE_ROOT must be an absolute path", 0) end
local receipt_path = fixture_root .. "/config-load-receipt.json"

local argv = {
  "/usr/bin/python3",
  "-c",
  "import json,sys; print(json.dumps(sys.argv[1:]))",
  "argument with spaces",
  "quote' dollar$ parens() semicolon; literal",
}
local argv_result, argv_error = rex.exec(argv, { timeout = 3 })

local timeout_result, timeout_error = rex.exec({ "/bin/sleep", "5" }, { timeout = 0.2, stdout = false, stderr = false })

local output_result, output_error = rex.exec(
  { "/usr/bin/python3", "-c", "import sys; sys.stdout.write('x' * 32768)" },
  { timeout = 3, stderr = false }
)

local receipt = {
  probe = "rex-exec-config-load-v1",
  argv = {
    error = argv_error,
    ok = argv_result and argv_result.ok,
    code = argv_result and argv_result.code,
    stdout = argv_result and argv_result.stdout,
  },
  timeout = {
    error = timeout_error,
    ok = timeout_result and timeout_result.ok,
    code = timeout_result and timeout_result.code,
    signal = timeout_result and timeout_result.signal,
    timed_out = timeout_result and timeout_result.timed_out,
  },
  output = {
    error = output_error,
    ok = output_result and output_result.ok,
    code = output_result and output_result.code,
    bytes = output_result and #output_result.stdout,
  },
}

local encoded, encode_error = rex.json.encode(receipt, { indent = true })
if not encoded then error(encode_error, 0) end
local file, file_error = io.open(receipt_path, "w")
if not file then error(file_error, 0) end
file:write(encoded, "\n")
file:close()

rex.action({
  name = "rex_projects_pr0_lifecycle",
  title = "rex-projects PR0 lifecycle fixture",
  description = "Creates one disposable terminal block that exits with status 23.",
  run = function(ctx)
    local flavor = "com.superlogical.terminal.shell"
    local program = {
      "/usr/bin/python3",
      "-c",
      "import os,sys,time; print('fixture-pid=' + str(os.getpid()), flush=True); time.sleep(0.25); sys.exit(23)",
    }
    local window, err = rex.session.new_window({
      focus = false,
      window_label = "rex-projects-pr0-lifecycle",
      layout = rex.layout.block({
        flavor = flavor,
        label = "rex-projects-pr0-exit-23",
        options = {
          shell = "none",
          login = false,
          command = program,
          cwd = fixture_root,
          exit = { on_completion = false, quick_exit_threshold_ms = 0 },
        },
      }),
    })
    if err then error(err, 0) end
    return {
      session_id = ctx.session_id,
      window_id = window.window_id,
      block_ids = window.block_ids,
      expected_exit_code = 23,
    }
  end,
})

rex.action({
  name = "rex_projects_pr0_long_lifecycle",
  title = "rex-projects PR0 bounded long lifecycle fixture",
  description = "Creates one direct-exec child that remains until its Rex block closes or 30 seconds pass.",
  run = function(ctx)
    local program = {
      "/usr/bin/python3",
      "-c",
      "import os,time; print('fixture-pid=' + str(os.getpid()) + ' ready', flush=True); time.sleep(30)",
    }
    local window, err = rex.session.new_window({
      focus = false,
      window_label = "rex-projects-pr0-long-lifecycle",
      layout = rex.layout.block({
        flavor = "com.superlogical.terminal.shell",
        label = "rex-projects-pr0-long-child",
        options = {
          shell = "none",
          login = false,
          command = program,
          cwd = fixture_root,
          exit = { on_completion = false, quick_exit_threshold_ms = 0 },
        },
      }),
    })
    if err then error(err, 0) end
    return {
      session_id = ctx.session_id,
      window_id = window.window_id,
      block_ids = window.block_ids,
      maximum_lifetime_seconds = 30,
    }
  end,
})
