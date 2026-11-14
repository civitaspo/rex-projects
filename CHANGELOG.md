# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-11-14

### 🚀 Features

- feat(core): add typed config and protocol boundaries ([#12](https://github.com/civitaspo/rex-projects/pull/12))
- feat(runtime): persist fenced intent and bounded agent mailboxes ([#13](https://github.com/civitaspo/rex-projects/pull/13))
- feat(review): add revision-bound human review bundles ([#15](https://github.com/civitaspo/rex-projects/pull/15))
- feat(learning): publish project knowledge and stage profile candidates ([#18](https://github.com/civitaspo/rex-projects/pull/18))
- feat: add Rex and ticket CLI adapters ([#19](https://github.com/civitaspo/rex-projects/pull/19))
- feat(orchestration): add pure workflow decisions ([#20](https://github.com/civitaspo/rex-projects/pull/20))
- feat(controller): add foreground runtime and durable CLI ([#16](https://github.com/civitaspo/rex-projects/pull/16))
- feat(operator): add typed operation planning ([#22](https://github.com/civitaspo/rex-projects/pull/22))
- feat(git): manage repository worktrees and host commits ([#23](https://github.com/civitaspo/rex-projects/pull/23))
- feat(effects): dispatch durable host operations ([#24](https://github.com/civitaspo/rex-projects/pull/24))
- feat(plugin): bootstrap a pinned immutable Rust runtime ([#14](https://github.com/civitaspo/rex-projects/pull/14))
- feat(release): refresh Lua runtime pin from verified assets ([#25](https://github.com/civitaspo/rex-projects/pull/25))
- feat(orchestration): validate typed role results ([#28](https://github.com/civitaspo/rex-projects/pull/28))
- feat: capture host environment for agent launches ([#26](https://github.com/civitaspo/rex-projects/pull/26))
- feat(tickets): add Linear CLI adapter ([#30](https://github.com/civitaspo/rex-projects/pull/30))
- feat(artifacts): add host-registered artifact IDs ([#31](https://github.com/civitaspo/rex-projects/pull/31))
- feat(roles): add typed role prompt contracts ([#32](https://github.com/civitaspo/rex-projects/pull/32))
- feat(merge): add typed GitHub merge procedures ([#21](https://github.com/civitaspo/rex-projects/pull/21))
- feat(runtime): persist Agent launch authority and Rex views ([#34](https://github.com/civitaspo/rex-projects/pull/34))
- feat(providers): add typed Claude Code and Codex adapters ([#38](https://github.com/civitaspo/rex-projects/pull/38))
- feat(agent): run finite provider turns with verified cleanup ([#39](https://github.com/civitaspo/rex-projects/pull/39))
- feat(runtime): add run-step package and filesystem spool ([#40](https://github.com/civitaspo/rex-projects/pull/40))
- feat: add durable agent launch reservations ([#41](https://github.com/civitaspo/rex-projects/pull/41))
- feat: integrate prototype ticket execution into main ([#117](https://github.com/civitaspo/rex-projects/pull/117))
- feat(recovery): resume exhausted MergeDecision claims ([#121](https://github.com/civitaspo/rex-projects/pull/121))
- feat(recovery): reconcile interrupted provider qualifications ([#122](https://github.com/civitaspo/rex-projects/pull/122))
- feat(learning): persist Supervisor finding batches ([#134](https://github.com/civitaspo/rex-projects/pull/134))
- feat(learning): publish durable Supervisor Topics ([#136](https://github.com/civitaspo/rex-projects/pull/136))
- feat(learning): publish immutable Topic revisions ([#139](https://github.com/civitaspo/rex-projects/pull/139))
- feat(learning): persist Supervisor profile candidates ([#141](https://github.com/civitaspo/rex-projects/pull/141))
- feat: qualify immutable profile candidates through provider CLI ([#143](https://github.com/civitaspo/rex-projects/pull/143))
- feat: stage frozen profile trial approval requests ([#145](https://github.com/civitaspo/rex-projects/pull/145))
- feat(learning): freeze selected skills for profile trials ([#148](https://github.com/civitaspo/rex-projects/pull/148))

### 🐛 Bug Fixes

- fix: lock server-managed workflows ([#5](https://github.com/civitaspo/rex-projects/pull/5))
- fix(runtime): retain operation-bound environment handoffs ([#35](https://github.com/civitaspo/rex-projects/pull/35))
- fix(store): accept pending agent start acknowledgements ([#36](https://github.com/civitaspo/rex-projects/pull/36))
- fix(environment): serialize one-use handoff consumption ([#37](https://github.com/civitaspo/rex-projects/pull/37))
- fix: bound diagnostics for expired terminal mailboxes ([#118](https://github.com/civitaspo/rex-projects/pull/118))
- fix: replay accepted terminal commit outcomes after expiry ([#119](https://github.com/civitaspo/rex-projects/pull/119))
- fix(runtime): reject stale TicketRuns before agent creation ([#123](https://github.com/civitaspo/rex-projects/pull/123))
- fix(runtime): persist the agent creation boundary ([#124](https://github.com/civitaspo/rex-projects/pull/124))
- fix(runtime): finalize rejected launches after controller restart ([#125](https://github.com/civitaspo/rex-projects/pull/125))
- fix(merge): block unverified request executors ([#127](https://github.com/civitaspo/rex-projects/pull/127))
- fix(dashboard): explain unresolved Agent launches ([#129](https://github.com/civitaspo/rex-projects/pull/129))
- fix(knowledge): validate Topic source files at their publication root ([#146](https://github.com/civitaspo/rex-projects/pull/146))
- fix(rex): preserve bounded command failure diagnostics ([#149](https://github.com/civitaspo/rex-projects/pull/149))
- fix(fixtures): handle Supervisor learning batches ([#150](https://github.com/civitaspo/rex-projects/pull/150))
- fix(postmortem): disclose missing validation evidence ([#151](https://github.com/civitaspo/rex-projects/pull/151))
- fix(runtime): drain owned agent turns before stopping the controller ([#157](https://github.com/civitaspo/rex-projects/pull/157))
- fix(cli): accept Coordinator clarification answers ([#159](https://github.com/civitaspo/rex-projects/pull/159))
- fix(acceptance): clean exited controller blocks after incomplete stop ([#160](https://github.com/civitaspo/rex-projects/pull/160))
- fix(runtime): preserve ticket delivery during Supervisor learning ([#162](https://github.com/civitaspo/rex-projects/pull/162))
- fix(rex): reconcile one-shot status anchors with Rex observations ([#164](https://github.com/civitaspo/rex-projects/pull/164))
- fix(rex): accept repeated terminal anchor observations ([#165](https://github.com/civitaspo/rex-projects/pull/165))
- fix(runtime): cancel unstarted launches on shutdown ([#166](https://github.com/civitaspo/rex-projects/pull/166))
- fix(test): acknowledge supervisor progress and instruction wakes ([#168](https://github.com/civitaspo/rex-projects/pull/168))
- fix(runtime): resolve automatic Worker commit mode before preparation ([#173](https://github.com/civitaspo/rex-projects/pull/173))
- fix(runtime): reconcile missing terminal ticket displays ([#176](https://github.com/civitaspo/rex-projects/pull/176))
- fix(runtime): continue prepared Workers after progress ([#178](https://github.com/civitaspo/rex-projects/pull/178))

### 📚 Documentation

- docs: explain managed workflow lock updates ([#6](https://github.com/civitaspo/rex-projects/pull/6))
- docs: add reviewed rex-projects prototype plan ([#8](https://github.com/civitaspo/rex-projects/pull/8))
- docs: add normalized GitHub CLI ticket adapter example ([#120](https://github.com/civitaspo/rex-projects/pull/120))
- docs: record the v2 design as ADRs ([#182](https://github.com/civitaspo/rex-projects/pull/182))

### 🚜 Refactoring

- refactor: use generic ticket CLI and Rust development tools ([#33](https://github.com/civitaspo/rex-projects/pull/33))

### ⚙️ Maintenance

- chore: initialize repository
- chore(repo-settings): sync managed files
- chore: add Lua project foundation ([#1](https://github.com/civitaspo/rex-projects/pull/1))
- ci(rust): add build and quality checks ([#9](https://github.com/civitaspo/rex-projects/pull/9))
- chore(repo-settings): sync managed files ([#10](https://github.com/civitaspo/rex-projects/pull/10))
- test: verify Rex and coding agent lifecycle contracts ([#11](https://github.com/civitaspo/rex-projects/pull/11))
- build(release): verify runtime assets and Lua pins ([#17](https://github.com/civitaspo/rex-projects/pull/17))
- test(cli): make foreground owner fixture failure-safe ([#27](https://github.com/civitaspo/rex-projects/pull/27))
- test(e2e): add local project acceptance fixtures ([#29](https://github.com/civitaspo/rex-projects/pull/29))
- test(dashboard): capture immediate PTY setup errors ([#126](https://github.com/civitaspo/rex-projects/pull/126))
- test(scheduler): cover dispatch wake convergence across restart ([#128](https://github.com/civitaspo/rex-projects/pull/128))
- test(runtime): isolate the parked pre-exec lease probe ([#131](https://github.com/civitaspo/rex-projects/pull/131))
- test(merge): connect approved Request with an advanced base ([#130](https://github.com/civitaspo/rex-projects/pull/130))
- test(runtime): exercise Rex event reconnect inventory ([#132](https://github.com/civitaspo/rex-projects/pull/132))
- test(acceptance): drive native Worker block-loss recovery ([#152](https://github.com/civitaspo/rex-projects/pull/152))
- test(runtime): verify recovery after missed Rex block events ([#153](https://github.com/civitaspo/rex-projects/pull/153))
- test(acceptance): bound Supervisor-to-Coordinator fixture retention ([#163](https://github.com/civitaspo/rex-projects/pull/163))
- test: cover Worker inbox through the public CLI ([#170](https://github.com/civitaspo/rex-projects/pull/170))

### ◀️ Reverts

- revert: restore main to pre-prototype baseline ([#180](https://github.com/civitaspo/rex-projects/pull/180))
- revert: restore main to before the prototype plan ([#181](https://github.com/civitaspo/rex-projects/pull/181))

<!-- generated by git-cliff -->
