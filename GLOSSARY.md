# rex-projects

rex-projects coordinates Agents that deliver tickets and improve a Project's delivery practices.

## Language

**Project**.
A collection of tickets and delivery practices, with an optional goal.
_Avoid_ mission, workspace.

**Goal Project**.
A Project organized around explicit acceptance conditions for a goal.

**Operations Project**.
A Project organized around recurring work and declared operation recipes rather than a mandatory final goal.

**Ticket**.
An externally tracked unit of requested work that belongs to a Project.
_Avoid_ task when referring to the external ticket.

**TicketRun**.
One attempt to deliver a Ticket, including its planning, changes, operations, and retrospective.

**Ticket status**.
The normalized external tracker state, mapped to Triage, Backlog, Ready, In Progress, In Review, Done, or Canceled. In Review means required human review is pending. Other active delivery uses In Progress, with detailed phases and waiting reasons held internally.

**Machine controller**.
The single foreground rex-projects process that schedules all Projects on the machine and owns durable orchestration.

**Role session**.
The continuing logical responsibility of a role across finite reasoning turns, parked waits, and provider process restarts.

**AgentRun**.
One finite execution attempt of an Agent in an assigned role session.

**Ticket tab**.
The single active Rex window for one external ticket, containing its Agent blocks across finite turns and TicketRun generations. Its logical view survives archival and read-only history reopening.

**Wake input**.
A deduplicated durable event that makes a role session eligible for another finite turn, stored and consumed with its launch intent.

**Factory context**.
Scoped child-process markers that let a personal hook select Rex's naming behavior and let human-only commands reject accidental Agent use. Factory role instructions and conservative observation supplement those markers. They are a cooperation contract, not human authentication.

**Agent mailbox**.
A run-scoped file exchange of requests and receipts between an Agent and the host controller, without Agent CLI access to SQLite. It works with provider sandboxes and broader automatic permissions.

**Managed clone**.
A factory-owned repository clone shared by registered Projects, with isolated Worker worktrees.

**rex-projects hook**.
A configured repeatable local check whose receipt binds the command, configuration, and outcome to the exact delivery head. It complements Git hooks, provider hooks, and remote checks.

**Agent profile**.
A named definition of a Coding Agent's execution settings and guidance, selected for a role.

**Profile candidate**.
A proposed change to an Agent profile's guidance, awaiting evaluation and a decision about ordinary use.

**Managed profile**.
An ordinary Agent profile that consolidates accepted improvements for a Project and role.

**Supervisor**.
The single Agent responsible for a Project's priorities, allocation, interventions, and learning across TicketRuns.

**Coordinator**.
The Agent responsible for delivery of one Ticket without implementing its changes.

**Planner**.
An Agent responsible for an implementation plan and its unresolved decisions.

**Worker**.
An Agent responsible for investigation and implementation of an assigned work item.

**Reviewer**.
An Agent responsible for independent assessment of a plan or change at a specific revision.

**Merge Decision**.
An Agent responsible for assessing merge evidence and explaining risk to the human.
_Avoid_ Merge Decition.

**Merge procedure**.
An ordered set of typed controller steps derived from one repository's merge instructions. It can prepare PR content, request or execute a merge, and verify the actual merged commit. Each step has its own durable receipt.

**Operator**.
An Agent responsible for configured release actions and confirmation of the required operational outcome.

**Postmortem**.
An Agent responsible for an evidence-backed retrospective and reusable findings from a TicketRun.

**Operation recipe**.
A declared delivery practice that maps a kind of Ticket to the work, evidence, and operational outcomes it requires.

**Human request**.
A durable question or decision that identifies the subject, evidence, and continuation awaiting the human's answer.

**Review bundle**.
The evidence and explanation a human needs to assess a particular change revision.

**Finding**.
A source-linked observation from a retrospective with an explicit scope and proposed improvement.

**Learning decision**.
A Supervisor's recorded assessment of a group of Findings, including changes, unresolved questions, or a reason to make no change.

**Improvement proposal**.
A reviewable change to Agent guidance that states its evidence, expected benefit, and a way to evaluate the result.
