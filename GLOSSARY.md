# rex-projects

rex-projects is a Rex plugin that runs cooperating coding Agents to complete the Tickets of several Projects at once, and improves how they work over time.

## Loops

**Inner loop**:
The part of the system that turns an intent snapshot into verified results and reports what happened. rex-projects is the inner loop.

**Outer loop**:
The part of the system that decides what to build, keeps intent current, and improves the Harness from what the inner loop reports. A Supervisor runs it.

**Harness**:
Everything around a model that shapes an Agent's results: the target repository's checks and docs, Playbooks, Skills, Roles, configuration, and rex-projects itself.
_Avoid_: profile, when you mean the whole environment

## Work

**Project**:
One repository with a goal, an autonomy level, and its Tickets.
_Avoid_: workspace, mission

**Ticket**:
A unit of work in a Project. A Project is complete when all of its Tickets have ended.
_Avoid_: task, issue (for the local record)

**Brief**:
The versioned intent of a Ticket. Amending a Brief creates a new version and delivers it to the Coordinator.
_Avoid_: spec, prompt

**External ref**:
A link from a Ticket to an item in an external tracker. A Ticket may have several.

**Origin**:
Where a Ticket came from, such as an external ref, a parent Ticket, or a Finding.

**Stage**:
The free-form name of the phase a Coordinator reports for a running Ticket. A Playbook defines the vocabulary.
_Avoid_: phase state, status

**Ticket state**:
One of `backlog`, `ready`, `running`, `waiting`, `verifying`, `done`, `abandoned`, or `failed`.
_Avoid_: status, when you mean a Stage

## Agents

**Agent**:
A logical worker with a Role inside a Ticket or Project. It outlives the processes that run it.

**Session**:
One run of an Agent in a Rex block, with the harness conversation it can resume.

**Role**:
A template for an Agent: base instructions, provider, and model.

**Coordinator**:
The one Agent per Ticket that plans the work, starts helper Agents, and reports the Ticket's progress. It does not implement.

**Helper Agent**:
An Agent a Coordinator starts for part of a Ticket, such as a Worker, Verifier, or Reviewer.

**Verifier**:
A helper Agent that checks a change it did not write.

**Postmortem**:
The Agent that reviews an ended Ticket and records Findings.
_Avoid_: retro agent

**Supervisor**:
The long-lived Agent that runs the outer loop for one Project.
_Avoid_: hypervisor, manager

**Factory Project**:
The Project whose repository is the shared rex-projects configuration. Its Supervisor improves shared Playbooks, Roles, and Skills.

## Control

**Playbook**:
A Markdown document that tells a Coordinator how to complete a kind of Ticket and declares its Stages, Gates, Verification, Roles, and budgets.
_Avoid_: workflow definition, pipeline

**Gate**:
A Stage a Coordinator may enter only after an Approval.

**Approval**:
A decision a Gate requires. Policy names who gives it: a human, the Supervisor, or nobody.

**Verification**:
The checks and Verifier run that a Ticket must pass before it is done.
_Avoid_: done check, acceptance

**Policy**:
Human-owned settings for a Project: its autonomy level, approvers, and budgets. Agents cannot change it.

**Autonomy level**:
How much of a Project's work runs without a human, from A0 (manual) to A3 (self-directing).

**Wake token**:
A fixed line typed into an idle Agent's terminal so that it reads its inbox.

## Learning

**Finding**:
An observation from a Postmortem, with evidence and a recurrence key.

**Improvement**:
A proposed change to the Harness derived from Findings, with the layer it targets.
_Avoid_: lesson, rule

**Fix ladder**:
The preference order for where an Improvement lands, from mechanical checks in the repository down to time-limited notes.

**Digest**:
A periodic summary of merged changes, reverts, and Project health that a human samples.
