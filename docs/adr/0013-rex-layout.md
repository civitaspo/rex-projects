---
status: accepted
---

# Rex layout: a session per Project, a tab per Ticket, a block per Agent

Each Project has its own Rex session, labelled `rxp:<project>`. Each Ticket has its own tab, and each Agent Session runs in its own block, with the Coordinator on the left and helper Agents stacked on the right. A Project's Supervisor has its own tab in that session. A control session, `rxp`, holds `serve` and the Factory Project's Supervisor. The UI opens as a floating layer from any session. Rex tab badges show status through `program_status`.

Background launches never take focus. Choosing a Ticket in the UI focuses and zooms the Agent that needs attention. A Ticket's tab closes after its Postmortem unless it is pinned.
