# Evidence

What this project knows, how it knows it, and how to check again. Nothing here is a promise about the future: Claude Code and the
gateway change, and an old observation is a record of that day, not a property of the software.

| Page | What it is |
|---|---|
| [findings.md](findings.md) | 22 numbered claims the design relies on. Each has the claim, component and version, environment, method, date, status and the command that reruns it |
| [runs.md](runs.md) | The dated run log: what was run, on which versions, where |
| [rerun.md](rerun.md) | How to run the repro harness (offline and live) and how to read `PASS`, `CHANGED`, `ERROR` and `SKIP` |
| [limitations.md](limitations.md) | The full list of open questions and untested paths |
| [desktop-and-cowork.md](desktop-and-cowork.md) | Why this client cannot route the Claude desktop app or Cowork, and the documented route |
| [../support-matrix.md](../support-matrix.md) | The compatibility statement: which versions, at which level, and what to rerun for a newer one |

A claim in this repository is *authoritative* (vendor documentation, cited), *observed* (a run showed it; versions, environment and date
kept) or *inferred* (read or reasoned; say so). Prefer the first two. See the support matrix for the documentation pages worth
re-reading at each Claude Code upgrade.
