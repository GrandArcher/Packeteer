Read [AGENTS.md](../AGENTS.md) and [BOT.md](../BOT.md) first and follow them. They are the rules for this repository: safety (observe by default, never announce a prefix that is not in the learned RIB view), Docker-first, plugins behind `pkg/plugin`, tests for every inject-path change, one issue per PR.

Before pushing: `make test lint` (same checks as CI).
