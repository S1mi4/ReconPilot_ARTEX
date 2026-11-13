# Issue tracker: GitHub

Issues and specs for this repo live in GitHub Issues in `S1mi4/ReconPilot_ARTEX`. Use the `gh` CLI with this repository. This is the writable `origin`; `RuoJi6/ARTEX` is the upstream remote.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

## Pull requests as a triage surface

**PRs as a request surface: no.**

## When a skill says "publish to the issue tracker"

Create a GitHub issue in `S1mi4/ReconPilot_ARTEX`.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments` in this repository.
