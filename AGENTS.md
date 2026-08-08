# AGENTS.md

Architecture, project layout, code style, and the classification-pipeline rules live in
[`CLAUDE.md`](CLAUDE.md) — read that first. This file carries the one thing that governs
how work gets landed rather than how it gets written.

## Pull requests

<!-- draft-pr-policy -->

`main` is protected: every change lands through a PR, and **every PR is opened as a
draft**.

```bash
gh pr create --draft --title "…" --body "…"
```

Draft is the resting state. A PR stays in draft for as long as it takes and through as
many pushes as it takes — finishing the work is not what takes it out of draft.

Only when Sai asks for it to be merged, and in this order:

1. `gh pr ready <n>` — take it out of draft.
2. `gh pr checks <n> --watch` — wait for the run to finish. Don't skip this: step 1 is
   what starts CI, so the checks are beginning from cold right here.
3. `gh pr merge <n> --squash --delete-branch` — merge only on green. If a check fails,
   fix it on the branch, push, and go back to step 2.

CI not running on drafts is deliberate. `ci.yml` lists `ready_for_review` in its `types:`
and guards every job on `github.event.pull_request.draft == false`, so a draft PR spends
no Actions minutes. Don't route around that — no marking a PR ready early to see whether
CI is happy, no `workflow_dispatch`, no pushing the branch elsewhere to provoke a run.
Run `pytest`, `ruff check .`, and `ruff format --check .` locally instead; that is the
same ground CI covers.

## Commit attribution

<!-- commit-attribution-policy -->

- All commits in this repo are owned solely by `sainihas <gsainihas@gmail.com>`. Never
  commit under any other identity.
- Never add a `Co-Authored-By:` trailer naming Claude, Anthropic, or any other AI tool.
- Never add the `🤖 Generated with [Claude Code]` footer to a commit message or PR body.

This applies to every agent and every environment — Claude Code, Codex, Cursor, cloud and
scheduled sessions, and edits made through the GitHub web UI. Local git hooks in
`~/.config/git/hooks/` enforce it on Sai's machine, but they do **not** run in cloud
sessions or web edits, so follow the rule directly rather than relying on them.
