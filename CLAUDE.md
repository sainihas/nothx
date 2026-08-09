# CLAUDE.md

Guidelines for AI assistants working with this codebase.

## Quick Start

```bash
pip install -e ".[dev]"   # Install with dev dependencies
pytest                     # Run tests
python -m nothx           # Run CLI
```

## Architecture

**5-layer classification pipeline** — each layer can decide or defer:

1. **User Rules** (`classifier/rules.py`) — Custom patterns, highest priority
2. **Preset Patterns** (`classifier/patterns.py`) — Known marketing/safe domains
3. **AI Classification** (`classifier/ai.py`) — LLM analyzes email headers
4. **Heuristics** (`classifier/heuristics.py`) — Rule-based scoring (0-100)
5. **Review Queue** — Uncertain cases for manual review

```
IMAP Inbox → Scanner → Classifier Engine → Unsubscriber or Review Queue
```

## Project Structure

```
nothx/
├── cli.py              # Click commands, entry point
├── config.py           # Dataclasses for configuration
├── models.py           # Core enums (Action, EmailType, etc.)
├── db.py               # SQLite layer
├── imap.py             # Email fetching
├── scanner.py          # Inbox scanning
├── unsubscriber.py     # Unsubscribe execution (RFC 8058, GET, mailto)
├── theme.py            # Rich console theme
└── classifier/
    ├── engine.py       # Orchestrates the 5 layers
    ├── ai.py           # AI classification
    ├── providers/      # Anthropic, OpenAI, Gemini, Ollama
    ├── heuristics.py   # Scoring logic
    ├── learner.py      # User preference learning
    └── patterns.py     # Pattern matching
```

## Common Tasks

### Adding a CLI command

```python
@main.command()
@click.option("--flag", help="Description")
def new_command(flag: bool):
    """Command description."""
    # Implementation
```

### Adding an AI provider

1. Create `classifier/providers/your_provider.py`
2. Extend `BaseAIProvider`
3. Register in `classifier/providers/factory.py`

### Adding a classification layer

1. Create module in `classifier/`
2. Implement `classify(stats: SenderStats) -> Optional[Classification]`
3. Return `None` to defer to next layer
4. Register in `classifier/engine.py`

## Code Style

- **Type hints**: All functions must have complete annotations
- **Dataclasses**: Use for data structures
- **Imports**: stdlib → third-party → local
- **Naming**: `snake_case` functions, `PascalCase` classes, `UPPER_CASE` constants

## Important Rules

### Do:
- Mock external services (IMAP, HTTP, AI APIs) in tests
- Use temporary databases for test isolation
- Gracefully degrade (AI → heuristics → review)
- Use parameterized queries for SQLite

### Don't:
- Read email bodies — only headers (From, Subject, Date, List-Unsubscribe)
- Log sensitive data (passwords, API keys)
- Auto-unsubscribe protected domains (banks, .gov, healthcare)
- Crash on external failures

## Testing

```bash
pytest                              # All tests
pytest --cov=nothx                  # With coverage
pytest tests/test_classifier.py -v  # Specific file
```

## Runtime Paths

- Config: `~/.nothx/config.json`
- Database: `~/.nothx/nothx.db`
- Logs: `~/.nothx/logs/`

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
Run `pytest --cov=nothx --cov-fail-under=55`, `ruff check .`, `ruff format --check .`,
and `mypy nothx` locally instead; that is the same ground CI covers.

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
