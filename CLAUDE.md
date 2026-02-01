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
@click.option('--flag', help='Description')
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
