# CLAUDE.md - AI Assistant Guide for nothx

## Project Overview

**nothx** is an AI-powered email unsubscribe tool that automatically scans, classifies, and unsubscribes users from unwanted marketing emails. It's a Python CLI application designed to run locally with privacy-first principles.

- **Version**: 0.1.0 (Beta)
- **Python**: 3.11+
- **License**: MIT
- **Entry Point**: `nothx/cli.py:main`

## Quick Reference

```bash
# Install dependencies (development)
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=nothx

# Run the CLI
python -m nothx <command>
# or after install:
nothx <command>
```

## Project Structure

```
nothx/
├── nothx/                      # Main package
│   ├── __init__.py             # Package init
│   ├── cli.py                  # CLI commands (click-based)
│   ├── config.py               # Configuration management
│   ├── models.py               # Data models & enums
│   ├── scanner.py              # Email inbox scanning
│   ├── imap.py                 # IMAP client & email fetching
│   ├── unsubscriber.py         # Unsubscribe execution
│   ├── db.py                   # SQLite database layer
│   ├── scheduler.py            # Cross-platform task scheduling
│   ├── logging.py              # Logging setup
│   └── classifier/             # 5-layer classification engine
│       ├── __init__.py
│       ├── engine.py           # Classification orchestrator
│       ├── rules.py            # User rules (Layer 1)
│       ├── patterns.py         # Preset patterns (Layer 2)
│       ├── ai.py               # AI classification (Layer 3)
│       ├── heuristics.py       # Heuristic scoring (Layer 4)
│       └── utils.py            # Pattern matching utilities
├── patterns/
│   └── defaults.json           # Default classification patterns
├── tests/                      # Test suite
│   ├── test_classifier.py      # Pattern & heuristic tests
│   ├── test_engine.py          # Classification engine tests
│   ├── test_config.py          # Configuration tests
│   ├── test_db.py              # Database tests
│   └── test_utils.py           # Utility tests
├── pyproject.toml              # Project configuration
├── README.md                   # User documentation
└── LICENSE                     # MIT License
```

## Architecture

### 5-Layer Classification System

The core architecture is a hierarchical classification pipeline where each layer can make a final decision or defer to the next:

1. **User Rules** (`classifier/rules.py`) - Highest priority, pattern matching for custom rules
2. **Preset Patterns** (`classifier/patterns.py`) - Known marketing/safe patterns from `patterns/defaults.json`
3. **AI Classification** (`classifier/ai.py`) - Claude API analyzes email headers
4. **Heuristic Scoring** (`classifier/heuristics.py`) - Rule-based scoring (0-100 scale)
5. **Review Queue** - Uncertain cases queued for manual review

### Key Data Flow

```
IMAP Inbox → Scanner → Classifier Engine → Action Decision
                                              ↓
                                    ┌─────────┴─────────┐
                                    ↓                   ↓
                              Unsubscriber         Review Queue
                                    ↓
                              RFC 8058 / GET / Mailto
```

## Key Components

### Models (`nothx/models.py`)

Core enums and dataclasses:
- `EmailType`: MARKETING, TRANSACTIONAL, SECURITY, NEWSLETTER, COLD_OUTREACH, UNKNOWN
- `Action`: KEEP, UNSUB, BLOCK, REVIEW
- `SenderStatus`: UNKNOWN, KEEP, UNSUBSCRIBED, BLOCKED, FAILED
- `UnsubMethod`: ONE_CLICK, GET, MAILTO
- `EmailHeader`: Parsed email metadata
- `SenderStats`: Aggregated stats per domain
- `Classification`: Result with confidence & reasoning

### Configuration (`nothx/config.py`)

Dataclasses for type-safe configuration:
- `AccountConfig` - Email credentials
- `AIConfig` - AI provider settings (Anthropic)
- `Config` - Master configuration

Config stored at: `~/.nothx/config.json` (mode 0600)

### Database (`nothx/db.py`)

SQLite database at `~/.nothx/nothx.db` with tables:
- `senders` - Domain tracking and status
- `unsub_log` - Unsubscribe attempt history
- `corrections` - User corrections for AI learning
- `runs` - Execution history
- `rules` - User-defined classification rules

### CLI Commands (`nothx/cli.py`)

Main commands using Click framework:
- `nothx init` - Setup wizard
- `nothx run` - Scan and process (supports `--dry-run`, `--verbose`, `--auto`)
- `nothx status` - Show statistics
- `nothx review` - Manual review queue
- `nothx undo [domain]` - Undo unsubscribes
- `nothx schedule` - Manage scheduling
- `nothx rule <pattern> <action>` - Add rules
- `nothx config` - View/modify settings

## Coding Conventions

### Type Hints

All functions must have complete type annotations:

```python
def classify_sender(
    stats: SenderStats,
    config: Config,
) -> Classification:
    ...
```

### Dataclasses

Use dataclasses for data structures:

```python
@dataclass
class Classification:
    action: Action
    confidence: float
    reasoning: str
    layer: str
```

### Error Handling

- Use try-except with logging
- Graceful degradation (AI → heuristics → review)
- Never crash on external failures (IMAP, HTTP, API)

### Naming

- `snake_case` for functions and variables
- `UPPER_CASE` for constants
- `PascalCase` for classes

### Imports

Standard library first, then third-party, then local:

```python
import json
from pathlib import Path

import click
from rich.console import Console

from nothx.models import Action, Classification
```

## Testing

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=nothx

# Specific test file
pytest tests/test_classifier.py

# Specific test
pytest tests/test_classifier.py::test_pattern_matching -v
```

### Test Patterns

- Use pytest fixtures for setup/teardown
- Mock external services (IMAP, HTTP, Anthropic API)
- Use temporary databases for isolation
- Test each classification layer independently

### Example Test Structure

```python
@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db') as f:
        db = Database(f.name)
        db.init()
        yield db

def test_classification_engine(temp_db):
    """Test the full classification pipeline."""
    engine = ClassificationEngine(config, temp_db)
    result = engine.classify(sender_stats)
    assert result.action == Action.UNSUB
```

## Important Patterns

### Privacy First

- **Never read email bodies** - Only headers (From, Subject, Date, List-Unsubscribe)
- Config files have 0600 permissions
- All data stored locally in `~/.nothx/`

### Confidence Thresholds

Default thresholds (configurable):
- Auto-unsubscribe: confidence >= 0.80
- Auto-keep: confidence >= 0.80
- Below threshold: goes to review queue

### Protected Domains

These categories are never auto-unsubscribed:
- Government (.gov)
- Banks and financial
- Healthcare
- Security notifications

### Unsubscribe Method Priority

1. RFC 8058 One-Click POST (best)
2. HTTPS GET request
3. Mailto (requires SMTP)

## Common Development Tasks

### Adding a New CLI Command

1. Add command in `nothx/cli.py`:
```python
@main.command()
@click.option('--flag', help='Description')
def new_command(flag: bool):
    """Command description."""
    console = Console()
    # Implementation
```

### Adding a Classification Layer

1. Create module in `nothx/classifier/`
2. Implement `classify(stats: SenderStats) -> Optional[Classification]`
3. Return `None` to defer to next layer
4. Register in `classifier/engine.py`

### Adding a Database Table

1. Add schema in `db.py` `init()` method
2. Add CRUD methods
3. Add migration logic if needed for existing databases

### Modifying Configuration

1. Add field to appropriate dataclass in `config.py`
2. Update `to_dict()` and `from_dict()` methods
3. Add CLI option in `cli.py` if user-configurable

## Dependencies

### Core
- `anthropic>=0.40.0` - Claude AI API
- `click>=8.0` - CLI framework
- `rich>=13.0` - Terminal formatting

### Development
- `pytest>=7.0` - Testing
- `pytest-cov>=4.0` - Coverage

### Standard Library (heavily used)
- `sqlite3` - Database
- `imaplib` - Email protocol
- `smtplib` - SMTP sending
- `email` - Message parsing
- `json` - Config serialization
- `pathlib` - File operations

## AI Integration Notes

### Anthropic API Usage

- Model: `claude-sonnet-4-20250514` (default)
- Only send email headers, never bodies
- Batch classification for efficiency
- Graceful fallback to heuristics on API failure

### Prompt Structure

AI receives:
- Domain name
- Email count
- Open rate
- Sample subject lines
- Previous user corrections (for learning)

## Security Considerations

- Never log sensitive data (passwords, API keys)
- Validate all external input
- Use parameterized queries for SQLite
- Timeout HTTP requests (30s default)
- Verify SSL certificates

## File Locations at Runtime

- Config: `~/.nothx/config.json`
- Database: `~/.nothx/nothx.db`
- Logs: `~/.nothx/logs/`
- macOS Schedule: `~/Library/LaunchAgents/com.nothx.auto.plist`
- Linux Schedule: `~/.config/systemd/user/nothx.{service,timer}`
