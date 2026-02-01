# Contributing to nothx

Thank you for your interest in contributing to nothx! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.11+
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/nothx/nothx.git
cd nothx

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests to verify setup
pytest
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Your Changes

- Follow the coding conventions in `CLAUDE.md`
- Add type hints to all functions
- Keep changes focused and minimal

### 3. Test Your Changes

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=nothx

# Run specific tests
pytest tests/test_classifier.py -v
```

### 4. Lint Your Code

```bash
# Check for issues
ruff check nothx tests

# Auto-fix issues
ruff check --fix nothx tests

# Format code
ruff format nothx tests
```

### 5. Submit a Pull Request

- Write a clear PR description
- Reference any related issues
- Ensure all tests pass

## Code Style

### Python Style

- Use type hints for all function parameters and returns
- Use dataclasses for data structures
- Follow PEP 8 (enforced by ruff)
- Keep functions small and focused

### Imports

Order imports as:
1. Standard library
2. Third-party packages
3. Local modules

```python
import json
from pathlib import Path

import click
from rich.console import Console

from nothx.models import Action
```

### Documentation

- Add docstrings to public functions
- Keep comments minimal - prefer clear code
- Update CLAUDE.md if adding new patterns

## Architecture Guidelines

### Adding a CLI Command

1. Add command in `nothx/cli.py`
2. Follow existing patterns for options/arguments
3. Use `rich` for output formatting
4. Add tests in `tests/`

### Adding a Classification Layer

1. Create module in `nothx/classifier/`
2. Implement `classify(stats: SenderStats) -> Optional[Classification]`
3. Return `None` to defer to next layer
4. Register in `classifier/engine.py`

### Database Changes

1. Add migration logic for existing databases
2. Use parameterized queries (no string formatting)
3. Add tests with temporary databases

## Testing Guidelines

- Use pytest fixtures for setup
- Mock external services (IMAP, HTTP, APIs)
- Use temporary files/databases for isolation
- Aim for high coverage on new code

## What We're Looking For

- Bug fixes
- Performance improvements
- Documentation improvements
- New classification patterns
- Email provider compatibility fixes
- Accessibility improvements

## What We're NOT Looking For

- Major architectural changes (discuss first)
- New dependencies without justification
- Features that compromise privacy
- Code that reads email bodies

## Questions?

Open an issue for discussion before starting large changes.
