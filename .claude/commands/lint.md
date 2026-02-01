# Lint Command

Check code quality using ruff.

## Usage

```
/lint [--fix]
```

## Behavior

1. Run ruff check on the codebase
2. Optionally auto-fix issues with --fix flag
3. Run ruff format to check formatting

## Commands

```bash
# Check for issues
ruff check nothx tests

# Auto-fix issues (if --fix specified)
ruff check --fix nothx tests

# Check formatting
ruff format --check nothx tests
```

## Output Format

Report results as:
- Number of issues found
- Categories of issues (if any)
- Files affected
