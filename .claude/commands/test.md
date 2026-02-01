# Test Command

Run the test suite with coverage reporting.

## Usage

```
/test [options]
```

## Behavior

1. Run pytest with coverage enabled
2. Show coverage report with missing lines
3. Report any failures clearly

## Command

```bash
pytest --cov=nothx --cov-report=term-missing
```

## Output Format

Report results as:
- Number of tests passed/failed
- Coverage percentage
- Any failing tests with error messages
