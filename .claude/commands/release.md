# Release Command

Prepare a new release version.

## Usage

```
/release <version>
```

## Behavior

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md with new version section
3. Run tests to verify nothing is broken
4. Stage changes for commit

## Steps

1. **Validate version format** - Must be semver (e.g., 0.2.0)
2. **Update pyproject.toml** - Change version field
3. **Update CHANGELOG.md** - Add new version header with date
4. **Run tests** - Ensure all tests pass
5. **Stage files** - `git add pyproject.toml CHANGELOG.md`

## Output Format

Report:
- Old version -> New version
- Files modified
- Test results
- Ready for commit (yes/no)

## Notes

- Do NOT commit or push automatically
- Do NOT create tags automatically
- Let the user review and commit manually
