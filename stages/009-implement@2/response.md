Reverted `.env.example` to its `origin/main` contents to address the only reviewer todo item: protected file changed.

Coverage for todo item:
- `protected files changed (.env.example)`: verified by exact comparison against `origin/main:.env.example`
- Regression/safety check: `poetry run pytest -q` → passed (`2746 passed, 22 skipped`)

Noticed, not touched:
- Existing test run emits several deprecation/runtime warnings, but they are pre-existing and unrelated to this fix.

STATUS: DONE