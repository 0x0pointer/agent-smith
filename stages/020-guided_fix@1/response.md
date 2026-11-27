Summary:
- Maintainer feedback recorded word-for-word in `/tmp/fabro/feedback.md`.
- Feedback asked to ignore the reviewer’s phase-control scoping issue because dashboard users are trusted and VPN-only.
- Updated `/tmp/fabro/spec.md` to reflect that accepted-risk exception:
  - AC5/AC6 now exclude legacy phase-control endpoints and typed phase steering from run-token isolation for this build.
  - Review focus now excludes those accepted-risk controls.
  - Added final section `Maintainer feedback after approval` with the feedback verbatim.
- No repository code or tests were changed in this escalation step, because the feedback dropped the blocked requirement rather than asking for a code fix.
- No red/green regression test was added for the ignored phase-control issue because it is now explicitly out of scope.

Verification run after the last edit:
- `poetry run pytest -q`
- Result: `2804 passed, 22 skipped, 11 warnings in 56.72s`

Could not / did not do:
- Did not implement run-scoped phase-control behavior; the maintainer explicitly accepted ignoring that issue for now.