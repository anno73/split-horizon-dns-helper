# Implementation progress: QNAP ACME DNS-01 custom filtering rules

**Branch:** `feature/qnap-acme-dns01-custom-filtering-rules`
**Status:** In progress.

## Done

- Reviewed the helper's current `permanent` rewrite behavior and command flow.
- Reviewed the QNAP Traefik DNS-01 notes and identified the recommended A-only
  AdGuard custom filtering rules.
- Confirmed the AdGuard Home API exposes filtering status and set-rules
  operations; rule updates replace the full user-rule list.
- Selected a dedicated start/end comment block with an in-block rationale as
  the ownership marker, preserving rules outside the block.
- Identified `traefik.backup.hubmann.casa` as a current overlap and migrated it
  from `permanent` into the new section in the ignored local config.
- Created the dedicated feature branch and added the plan and tracker under
  `Plans/`.
- Implemented the AdGuard status/set-rules calls, A-only rule generation,
  start/end marker reconciliation, conflict checks, and source-host exclusion
  from normal DNS rewrite sync.
- Updated the config template and README; the ignored active config parses and
  has no permanent/custom-rule overlap.
- Added 11 focused tests covering marker reconciliation, API request shapes,
  collision aborts, sync/dry-run, and rewrite exclusion. All tests pass.
- Python syntax checks and `git diff --check` pass.

## Still to do

- Review/stage only feature files, excluding the ignored config and pre-existing
  unrelated untracked files and mode-only worktree change.
- Commit with the required co-author trailer.
- Fetch and inspect upstream changes, then merge and push if the verified
  feature branch can be integrated safely.
