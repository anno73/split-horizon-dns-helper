# QNAP ACME DNS-01 custom filtering rules

**Branch:** `feature/qnap-acme-dns01-custom-filtering-rules`

## Goal

Manage the QNAP Traefik DNS-01 A-only custom filtering rules in AdGuard Home.
The A-only condition preserves private A answers while allowing SOA lookups
needed for ACME zone discovery to reach the authoritative DNS.

## Implementation

1. Create `feature/qnap-acme-dns01-custom-filtering-rules`, preserving all
   existing local changes and unrelated untracked files.
2. Extend `split-dns-helper.py` with a `custom_filtering_rules` config section
   that maps answers to hostnames and generates the AdGuard rule format from
   the QNAP DNS-01 notes.
3. Use AdGuard Home's filtering status and set-rules API. Preserve all rules
   outside a dedicated helper-owned comment block. The block must have explicit
   start/end comments and explain that A-only rewrites let SOA queries pass for
   ACME DNS-01. Replace the whole block during sync to update or remove
   helper-managed rules without replacing unrelated user rules.
4. Compare hostnames in `permanent` and `custom_filtering_rules` before
   executing commands. Print a warning and abort on overlap, before any
   external read or write, so the config must be corrected first.
5. Add the QNAP entries to the ignored local `config.yml`, moving
   `traefik.backup.hubmann.casa` from `permanent` into the new section. Do not
   stage this ignored file or expose its credentials.
6. Update `config.yml.template` and `README.md` with the section format,
   managed marker behavior, collision behavior, and QNAP ACME/SOA rationale.
7. Commit only feature files. Merge and push the verified branch if the
   upstream is accessible and its state permits a safe integration.

## Testing

1. Add focused tests for generated A-only rules, marker-block replacement,
   preservation of unrelated rules, empty-section cleanup, and overlap
   detection.
2. Test that overlap warns and aborts before AdGuard API calls or other
   mutations.
3. Exercise sync with mocked AdGuard status/set-rules calls, including dry-run
   behavior and API errors.
4. Run Python syntax validation and the focused test suite using `uv`.
5. Review the final diff and verify ignored config credentials and unrelated
   worktree changes are not included in the commit.
