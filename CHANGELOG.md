# Changelog

## 0.3.0 - 2026-03-28

### Added
- added regression tests for gist submission messaging

### Changed
- show the created gist URL in the final submission message
- use a single final notification so the gist URL does not get buried by a follow-up prompt
- fall back more gracefully when parsing `gh gist create` output

## 0.2.0 - 2026-03-28

### Added
- extracted redaction logic into `extensions/redaction.ts`
- added `bun test` coverage for privacy redaction heuristics
- added structured JSONL redaction with recursive string traversal
- added heuristic detection for long random-looking opaque tokens
- added explicit placeholders for opaque token classes:
  - `[REDACTED_OPAQUE_BASE64]`
  - `[REDACTED_OPAQUE_HEX]`
  - `[REDACTED_OPAQUE]`
- added dedicated UUID placeholder: `[REDACTED_UUID]`

### Changed
- strengthened privacy redaction for public gist publishing
- preserved likely-safe values such as model-like slugs and git hashes in safe context
- updated README development notes for test workflow
