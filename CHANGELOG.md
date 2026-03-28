# Changelog

## 0.5.0 - 2026-03-28

### Added
- added a detect-secrets-inspired secret plugin pipeline for auto-redaction and review
- added built-in secret plugins for private keys, provider tokens, bearer tokens, keyword assignments, and entropy-based opaque strings
- added regression tests for plugin initialization and private-key redaction

### Changed
- unified auto-redaction and review-mode secret detection so both use the same plugin stack
- expanded internal/private URL redaction to also cover `.home`, `.arpa`, and `.test`

## 0.4.0 - 2026-03-28

### Added
- added a transcript-style redaction review UI focused on under-redaction
- added manual literal and regex redaction actions with undo support
- added review-model tests for transcript extraction and manual redaction helpers

### Changed
- replaced the raw full-session editor as the default review step with a block-based reviewer
- kept the raw editor as an explicit escape hatch from the reviewer
- sanitized reviewer display output to avoid TUI glitches from ANSI/control sequences
- reduced false positives for file line references such as `README.md:32-49` and `package.json:23-38`

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
