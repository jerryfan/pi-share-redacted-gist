# pi-share-redacted-gist

Publish a redacted pi session as a public GitHub gist.

Installs one pi extension command:

- `/share-redacted`

## What it does

- reads the current persisted pi session file, or `--session @path`
- redacts common sensitive patterns plus long random-looking opaque tokens
- opens a transcript-style review UI by default
- asks for publication attestation unless `--yes`
- creates a public GitHub gist with:
  - `<session>.redacted.jsonl`
  - `openagentsessions.json`
- prints the gist URL and submission hint for openagentsessions

## Install

```bash
pi install npm:pi-share-redacted-gist
```

Then inside pi:

```text
/reload
```

## Usage

```text
/share-redacted
/share-redacted --session @~/.pi/agent/sessions/your-session.jsonl
/share-redacted --topic "auth bugfix" --language "typescript" --tags "bugfix,auth"
/share-redacted --desc "Open agent session (CC0)" --no-review --yes
```

Review UI:

- transcript blocks instead of raw JSONL
- highlights suspicious leftovers the automatic redactor did not catch
- `r` redacts the current suspicious value everywhere
- `s` marks the current suspicious value safe
- `a` adds a literal global redaction
- `x` adds a regex global redaction
- `u` undoes the last manual action
- `e` opens the raw editor as an escape hatch

Flags:

- `--session @path`
- `--desc "text"`
- `--topic "text"`
- `--language "text"`
- `--tags "a,b,c"`
- `--no-review`
- `--yes`

## Requirements

- `gh` CLI installed and authenticated
- a persisted pi session file

## Package notes

- package code license: MIT
- published session metadata license: `CC0-1.0`

## Development

```bash
bun test
bun run check
npm pack --dry-run
```

## Publish

```bash
npm login
npm publish
```
