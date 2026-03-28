# pi-share-redacted-gist

Publish a redacted pi session as a public GitHub gist and/or Hugging Face dataset. Hugging Face support is first-class.

Installs one pi extension command:

- `/share-redacted`

## What it does

- reads the current persisted pi session file, or `--session @path`
- redacts common sensitive patterns plus a detect-secrets-inspired plugin stack for secrets/tokens
- wholesale-redacts tool read/write/edit payloads plus obvious bash-read outputs for high-risk files like `.env`, SSH keys, cloud credentials, and kube/docker configs
- opens a transcript-style review UI by default
- asks for publication attestation unless `--yes`
- publishes two files:
  - `<session>.redacted.jsonl`
  - `openagentsessions.json`
- can publish to:
  - a public GitHub gist
  - a Hugging Face dataset
  - both
- stores Hugging Face uploads under timestamped paths like `sessions/2026-03-28T17-10-55Z-session.redacted/`
- prints the published URL(s) and an openagentsessions submission hint when a gist was created

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
/share-redacted --publisher huggingface --dataset lukaskawerau/openagentsessions
/share-redacted --publisher both --desc "Open agent session (CC0)" --no-review --yes
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
- `--publisher gist|huggingface|both`
- `--dataset owner/name`
- `--no-review`
- `--yes`

## Hugging Face config

Config files are merged, with project-local values overriding global ones:

- `~/.pi/agent/pi-share-redacted-gist.json`
- `<cwd>/.pi/pi-share-redacted-gist.json`

Example:

```json
{
  "publishers": {
    "gist": {
      "enabled": true
    },
    "huggingface": {
      "enabled": true,
      "datasets": [
        "lukaskawerau/openagentsessions",
        "my-org/internal-agent-sessions"
      ],
      "defaultDataset": "lukaskawerau/openagentsessions",
      "visibility": "public",
      "pathPrefix": "sessions"
    }
  },
  "redaction": {
    "sensitiveFiles": {
      "enabled": true,
      "extraPatterns": [
        "config/private.settings",
        "/(^|\\/)secrets\\/[^/]+\\.txt$/i"
      ]
    }
  }
}
```

Recommended setup:

1. create or pick a dataset repo you can already write to
2. add a Hugging Face access token via `HF_TOKEN` or pi `auth.json`
3. configure that dataset in `pi-share-redacted-gist.json`
4. run `/share-redacted --publisher huggingface` or `/share-redacted --publisher both`

`redaction.sensitiveFiles.extraPatterns` accepts either exact basename/path-suffix matches or `/regex/flags` strings.

Auth:

- `HF_TOKEN` environment variable
- or `~/.pi/agent/auth.json`:

```json
{
  "huggingface": { "type": "api_key", "key": "hf_..." }
}
```

The `key` field can also use pi auth-file indirection such as shell commands (`"!op read ..."`) or env var names.

Notes:

- if your token can create repos, the extension will create the configured dataset when missing
- if your token cannot create repos, point the config at an existing dataset you already control
- Hugging Face uploads land under `sessions/<timestamp>-<session-name>/`

## Requirements

- for GitHub gist publishing: `gh` CLI installed and authenticated
- for Hugging Face publishing: `HF_TOKEN` or `~/.pi/agent/auth.json` entry for `huggingface`
- a persisted pi session file

## Legal / warranty notice

This extension is provided **as-is**, with **no warranty** of any kind, express or implied.

By using it, you accept that:

- you are solely responsible for reviewing anything before you publish it
- you are solely responsible for any credentials, secrets, personal data, source code, or other information you choose to share
- automatic redaction can reduce risk, but it cannot guarantee that every sensitive value or file will be caught
- the authors and contributors are not liable for any loss, damages, claims, or other consequences arising from use of this extension or from any data you publish with it

If leaking a session would hurt, assume the redactor missed something and review it manually before publishing. Paranoia earns its keep.

## Package notes

- package code license: MIT
- published session metadata license: `CC0-1.0`
- secret scanning uses a detect-secrets-inspired plugin pipeline
- built-in secret plugins also detect Hugging Face access tokens (`hf_...`)
- built-in secret plugins:
  - `PrivateKeyDetector`
  - `GitHubTokenDetector`
  - `AwsKeyDetector`
  - `OpenAIDetector`
  - `HuggingFaceTokenDetector`
  - `GoogleApiKeyDetector`
  - `SlackTokenDetector`
  - `JwtDetector`
  - `BearerTokenDetector`
  - `KeywordDetector`
  - `HexHighEntropyString`
  - `Base64HighEntropyString`
  - `OpaqueTokenDetector`

## Development

```bash
bun test
bun run check
npm pack --dry-run
```