# AI backends and response protocol

`aurlens setup` creates private user settings. `scan` loads those settings unless `--no-ai` or an explicit `--config` is supplied. Configuration is UTF-8 TOML with one `[ai]` table. Unknown keys, duplicate fields, invalid endpoints, and missing source-disclosure consent are rejected. Settings and credential files inside the current or baseline checkout are rejected before dispatch.

## HTTP backend

```toml
[ai]
backend = "http"
endpoint = "http://127.0.0.1:8080/v1/chat/completions"
model = "your-model"
send_source = true
allow_loopback_http = true
timeout_seconds = 30
max_request_bytes = 4194304
max_response_bytes = 131072
# api_key_env = "AURLENS_API_KEY"
```

Omitting `backend` preserves the original HTTP configuration format. `endpoint` is the complete URL; AURLens does not append a path. HTTP requires numeric loopback and explicit opt-in. HTTPS can use an explicitly selected cloud host. Credentials in URLs, query strings, and fragments are rejected. `api_key_env` names an environment variable; its value becomes a Bearer authorization header. Alternatively, `api_key_file` names an absolute, regular, user-owned file with no group or other permissions. The two credential options are mutually exclusive. Keys are limited to 8,192 bytes and contain no control characters.

## Codex backend

```toml
[ai]
backend = "codex"
executable = "/absolute/path/to/codex"
send_source = true
timeout_seconds = 120
# model = "an-explicit-model"
```

The executable must support the restricted `codex exec` profile. An omitted model uses the CLI default and appears as `codex-default` in reports. Codex handles its own saved login. AURLens does not read or copy its authentication files.

The process runs in a private empty directory with a read-only sandbox, shell execution disabled, ignored ambient configuration and instructions, and disabled hooks, plugins, MCP servers, and subagents. Some utility tools may remain available through Codex model metadata. Any tool activity makes the review incomplete. The package snapshot travels through stdin. Output, runtime, and process cleanup are bounded. The final structured response passes the same evidence verification as HTTP responses.

## HTTP request and shared opinion schema

The request contains `model`, `response_format = {"type":"json_object"}`, and system and user messages. The user message is a JSON string containing `snapshot_digest`, `files`, and `changes`. Each text file has a relative `path`, `mode`, `sha256`, and full reviewed `text`. A file that is not text has `path`, `mode`, `sha256`, `size` and `"opaque": true`, and no `text`: its bytes are not sent. Evidence cannot point into such a file. `changes` is null without a baseline and a list of change records otherwise. No tools are supplied.

This is the [Chat Completions request shape](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). JSON mode alone does not validate the application schema; AURLens validates the model's response separately.

A successful completion has exactly one choice, an assistant text message, and `finish_reason = "stop"`. Refusals and tool calls are unsupported. Empty null metadata fields are accepted. The message content must be a JSON object of this form:

```json
{
  "snapshot_digest": "the exact hash supplied in the request",
  "summary": "Description of the observed package behavior.",
  "findings": [
    {
      "severity": "review",
      "message": "Explain the specific concern.",
      "evidence": [
        {"path": "PKGBUILD", "line": 8, "quote": "an exact substring on line 8"}
      ]
    }
  ]
}
```

An empty findings list is valid. Severity is `info`, `review` or `block`. An `info` finding is listed in the report and does not change the decision; `review` leads to `manual_review` and `block` to `blocked`. The instructions sent with every request reserve `review` for a concrete security risk and `block` for behaviour with no honest use in a recipe, and ask for packaging style and facts true of every source build to be `info` or left out. A model cannot lower or remove a finding from a deterministic rule, whatever severity it uses. See [rules and severities](rules.md). Each finding needs at least one evidence item, with a string `path`, an integer `line` and a string `quote`. Evidence of another shape, and duplicate or unknown inner fields, are errors. A returned safety score or verdict is not part of the protocol.

Evidence is verified when it names a current text file of the snapshot, a line number within that file, and a nonempty exact substring of that line. A finding with evidence that is not verified is kept as an unverified finding rather than making the AI review incomplete:

- The evidence that does not match is dropped; the evidence that matches is kept. A finding with none left has an empty `evidence` list.
- Its `rule_id` is `AI-UNVERIFIED-` followed by its position in the model's list (`AI-UNVERIFIED-002`); a verified finding is `AI-` and its position (`AI-001`). `source` is `ai` for both.
- Its message starts with "The citation the model gave for this could not be verified against the recipe." followed by the model's message.
- `block` becomes `review`, because nobody can check the claim and it must not stop an install with no way forward. `review` and `info` are unchanged, and the decision and `risk` follow as for any model finding.

Nothing is shown as a citation unless it matches the snapshot. A consumer that wants to treat unverified findings differently selects them by the `AI-UNVERIFIED-` prefix.

There may be at most 64 findings and 16 evidence items per finding. The summary is limited to 4,096 bytes; a finding message and an evidence quote are each limited to 2,048 bytes. Configurable request duration is 1 to 120 seconds. Request and response byte limits cannot exceed 8 MiB and 1 MiB respectively.

These limits apply whether or not the evidence matches: more findings or evidence items, or a longer path or quote, make the AI review incomplete (`ai_opinion_bounds`), as do a wrong `snapshot_digest`, a malformed or truncated response, and every other failure above. Only evidence that does not match the snapshot is handled as described in the previous section.

AI errors contain fixed machine-readable reason codes. Raw server error bodies and authorization headers are not included. The application reports unavailable or incompatible models as incomplete rather than retrying a different provider or treating the scan as clean.
