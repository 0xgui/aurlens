# AI endpoint protocol

Configuration is an explicit UTF-8 TOML file with one `[ai]` table. Unknown keys, duplicate fields, invalid endpoints, and missing source-disclosure consent are rejected.

```toml
[ai]
endpoint = "http://127.0.0.1:8080/v1/chat/completions"
model = "your-model"
send_source = true
allow_loopback_http = true
timeout_seconds = 30
max_request_bytes = 4194304
max_response_bytes = 131072
# api_key_env = "AURLENS_API_KEY"
```

`endpoint` is the complete URL; AURLens does not append a path. HTTP requires numeric loopback and explicit opt-in. HTTPS can use an explicitly selected cloud host. Credentials in URLs, query strings, and fragments are rejected. `api_key_env` names an environment variable; its value becomes a Bearer authorization header.

The request contains `model`, `response_format = {"type":"json_object"}`, and system and user messages. The user message is a JSON string containing `snapshot_digest`, `files`, and `changes`. Each file has a relative `path`, `mode`, `sha256`, and full reviewed `text`. `changes` is null without a baseline and a list of change records otherwise. No tools are supplied.

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

An empty findings list is valid. Severity is `review` or `block`. Each finding needs at least one evidence item. Evidence must point to a current snapshot file, a positive one-based line number, and an exact nonempty substring of that line. Duplicate or unknown inner fields are errors. A returned safety score or verdict is not part of the protocol.

There may be at most 64 findings and 16 evidence items per finding. The summary is limited to 4,096 bytes; a finding message and an evidence quote are each limited to 2,048 bytes. Configurable request duration is 1 to 120 seconds. Request and response byte limits cannot exceed 8 MiB and 1 MiB respectively.

AI errors contain fixed machine-readable reason codes. Raw server error bodies and authorization headers are not included. The application reports unavailable or incompatible models as incomplete rather than retrying a different provider or treating the scan as clean.
