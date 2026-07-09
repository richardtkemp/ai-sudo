# askgw Protocol Reference

The `askgw/1` protocol defines how a client application communicates with the foci ask gateway — a local Unix-socket server that forwards questions to the foci user's chat (Telegram, Discord, Android app). The user responds inline; the answer routes back over the socket.

For setup and configuration of the ask gateway itself, see the [foci ASKGW docs](https://github.com/richardtkemp/foci/blob/main/docs/ASKGW.md).

## Transport

Newline-delimited JSON over a Unix socket (default path: `~/data/askgw.sock`). The client connects, sends one `ask` frame per line, and reads response frames back. The connection stays open for multiple asks; each is matched by `id`.

## Version

Every frame includes `"protocol": "askgw/1"`.

## Frame types

| Direction | Type | Purpose |
|-----------|------|---------|
| Client → foci | `ask` | Present one or more questions to the human |
| Client → foci | `cancel` | Withdraw a pending question |
| Client → foci | `notify` | Informational (tolerated, no action taken) |
| foci → Client | `answer` | The human's response (or timeout/dismissed/unavailable) |
| foci → Client | `ack` | Question accepted and presented to the human |
| foci → Client | `error` | Validation failure or server error |

## `ask` frame

Sent by the client to present a question.

```json
{
  "protocol": "askgw/1",
  "type": "ask",
  "id": "my-unique-id",
  "source": "myapp",
  "title": "Deploy to production?",
  "urgency": "normal",
  "timeout_seconds": 120,
  "agent": "arnix",
  "questions": [
    {
      "key": "deploy",
      "header": "Deployment",
      "question": "Deploy v1.2.3 to production?",
      "multiSelect": false,
      "options": [
        { "label": "Yes", "description": "Deploy now" },
        { "label": "No", "description": "Abort" }
      ]
    }
  ]
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `protocol` | yes | Must be `"askgw/1"` |
| `type` | yes | Must be `"ask"` |
| `id` | yes | Unique identifier for this ask (per connection). **Must not contain `:`** — used internally for button routing |
| `source` | no | Human-readable name of the calling application |
| `title` | no | Title shown in the notification |
| `urgency` | no | `"normal"` (default) or `"high"` |
| `timeout_seconds` | no | Seconds before the question auto-expires. Falls back to the server's `default_timeout_seconds`. `0` = no timeout |
| `agent` | no | Which foci agent to route to. Falls back to the server's `default_agent` |
| `questions` | yes | Array of questions (at least one) |

### Question object

| Field | Required | Description |
|-------|----------|-------------|
| `key` | yes | Unique key within this ask. Used to key the answer |
| `header` | no | Short label shown above the question |
| `question` | yes | The question text |
| `multiSelect` | no | If `true`, the user can select multiple options |
| `options` | yes | Array of options (at least one) |

### Option object

| Field | Required | Description |
|-------|----------|-------------|
| `label` | yes | The selectable label. Must be unique within the question |
| `description` | no | Optional description shown alongside the label |

### Validation rules

- `id` must not contain `:`.
- `questions` must be non-empty.
- Each question `key` must be unique within the ask.
- Each question must have non-empty `question` text and at least one option.
- Option labels must be non-empty and unique within the question.

### Multi-question flows

When `questions` has multiple entries, they are presented to the human one at a time. Answering one advances to the next. The final `answer` frame includes all responses keyed by question `key`.

## `answer` frame

Sent by foci when the human responds (or the question expires).

```json
{
  "protocol": "askgw/1",
  "type": "answer",
  "id": "my-unique-id",
  "status": "answered",
  "answers": {
    "deploy": "Yes"
  }
}
```

### Status values

| Status | Meaning |
|--------|---------|
| `answered` | The human selected an option |
| `timeout` | No response within the timeout period |
| `dismissed` | The human dismissed the prompt without answering |
| `unavailable` | No active session for the target agent |

### Answer format

For single-select questions, `answers[key]` is the selected option label as a JSON string. For multi-select questions, it is a JSON array of selected labels.

## `cancel` frame

Sent by the client to withdraw a pending question.

```json
{
  "protocol": "askgw/1",
  "type": "cancel",
  "id": "my-unique-id",
  "reason": "never mind"
}
```

Foci cancels the prompt UI and tears down the entry. No `answer` frame is sent for a cancelled ask.

## `ack` frame

Sent by foci immediately after accepting an `ask` frame, confirming the question has been presented to the human.

```json
{
  "protocol": "askgw/1",
  "type": "ack",
  "id": "my-unique-id"
}
```

## `error` frame

Sent by foci on validation failure or server error.

```json
{
  "protocol": "askgw/1",
  "type": "error",
  "id": "my-unique-id",
  "code": "malformed",
  "message": "ask frame missing id"
}
```

### Error codes

| Code | Fatal? | Meaning |
|------|--------|---------|
| `bad_protocol` | yes (closes connection) | Protocol field missing or mismatched |
| `malformed` | yes if envelope fails, no otherwise | JSON parse or validation error |
| `unknown_type` | no | Unrecognized frame type |
| `rejected` | no | Registry rejected the ask (e.g. duplicate id) |
| `too_large` | no | Frame exceeds `max_frame_bytes` |

Fatal errors close the connection. Non-fatal errors return the error frame and continue processing subsequent frames on the same connection.

## Sequence diagram

```
Client                       Foci
  |                             |
  |--- ask (id, questions) ---->|
  |<-- ack (id) --------------- |  question presented to human
  |                             |
  |                        human responds (or timeout)
  |                             |
  |<-- answer (id, answers) ----|
  |                             |
```

Cancellation flow:

```
Client                       Foci
  |                             |
  |--- ask (id, questions) ---->|
  |<-- ack (id) --------------- |
  |                             |
  |--- cancel (id) ------------>|  client withdraws
  |                             |  prompt UI torn down
  |                             |
  | (no answer frame sent)      |
  |                             |
```
