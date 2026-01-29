# Telegram Bridge (Long Polling)

This runs a local bot that executes PowerShell commands you send via Telegram and can forward messages to Codex CLI.

## Setup

1) Edit `config.json` and set:
   - token: your bot token
   - password: a strong password
   - allowed_chat_ids: set to your single chat ID (e.g., [123456789])
   - codex_command: the command array to run Codex CLI
   - codex_workdir: working directory for Codex (`-C`)
   - gui: set to true to show a local GUI log window
   - codex_sandbox: read-only | workspace-write | danger-full-access

2) Run:

```
py telegram_bridge.py
```

If `py` is not available, install Python 3 and ensure the `py` launcher is on PATH.

## Commands

- `/help`
- `/status <password>`
- `/run <password> <powershell command>`

## Codex forwarding

Any non-command message is:
- appended to `inbox.jsonl`
- sent to Codex via `codex exec "<message>"`
- returned to Telegram
- written to `codex_reply.txt`

## GUI

Set `"gui": true` in `config.json` to show a live log window.
You can edit config directly in the GUI and control sandbox mode there.

## Notes

- This uses long polling and does NOT require a public domain.
- If you want webhook mode, you must have a public domain or IP.
