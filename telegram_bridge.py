import json
import os
import sys
import time
import urllib.parse
import urllib.request
import subprocess
import threading
import queue
import shlex
import re
try:
    import tkinter as tk
    from tkinter.scrolledtext import ScrolledText
except Exception:
    tk = None
    ScrolledText = None

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
STATE_PATH = os.path.join(os.path.dirname(__file__), "state.json")
INBOX_PATH = os.path.join(os.path.dirname(__file__), "inbox.jsonl")
REPLY_PATH = os.path.join(os.path.dirname(__file__), "codex_reply.txt")
TELEGRAM_API = "https://api.telegram.org"

# Ensure console streams don't choke on UTF-8 output in GBK locales.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

LOG_QUEUE = queue.Queue()
CONFIG_LOCK = threading.Lock()
GLOBAL_CONFIG = None


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_state():
    if not os.path.exists(STATE_PATH):
        return {"offset": 0}
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f)


def api_request(token, method, data=None, timeout=50):
    url = f"{TELEGRAM_API}/bot{token}/{method}"
    if data is None:
        data = {}
    payload = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=payload)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def send_message(token, chat_id, text):
    # Telegram max message length is 4096
    chunk_size = 3900
    for i in range(0, len(text), chunk_size):
        api_request(token, "sendMessage", {"chat_id": chat_id, "text": text[i:i + chunk_size]})


def is_allowed(chat_id, allowed_chat_ids):
    return not allowed_chat_ids or chat_id in allowed_chat_ids


def run_powershell(cmd):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = result.stdout.strip()
    err = result.stderr.strip()
    code = result.returncode
    combined = out
    if err:
        combined = (combined + "\n" if combined else "") + "[stderr] " + err
    if not combined:
        combined = "(no output)"
    return code, combined


def append_inbox(chat_id, text):
    entry = {
        "chat_id": chat_id,
        "text": text,
        "ts": int(time.time()),
    }
    with open(INBOX_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_line(text):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {text}"
    print(line)
    LOG_QUEUE.put(line)


def run_codex(config, prompt):
    cmd = config.get("codex_command")
    if not cmd:
        raise RuntimeError("codex_command not set in config.json")
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    extra_args = config.get("codex_extra_args", [])
    if not isinstance(extra_args, list):
        extra_args = shlex.split(str(extra_args))

    # Remove any existing sandbox/approval/workdir flags so GUI settings take precedence.
    sanitized = []
    skip_next = False
    for i, arg in enumerate(extra_args):
        if skip_next:
            skip_next = False
            continue
        if arg in ("--sandbox", "--ask-for-approval", "-C", "--cd"):
            skip_next = True
            continue
        sanitized.append(arg)

    sandbox = config.get("codex_sandbox")
    workdir = config.get("codex_workdir")
    if sandbox:
        sanitized += ["--sandbox", sandbox]
    if workdir:
        sanitized += ["-C", workdir]

    full_cmd = cmd + ["exec"] + sanitized + [prompt]
    timeout = int(config.get("codex_timeout_sec", 300))
    result = subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    out = result.stdout.strip()
    err = result.stderr.strip()
    if err:
        out = (out + "\n" if out else "") + "[stderr] " + err
    if not out:
        out = "(no output)"
    return result.returncode, out


def strip_thinking(text):
    # Remove common "thinking" blocks and tags from model output.
    text = re.sub(r"```thinking[\s\S]*?```", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<thinking>[\s\S]*?</thinking>", "", text, flags=re.IGNORECASE)
    # Drop lines that look like inline thinking labels.
    lines = []
    for line in text.splitlines():
        if line.strip().lower().startswith(("thinking:", "thoughts:", "analysis:")):
            continue
        lines.append(line)
    return "\n".join(lines).strip() or "(no output)"


def handle_message(token, config, message):
    chat = message.get("chat", {})
    chat_id = chat.get("id")
    text = message.get("text", "")

    if not is_allowed(chat_id, config.get("allowed_chat_ids", [])):
        return

    if not text:
        return

    log_line(f"TG {chat_id}: {text}")

    password = config.get("password", "")
    if text.startswith("/help"):
        send_message(token, chat_id, "Commands:\n/run <password> <powershell command>\n/status <password>")
        return

    if text.startswith("/status "):
        parts = text.split(" ", 1)
        if len(parts) < 2 or parts[1].strip() != password:
            send_message(token, chat_id, "Invalid password.")
            return
        send_message(token, chat_id, "OK")
        return

    if text.startswith("/run "):
        parts = text.split(" ", 2)
        if len(parts) < 3:
            send_message(token, chat_id, "Usage: /run <password> <powershell command>")
            return
        if parts[1].strip() != password:
            send_message(token, chat_id, "Invalid password.")
            return
        cmd = parts[2]
        code, output = run_powershell(cmd)
        send_message(token, chat_id, f"Exit {code}\n{output}")
        return

    append_inbox(chat_id, text)
    try:
        log_line("Codex: exec")
        code, output = run_codex(config, text)
        if not config.get("show_thinking", False):
            output = strip_thinking(output)
        with open(REPLY_PATH, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        send_message(token, chat_id, output if code == 0 else f"Exit {code}\n{output}")
        log_line(f"Codex -> TG {chat_id}: {output}")
    except Exception as exc:
        send_message(token, chat_id, f"Codex error: {exc}")
        log_line(f"Codex error: {exc}")

def poll_loop(config):
    token = config.get("token", "")
    if not token or token == "PUT_NEW_TOKEN_HERE":
        log_line("Set token in config.json")
        return

    state = load_state()
    offset = int(state.get("offset", 0))

    poll_interval = int(config.get("poll_interval_sec", 2))
    timeout = int(config.get("request_timeout_sec", 50))

    while True:
        try:
            resp = api_request(
                token,
                "getUpdates",
                {"timeout": timeout, "offset": offset + 1},
                timeout=timeout + 10,
            )
            if resp.get("ok"):
                for upd in resp.get("result", []):
                    offset = max(offset, upd.get("update_id", offset))
                    msg = upd.get("message")
                    if msg:
                        with CONFIG_LOCK:
                            current = GLOBAL_CONFIG or config
                        handle_message(token, current, msg)
                state["offset"] = offset
                save_state(state)
        except Exception as exc:
            log_line(f"Error: {exc}")
        time.sleep(poll_interval)


def start_gui():
    if tk is None or ScrolledText is None:
        log_line("Tkinter not available; running without GUI.")
        return False
    root = tk.Tk()
    root.title("Telegram ↔ Codex Bridge")
    root.geometry("1000x820")
    root.configure(bg="#111111")

    container = tk.Frame(root, bg="#111111")
    container.pack(fill="both", expand=True)

    sidebar = tk.Frame(container, bg="#111111", width=280)
    sidebar.pack(side="left", fill="y")

    log_frame = tk.Frame(container, bg="#111111")
    log_frame.pack(side="right", fill="both", expand=True)

    text = ScrolledText(log_frame, wrap="word", bg="#0b0b0b", fg="#e6e6e6", insertbackground="#e6e6e6")
    text.pack(fill="both", expand=True, padx=8, pady=8)

    def pump():
        try:
            while True:
                line = LOG_QUEUE.get_nowait()
                text.insert("end", line + "\n")
                text.see("end")
        except queue.Empty:
            pass
        root.after(200, pump)

    def make_label(parent, label):
        return tk.Label(parent, text=label, bg="#111111", fg="#e6e6e6")

    def make_entry(parent):
        return tk.Entry(parent, bg="#1a1a1a", fg="#e6e6e6", insertbackground="#e6e6e6")

    def set_entry(entry, value):
        entry.delete(0, "end")
        entry.insert(0, value)

    with CONFIG_LOCK:
        cfg = GLOBAL_CONFIG or load_config()

    make_label(sidebar, "Token").pack(anchor="w", padx=8, pady=(8, 0))
    token_entry = make_entry(sidebar)
    token_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Password").pack(anchor="w", padx=8, pady=(8, 0))
    pass_entry = make_entry(sidebar)
    pass_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Allowed chat IDs (comma)").pack(anchor="w", padx=8, pady=(8, 0))
    chat_entry = make_entry(sidebar)
    chat_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Codex command").pack(anchor="w", padx=8, pady=(8, 0))
    cmd_entry = make_entry(sidebar)
    cmd_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Work dir (-C)").pack(anchor="w", padx=8, pady=(8, 0))
    workdir_entry = make_entry(sidebar)
    workdir_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Extra args").pack(anchor="w", padx=8, pady=(8, 0))
    args_entry = make_entry(sidebar)
    args_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Sandbox").pack(anchor="w", padx=8, pady=(8, 0))
    sandbox_var = tk.StringVar()
    sandbox_menu = tk.OptionMenu(sidebar, sandbox_var, "", "read-only", "workspace-write", "danger-full-access")
    sandbox_menu.configure(bg="#1a1a1a", fg="#e6e6e6", highlightthickness=0)
    sandbox_menu["menu"].configure(bg="#1a1a1a", fg="#e6e6e6")
    sandbox_menu.pack(fill="x", padx=8)

    make_label(sidebar, "Approval").pack(anchor="w", padx=8, pady=(8, 0))
    approval_var = tk.StringVar()
    approval_menu = tk.OptionMenu(sidebar, approval_var, "", "untrusted", "on-failure", "on-request", "never")
    approval_menu.configure(bg="#1a1a1a", fg="#e6e6e6", highlightthickness=0)
    approval_menu["menu"].configure(bg="#1a1a1a", fg="#e6e6e6")
    approval_menu.pack(fill="x", padx=8)

    make_label(sidebar, "Poll interval (sec)").pack(anchor="w", padx=8, pady=(8, 0))
    poll_entry = make_entry(sidebar)
    poll_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Request timeout (sec)").pack(anchor="w", padx=8, pady=(8, 0))
    req_entry = make_entry(sidebar)
    req_entry.pack(fill="x", padx=8)

    make_label(sidebar, "Codex timeout (sec)").pack(anchor="w", padx=8, pady=(8, 0))
    codex_timeout_entry = make_entry(sidebar)
    codex_timeout_entry.pack(fill="x", padx=8)

    gui_var = tk.BooleanVar(value=bool(cfg.get("gui", False)))
    gui_check = tk.Checkbutton(
        sidebar,
        text="Enable GUI",
        variable=gui_var,
        bg="#111111",
        fg="#e6e6e6",
        selectcolor="#111111",
        activebackground="#111111",
        activeforeground="#e6e6e6",
    )
    gui_check.pack(anchor="w", padx=8, pady=(8, 0))

    thinking_var = tk.BooleanVar(value=bool(cfg.get("show_thinking", False)))
    thinking_check = tk.Checkbutton(
        sidebar,
        text="Show thinking",
        variable=thinking_var,
        bg="#111111",
        fg="#e6e6e6",
        selectcolor="#111111",
        activebackground="#111111",
        activeforeground="#e6e6e6",
    )
    thinking_check.pack(anchor="w", padx=8, pady=(4, 0))

    def refresh_fields():
        with CONFIG_LOCK:
            c = GLOBAL_CONFIG or load_config()
        set_entry(token_entry, c.get("token", ""))
        set_entry(pass_entry, c.get("password", ""))
        set_entry(chat_entry, ",".join(str(x) for x in c.get("allowed_chat_ids", [])))
        cmd = c.get("codex_command", "")
        if isinstance(cmd, list):
            cmd = subprocess.list2cmdline(cmd)
        set_entry(cmd_entry, cmd)
        args = c.get("codex_extra_args", [])
        if isinstance(args, list):
            args = " ".join(args)
        set_entry(workdir_entry, c.get("codex_workdir", ""))
        set_entry(args_entry, args)
        sandbox_var.set(c.get("codex_sandbox", ""))
        approval_var.set(c.get("codex_approval", ""))
        set_entry(poll_entry, str(c.get("poll_interval_sec", 2)))
        set_entry(req_entry, str(c.get("request_timeout_sec", 50)))
        set_entry(codex_timeout_entry, str(c.get("codex_timeout_sec", 300)))
        gui_var.set(bool(c.get("gui", False)))
        thinking_var.set(bool(c.get("show_thinking", False)))

    def save_config_gui():
        try:
            allowed = [int(x.strip()) for x in chat_entry.get().split(",") if x.strip()]
        except ValueError:
            log_line("Invalid chat_id list. Use comma-separated integers.")
            return
        cmd_text = cmd_entry.get().strip()
        cmd_value = shlex.split(cmd_text) if cmd_text else []
        args_text = args_entry.get().strip()
        args_value = shlex.split(args_text) if args_text else []
        new_cfg = {
            "token": token_entry.get().strip(),
            "password": pass_entry.get().strip(),
            "allowed_chat_ids": allowed,
            "poll_interval_sec": int(poll_entry.get().strip() or 2),
            "request_timeout_sec": int(req_entry.get().strip() or 50),
            "codex_command": cmd_value,
            "codex_workdir": workdir_entry.get().strip(),
            "codex_extra_args": args_value,
            "codex_sandbox": sandbox_var.get().strip() or None,
            "codex_approval": approval_var.get().strip() or None,
            "codex_timeout_sec": int(codex_timeout_entry.get().strip() or 300),
            "gui": bool(gui_var.get()),
            "show_thinking": bool(thinking_var.get()),
        }
        with CONFIG_LOCK:
            global GLOBAL_CONFIG
            GLOBAL_CONFIG = new_cfg
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(new_cfg, f, ensure_ascii=False, indent=2)
        log_line("Config saved.")

    refresh_fields()

    save_btn = tk.Button(sidebar, text="Save Config", command=save_config_gui, bg="#1f1f1f", fg="#e6e6e6")
    save_btn.pack(fill="x", padx=8, pady=(8, 8))

    root.after(200, pump)
    root.mainloop()
    return True


def main():
    config = load_config()
    gui_enabled = bool(config.get("gui", False))
    if gui_enabled and tk is not None:
        with CONFIG_LOCK:
            global GLOBAL_CONFIG
            GLOBAL_CONFIG = config
        t = threading.Thread(target=poll_loop, args=(config,), daemon=True)
        t.start()
        start_gui()
    else:
        poll_loop(config)


if __name__ == "__main__":
    main()
