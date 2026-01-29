# Telegram -Codex Bridge

A local Telegram bot bridge that forwards messages to Codex CLI and sends replies back to Telegram. Includes a dark GUI for live logs and configuration.

本项目是一个本地 Telegram 机器人桥接器：把 Telegram 消息转发给 Codex CLI，并把 Codex 回复回传到 Telegram，同时提供黑色主题 GUI 方便查看日志和修改配置。

## Features / 功能

- Long polling (no public domain required)
- Forward Telegram messages to `codex exec`
- Reply back to Telegram automatically
- GUI for live logs and config editing
- Optional thinking-output filter

- 长轮询（不需要公网域名）
- Telegram 消息转发到 `codex exec`
- 自动把 Codex 回复回传 Telegram
- GUI 实时日志与配置编辑
- 可选隐藏 thinking 输出

## Requirements / 环境要求

- Python 3.8+
- Node.js (for Codex CLI wrapper)
- Codex CLI installed via npm (or another path you configure)

- Python 3.8+
- Node.js（用于运行 Codex CLI）
- 已安装 Codex CLI（npm 安装或自定义路径）

## Setup / 使用步骤

1. Edit `config.json`:
   - `token`: Telegram bot token
   - `password`: command password
   - `allowed_chat_ids`: list of allowed chat IDs
   - `codex_command`: command array to run Codex CLI
   - `codex_workdir`: working directory (`-C`)
   - `codex_extra_args`: extra CLI args (e.g. `--skip-git-repo-check`)
   - `codex_sandbox`: `read-only` | `workspace-write` | `danger-full-access`
   - `show_thinking`: `true` or `false`

1. 编辑 `config.json`：
   - `token`：Telegram 机器人 token
   - `password`：命令口令
   - `allowed_chat_ids`：允许的 chat_id 列表
   - `codex_command`：Codex CLI 启动命令数组
   - `codex_workdir`：工作目录（`-C`）
   - `codex_extra_args`：额外参数（如 `--skip-git-repo-check`）
   - `codex_sandbox`：`read-only` | `workspace-write` | `danger-full-access`
   - `show_thinking`：是否显示 thinking

2. Run / 运行：

```bash
py telegram_bridge.py
```

## Deployment / 部署

Clone and run locally:

```bash
git clone <your-repo-url>
cd telegram-bridge
py telegram_bridge.py
```

For dependencies (none required):

```bash
pip install -r requirements.txt
```

本地克隆后直接运行：

```bash
git clone <your-repo-url>
cd telegram-bridge
py telegram_bridge.py
```

依赖安装（本项目无第三方依赖）：

```bash
pip install -r requirements.txt
```
![Uploading image.png…]()

## Telegram Commands / 指令

- `/help`
- `/status <password>`
- `/run <password> <powershell command>`

All other messages are forwarded to Codex.

除以上命令外，其它消息都会转发给 Codex。


## FAQ / 常见问题

**Q: 为什么没有 webhook？**
A: 本项目使用长轮询，不需要公网域名或反向代理。

**Q: 为什么提示 not inside a trusted directory？**
A: 在 `codex_extra_args` 里加 `--skip-git-repo-check`。

**Q: 为什么输出全是乱码或 UnicodeDecodeError？**
A: 请用 `py -X utf8 telegram_bridge.py` 运行，或确认系统编码为 UTF-8。

**Q: thinking 输出太长怎么办？**
A: 在 GUI 勾选/取消 “Show thinking”，或在 `config.json` 设置 `show_thinking`。

## Notes / 说明

- Long polling means no webhook/domain required.
- For Windows, keep paths escaped in JSON (e.g., `D:\\codex-project`).

- 长轮询不需要 webhook 或公网域名。
- Windows 路径在 JSON 里需要转义（例如 `D:\\codex-project`）。

## Files / 文件说明

- `telegram_bridge.py` - main script
- `config.json` - runtime config
- `inbox.jsonl` - raw incoming messages
- `codex_reply.txt` - last Codex reply
- `requirements.txt` - dependency list

- `telegram_bridge.py` - 主脚本
- `config.json` - 运行配置
- `inbox.jsonl` - 原始接收消息
- `codex_reply.txt` - 最近一次 Codex 回复
- `requirements.txt` - 依赖列表


