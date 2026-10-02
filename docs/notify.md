# Notifications for unattended runs

Run Diagward from cron, a systemd timer or the Windows Task Scheduler and
let the server report its own hardware problems to **Telegram**, **Zalo**,
**Slack**, **Discord**, any **webhook** or **e-mail**.

```sh
sudo diagward check -q --notify-config /etc/diagward/notify.conf
```

By default a message is sent **only when something changed** since the last
run, so a daily check does not spam the channel with the same failing disk:

| Situation | Sent? |
|---|---|
| First run and there are problems (warnings or critical) | yes, every problem is "new" |
| A new problem appears | yes |
| A problem gets worse (warning → critical) | yes |
| A problem is gone (or dropped below warning) | yes, a recovery message |
| A problem got better but is still a problem (critical → warning) | no, but it is listed when a message goes out |
| Only notes (Info) or OK results changed | no |
| A check could not run this time (e.g. no root) | no, but the message says so when one goes out |
| Nothing changed | no (`--notify-always` sends anyway) |

The message, in Vietnamese or English, says the host, the verdict, vendor,
model and serial, the new problems with what to do and the serial of the part to replace
(the first `top` of them), the resolved ones, and a short line about checks that could not run
when that changed.

```
✗ srv-db01: CẦN XỬ LÝ NGAY
Dell Inc. PowerEdge R740 · serial 8XK2LM2
1 lỗi nghiêm trọng · 2 cảnh báo

Vấn đề mới (2):
✗ Nghiêm trọng: Ổ /dev/sda sắp hỏng: 81 sector không đọc được
   → Sao lưu dữ liệu trên /dev/sda ngay. Thay ổ (SAMSUNG HD502HI, serial S1VZJ9CS712490)…
⚠ Cảnh báo: Thanh RAM CPU_SrcID#1_MC#0_Chan#1_DIMM#0 liên tục bị lỗi (đã được ECC sửa)
   → Lên kế hoạch thay thanh RAM ở lần bảo trì tới…

Đã hết lỗi (1):
✓ PSU 2: bộ nguồn bị hỏng

Còn 1 vấn đề khác chưa xử lý (đã báo trước đây).
Lần này không kiểm tra được: Tình trạng S.M.A.R.T.
Diagward 0.1.0 · 2026-10-01 09:00 +07:00
```

## Quick start

```sh
sudo mkdir -p /etc/diagward
sudo install -m 600 /dev/null /etc/diagward/notify.conf
sudoedit /etc/diagward/notify.conf          # see the examples below
sudo diagward notify-test --notify-config /etc/diagward/notify.conf
sudo diagward check --notify-config /etc/diagward/notify.conf
```

`notify-test` sends a test message to every channel and prints which ones
worked (exit code 0 when all did, 3 otherwise). Then schedule the check
([below](#scheduling)).

## The config file

A small INI-style text file (UTF-8; a BOM from Notepad is fine):

```ini
# /etc/diagward/notify.conf  (chmod 600)
# vi or en; default: --lang, else the environment
lang = vi
# problems listed per message (1-50)
top = 5
# warn (default) or crit: what counts as a problem
min_severity = warn
# seconds per request / SMTP session (2-120)
timeout = 15

[telegram]
token = 123456789:AAH_your_bot_token
chat_id = -1001234567890

[zalo]
token = 1234567890:your-zalo-bot-token
chat_id = 9a1b2c3d4e5f

[slack]
url = https://hooks.slack.com/services/T000/B000/XXXXXXXX

[discord]
url = https://discord.com/api/webhooks/123456/abcdef
username = Diagward

[webhook]
url = https://monitor.example.com/diagward
header = Authorization: Bearer abc123
secret = a-long-random-string
include_report = false

[email]
host = smtp.example.com
port = 587
tls = starttls
user = alerts@example.com
password = app-password
from = Diagward <alerts@example.com>
to = ops@example.com, oncall@example.com
```

Rules:

* Lines starting with `#` or `;` are comments. A comment after a value is
  **not** supported (tokens may contain `#`); put comments on their own line.
* A value may be quoted (`"..."` or `'...'`).
* Instead of writing a secret in the file, a value can be
  `env:NAME` (an environment variable) or `file:/path` (the content of a
  file holding just that value on one line, e.g. a systemd credential: `token = file:/run/credentials/diagward.service/tg`).
* To use two channels of the same kind, name the sections:
  `[telegram ops]` and `[telegram boss]`.
* Unknown keys and sections are errors (typos do not silently disable a
  channel). The config is read **before** the collection starts, so a
  mistake fails at once with exit code 3; error messages give the line
  number and never quote a value.
* The language is `--lang` if given, else `lang =` from this file, else the
  environment (`DIAGWARD_LANG`, `LANG`, …). Cron jobs usually run with
  `LANG=C`, so set `lang = vi` here for Vietnamese messages.

The path can also come from `DIAGWARD_NOTIFY_CONFIG` instead of
`--notify-config`.

### Telegram

1. Talk to [@BotFather](https://t.me/BotFather), `/newbot`, copy the token.
2. Add the bot to your group (or send it a message in private).
3. Find the chat id: open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser after
   writing something in the chat; it is `"chat":{"id":...}` (groups and
   channels are negative, e.g. `-1001234567890`). A public channel can use
   `@channelname`.

Keys: `token`, `chat_id`, optional `thread_id` (a topic in a forum group),
optional `api_url` (a self-hosted Bot API server). Messages use
`parse_mode=HTML` with `<`, `>` and `&` escaped, and are kept under
Telegram's 4096-character limit (long lists end with "… và N mục khác").

### Zalo (Zalo Bot Platform)

Zalo's [Bot Platform](https://bot.zaloplatforms.com) (2025) has a Bot API
modelled on Telegram's. Diagward uses the documented
[`sendMessage`](https://docs.zaloplatforms.com/docs/BOT/apis/sendMessage)
method: `POST https://bot-api.zaloplatforms.com/bot<TOKEN>/sendMessage` with
`chat_id` and `text` (1 to 2000 characters); the answer is
`{"ok": true, "result": {...}}`.

1. Create a bot at [bot.zaloplatforms.com](https://bot.zaloplatforms.com)
   and copy its token.
2. From the Zalo account that should receive alerts, send the bot a message.
3. Get the chat id with
   [`getUpdates`](https://docs.zaloplatforms.com/docs/BOT/apis/getUpdates)
   (`curl -X POST https://bot-api.zaloplatforms.com/bot<TOKEN>/getUpdates`):
   it is `message.chat.id`. `getUpdates` does not work while a webhook is set
   for the bot.

Keys: `token`, `chat_id`, optional `api_url`. Zalo messages are sent as
plain text (no `parse_mode`) and kept under 2000 characters.

Not verified: the implementation follows the official documentation and is
tested against a local fake of that API; it has **not** been run against
Zalo's real servers yet (no bot account was available). The error answer
format is assumed to match Telegram's (`ok`, `error_code`, `description`);
any non-2xx answer or `"ok": false` is reported as a failure either way.
Please report a mismatch.

### Slack

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for
the channel and put its URL in `url =`. The text uses Slack's mrkdwn with
`&`, `<`, `>` escaped.

### Discord

Channel settings → Integrations → Webhooks → New webhook → Copy URL.
Optional `username =`. Mentions are disabled (`allowed_mentions`), so a log
line containing `@everyone` cannot ping a server; markdown characters are
escaped; messages stay under 2000 characters.

### Generic webhook

`POST` of JSON to `url =`, with optional `header = Name: value` lines
(repeatable) and, with `secret =`, a signature header
`X-Diagward-Signature: sha256=<hex HMAC-SHA256 of the body>`.
`X-Diagward-Event` carries the event. Any 2xx answer is success.

```jsonc
{
  "tool": "diagward",
  "version": "0.1.0",
  "event": "problem",                  // problem | recovery | status | test
  "host": "srv-db01",
  "vendor": "Dell Inc.", "model": "PowerEdge R740", "serial": "8XK2LM2",
  "verdict": "crit",                   // ok | info | warn | crit
  "headline": "CẦN XỬ LÝ NGAY",
  "summary": "[Diagward] srv-db01: CẦN XỬ LÝ NGAY (2 vấn đề mới)",
  "counts": {"crit": 1, "warn": 2, "info": 1},
  "new":      [{"id": "disk.smart_pending", "target": "/dev/sda", "component": "disk",
                "severity": "crit", "title": "...", "action": "...",
                "part": "SAMSUNG HD502HI, serial S1VZJ9CS712490"}],  // part: when the texts do not quote the serial
  "worsened": [{"...": "...", "previous": "warn"}],
  "improved": [],
  "resolved": [{"id": "ipmi.psu", "target": "PSU 2", "severity": "ok", "previous": "crit", "title": "..."}],
  "current":  [ /* every current problem */ ],
  "notChecked":   ["Tình trạng S.M.A.R.T."],   // checks that stopped running
  "checkedAgain": [],
  "incomplete": false,                 // the collection did not finish
  "lang": "vi",
  "time": "2026-10-01T09:00:27+07:00",
  "text": "the same message as the chat channels, plain text",
  "report": { /* the full JSON report, only with include_report = true */ }
}
```

Verify the signature (Python):

```python
import hmac, hashlib
ok = hmac.compare_digest(
    request.headers["X-Diagward-Signature"],
    "sha256=" + hmac.new(SECRET, request.body, hashlib.sha256).hexdigest())
```

### E-mail (SMTP)

| `tls =` | Port (default) | Notes |
|---|---|---|
| `starttls` (default) | 587 | the server **must** offer STARTTLS, or nothing is sent (no fallback to plain text) |
| `tls` | 465 | implicit TLS (SMTPS) |
| `none` | 25 | only allowed when `host` is `localhost`/`127.0.0.1` (a local Postfix relay) |

`user` and `password` go together (AUTH PLAIN, only over TLS or to
localhost). `to =` takes a comma-separated list. The mail is UTF-8 plain
text with the full list of problems (up to 50) and complete actions; the
subject is the one-line summary. For Gmail and Microsoft 365 use an *app
password*.

## Security

* **Secrets only in the file**, never on the command line (where `ps` and
  shell history would show them), never in the state file, the bundle or the
  report. Every error message from a channel is passed through a redactor
  that removes the tokens, webhook URLs (and their path and query parts),
  header values and passwords; errors name the host only
  (`cannot reach hooks.slack.com …`).
* **File mode.** On Linux and other Unix systems Diagward refuses a config
  that group or others can read or write (`chmod 600` fixes it), unless you
  pass `--force` (it then prints a warning). On Windows, mode bits do not
  exist; protect the file with an ACL:

  ```powershell
  icacls C:\ProgramData\Diagward\notify.conf /inheritance:r /grant:r "SYSTEM:F" "Administrators:F"
  ```

* **HTTPS only.** `url =` and `api_url =` must be `https://`; plain `http://`
  is accepted only for `localhost`/`127.0.0.1`/`::1`. Redirects are not
  followed (the payload and headers would go elsewhere). TLS 1.2+, the system
  certificate store.
* **Bounded.** Each request has a timeout (`timeout =`, 15 s by default).
  Transient errors (network, HTTP 408/429/5xx, SMTP 4xx) are tried up to 3
  times in all, with backoff (2 s, then 4 s), honouring `Retry-After` up to 30 s. All channels
  are sent in parallel and the whole step is capped at 3 minutes. Errors such
  as a wrong token (401/403/404) or an untrusted certificate are not retried.
* **Never changes the result.** A channel that fails prints a warning on
  stderr (`Warning: notification not sent: slack: HTTP 404 …`); the others
  are still sent, and the exit code stays the check's verdict (0-3).

## The state file

The previous result is kept in a small JSON file:

| | Default |
|---|---|
| Linux, root | `/var/lib/diagward/state.json` |
| Linux, other users | `$XDG_STATE_HOME/diagward/state.json` or `~/.local/state/diagward/state.json` |
| Windows | `%ProgramData%\Diagward\state.json` |

or `--state FILE`. It holds the host name, the verdict, and for each
finding its id, target, severity, component and title, plus the checks that
could not run. Nothing secret. Problems are matched by **finding id +
target** (e.g. `disk.smart_pending` + `/dev/sda`), so a counter that keeps
rising (250 → 300 corrected ECC errors) is not a new problem; a change of
severity is.

Details that avoid false alarms:

* A problem is reported as **resolved** only when its component was checked
  this time and nothing in that component is checked *less* than before. A
  run without root (no S.M.A.R.T.) does not "fix" a failing disk found by an
  earlier root run, and a run that could not reach the BMC does not "fix" a
  failed PSU: those problems are carried over until a run can look again.
* If the collection was interrupted, nothing is reported as resolved.
* If no channel could deliver a change, the state is **not** updated, so the
  change is sent again on the next run instead of being lost.
* A state file from another host name, a corrupt one or one from another
  version is treated as a first run and replaced.
* Problems found in logs (disk I/O errors, unexpected reboots, machine
  checks) stay in the log window (`--since`, 7 days by default); their
  recovery message comes when they age out of it.

## Scheduling

Diagward never installs timers itself; pick one of these. Run the check as
root / SYSTEM so every check can run. Once or a few times a day is plenty:
a check takes from 20 seconds to a few minutes.

### cron

```cron
# /etc/cron.d/diagward
17 7 * * * root /usr/local/bin/diagward check -q --notify-config /etc/diagward/notify.conf >/dev/null 2>>/var/log/diagward.log
```

### systemd service + timer

```ini
# /etc/systemd/system/diagward.service
[Unit]
Description=Diagward hardware check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/diagward check -q --notify-config /etc/diagward/notify.conf
# 1 = warnings, 2 = critical problems: a result, not a failed unit
SuccessExitStatus=1 2
Nice=10
IOSchedulingClass=idle
```

```ini
# /etc/systemd/system/diagward.timer
[Unit]
Description=Daily Diagward hardware check

[Timer]
OnCalendar=*-*-* 07:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now diagward.timer
systemctl list-timers diagward.timer
journalctl -u diagward.service        # the one-line verdicts and any warning
```

### Windows Task Scheduler

From an elevated Command Prompt or PowerShell:

```bat
schtasks /Create /TN "Diagward" /SC DAILY /ST 07:00 /RU SYSTEM /RL HIGHEST /F ^
  /TR "\"C:\Program Files\Diagward\diagward.exe\" check -q --notify-config C:\ProgramData\Diagward\notify.conf"
schtasks /Run /TN "Diagward"
```

(In PowerShell, write the command on one line instead of using `^`.)

## Tiếng Việt

Cho máy chủ tự báo lỗi phần cứng qua Telegram, Zalo, Slack, Discord,
webhook hoặc e-mail khi chạy định kỳ (cron, systemd timer, Task Scheduler):

1. Tạo tệp `/etc/diagward/notify.conf` (Windows:
   `C:\ProgramData\Diagward\notify.conf`) theo mẫu ở trên, rồi
   `chmod 600` (Windows: dùng lệnh `icacls` ở mục Security). Diagward từ
   chối tệp mà người dùng khác đọc được, trừ khi thêm `--force`.
2. Chạy `sudo diagward notify-test --notify-config /etc/diagward/notify.conf`
   để gửi tin nhắn thử tới từng kênh.
3. Lên lịch `diagward check -q --notify-config /etc/diagward/notify.conf`
   bằng một trong các cách ở mục [Scheduling](#scheduling). Đặt `lang = vi`
   trong tệp cấu hình để tin nhắn luôn bằng tiếng Việt (cron thường chạy với
   `LANG=C`).

Mặc định chỉ gửi khi có thay đổi: lần đầu chạy mà có lỗi, có lỗi mới, lỗi
nặng hơn, hoặc lỗi đã hết (tin "Đã hết lỗi"). Thay đổi chỉ ở mức lưu ý
(Info) thì không gửi. Muốn lần nào cũng gửi, thêm `--notify-always`. Muốn
chỉ báo lỗi nghiêm trọng, đặt `min_severity = crit`.

Token, URL webhook, mật khẩu chỉ nằm trong tệp cấu hình (hoặc biến môi
trường qua `env:TÊN`, tệp riêng qua `file:/đường/dẫn`), không bao giờ xuất
hiện trên dòng lệnh, trong log, thông báo lỗi, bundle hay báo cáo. Không gửi
được thông báo thì chỉ in cảnh báo; mã thoát vẫn là kết quả kiểm tra.

Zalo: dùng Zalo Bot Platform (bot.zaloplatforms.com), API `sendMessage`
giống Telegram. Phần này được viết theo tài liệu chính thức và kiểm thử với
máy chủ giả lập, chưa thử với máy chủ thật của Zalo.
