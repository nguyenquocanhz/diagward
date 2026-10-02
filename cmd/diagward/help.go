package main

import (
	"fmt"
	"strings"
)

func (a *app) cmdHelp(args []string) int {
	topic := ""
	fs := newFlagSet("help", a)
	if pos, err := parseArgs(fs, args); err == nil && len(pos) > 0 {
		topic = pos[0]
	}
	if topic != "" {
		if _, ok := helpTexts[topic]; !ok && topic != "analyse" {
			a.errorf(a.t("no help for %q", "không có hướng dẫn cho %q"), topic)
			a.printHelp("")
			return exitError
		}
	}
	a.printHelp(topic)
	return exitOK
}

func (a *app) printHelp(topic string) {
	if topic == "analyse" {
		topic = "analyze"
	}
	h, ok := helpTexts[topic]
	if !ok {
		h = helpTexts[""]
	}
	text := h[0]
	if a.lang == "vi" {
		text = h[1]
	}
	text = strings.TrimRight(strings.ReplaceAll(text, "{version}", version), "\n") + "\n"
	if out := pick(a.lang, outputHelp, topic); out != "" {
		text += out
	}
	switch topic {
	case "", "check", "analyze", "bmc":
		text += exitHelp[a.langIdx()]
	case "collect", "install-tools", "notify-test":
		text += exitHelpSimple[a.langIdx()]
	}
	fmt.Fprint(a.stdout, strings.TrimLeft(text, "\n"))
}

func (a *app) langIdx() int {
	if a.lang == "vi" {
		return 1
	}
	return 0
}

func pick(lang string, m map[string][2]string, topic string) string {
	h, ok := m[topic]
	if !ok {
		return ""
	}
	if lang == "vi" {
		return h[1]
	}
	return h[0]
}

// exitHelpSimple is for the commands that give no verdict.
var exitHelpSimple = [2]string{`
Exit codes:
  0  done
  3  error: bad usage, collection or install failed, or a file could not be written
`, `
Mã thoát (exit code):
  0  thành công
  3  lỗi: sai cú pháp, thu thập hoặc cài đặt thất bại, hoặc không ghi được tệp
`}

var exitHelp = [2]string{`
Exit codes:
  0  no hardware problem found (OK / info only)
  1  warnings: degraded or wearing out, plan a fix soon
  2  critical: failed or failing now, act today
  3  error: bad usage, collection failed or a file could not be written
`, `
Mã thoát (exit code):
  0  không phát hiện lỗi phần cứng (OK / chỉ có thông tin)
  1  cảnh báo: xuống cấp hoặc sắp hao mòn, nên lên kế hoạch xử lý
  2  nghiêm trọng: đã hỏng hoặc sắp hỏng, xử lý ngay hôm nay
  3  lỗi: sai cú pháp, thu thập thất bại hoặc không ghi được tệp
`}

const outputFlagsEN = `
Output:
  --html FILE      also write a self-contained HTML report ("-" = stdout)
  --md FILE        also write a Markdown report for tickets and chat ("-" = stdout)
  --json FILE      also write the full result as JSON ("-" = stdout; the text
                   report then goes to stderr)
  -v, --verbose    show tables, evidence and every coverage item
  -q, --quiet      print only a one-line verdict (for cron and monitoring);
                   the exit code tells the result
  --no-color       no colours (also when NO_COLOR is set)
  --ascii          ASCII only (no box drawing or symbols)
  --lang vi|en     language (default: DIAGWARD_LANG, LANG, Windows locale)
`

const outputFlagsVI = `
Đầu ra:
  --html TỆP       ghi thêm báo cáo HTML độc lập ("-" = stdout)
  --md TỆP         ghi thêm báo cáo Markdown để dán vào ticket/chat ("-" = stdout)
  --json TỆP       ghi toàn bộ kết quả dạng JSON ("-" = stdout; khi đó báo cáo
                   chữ chuyển sang stderr)
  -v, --verbose    hiện bảng chi tiết, bằng chứng và mọi mục kiểm tra
  -q, --quiet      chỉ in một dòng kết luận (cho cron/giám sát); kết quả nằm
                   ở mã thoát
  --no-color       không tô màu (cũng tắt khi có biến NO_COLOR)
  --ascii          chỉ dùng ký tự ASCII (không khung, không ký hiệu)
  --lang vi|en     ngôn ngữ (mặc định: DIAGWARD_LANG, LANG, ngôn ngữ Windows)
`

var outputHelp = map[string][2]string{
	"check":   {outputFlagsEN + "  --save FILE.dwb  also save the raw data (bundle) for later analysis\n", outputFlagsVI + "  --save TỆP.dwb   lưu thêm dữ liệu thô (bundle) để phân tích sau\n"},
	"analyze": {outputFlagsEN, outputFlagsVI},
	"bmc":     {outputFlagsEN + "  --save FILE.dwb  also save the raw data (bundle) for later analysis\n", outputFlagsVI + "  --save TỆP.dwb   lưu thêm dữ liệu thô (bundle) để phân tích sau\n"},
}

var helpTexts = map[string][2]string{
	"": {`Diagward {version}: server hardware diagnosis for IT support

Checks disks (S.M.A.R.T.), RAID, RAM (ECC), CPU, temperatures, fans, power
supplies, the BMC, network cards and the system logs, explains every problem
and what to do, and lists the serial numbers needed for a warranty case.

Usage:
  diagward [check] [flags]             check this server (the default)
  diagward collect [-o FILE.dwb]       collect only and save a bundle to send to support
  diagward analyze FILE.dwb            analyse a saved bundle (works on any computer)
  diagward bmc HOST --user USER        read a server's BMC (iDRAC, iLO, XClarity,
                                       Supermicro, OpenBMC) over the network
  diagward install-tools [--yes]       install the helper tools (smartctl, sensors,
                                       ipmitool, ...) on Linux
  diagward notify-test --notify-config FILE
                                       send a test message to every notification channel
  diagward version                     print the version
  diagward help [command]              help for a command

Examples:
  sudo diagward                        full check, report in the terminal
  sudo diagward check --html srv01.html
  sudo diagward check -q               one line for cron/monitoring (exit code 0-3)
  sudo diagward check -q --notify-config /etc/diagward/notify.conf
                                       for cron: alert Telegram/Zalo/Slack/... on changes
  sudo diagward collect -o srv01.dwb   then: diagward analyze srv01.dwb
  diagward bmc 10.0.0.15 --user root --insecure

Run as root (Linux) or as Administrator (Windows) for a complete check.
`, `Diagward {version}: chẩn đoán phần cứng máy chủ cho IT support

Kiểm tra ổ cứng (S.M.A.R.T.), RAID, RAM (ECC), CPU, nhiệt độ, quạt, nguồn,
BMC, card mạng và nhật ký hệ thống; giải thích từng lỗi, nói rõ cần làm gì
và liệt kê serial linh kiện để làm bảo hành.

Cách dùng:
  diagward [check] [tùy chọn]          kiểm tra máy chủ này (mặc định)
  diagward collect [-o TỆP.dwb]        chỉ thu thập và lưu bundle để gửi bộ phận hỗ trợ
  diagward analyze TỆP.dwb             phân tích bundle đã lưu (chạy trên máy bất kỳ)
  diagward bmc ĐỊA_CHỈ --user TÀI_KHOẢN
                                       đọc BMC của máy chủ (iDRAC, iLO, XClarity,
                                       Supermicro, OpenBMC) qua mạng
  diagward install-tools [--yes]       cài các công cụ hỗ trợ (smartctl, sensors,
                                       ipmitool, ...) trên Linux
  diagward notify-test --notify-config TỆP
                                       gửi tin nhắn thử tới mọi kênh thông báo
  diagward version                     in phiên bản
  diagward help [lệnh]                 hướng dẫn cho từng lệnh

Ví dụ:
  sudo diagward                        kiểm tra đầy đủ, báo cáo ngay trên terminal
  sudo diagward check --html srv01.html
  sudo diagward check -q               một dòng cho cron/giám sát (mã thoát 0-3)
  sudo diagward check -q --notify-config /etc/diagward/notify.conf
                                       cho cron: báo qua Telegram/Zalo/Slack/... khi có thay đổi
  sudo diagward collect -o srv01.dwb   rồi: diagward analyze srv01.dwb
  diagward bmc 10.0.0.15 --user root --insecure

Chạy bằng root (Linux) hoặc Administrator (Windows) để kiểm tra đầy đủ.
`},

	"check": {`Usage: diagward check [flags]

Collects hardware data from this server (read-only), analyses it and prints
the report. "diagward" with no command does the same.

Collection:
  --since N        how many days of logs to read (N or Nd, default 7)
  --timeout SEC    per-command timeout in seconds (default 30)
  --bench DIR      opt-in disk speed test: writes and reads back a file in DIR
                   (deleted afterwards; adds disk load; Linux only)
  --bench-size SIZE
                   size of the test file, 16M to 64G (default 256M)
  --memtest SIZE   opt-in RAM test with memtester, e.g. 1G (takes minutes and
                   loads CPU and RAM; Linux only, needs root)

Notifications (for cron, systemd timers, Task Scheduler; see docs/notify.md):
  --notify-config FILE
                   send the result to the channels in FILE (Telegram, Zalo,
                   Slack, Discord, webhook, e-mail); also DIAGWARD_NOTIFY_CONFIG.
                   By default only when something changed: new or worse
                   problems, problems resolved, the first run with problems
  --state FILE     where the previous result is kept (default
                   /var/lib/diagward/state.json as root, ~/.local/state/diagward
                   otherwise, %ProgramData%\Diagward on Windows)
  --notify-always  send on every run, even when nothing changed
  --force          accept a config file that other users can read
A notification that cannot be sent prints a warning; it never changes the
exit code.
`, `Cách dùng: diagward check [tùy chọn]

Thu thập dữ liệu phần cứng của máy chủ này (chỉ đọc, không thay đổi gì),
phân tích và in báo cáo. Gõ "diagward" không kèm lệnh cũng chạy lệnh này.

Thu thập:
  --since N        đọc nhật ký bao nhiêu ngày gần nhất (N hoặc Nd, mặc định 7)
  --timeout GIÂY   thời gian chờ tối đa cho mỗi lệnh (mặc định 30 giây)
  --bench THƯ_MỤC  đo tốc độ ổ (chỉ chạy khi bạn yêu cầu): ghi rồi đọc lại một
                   tệp trong THƯ_MỤC (xóa ngay sau đó; ổ sẽ tải nặng; chỉ Linux)
  --bench-size DUNG_LƯỢNG
                   dung lượng tệp đo, từ 16M đến 64G (mặc định 256M)
  --memtest DUNG_LƯỢNG
                   test RAM bằng memtester, ví dụ 1G (chỉ chạy khi bạn yêu cầu;
                   mất vài phút, CPU và RAM tải nặng; chỉ Linux, cần root)

Thông báo (cho cron, systemd timer, Task Scheduler; xem docs/notify.md):
  --notify-config TỆP
                   gửi kết quả tới các kênh khai báo trong TỆP (Telegram, Zalo,
                   Slack, Discord, webhook, e-mail); hoặc đặt DIAGWARD_NOTIFY_CONFIG.
                   Mặc định chỉ gửi khi có thay đổi: lỗi mới hoặc nặng hơn,
                   lỗi đã hết, lần chạy đầu tiên có lỗi
  --state TỆP      nơi lưu kết quả lần trước (mặc định /var/lib/diagward/state.json
                   khi chạy root, ~/.local/state/diagward với người dùng khác,
                   %ProgramData%\Diagward trên Windows)
  --notify-always  lần nào cũng gửi, kể cả khi không có gì thay đổi
  --force          vẫn dùng tệp cấu hình dù người dùng khác đọc được
Không gửi được thông báo thì chỉ in cảnh báo, mã thoát không thay đổi.
`},

	"collect": {`Usage: diagward collect [-o FILE.dwb] [--since N] [--timeout SEC] [-q]

Collects the same data as "check" but only saves it to a bundle file (.dwb)
without analysing it. Customers can run this and send the file; support
staff analyse it anywhere with "diagward analyze FILE.dwb".

  -o FILE.dwb      where to save (default diagward-<host>-<date>.dwb here)
  --since N        days of logs to read (default 7)
  --timeout SEC    per-command timeout in seconds (default 30)
  -q, --quiet      print only the saved file's path
  --lang vi|en     language
`, `Cách dùng: diagward collect [-o TỆP.dwb] [--since N] [--timeout GIÂY] [-q]

Thu thập dữ liệu giống "check" nhưng chỉ lưu vào tệp bundle (.dwb), không
phân tích. Khách hàng có thể chạy lệnh này rồi gửi tệp; bộ phận hỗ trợ phân
tích ở máy bất kỳ bằng "diagward analyze TỆP.dwb".

  -o TỆP.dwb       nơi lưu (mặc định diagward-<máy>-<ngày>.dwb ở thư mục hiện tại)
  --since N        số ngày nhật ký cần đọc (mặc định 7)
  --timeout GIÂY   thời gian chờ tối đa cho mỗi lệnh (mặc định 30)
  -q, --quiet      chỉ in đường dẫn tệp đã lưu
  --lang vi|en     ngôn ngữ
`},

	"analyze": {`Usage: diagward analyze FILE.dwb [flags]

Analyses a bundle saved by "diagward collect", "diagward check --save" or
"diagward bmc --save". Works on any computer (Linux, Windows, macOS).
`, `Cách dùng: diagward analyze TỆP.dwb [tùy chọn]

Phân tích bundle đã lưu bằng "diagward collect", "diagward check --save"
hoặc "diagward bmc --save". Chạy được trên máy bất kỳ (Linux, Windows, macOS).
`},

	"bmc": {`Usage: diagward bmc HOST [--user USER] [flags]

Reads a server's management controller over the network (Redfish over HTTPS,
or IPMI over LAN with ipmitool): health, sensors, fans, power supplies,
event log and part serial numbers. Works even when the server hangs or does
not boot.

  --user USER      BMC user (or DIAGWARD_BMC_USER; asked when missing)
  --port N         port (default 443 for Redfish, 623 for IPMI)
  --protocol P     auto (Redfish, then IPMI), redfish or ipmi (default auto)
  --insecure, -k   accept the BMC's self-signed TLS certificate
  --since N        days of event log to read (default 30)
  --timeout SEC    timeout for the whole collection (default 120)

Password: set DIAGWARD_BMC_PASSWORD, or type it when asked (not echoed).
For safety it is never accepted as a command-line flag.
`, `Cách dùng: diagward bmc ĐỊA_CHỈ [--user TÀI_KHOẢN] [tùy chọn]

Đọc bộ điều khiển quản trị (BMC) của máy chủ qua mạng (Redfish qua HTTPS,
hoặc IPMI over LAN bằng ipmitool): tình trạng, cảm biến, quạt, nguồn, nhật
ký sự kiện và serial linh kiện. Dùng được cả khi máy chủ treo hoặc không
khởi động được.

  --user TÀI_KHOẢN tài khoản BMC (hoặc DIAGWARD_BMC_USER; sẽ hỏi nếu thiếu)
  --port N         cổng (mặc định 443 cho Redfish, 623 cho IPMI)
  --protocol P     auto (thử Redfish rồi IPMI), redfish hoặc ipmi (mặc định auto)
  --insecure, -k   chấp nhận chứng chỉ TLS tự ký của BMC
  --since N        số ngày nhật ký sự kiện cần đọc (mặc định 30)
  --timeout GIÂY   thời gian chờ cho cả lần đọc (mặc định 120)

Mật khẩu: đặt biến DIAGWARD_BMC_PASSWORD, hoặc gõ khi được hỏi (không hiện
ra màn hình). Vì an toàn, không bao giờ nhận mật khẩu qua tham số dòng lệnh.
`},

	"install-tools": {`Usage: diagward install-tools [--yes] [--memtester]

Linux: finds which helper tools this server needs and lacks (smartctl,
sensors, ipmitool when there is a BMC, nvme, mdadm when there are md arrays,
dmidecode, ethtool, rasdaemon), shows ONE install command for the
distribution (dnf/yum, apt, zypper, ...), runs it after you confirm, then
offers the follow-ups: sensors-detect --auto, loading the IPMI drivers and
enabling smartd/rasdaemon. Needs root.

Windows: prints what to install (smartmontools, RAID controller tools).

  -y, --yes        do not ask before running commands
  --memtester      also install memtester (for "check --memtest"; EPEL on
                   AlmaLinux/Rocky/RHEL)
  --lang vi|en     language
`, `Cách dùng: diagward install-tools [--yes] [--memtester]

Linux: tìm các công cụ hỗ trợ máy chủ này cần mà chưa có (smartctl, sensors,
ipmitool khi có BMC, nvme, mdadm khi có RAID mềm, dmidecode, ethtool,
rasdaemon), đưa ra MỘT lệnh cài phù hợp bản phân phối (dnf/yum, apt,
zypper, ...), chạy sau khi bạn đồng ý, rồi đề xuất các bước tiếp theo:
sensors-detect --auto, nạp driver IPMI, bật smartd/rasdaemon. Cần quyền root.

Windows: in hướng dẫn cần cài gì (smartmontools, công cụ card RAID).

  -y, --yes        không hỏi lại trước khi chạy lệnh
  --memtester      cài thêm memtester (cho "check --memtest"; cần EPEL trên
                   AlmaLinux/Rocky/RHEL)
  --lang vi|en     ngôn ngữ
`},

	"notify-test": {`Usage: diagward notify-test --notify-config FILE [--force]

Sends a test message to every channel in FILE and shows which ones work.
Run it once after writing the config (see docs/notify.md for the format).
The exit code is 3 when the message could not be sent to some channel.

  --notify-config FILE
                   the notification config (or DIAGWARD_NOTIFY_CONFIG)
  --force          accept a config file that other users can read
  --lang vi|en     language (the config's lang = applies otherwise)
`, `Cách dùng: diagward notify-test --notify-config TỆP [--force]

Gửi một tin nhắn thử tới từng kênh trong TỆP và cho biết kênh nào gửi được.
Nên chạy một lần sau khi viết xong tệp cấu hình (định dạng xem docs/notify.md).
Mã thoát là 3 nếu có kênh không gửi được.

  --notify-config TỆP
                   tệp cấu hình thông báo (hoặc biến DIAGWARD_NOTIFY_CONFIG)
  --force          vẫn dùng tệp cấu hình dù người dùng khác đọc được
  --lang vi|en     ngôn ngữ (nếu không có thì theo lang = trong tệp cấu hình)
`},

	"version": {"Usage: diagward version\n", "Cách dùng: diagward version\n"},
	"help":    {"Usage: diagward help [command]\n", "Cách dùng: diagward help [lệnh]\n"},
}
