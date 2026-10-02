# Diagward architecture (and the contract every part follows)

Diagward diagnoses server **hardware** for IT support staff: disks (S.M.A.R.T.),
RAID, RAM (ECC), CPU (machine checks, throttling), temperatures, fans, power
supplies, BMC event logs, NICs and the kernel/event logs that reveal failing
hardware. It explains each problem in Vietnamese or English, says what to
do, and lists the serial numbers needed for a warranty case.

```
   target machine                         anywhere
 ┌──────────────────────┐   framed text   ┌────────────────────────────────────┐
 │ collector script      │ ─────────────▶ │ collect.ParseFramed → Bundle (.dwb) │
 │ (sh / PowerShell)     │  local or SSH  │ diag.Analyze → model.Report         │
 └──────────────────────┘                 │ report.Text / HTML / Markdown / JSON│
                                           └────────────────────────────────────┘
```

1. **Collect** (`collect/`). One script per OS, assembled from snippets in
   `collect/linux/NN-domain.sh` and `collect/windows/NN-domain.ps1`, run in
   file-name order. Snippets only *read*: they never change the system
   (except the opt-in disk/memory tests, which clean up after themselves).
   Output is a series of framed **sections**.
2. **Bundle** (`collect.Bundle`). The parsed sections plus metadata. It can be
   saved (`.dwb`, gzip JSON) and analysed later on another machine — a
   customer can run `diagward collect` and send the file.
3. **Analyze** (`diag.Analyze`). Runs every domain check
   (`internal/checks/<domain>`). Each returns a `model.Result`: findings,
   tables, coverage and typed facts. A panicking check becomes "failed"
   coverage; the report is still produced.
4. **Report** (`report/`). Renders a `model.Report` as terminal text, a
   self-contained HTML file, Markdown (for tickets/chat) or JSON.

Out-of-band: `bmc/` reads a server's BMC (Redfish over HTTPS, or IPMI over
LAN through `ipmitool`) into a Bundle with `OS = "bmc"`, so a server that
hangs or will not boot can still be diagnosed from a laptop.

Termward (the SSH manager) imports `collect`, `diag`, `model` and `report`
and runs the same script over its SSH connections.

## Ownership

| Path | Owner | Contents |
|---|---|---|
| `model/`, `collect/{bundle,frame,script,env}.go`, `collect/*/00-common.*`, `collect/*/99-end.*`, `diag/`, `internal/{hint,units,testkit}` | framework | shared contract — change only with care |
| `internal/checks/system`, `network`, `filesystem` + `collect/*/10-system.*`, `50-network.*`, `55-filesystem.*` | system | identity, virtualisation, NICs/bonds, mounts/space |
| `internal/checks/cpu`, `memory` + `20-cpu.*`, `21-memory.*` | cpu/memory | DIMMs, ECC/EDAC, MCE, rasdaemon/mcelog, throttling, memtester |
| `internal/checks/disk` + `30-disk.*` | disk | lsblk, S.M.A.R.T. (ATA/NVMe/SCSI, behind RAID), smartd, disk benchmark |
| `internal/checks/raid` + `35-raid.*` | raid | mdadm, ZFS, LVM RAID, Btrfs, hardware RAID CLIs, Storage Spaces |
| `internal/checks/sensors`, `ipmi` + `40-sensors.*`, `45-ipmi.*` | sensors/ipmi | lm-sensors, hwmon, thermal zones, ipmitool SDR/SEL/chassis/FRU |
| `internal/checks/logs` + `60-logs.*` | logs | kernel log / journal patterns, unexpected reboots, Windows event log |
| `internal/checks/redfish`, `bmc/` | bmc | Redfish client and analysis, IPMI-over-LAN collection |
| `report/` | report | text/HTML/Markdown/JSON renderers |
| `cmd/diagward`, `collect/local.go`, `internal/install` | cli | commands, local runner, tool installer |

## Sections

### Framing

```
==DW:<boundary>:BEGIN <name>
<stdout>
==DW:<boundary>:ERR
<stderr>
==DW:<boundary>:END rc=<n> ms=<n> [missing=<what>] [skipped=<why>] [timeout] [truncated]
```

Before a step the helpers also print `==DW:<boundary>:RUN <name>`; the
local runner uses it for progress and stops a collector whose step makes no
progress for max(4 × timeout, 3 min) (hung driver), recording `meta.stalled`.

Always use the helpers; never print markers yourself.

**Linux (`00-common.sh`)** — POSIX sh only (dash, busybox ash, bash, CentOS 7
sh): no `local`, no arrays, no `[[ ]]`, no `$'..'`, no `echo -e`, no
`<<<`, no process substitution. Prefix your variables (`_dk_` for disk,
`_rd_` for raid, ...). `LC_ALL=C` is set.

| Helper | Use |
|---|---|
| `dw_has CMD` | is a command installed |
| `dw_run NAME CMD ARGS...` | run one command under the timeout; records `missing=CMD` if absent |
| `dw_sh NAME 'SNIPPET'` | run a self-contained sh snippet (pipes, loops) under the timeout; helpers are **not** available inside, `DW_*` vars are |
| `dw_fn NAME FUNC ARGS...` | run a shell function of yours in a subshell (no overall timeout: prefix risky commands with `$DW_TO`; a 124/137 return is flagged `timeout`) |
| `dw_run_t SECS NAME CMD ARGS...` | `dw_run` with its own timeout (long tests such as memtester) |
| `dw_file NAME PATH` | capture a small file |
| `dw_sysfs NAME GLOB...` | dump `path=value` (first line) for every readable file matching the globs |
| `dw_missing NAME WHAT` / `dw_skip NAME REASON` | record a tool that is absent / a check deliberately skipped (`not-root`, `virtual`, `container`, `disabled`, `not-applicable`, `bmc-timeout`, `low-memory`; one word, the Go side explains it) |
| `$DW_TO` | `timeout -k 5 $DW_TIMEOUT` (or empty) |
| `$DW_ROOT` | 1 when running as root |
| `$DW_VM`, `$DW_CONTAINER` | systemd-detect-virt results ("" on bare metal / not a container; `wsl` counts as a container) |
| `$DW_SINCE_DAYS`, `$DW_MAXLINES`, `$DW_BENCH_DIR`, `$DW_BENCH_MB`, `$DW_MEMTEST` | options |

Anything that can hang (smartctl on a dying disk, ipmitool on a wedged BMC,
`df` on a stale NFS mount) must run under `$DW_TO`. In containers
(`$DW_CONTAINER` set) skip hardware probes with `dw_skip NAME container`. On
VMs still try cheap probes (they may work with passthrough) but do not
treat their absence as a problem.

**Windows (`00-common.ps1`)** — PowerShell 5.1 compatible (no `??`, no
`?.`, no ternary, no `-Parallel`, no `ForEach-Object -Parallel`, no
`ConvertFrom-Json -AsHashtable`).

| Helper | Use |
|---|---|
| `DW-Json NAME { block } [depth]` | emit the block's objects as a JSON **array** (select properties first!) |
| `DW-Text NAME { block }` | emit as text |
| `DW-Exe NAME EXE @(args) [workdir]` | run an external program (PATH or common vendor dirs) under the timeout and emit it; `missing=EXE` if absent |
| `DW-Run EXE @(args) [workdir] [timeout]` | run it and **return** `@{Out;Err;Rc;Ms;Flags;Path}` (or `$null` if absent) for post-processing, then `DW-Emit` yourself |
| `DW-Missing NAME WHAT` / `DW-Skip NAME REASON` | as on Linux (`not-admin`, `virtual`, ...) |
| `DW-FindExe NAME`, `DW-Has NAME` | lookups |
| `$DW_ADMIN` | running elevated |

Write dates as ISO strings (`.ToUniversalTime().ToString('o')`); parse them
in Go with `collect.WinTime`. Decode arrays with `collect.DecodeJSON`.

### Naming

* `<domain>.<name>` — e.g. `disk.lsblk`, `raid.mdstat`, `memory.edac`.
* Windows-only sections: `<domain>.win_<name>` — e.g. `disk.win_physical`.
* One section per instance: `<domain>.<name>:<instance>` — e.g.
  `disk.smart:/dev/sda`, `disk.smart:/dev/bus/0,megaraid,3` (no spaces).
  Read them with `b.Prefix("disk.smart:")`.
* A tool whose output format is the same on every OS (smartctl, storcli,
  ipmitool) uses the **same** section name on every OS, so one parser serves
  all (e.g. smartctl on Windows still writes `disk.smart:<dev>`).
* `meta.*` is reserved for the framework.

## Domain check API

```go
package disk
func Check(b *collect.Bundle, env model.Env) model.Result
```

* Must never panic on odd input: unknown formats, truncated output, empty
  sections, sections from a newer/older collector, sections absent entirely.
* If none of the domain's sections are present (e.g. a BMC bundle for a
  Linux-only domain), return an empty Result — no coverage noise.
* Every check the domain *could* run gets a `model.Coverage` entry:
  `ran`, `partial` (ran, some data unavailable), `skipped` (tool missing →
  `Reason: hint.Missing(tool)`, `Fix: hint.Install(env, tool)`; not root →
  `hint.NeedRoot(env)` / `hint.RunAsRoot(env)`; VM/container →
  `hint.Virtual(env)`), or `failed` (ran but output unusable — include the
  stderr in Reason).
* When a coverage entry has one command that enables the check, put it in
  `Coverage.Cmd` (copy-paste ready) and keep `Fix` to the explanation;
  `hint.InstallFix(env, tool)` returns both. Name real CLI flags in texts:
  `diagward check --bench /var/tmp` (`--bench-size 1G`), `diagward check
  --memtest 2G`, `diagward bmc <address>`, `sudo diagward install-tools`.
  `hint.RootFix(env)` gives the not-root Fix + Cmd (`sudo diagward check`),
  `hint.ServiceCmd(env, svc)` the `systemctl enable --now` command.
* A skipped check that cannot exist on the platform or is covered by
  another domain sets `Coverage.NotApplicable`; it is not shown as a gap and
  does not make the component "partial".
* Put typed data in `Result.Facts` (exported structs with JSON tags).
  Domains may read another domain's *sections* and import its exported
  helper packages (e.g. memory imports `internal/checks/cpu/ras`), but must
  not duplicate another domain's finding for the same fact.
* Tables show inventory with a status per row (disks with key S.M.A.R.T.
  values, DIMMs with ECC counts, sensors with thresholds).

### Findings

* `ID` = `<domain>.<rule>` (snake_case), stable. `Component` = one of the
  `model.Comp*` constants (a domain may report other components: the ipmi
  domain reports fans, power, thermal...).
* `Target` names the thing; `Part` carries vendor/model/serial/location
  whenever the finding means "replace this part".
* `Title` one line: what is wrong, with the target. `Detail`: what was
  measured and why it matters. `Action`: concrete next steps, most urgent
  first (back up, replace part X serial Y, check cable, update firmware...).
* `Evidence`: the raw lines that prove it (`units.Evidence(lines, 10)`).
* Emit one **OK** finding per check that passed with something worth
  confirming ("4 disks passed S.M.A.R.T.", "RAID md0 healthy [UU]"), so the
  report shows what was verified. Keep OK findings few; tables hold detail.

### Severity

| Level | Meaning | Examples |
|---|---|---|
| `Crit` | failed or failing now, data or uptime at risk — act today | S.M.A.R.T. FAILED; pending/uncorrectable sectors; NVMe critical warning; RAID degraded/failed/missing member; uncorrectable ECC; fatal MCE; PSU failed or input lost; fan at 0 RPM / failed; temperature ≥ critical threshold; filesystem remounted read-only; disk I/O errors in the kernel log |
| `Warn` | degraded or wearing out — plan a fix soon | reallocated sectors; CRC errors (cable); SSD wear ≥ 80 %; corrected ECC errors rising; temperature ≥ high threshold; RAID rebuilding; controller battery/cache problem; NIC errors or link flapping; redundancy lost; unexpected reboots; throttling; SEL almost full |
| `Info` | notable, nothing to do now | smartd/rasdaemon not running; old disk (power-on > 5 years); scheduled RAID check running |
| `OK` | verified healthy | one summary per check |

Prefer certainty: do not raise `Crit` on a heuristic. Thresholds must be
justified in a code comment (vendor docs, Backblaze stats, kernel docs).

### Language

Both `EN` and `VI` are required for titles, actions and coverage names.
Write Vietnamese the way Vietnamese sysadmins talk: keep established
English terms (S.M.A.R.T., RAID, ECC, sector, firmware, BMC, PSU, SSD, NVMe,
rebuild, controller), use "ổ cứng", "thanh RAM", "khe", "nguồn", "quạt",
"cảnh báo", "lỗi", "thay", "sao lưu ngay". Short, direct, polite, no
machine-translation tone. Example:

* EN: "Disk /dev/sda is failing: 24 sectors could not be read"
* VI: "Ổ /dev/sda sắp hỏng: 24 sector không đọc được"
* Action VI: "Sao lưu dữ liệu ngay. Thay ổ /dev/sda (serial ZA1234). Nếu ổ nằm trong RAID, kiểm tra RAID đã rebuild xong trước khi rút ổ."

## Cross-domain rules

* The **logs** domain reports what the kernel log / event log says; the
  component domains report what their own counters say (EDAC, S.M.A.R.T.,
  mdstat, SEL). Both may appear: they are different evidence. A log finding
  about a disk names the device (`Part{Kind:"disk", Location:"/dev/sda"}`);
  `diag` then fills in model and serial from the disk domain's inventory.
* The logs domain reads `disk.lsblk` (name, kname, tran, pkname),
  `disk.win_physical` (DeviceId, BusType), `disk.win_diskdrive` (Index,
  InterfaceType, PNPDeviceID) and `filesystem.win_volume` (DriveLetter,
  DriveType) to tell USB or detached disks from server disks: keep those
  fields. The filesystem domain reports ZFS pool capacity (from
  `raid.zpool_list`); the raid domain does not.
* Temperatures of disks belong to the disk domain; the sensors domain shows
  nvme/drivetemp hwmon chips in its table but does not raise findings for
  them.
* On Linux ≥ 6.6 an ext4 error leaves the mount flags alone and
  /proc/mounts shows `emergency_ro` or `shutdown`; treat these like `ro`.
* `ComponentSummary.Partial` is set by `diag` when a component was checked
  but some of its checks were skipped/partial/failed.

## Tests

* Fixtures live in `internal/checks/<domain>/testdata/`. Prefer **real**
  output (from public test suites such as prometheus/procfs, node_exporter,
  smartmontools, scrutiny, DMTF Redfish mockups, or the tool's docs) over
  invented samples; record the origin of each fixture in
  `testdata/SOURCES.md` (URL + licence, or "synthesised from <doc link>").
* Cover: healthy, each failure rule, tool missing, not root, VM/container,
  Windows (if the domain has Windows support), garbage/truncated input.
* Call `testkit.Validate(t, res)` on every Result.
* Shell: `wsl -e dash -n collect/linux/NN-x.sh` and run the full script in
  WSL (`go run ./internal/devtools/dwdev -os linux -list`). WSL is Ubuntu,
  root; `apt-get install -y <tool>` there is fine for checking a tool's
  behaviour without the hardware.
* PowerShell: run `go run ./internal/devtools/dwdev -os windows -section <name>`
  on the Windows dev machine (not elevated).
* `gofmt`, `go vet` and `go test` your packages. Use only the standard
  library plus what `go.mod` already has.
