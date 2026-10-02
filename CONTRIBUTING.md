# Contributing

Thanks for helping. The most valuable contributions are **real outputs from
real hardware**: a failing disk's `smartctl -x -j`, a degraded RAID
controller's `storcli /call show all J`, an `ipmitool sel elist` with a power
supply fault. Real samples become test fixtures and make every rule more
trustworthy.

## Sharing a sample

1. Run `sudo diagward collect -o server.dwb` on the affected machine.
2. Check the file for anything you cannot share (hostnames, IP addresses,
   serial numbers) — it is gzip-compressed JSON.
3. Open an issue describing what was wrong with the hardware and attach the
   bundle (or the relevant section output).

## Code

- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first: it describes the
  collector, the section naming rules, severities and the Vietnamese/English
  wording style.
- Collector snippets must stay POSIX sh (dash, busybox, CentOS 7) and
  PowerShell 5.1 compatible, and must only read.
- Every rule needs a test with a real-format fixture and a comment that
  justifies its threshold.
- `gofmt`, `go vet ./...` and `go test ./...` must pass.

```bash
go test ./...
go run ./internal/devtools/dwdev -os linux -list      # run the collector, list sections
go run ./cmd/diagward check -v                        # full check on this machine
```
