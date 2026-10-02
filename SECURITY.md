# Security

## What Diagward does on a server

- The collector only **reads**: it runs inspection commands (`smartctl`,
  `dmidecode`, `ipmitool sdr/sel`, `journalctl`, PowerShell `Get-*` cmdlets)
  and reads `/proc` and `/sys`. It does not change settings, install
  anything, or send data anywhere.
- Two checks write, and only when you ask for them: `--bench DIR` writes and
  deletes one test file in `DIR`, and `--memtest SIZE` runs `memtester`.
- `diagward install-tools` installs packages, and only after it shows you
  the command and you confirm.
- Reports and bundles stay on the machine where you create them. They
  contain hardware inventory (serial numbers, BMC address), hostnames and
  log lines. Review them before sending them outside your organisation.

## BMC access

- `diagward bmc` asks for the password interactively or reads
  `DIAGWARD_BMC_PASSWORD`; it never accepts it as a command-line flag. For
  IPMI over LAN the password is passed to `ipmitool` through the
  `IPMI_PASSWORD` environment variable, never on its command line.
- TLS certificates are verified by default. `--insecure` skips verification
  for BMCs with self-signed certificates; use it only on a management
  network you trust.
- Credentials are never written to bundles, reports or logs.

## Reporting a vulnerability

Please report security problems privately through
[GitHub security advisories](https://github.com/nguyenquocanhz/diagward/security/advisories/new)
rather than a public issue.
