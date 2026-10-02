# IPMI (in-band) on Windows: ipmitool.exe through the Microsoft IPMI driver,
# when ipmitool is installed (e.g. with Dell OpenManage BMC Utility). Same
# section names as Linux and the out-of-band BMC collector, so one parser
# serves all. ipmi.win_devices tells the analysis whether a BMC exists.
# Read-only commands only; the SEL is never cleared here.

$IP_SECS = @('ipmi.mc', 'ipmi.chassis', 'ipmi.sel_info', 'ipmi.sel_time', 'ipmi.sdr', 'ipmi.sel', 'ipmi.fru', 'ipmi.lan', 'ipmi.power')

$IP_EXE = DW-FindExe 'ipmitool'
if (-not $IP_EXE) {
  foreach ($d in @("$env:ProgramFiles\Dell\SysMgt\bmc", "${env:ProgramFiles(x86)}\Dell\SysMgt\bmc", "$env:ProgramFiles\ipmitool", "$env:SystemDrive\ipmitool")) {
    if (-not $d) { continue }
    $p = Join-Path $d 'ipmitool.exe'
    if (Test-Path -LiteralPath $p) { $IP_EXE = $p; break }
  }
}

# The device name is localised on some Windows languages; the ACPI hardware
# ID of an IPMI system interface (IPI0001) is not.
DW-Json 'ipmi.win_devices' {
  $pnp = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "Name LIKE '%IPMI%' OR PNPDeviceID LIKE 'ACPI\\IPI0001%'" -ErrorAction SilentlyContinue |
      Select-Object -First 4 Name, Status, PNPDeviceID)
  $wmi = $null
  if ($DW_ADMIN) {
    try { $wmi = @(Get-CimInstance -Namespace 'root\wmi' -ClassName Microsoft_IPMI -ErrorAction Stop).Count } catch { $wmi = -1 }
  }
  [pscustomobject]@{ pnp = $pnp; wmiIpmi = $wmi; ipmitool = $IP_EXE; admin = $DW_ADMIN }
}

# Ip-Run NAME ARGS [MODE] [TIMEOUT_S] - DW-Run, then post-process stdout
# before it is emitted: 'sel' keeps the newest $DW_MAXLINES lines, 'lan'
# redacts the SNMP community string (a credential that must not leave the
# server). Returns the exit code.
function Ip-Run([string]$Name, [string[]]$ArgList, [string]$Mode = '', [int]$TimeoutS = 0) {
  $r = DW-Run $IP_EXE $ArgList '' $TimeoutS
  if ($null -eq $r) { DW-Missing $Name 'ipmitool'; return 127 }
  $out = $r.Out
  $err = $r.Err
  if ($null -eq $out) { $out = '' }
  if ($Mode -eq 'sel') {
    $lines = @($out -split "`r?`n" | Where-Object { $_ -ne '' })
    $max = 3000
    try { $max = [int]$DW_MAXLINES } catch {}
    if ($lines.Count -gt $max) {
      $err = ("diagward: kept the newest $max of $($lines.Count) SEL entries`n" + $err)
      $lines = $lines[($lines.Count - $max)..($lines.Count - 1)]
    }
    $out = $lines -join "`n"
  } elseif ($Mode -eq 'lan') {
    $out = $out -replace '(?m)^(SNMP Community String\s*:).*$', '$1 <redacted>'
  }
  DW-Emit $Name $out $err $r.Rc $r.Ms $r.Flags
  return $r.Rc
}

if (-not $IP_EXE) {
  foreach ($s in $IP_SECS) { DW-Missing $s 'ipmitool' }
} elseif (-not $DW_ADMIN) {
  foreach ($s in $IP_SECS) { DW-Skip $s 'not-admin' }
} else {
  # Builds with the Microsoft driver interface list "ms" under Interfaces
  # in their usage text (printed on stdout or stderr, exit code non-zero).
  $IP_IF = @()
  $h = DW-Run $IP_EXE @('-h') '' 10
  if ($h -and (($h.Out + "`n" + $h.Err) -match '(?m)^\s+ms\s')) { $IP_IF = @('-I', 'ms') }

  $rc = Ip-Run 'ipmi.mc' ($IP_IF + @('mc', 'info'))
  if ($rc -eq 124) {
    # A wedged BMC makes every command wait for the full timeout.
    foreach ($s in $IP_SECS) { if ($s -ne 'ipmi.mc') { DW-Skip $s 'bmc-timeout' } }
  } else {
    [void](Ip-Run 'ipmi.chassis' ($IP_IF + @('chassis', 'status')))
    [void](Ip-Run 'ipmi.sel_info' ($IP_IF + @('sel', 'info')))
    [void](Ip-Run 'ipmi.sel_time' ($IP_IF + @('sel', 'time', 'get')))
    # SDR, SEL and FRU walk many records: allow four times the timeout. On a
    # timeout DW-Run kills ipmitool and keeps what it printed so far.
    $ipLong = $DW_TIMEOUT_S * 4
    [void](Ip-Run 'ipmi.sdr' ($IP_IF + @('sdr', 'elist')) '' $ipLong)
    [void](Ip-Run 'ipmi.sel' ($IP_IF + @('sel', 'elist')) 'sel' $ipLong)
    [void](Ip-Run 'ipmi.fru' ($IP_IF + @('fru', 'print')) '' $ipLong)
    [void](Ip-Run 'ipmi.lan' ($IP_IF + @('lan', 'print')) 'lan')
    [void](Ip-Run 'ipmi.power' ($IP_IF + @('dcmi', 'power', 'reading')))
  }
}
