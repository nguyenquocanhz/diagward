# IPMI (in-band) on Windows: ipmitool.exe through the Microsoft IPMI driver,
# when ipmitool is installed (e.g. with Dell OpenManage BMC Utility). Same
# section names as Linux and the out-of-band BMC collector, so one parser
# serves all. ipmi.win_devices tells the analysis whether a BMC exists.
# Read-only commands only; the SEL is never cleared here.

$IP_SECS = @('ipmi.mc', 'ipmi.chassis', 'ipmi.sel_info', 'ipmi.sdr', 'ipmi.sel', 'ipmi.fru', 'ipmi.lan', 'ipmi.power')

$IP_EXE = DW-FindExe 'ipmitool'
if (-not $IP_EXE) {
  foreach ($d in @("$env:ProgramFiles\Dell\SysMgt\bmc", "${env:ProgramFiles(x86)}\Dell\SysMgt\bmc", "$env:ProgramFiles\ipmitool", "$env:SystemDrive\ipmitool")) {
    if (-not $d) { continue }
    $p = Join-Path $d 'ipmitool.exe'
    if (Test-Path -LiteralPath $p) { $IP_EXE = $p; break }
  }
}

DW-Json 'ipmi.win_devices' {
  $pnp = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "Name LIKE '%IPMI%'" -ErrorAction SilentlyContinue |
      Select-Object -First 4 Name, Status, PNPDeviceID)
  $wmi = $null
  if ($DW_ADMIN) {
    try { $wmi = @(Get-CimInstance -Namespace 'root\wmi' -ClassName Microsoft_IPMI -ErrorAction Stop).Count } catch { $wmi = -1 }
  }
  [pscustomobject]@{ pnp = $pnp; wmiIpmi = $wmi; ipmitool = $IP_EXE; admin = $DW_ADMIN }
}

# Ip-Run NAME ARGS MODE - like DW-Exe, but post-processes stdout before it is
# emitted: 'sel' keeps the newest $DW_MAXLINES lines, 'lan' redacts the SNMP
# community string (a credential that must not leave the server).
function Ip-Run([string]$Name, [string[]]$ArgList, [string]$Mode) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $IP_EXE
  $psi.Arguments = ($ArgList -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $flags = ''
  $out = ''
  $err = ''
  try {
    $p = [Diagnostics.Process]::Start($psi)
    $ot = $p.StandardOutput.ReadToEndAsync()
    $et = $p.StandardError.ReadToEndAsync()
    if ($p.WaitForExit($DW_TIMEOUT_S * 1000)) {
      $p.WaitForExit()
      $rc = $p.ExitCode
    } else {
      try { $p.Kill() } catch {}
      $rc = 124
      $flags = 'timeout'
    }
    $out = $ot.Result
    $err = $et.Result
  } catch {
    $rc = 1
    $err = $_.ToString()
  }
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
  DW-Emit $Name $out $err $rc $sw.ElapsedMilliseconds $flags
}

if (-not $IP_EXE) {
  foreach ($s in $IP_SECS) { DW-Missing $s 'ipmitool' }
} elseif (-not $DW_ADMIN) {
  foreach ($s in $IP_SECS) { DW-Skip $s 'not-admin' }
} else {
  # Builds with the Microsoft driver interface list "ms" under Interfaces.
  $IP_IF = @()
  try {
    $help = (& $IP_EXE -h 2>&1 | Out-String)
    if ($help -match '(?m)^\s+ms\s') { $IP_IF = @('-I', 'ms') }
  } catch {}

  $sw = [Diagnostics.Stopwatch]::StartNew()
  DW-Exe 'ipmi.mc' $IP_EXE ($IP_IF + @('mc', 'info'))
  if ($sw.ElapsedMilliseconds -ge ($DW_TIMEOUT_S * 1000)) {
    # A wedged BMC makes every command wait for the full timeout.
    foreach ($s in $IP_SECS) { if ($s -ne 'ipmi.mc') { DW-Skip $s 'bmc-timeout' } }
  } else {
    DW-Exe 'ipmi.chassis' $IP_EXE ($IP_IF + @('chassis', 'status'))
    DW-Exe 'ipmi.sel_info' $IP_EXE ($IP_IF + @('sel', 'info'))
    # SDR, SEL and FRU walk many records: allow four times the timeout.
    $ipSaved = $DW_TIMEOUT_S
    $DW_TIMEOUT_S = $DW_TIMEOUT_S * 4
    DW-Exe 'ipmi.sdr' $IP_EXE ($IP_IF + @('sdr', 'elist'))
    Ip-Run 'ipmi.sel' ($IP_IF + @('sel', 'elist')) 'sel'
    DW-Exe 'ipmi.fru' $IP_EXE ($IP_IF + @('fru', 'print'))
    $DW_TIMEOUT_S = $ipSaved
    Ip-Run 'ipmi.lan' ($IP_IF + @('lan', 'print')) 'lan'
    DW-Exe 'ipmi.power' $IP_EXE ($IP_IF + @('dcmi', 'power', 'reading'))
  }
}
