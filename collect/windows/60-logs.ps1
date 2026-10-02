# 60-logs.ps1 - logs domain: System event log entries that reveal failing
# hardware, unexpected reboots and blue screens. PowerShell 5.1 compatible.
#
# Messages are localised (Vietnamese Windows writes Vietnamese text), so the
# Go side classifies by provider + event ID + level only; the message is kept
# for the report. Properties (insertion strings) are language-neutral: device
# paths (\Device\Harddisk1\DR1), bugcheck codes, volume names.
#
# logs.win_events   hardware-relevant error/warning events (newest first)
#                   [{t, p, id, l, m, x}] t=UTC ISO time, p=provider, l=level
#                   (1 critical, 2 error, 3 warning), m=message (400 chars),
#                   x=first 8 properties as strings (Kernel-Power 41: [0]
#                   BugcheckCode in decimal, [5] SleepInProgress,
#                   [6] PowerButtonTimestamp)
# logs.win_summary  every error/warning provider+ID in the window with a count
# logs.win_boots    boot/shutdown bookkeeping events (planned restarts, 41/6008)
# logs.win_meta     [{read, readMax, wanted, wantedMax, oldest}]: how many
#                   events were read, so a cap hit is reported as partial

$_lg_days = 7
try { $_lg_days = [int]$DW_SINCE_DAYS } catch {}
$_lg_max = 3000
try { $_lg_max = [int]$DW_MAXLINES } catch {}
$_lg_start = (Get-Date).AddDays(-$_lg_days)

# Providers and event IDs that matter. An empty ID list means every ID.
$_lg_want = @{
  'Microsoft-Windows-WHEA-Logger'               = @()
  'Microsoft-Windows-Kernel-Power'              = @(41)
  'EventLog'                                    = @(6008)
  'Microsoft-Windows-WER-SystemErrorReporting'  = @(1001)
  'BugCheck'                                    = @(1001)
  'disk'                                        = @(7, 11, 15, 51, 52, 153, 154, 157)
  'Ntfs'                                        = @(50, 55, 98, 137, 140)
  'Microsoft-Windows-Ntfs'                      = @(50, 55, 98, 137, 140)
  'volmgr'                                      = @(45, 46, 161, 162)
  'Microsoft-Windows-Kernel-Processor-Power'    = @(37)
  'Microsoft-Windows-Resource-Exhaustion-Detector' = @(2004)
  'Microsoft-Windows-NDIS'                      = @(10317, 10400)
}
# Storage miniport drivers log "reset to device" (129), "did not respond" (9)
# and "controller error" (11) under their own driver name.
$_lg_storRe = '^(stor\w*|iaStor\w*|LSI_\w+|megasas\w*|percsas\w*|HpCISSs\d*|HpSAMD|SmartPqi|arcsas|ADPU320|mpt\w*|ql2\w+|elx\w+|nvme\w*|vhdmp|UASPStor|USBSTOR|amd_?sata|amdxata|mvs\w*|RSTe\w*|vsmraid|3ware|MegaSR\w*|SmartRAID\w*)$'
# NIC drivers: Intel (ID 27 "link is disconnected"), Broadcom/QLogic (ID 4
# "link is down"), Mellanox/NVIDIA WinOF (ID 14 "link is down").
$_lg_nicRe = '^(e1\w*express|e1\w*65|ixgb\w*|ixn\w*|ixs\w*|ixt\w*|i40e\w*|icea\w*|iavf\w*|b57nd60\w*|l2nd\w*|bxnd\w*|bxvbd\w*|bnxtnd\w*|q57nd60\w*|evbd\w*|qebdrv\w*|mlx4\w*|mlx5\w*|ibbus)$'

function _lg_Wanted($e) {
  $p = [string]$e.ProviderName
  if ($p -eq 'Microsoft-Windows-MemoryDiagnostics-Results') { return $false }
  if ($_lg_want.ContainsKey($p)) {
    $ids = $_lg_want[$p]
    return ($ids.Count -eq 0 -or ($ids -contains $e.Id))
  }
  if ($p -match $_lg_storRe -and @(9, 11, 129) -contains $e.Id) { return $true }
  if ($p -match $_lg_nicRe -and @(4, 14, 27) -contains $e.Id) { return $true }
  return $false
}

function _lg_Props($e) {
  $out = @()
  $n = 0
  foreach ($pr in @($e.Properties)) {
    if ($n -ge 8) { break }
    $n++
    $v = $pr.Value
    if ($null -eq $v -or $v -is [byte[]]) { $out += ''; continue }
    $s = [string]$v
    if ($s.Length -gt 200) { $s = $s.Substring(0, 200) }
    $out += $s
  }
  return , $out
}

function _lg_Event($e) {
  $m = ''
  try { $m = [string]$e.Message } catch {}
  if (-not $m) { $m = '' }
  $m = ($m -replace '\s+', ' ').Trim()
  if ($m.Length -gt 400) { $m = $m.Substring(0, 400) }
  $t = $null
  if ($e.TimeCreated) { $t = $e.TimeCreated.ToUniversalTime().ToString('o') }
  [pscustomobject]@{
    t  = $t
    p  = [string]$e.ProviderName
    id = [int]$e.Id
    l  = [int]$e.Level
    m  = $m
    x  = (_lg_Props $e)
  }
}

# One read of the System log (levels 1-3) shared by both sections.
$_lg_readMax = 50000
$_lg_err = $null
$_lg_ev = @()
try {
  $_lg_ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $_lg_start } -MaxEvents $_lg_readMax -ErrorAction Stop)
} catch {
  if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $_lg_err = $_.ToString() }
  $_lg_ev = @()
}

$_lg_wanted = 0
DW-Json 'logs.win_events' {
  if ($_lg_err) { Write-Error $_lg_err }
  foreach ($e in $_lg_ev) {
    if ($script:_lg_wanted -ge $_lg_max) { break }
    if (_lg_Wanted $e) { $script:_lg_wanted++; _lg_Event $e }
  }
} 4

DW-Json 'logs.win_meta' {
  $oldest = $null
  if ($_lg_ev.Count -gt 0 -and $_lg_ev[-1].TimeCreated) { $oldest = $_lg_ev[-1].TimeCreated.ToUniversalTime().ToString('o') }
  [pscustomobject]@{ read = [int]$_lg_ev.Count; readMax = [int]$_lg_readMax; wanted = [int]$script:_lg_wanted; wantedMax = [int]$_lg_max; oldest = $oldest }
}

DW-Json 'logs.win_summary' {
  if ($_lg_err) { Write-Error $_lg_err }
  $_lg_ev | Group-Object ProviderName, Id, Level | ForEach-Object {
    $f = $_.Group[0]
    $last = $null
    if ($f.TimeCreated) { $last = $f.TimeCreated.ToUniversalTime().ToString('o') }
    [pscustomobject]@{ p = [string]$f.ProviderName; id = [int]$f.Id; l = [int]$f.Level; n = [int]$_.Count; last = $last }
  } | Sort-Object n -Descending | Select-Object -First 200
}

# Boot bookkeeping: 6005/6006/6009 (EventLog started/stopped), 6008
# (unexpected), Kernel-General 12/13 (OS start/shutdown), Kernel-Power 41,
# User32 1074 (who asked for a restart/shutdown, and why).
DW-Json 'logs.win_boots' {
  $q = @(
    @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6005, 6006, 6008, 6009; StartTime = $_lg_start },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12, 13; StartTime = $_lg_start },
    @{ LogName = 'System'; ProviderName = 'User32'; Id = 1074; StartTime = $_lg_start },
    @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $_lg_start }
  )
  foreach ($h in $q) {
    try {
      Get-WinEvent -FilterHashtable $h -MaxEvents 500 -ErrorAction Stop | ForEach-Object { _lg_Event $_ }
    } catch {
      if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { Write-Error $_.ToString() }
    }
  }
} 4
