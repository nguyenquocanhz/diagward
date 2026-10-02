# Common helpers for the Windows collector. Must run on Windows PowerShell 5.1
# (Windows Server 2016+) and PowerShell 7. Variables set by Go before this
# file: $DW_B, $DW_VERSION, $DW_SINCE_DAYS, $DW_BENCH_DIR, $DW_BENCH_MB,
# $DW_MEMTEST, $DW_MAXLINES, $DW_TIMEOUT (all strings).
#
# Rules for domain snippets:
#  * Select only the properties you need (Select-Object) — raw CIM objects
#    serialise to huge JSON.
#  * Convert dates to ISO strings yourself: $_.TimeCreated.ToUniversalTime().ToString('o').
#    (PowerShell 5.1 would write "\/Date(ms)\/".)
#  * Enums serialise as numbers; that is fine, the Go side maps them.
#  * Never prompt, never write to the host, never change anything.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}

$DW_MAXCHARS = 4194304
$DW_TIMEOUT_S = 30
try { $DW_TIMEOUT_S = [int]$DW_TIMEOUT } catch {}
$DW_ADMIN = $false
try {
  $DW_ADMIN = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

# Extra places vendor tools are commonly installed.
$DW_TOOLDIRS = @(
  "$env:ProgramFiles\smartmontools\bin",
  "${env:ProgramFiles(x86)}\smartmontools\bin",
  "$env:ProgramFiles\Dell\SysMgt\oma\bin",
  "$env:ProgramFiles\Dell\SysMgt\iSM\bin",
  "$env:ProgramFiles\Smart Storage Administrator\ssacli\bin",
  "$env:ProgramFiles\Compaq\Hpacucli\Bin",
  "$env:SystemDrive\storcli", "$env:SystemDrive\perccli",
  "$env:ProgramFiles\Broadcom\StorCLI", "$env:ProgramFiles\Dell\PERCCLI"
)

function DW-Emit([string]$Name, [string]$Out, [string]$Err, [int]$Rc, [long]$Ms, [string]$Flags) {
  if ($null -eq $Out) { $Out = '' }
  if ($null -eq $Err) { $Err = '' }
  if ($Out.Length -gt $DW_MAXCHARS) { $Out = $Out.Substring(0, $DW_MAXCHARS); $Flags = ("$Flags truncated").Trim() }
  if ($Err.Length -gt 65536) { $Err = $Err.Substring(0, 65536) }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append("==DW:${DW_B}:BEGIN $Name`n").Append($Out).Append("`n==DW:${DW_B}:ERR`n").Append($Err)
  [void]$sb.Append("`n==DW:${DW_B}:END rc=$Rc ms=$Ms")
  if ($Flags) { [void]$sb.Append(' ').Append($Flags) }
  [void]$sb.Append("`n")
  [Console]::Out.Write($sb.ToString())
  [Console]::Out.Flush()
}

# DW-Has NAME — is a command available?
function DW-Has([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# DW-FindExe NAME — full path of an executable on PATH or in $DW_TOOLDIRS, or $null.
function DW-FindExe([string]$Name) {
  $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { return $c.Source }
  foreach ($d in $DW_TOOLDIRS) {
    if (-not $d) { continue }
    $p = Join-Path $d $Name
    if (Test-Path -LiteralPath $p) { return $p }
    if (Test-Path -LiteralPath "$p.exe") { return "$p.exe" }
  }
  return $null
}

# DW-Json NAME { scriptblock } [DEPTH] — run the block and emit its output as
# a JSON array (always an array, even for one or zero objects).
function DW-Json([string]$Name, [scriptblock]$Script, [int]$Depth = 5) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $errs = New-Object System.Collections.Generic.List[string]
  $rc = 0
  $out = '[]'
  try {
    $items = New-Object System.Collections.Generic.List[object]
    & $Script 2>&1 | ForEach-Object {
      if ($_ -is [System.Management.Automation.ErrorRecord]) { $errs.Add($_.ToString()) }
      elseif ($null -ne $_) { $items.Add($_) }
    }
    $out = ConvertTo-Json -InputObject @($items.ToArray()) -Depth $Depth -Compress
    if (-not $out) { $out = '[]' }
  } catch {
    $rc = 1
    $errs.Add($_.ToString())
  }
  DW-Emit $Name $out ($errs -join "`n") $rc $sw.ElapsedMilliseconds ''
}

# DW-Text NAME { scriptblock } — run the block and emit its output as text.
function DW-Text([string]$Name, [scriptblock]$Script) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $errs = New-Object System.Collections.Generic.List[string]
  $rc = 0
  $out = ''
  try {
    $lines = New-Object System.Collections.Generic.List[string]
    & $Script 2>&1 | ForEach-Object {
      if ($_ -is [System.Management.Automation.ErrorRecord]) { $errs.Add($_.ToString()) }
      elseif ($null -ne $_) { $lines.Add(($_ | Out-String -Width 4096).TrimEnd()) }
    }
    $out = $lines -join "`n"
  } catch {
    $rc = 1
    $errs.Add($_.ToString())
  }
  DW-Emit $Name $out ($errs -join "`n") $rc $sw.ElapsedMilliseconds ''
}

# DW-Exe NAME EXE [ARGS...] — run an external program under the timeout.
# Records missing=EXE when it cannot be found.
function DW-Exe([string]$Name, [string]$Exe, [string[]]$ArgList = @()) {
  $path = DW-FindExe $Exe
  if (-not $path) { DW-Missing $Name $Exe; return }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $quoted = foreach ($a in $ArgList) {
    if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $path
  $psi.Arguments = ($quoted -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $flags = ''
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
    $out = ''
    $err = $_.ToString()
  }
  DW-Emit $Name $out $err $rc $sw.ElapsedMilliseconds $flags
}

# DW-Missing NAME WHAT / DW-Skip NAME REASON
# Reasons: not-admin, virtual, disabled, not-applicable.
function DW-Missing([string]$Name, [string]$What) { DW-Emit $Name '' '' 127 0 "missing=$($What -replace '\s','_')" }
function DW-Skip([string]$Name, [string]$Reason) { DW-Emit $Name '' '' 0 0 "skipped=$Reason" }

# ---- meta sections (owned by the framework, read by collect.EnvOf) ----

DW-Json 'meta.ident' {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
  [pscustomobject]@{
    hostname  = $env:COMPUTERNAME
    fqdn      = $(try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME })
    user      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    admin     = $DW_ADMIN
    caption   = $os.Caption
    version   = $os.Version
    build     = $os.BuildNumber
    arch      = $env:PROCESSOR_ARCHITECTURE
    lastBoot  = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null })
    now       = (Get-Date).ToUniversalTime().ToString('o')
    ps        = $PSVersionTable.PSVersion.ToString()
    collector = $DW_VERSION
  }
}

DW-Json 'meta.virt' {
  $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
  [pscustomobject]@{
    manufacturer      = $cs.Manufacturer
    model             = $cs.Model
    hypervisorPresent = $cs.HypervisorPresent
    biosManufacturer  = $bios.Manufacturer
    biosVersion       = $bios.SMBIOSBIOSVersion
  }
}
