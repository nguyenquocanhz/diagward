# RAID domain: Storage Spaces (pools, virtual disks, pool disks, repair jobs),
# RAID controller detection (Win32_SCSIController) and the vendor RAID CLIs
# (storcli/perccli/ssacli/arcconf/MegaCli) when installed. Read-only.
# Section names for the vendor CLIs match the Linux collector so one parser
# serves both.

# More places the vendor CLIs are installed by their Windows packages.
$DW_TOOLDIRS += @(
  "$env:ProgramFiles\HP\hpssacli\bin",
  "$env:ProgramFiles\HPE\ssacli\bin",
  "$env:ProgramFiles\Adaptec\maxView Storage Manager\cmdline",
  "$env:ProgramFiles\Adaptec\Adaptec Storage Manager",
  "$env:ProgramFiles\Microsemi\maxView Storage Manager\cmdline",
  "${env:ProgramFiles(x86)}\MegaRAID Storage Manager",
  "$env:SystemDrive\MegaCli"
)

# Enum values are written as their names ([string]), arrays joined by ','.
function RD-Str($v) {
  if ($null -eq $v) { return $null }
  return (@($v) | ForEach-Object { [string]$_ }) -join ','
}

if (DW-Has 'Get-StoragePool') {
  DW-Json 'raid.win_pools' {
    Get-StoragePool -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        FriendlyName      = $_.FriendlyName
        HealthStatus      = (RD-Str $_.HealthStatus)
        OperationalStatus = (RD-Str $_.OperationalStatus)
        IsPrimordial      = [bool]$_.IsPrimordial
        IsReadOnly        = [bool]$_.IsReadOnly
        Size              = $_.Size
        AllocatedSize     = $_.AllocatedSize
      }
    }
  }
  $rdPools = @()
  try { $rdPools = @(Get-StoragePool -IsPrimordial $false -ErrorAction Stop) } catch {}
  if ($rdPools.Count -gt 0) {
    DW-Json 'raid.win_vdisks' {
      foreach ($p in $rdPools) {
        Get-VirtualDisk -StoragePool $p -ErrorAction SilentlyContinue | ForEach-Object {
          [pscustomobject]@{
            FriendlyName          = $_.FriendlyName
            ResiliencySettingName = $_.ResiliencySettingName
            HealthStatus          = (RD-Str $_.HealthStatus)
            OperationalStatus     = (RD-Str $_.OperationalStatus)
            DetachedReason        = (RD-Str $_.DetachedReason)
            Size                  = $_.Size
            PoolName              = $p.FriendlyName
          }
        }
      }
    }
    DW-Json 'raid.win_pdisks' {
      foreach ($p in $rdPools) {
        Get-PhysicalDisk -StoragePool $p -ErrorAction SilentlyContinue | ForEach-Object {
          [pscustomobject]@{
            FriendlyName      = $_.FriendlyName
            SerialNumber      = $(if ($_.SerialNumber) { ([string]$_.SerialNumber).Trim() } else { $null })
            Model             = $_.Model
            Manufacturer      = $_.Manufacturer
            FirmwareVersion   = $_.FirmwareVersion
            MediaType         = (RD-Str $_.MediaType)
            BusType           = (RD-Str $_.BusType)
            HealthStatus      = (RD-Str $_.HealthStatus)
            OperationalStatus = (RD-Str $_.OperationalStatus)
            Usage             = (RD-Str $_.Usage)
            Size              = $_.Size
            DeviceId          = $_.DeviceId
            PhysicalLocation  = $_.PhysicalLocation
            SlotNumber        = $_.SlotNumber
            PoolName          = $p.FriendlyName
          }
        }
      }
    }
    DW-Json 'raid.win_jobs' {
      Get-StorageJob -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
          Name             = $_.Name
          JobState         = (RD-Str $_.JobState)
          PercentComplete  = $_.PercentComplete
          IsBackgroundTask = [bool]$_.IsBackgroundTask
          BytesProcessed   = $_.BytesProcessed
          BytesTotal       = $_.BytesTotal
        }
      }
    }
  }
} else {
  DW-Missing 'raid.win_pools' 'Get-StoragePool'
}

DW-Json 'raid.win_controllers' {
  Get-CimInstance Win32_SCSIController -ErrorAction Stop |
    Select-Object Name, Manufacturer, DriverName, PNPDeviceID, Status
}

# ---- vendor RAID CLIs ----
$rdSc = $null; foreach ($n in @('storcli64', 'storcli')) { if (-not $rdSc) { $rdSc = DW-FindExe $n } }
$rdPc = $null; foreach ($n in @('perccli64', 'perccli')) { if (-not $rdPc) { $rdPc = DW-FindExe $n } }
$rdHp = $null; foreach ($n in @('ssacli', 'hpssacli', 'hpacucli')) { if (-not $rdHp) { $rdHp = DW-FindExe $n } }
$rdAc = DW-FindExe 'arcconf'
$rdMc = $null; foreach ($n in @('MegaCli64', 'MegaCli')) { if (-not $rdMc) { $rdMc = DW-FindExe $n } }

if ($rdSc -or $rdPc -or $rdHp -or $rdAc -or $rdMc) {
  if (-not $DW_ADMIN) {
    DW-Skip 'raid.hw' 'not-admin'
  } else {
    # The CLIs write log files (storcli.log, UcliEvt.log, MegaSAS.log) into
    # the process working directory: point it at a temporary folder.
    $rdOldCwd = [Environment]::CurrentDirectory
    $rdTmp = Join-Path ([IO.Path]::GetTempPath()) ('diagward-raid-' + [guid]::NewGuid().ToString('N'))
    try {
      New-Item -ItemType Directory -Path $rdTmp -Force | Out-Null
      [Environment]::CurrentDirectory = $rdTmp
      foreach ($fam in @(@('storcli', $rdSc), @('perccli', $rdPc))) {
        if (-not $fam[1]) { continue }
        $p = $fam[0]; $exe = $fam[1]
        DW-Exe "raid.${p}_ctrl" $exe @('/call', 'show', 'all', 'J')
        DW-Exe "raid.${p}_vd" $exe @('/call/vall', 'show', 'all', 'J')
        DW-Exe "raid.${p}_pd" $exe @('/call/eall/sall', 'show', 'all', 'J')
        DW-Exe "raid.${p}_rebuild" $exe @('/call/eall/sall', 'show', 'rebuild', 'J')
        DW-Exe "raid.${p}_bbu" $exe @('/call/bbu', 'show', 'all', 'J')
        DW-Exe "raid.${p}_cv" $exe @('/call/cv', 'show', 'all', 'J')
      }
      if ($rdHp) {
        DW-Exe 'raid.ssacli_config' $rdHp @('ctrl', 'all', 'show', 'config', 'detail')
        DW-Exe 'raid.ssacli_status' $rdHp @('ctrl', 'all', 'show', 'status')
      }
      if ($rdAc) {
        DW-Exe 'raid.arcconf_list' $rdAc @('LIST')
        $rdN = 0
        try {
          $psi = New-Object System.Diagnostics.ProcessStartInfo
          $psi.FileName = $rdAc; $psi.Arguments = 'LIST'
          $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
          $proc = [Diagnostics.Process]::Start($psi)
          $ot = $proc.StandardOutput.ReadToEndAsync()
          if ($proc.WaitForExit($DW_TIMEOUT_S * 1000)) {
            if ($ot.Result -match 'Controllers found:\s*(\d+)') { $rdN = [int]$Matches[1] }
          } else { try { $proc.Kill() } catch {} }
        } catch {}
        for ($i = 1; $i -le [Math]::Min($rdN, 16); $i++) {
          DW-Exe "raid.arcconf:$i" $rdAc @('GETCONFIG', "$i", 'AL')
        }
      }
      if ($rdMc -and -not $rdSc -and -not $rdPc) {
        DW-Exe 'raid.megacli_ld' $rdMc @('-LDInfo', '-Lall', '-aALL', '-NoLog')
        DW-Exe 'raid.megacli_pd' $rdMc @('-PDList', '-aALL', '-NoLog')
        DW-Exe 'raid.megacli_bbu' $rdMc @('-AdpBbuCmd', '-aALL', '-NoLog')
      }
    } finally {
      [Environment]::CurrentDirectory = $rdOldCwd
      Remove-Item -LiteralPath $rdTmp -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
