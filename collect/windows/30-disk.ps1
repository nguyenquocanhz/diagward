# ---- disk: physical disks (Get-PhysicalDisk, Win32_DiskDrive), storage
# reliability counters and S.M.A.R.T. failure prediction (Administrator), and
# smartctl when smartmontools is installed. Owner: disk domain. Functions: DK-*
#
# Sections:
#   disk.win_physical     Get-PhysicalDisk (enums written as names)
#   disk.win_reliability  Get-StorageReliabilityCounter per disk (admin)
#   disk.win_predict      root\wmi MSStorageDriver_FailurePredictStatus (admin)
#   disk.win_diskdrive    Win32_DiskDrive
#   disk.smart_version, disk.smart_scan, disk.smart:<dev>[,<type>]
#                         smartctl, same names and formats as on Linux

if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
  DW-Json 'disk.win_physical' {
    Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName, SerialNumber,
      @{ n = 'MediaType'; e = { [string]$_.MediaType } },
      @{ n = 'BusType'; e = { [string]$_.BusType } },
      Size,
      @{ n = 'HealthStatus'; e = { [string]$_.HealthStatus } },
      @{ n = 'OperationalStatus'; e = { (@($_.OperationalStatus) | ForEach-Object { [string]$_ }) -join ',' } },
      FirmwareVersion, DeviceId, SpindleSpeed, Model, Manufacturer, PhysicalLocation
  }
} else {
  DW-Missing 'disk.win_physical' 'Get-PhysicalDisk'
}

if ($DW_ADMIN) {
  DW-Json 'disk.win_reliability' {
    foreach ($pd in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
      $c = $null
      try {
        $c = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
      } catch {
        Write-Error ('disk ' + $pd.DeviceId + ': ' + $_.Exception.Message)
        continue
      }
      if ($null -eq $c) { continue }
      [pscustomobject]@{
        DiskDeviceId           = [string]$pd.DeviceId
        Temperature            = $c.Temperature
        TemperatureMax         = $c.TemperatureMax
        Wear                   = $c.Wear
        ReadErrorsTotal        = $c.ReadErrorsTotal
        ReadErrorsCorrected    = $c.ReadErrorsCorrected
        ReadErrorsUncorrected  = $c.ReadErrorsUncorrected
        WriteErrorsTotal       = $c.WriteErrorsTotal
        WriteErrorsCorrected   = $c.WriteErrorsCorrected
        WriteErrorsUncorrected = $c.WriteErrorsUncorrected
        PowerOnHours           = $c.PowerOnHours
        StartStopCycleCount    = $c.StartStopCycleCount
        LoadUnloadCycleCount   = $c.LoadUnloadCycleCount
        ReadLatencyMax         = $c.ReadLatencyMax
        WriteLatencyMax        = $c.WriteLatencyMax
        FlushLatencyMax        = $c.FlushLatencyMax
        ManufactureDate        = [string]$c.ManufactureDate
      }
    }
  }
  # Throws "Not supported" when no disk exposes ATA failure prediction
  # (NVMe, RAID volumes); the analysis treats that as "no data".
  DW-Json 'disk.win_predict' {
    Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
      Select-Object InstanceName, Active, PredictFailure, Reason
  }
} else {
  DW-Skip 'disk.win_reliability' 'not-admin'
  DW-Skip 'disk.win_predict' 'not-admin'
}

DW-Json 'disk.win_diskdrive' {
  Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
    Select-Object Index, Model, SerialNumber, Status, InterfaceType, PNPDeviceID, Size, FirmwareRevision
}

# smartctl (smartmontools for Windows), same sections as on Linux. DW-Run
# returns $null when smartctl is not installed.
$DK_v = DW-Run 'smartctl' @('--version')
if ($null -eq $DK_v) {
  DW-Missing 'disk.smart_scan' 'smartctl'
} else {
  DW-Emit 'disk.smart_version' $DK_v.Out $DK_v.Err $DK_v.Rc $DK_v.Ms $DK_v.Flags
  if (-not $DW_ADMIN) {
    DW-Skip 'disk.smart_scan' 'not-admin'
  } else {
    $DK_json = @()
    # "smartctl 7.4 2023-08-01 r5530 ..." or "smartctl pre-7.5 ..." (SVN build)
    if ($DK_v.Out -match 'smartctl (?:pre-)?(\d+)\.') { if ([int]$Matches[1] -ge 7) { $DK_json = @('-j') } }
    $DK_scan = DW-Run 'smartctl' @('--scan-open')
    DW-Emit 'disk.smart_scan' $DK_scan.Out $DK_scan.Err $DK_scan.Rc $DK_scan.Ms $DK_scan.Flags
    $DK_n = 0
    foreach ($DK_line in ($DK_scan.Out -split "`r?`n")) {
      # "/dev/sda -d ata # ...", "/dev/csmi0,1 -d ata # ...", "/dev/nvme0 -d nvme # ..."
      if ($DK_line -notmatch '^\s*(/\S+)(?:\s+-d\s+(\S+))?') { continue }
      $DK_dev = $Matches[1]
      $DK_type = $Matches[2]
      $DK_n++
      if ($DK_n -gt 64) { break }
      $DK_name = $DK_dev
      $DK_dargs = @()
      if ($DK_type) {
        $DK_dargs = @('-d', $DK_type)
        if ($DK_type -match ',') { $DK_name = "$DK_dev,$DK_type" }
      }
      # -n standby: do not spin up a sleeping disk. If -x is rejected (exit
      # bit 0: command line did not parse), retry with -a, as on Linux.
      $DK_r = DW-Run 'smartctl' (@('-x') + $DK_json + @('-n', 'standby') + $DK_dargs + @($DK_dev))
      if ($DK_r.Rc -lt 124 -and ($DK_r.Rc -band 1)) {
        $DK_r = DW-Run 'smartctl' (@('-a') + $DK_json + @('-n', 'standby') + $DK_dargs + @($DK_dev))
      }
      DW-Emit "disk.smart:$DK_name" $DK_r.Out $DK_r.Err $DK_r.Rc $DK_r.Ms $DK_r.Flags
    }
  }
}

# The dd speed test is Linux-only; record why it did not run when asked.
if ($DW_BENCH_DIR) { DW-Skip 'disk.bench' 'not-applicable' }
