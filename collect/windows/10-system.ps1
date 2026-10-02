# ---- system: identity (SMBIOS via CIM), CPU summary, load, pending reboot.
# Owner: system domain. Only reads. Dates are written as ISO strings.
# Performance counters come from the Win32_PerfFormattedData_* classes, never
# Get-Counter: counter paths are localised on non-English Windows.

function DwSyIso($d) {
  if ($null -eq $d) { return $null }
  try { return ([datetime]$d).ToUniversalTime().ToString('o') } catch { return $null }
}

DW-Json 'system.win_computer' {
  Get-CimInstance Win32_ComputerSystem -ErrorAction Stop |
    Select-Object Manufacturer, Model, SystemFamily, SystemSKUNumber, TotalPhysicalMemory,
      NumberOfProcessors, NumberOfLogicalProcessors, SystemType, Domain, PartOfDomain, HypervisorPresent
}

DW-Json 'system.win_bios' {
  Get-CimInstance Win32_BIOS -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Manufacturer      = $_.Manufacturer
      SerialNumber      = $_.SerialNumber
      SMBIOSBIOSVersion = $_.SMBIOSBIOSVersion
      ReleaseDate       = (DwSyIso $_.ReleaseDate)
      Version           = $_.Version
    }
  }
}

DW-Json 'system.win_baseboard' {
  Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object Manufacturer, Product, SerialNumber, Version
}

DW-Json 'system.win_enclosure' {
  Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Manufacturer   = $_.Manufacturer
      SerialNumber   = $_.SerialNumber
      SMBIOSAssetTag = $_.SMBIOSAssetTag
      ChassisTypes   = @($_.ChassisTypes | ForEach-Object { [int]$_ })
    }
  }
}

DW-Json 'system.win_os' {
  Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      Caption                = $_.Caption
      Version                = $_.Version
      BuildNumber            = $_.BuildNumber
      OSArchitecture         = $_.OSArchitecture
      LastBootUpTime         = (DwSyIso $_.LastBootUpTime)
      InstallDate            = (DwSyIso $_.InstallDate)
      LocalDateTime          = (DwSyIso $_.LocalDateTime)
      TotalVisibleMemorySize = $_.TotalVisibleMemorySize
      FreePhysicalMemory     = $_.FreePhysicalMemory
    }
  }
}

DW-Json 'system.win_cpu' {
  Get-CimInstance Win32_Processor -ErrorAction Stop |
    Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, SocketDesignation, MaxClockSpeed
}

DW-Json 'system.win_reboot' {
  $cbs = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
  $wu = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  $pfro = $false
  try {
    $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
    if ($v.PendingFileRenameOperations) { $pfro = $true }
  } catch {}
  [pscustomobject]@{ cbsRebootPending = $cbs; wuRebootRequired = $wu; pendingFileRename = $pfro }
}

# Three samples one second apart: CPU %, processor queue, disk idle/queue.
DW-Json 'system.win_perf' {
  for ($i = 0; $i -lt 3; $i++) {
    if ($i -gt 0) { Start-Sleep -Seconds 1 }
    $sys = Get-CimInstance Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    $dsk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    [pscustomobject]@{
      ProcessorQueueLength   = $sys.ProcessorQueueLength
      PercentProcessorTime   = $cpu.PercentProcessorTime
      DiskPercentIdleTime    = $dsk.PercentIdleTime
      DiskAvgQueueLength     = $dsk.AvgDiskQueueLength
      SystemUpTime           = $sys.SystemUpTime
    }
  }
}
