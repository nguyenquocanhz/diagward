# Memory: DIMM inventory, ECC type, usage, page file and the results of the
# Windows Memory Diagnostic (mdsched.exe). Owner: cpu/memory domain.

DW-Json 'memory.win_physical' {
  Get-CimInstance Win32_PhysicalMemory -OperationTimeoutSec $DW_TIMEOUT_S -ErrorAction Stop | Select-Object BankLabel, DeviceLocator, Capacity, Speed,
    ConfiguredClockSpeed, Manufacturer, PartNumber, SerialNumber, SMBIOSMemoryType, MemoryType, TypeDetail, FormFactor,
    DataWidth, TotalWidth
}

DW-Json 'memory.win_array' {
  # MemoryErrorCorrection: 3 None, 4 Parity, 5 Single-bit ECC, 6 Multi-bit ECC, 7 CRC.
  Get-CimInstance Win32_PhysicalMemoryArray -OperationTimeoutSec $DW_TIMEOUT_S -ErrorAction Stop | Select-Object MemoryErrorCorrection, MemoryDevices,
    MaxCapacity, MaxCapacityEx, Use, Location
}

DW-Json 'memory.win_os' {
  $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec $DW_TIMEOUT_S -ErrorAction Stop
  # Performance counters through CIM: the class names are not localised
  # (Get-Counter paths are, on non-English Windows).
  $pm = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -OperationTimeoutSec $DW_TIMEOUT_S -ErrorAction SilentlyContinue
  [pscustomobject]@{
    TotalVisibleMemorySize = $os.TotalVisibleMemorySize
    FreePhysicalMemory     = $os.FreePhysicalMemory
    TotalVirtualMemorySize = $os.TotalVirtualMemorySize
    FreeVirtualMemory      = $os.FreeVirtualMemory
    SizeStoredInPagingFiles = $os.SizeStoredInPagingFiles
    FreeSpaceInPagingFiles = $os.FreeSpaceInPagingFiles
    AvailableBytes         = $(if ($pm) { $pm.AvailableBytes } else { $null })
    CommittedBytes         = $(if ($pm) { $pm.CommittedBytes } else { $null })
    CommitLimit            = $(if ($pm) { $pm.CommitLimit } else { $null })
    PagesInputPerSec       = $(if ($pm) { $pm.PagesInputPerSec } else { $null })
    LastBootUpTime         = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null })
  }
}

DW-Json 'memory.win_pagefile' {
  Get-CimInstance Win32_PageFileUsage -OperationTimeoutSec $DW_TIMEOUT_S -ErrorAction Stop | Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage
}

DW-Json 'memory.win_memdiag' {
  # 1101/1201 = no errors, 1102/1202 = hardware errors found,
  # 1103 = cancelled, 1104 = could not complete. Readable without admin.
  try {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -MaxEvents 20 -ErrorAction Stop |
      ForEach-Object {
        [pscustomobject]@{
          Id          = $_.Id
          Level       = $_.Level
          TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
          Message     = $(if ($_.Message) { ($_.Message -replace '\s+', ' ').Trim() } else { '' })
        }
      }
  } catch {
    # No events yet, or the provider is not registered (Server Core).
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and $_.FullyQualifiedErrorId -notlike 'NoMatchingProvidersFound*') { throw }
  }
}

if ($DW_MEMTEST) {
  # memtester does not exist on Windows; the Go side explains mdsched.exe.
  DW-Skip 'memory.memtest' 'not-applicable'
}
