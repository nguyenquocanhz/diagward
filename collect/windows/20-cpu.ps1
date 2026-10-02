# CPU inventory and status (Win32_Processor). Machine-check events on
# Windows are WHEA-Logger events in the System log: the logs domain reads
# them. Owner: cpu/memory domain.

DW-Json 'cpu.win_processor' {
  Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object DeviceID, Name, Manufacturer, SocketDesignation,
    NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors, CurrentClockSpeed, MaxClockSpeed,
    LoadPercentage, Status, CpuStatus, Availability, ProcessorId
}
