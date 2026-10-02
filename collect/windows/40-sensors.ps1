# Sensors on Windows: what the OS can see without vendor agents.
#  * ACPI thermal zones (root\wmi MSAcpi_ThermalZoneTemperature, needs
#    Administrator; CurrentTemperature is in tenths of a Kelvin; most
#    servers do not implement it and return "Not supported").
#  * Win32_Fan / Win32_TemperatureProbe (SMBIOS, rarely populated).
#  * LibreHardwareMonitor / OpenHardwareMonitor WMI providers, when one of
#    them is running (class Sensor: SensorType, Name, Value, Min, Max, Parent).
# Read-only. Fans, PSUs and BMC events are read through IPMI (45-ipmi.ps1)
# or out-of-band with `diagward bmc`.

if ($DW_ADMIN) {
  DW-Json 'sensors.win_thermalzone' {
    Get-CimInstance -Namespace 'root\wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop |
      Select-Object InstanceName, CurrentTemperature, CriticalTripPoint, PassiveTripPoint, Active
  }
} else {
  DW-Skip 'sensors.win_thermalzone' 'not-admin'
}

DW-Json 'sensors.win_fan' {
  Get-CimInstance -ClassName Win32_Fan -ErrorAction SilentlyContinue |
    Select-Object Name, DeviceID, Status, ActiveCooling, DesiredSpeed, VariableSpeed
}

DW-Json 'sensors.win_probe' {
  Get-CimInstance -ClassName Win32_TemperatureProbe -ErrorAction SilentlyContinue |
    Select-Object Name, DeviceID, Status, CurrentReading, MaxReadable, MinReadable, Resolution, Accuracy
}

function Sn-HwMon([string]$Section, [string]$Ns) {
  $has = $null
  try {
    $has = Get-CimInstance -Namespace 'root' -ClassName __NAMESPACE -Filter "Name='$Ns'" -ErrorAction Stop
  } catch {}
  if (-not $has) { DW-Missing $Section $Ns; return }
  DW-Json $Section {
    Get-CimInstance -Namespace "root\$Ns" -ClassName Sensor -ErrorAction Stop |
      Where-Object { 'Temperature', 'Fan', 'Voltage', 'Power', 'Current' -contains [string]$_.SensorType } |
      Select-Object SensorType, Name, Value, Min, Max, Parent, Identifier
  }
}
Sn-HwMon 'sensors.win_lhm' 'LibreHardwareMonitor'
Sn-HwMon 'sensors.win_ohm' 'OpenHardwareMonitor'
