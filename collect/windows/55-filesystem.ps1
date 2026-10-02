# ---- filesystem: volume space and health, dirty bit (chkdsk pending).
# Owner: system domain. Only reads. Enum values come from the Storage
# module's type data, which writes fixed English names ("Fixed", "Healthy")
# on every display language.

if (DW-Has 'Get-Volume') {
  DW-Json 'filesystem.win_volume' {
    # Win32_Volume (readable without elevation) gives what Get-Volume lacks:
    # the mount folder of a volume without a drive letter (mounted folders,
    # C:\ClusterStorage\VolumeN), and which volume is the EFI/System Reserved
    # (SystemVolume) or Windows (BootVolume) one. Matched on the GUID path.
    $wv = @{}
    try {
      Get-CimInstance Win32_Volume -ErrorAction Stop | ForEach-Object {
        if ($_.DeviceID) { $wv[[string]$_.DeviceID] = $_ }
      }
    } catch {}
    Get-Volume -ErrorAction Stop | ForEach-Object {
      $w = $null
      if ($_.Path -and $wv.ContainsKey([string]$_.Path)) { $w = $wv[[string]$_.Path] }
      $mp = $null; $sys = $false; $boot = $false
      if ($w) { $mp = $w.Name; $sys = [bool]$w.SystemVolume; $boot = [bool]$w.BootVolume }
      [pscustomobject]@{
        DriveLetter       = "$($_.DriveLetter)".Trim([char]0)
        FileSystemLabel   = $_.FileSystemLabel
        FileSystem        = $_.FileSystem
        DriveType         = "$($_.DriveType)"
        HealthStatus      = "$($_.HealthStatus)"
        OperationalStatus = @($_.OperationalStatus | ForEach-Object { "$_" })
        Size              = $_.Size
        SizeRemaining     = $_.SizeRemaining
        Path              = $_.Path
        MountPath         = $mp
        SystemVolume      = $sys
        BootVolume        = $boot
      }
    }
  }
} else {
  DW-Missing 'filesystem.win_volume' 'Get-Volume'
}

# Win32_Volume.DirtyBitSet is only filled in for Administrators.
if ($DW_ADMIN) {
  DW-Json 'filesystem.win_dirty' {
    Get-CimInstance Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 } |
      Select-Object DriveLetter, Name, DeviceID, Label, FileSystem, DirtyBitSet, Capacity, FreeSpace
  }
} else {
  DW-Skip 'filesystem.win_dirty' 'not-admin'
}
