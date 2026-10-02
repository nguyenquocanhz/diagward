# ---- filesystem: volume space and health, dirty bit (chkdsk pending).
# Owner: system domain. Only reads.

if (DW-Has 'Get-Volume') {
  DW-Json 'filesystem.win_volume' {
    Get-Volume -ErrorAction Stop | ForEach-Object {
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
      Select-Object DriveLetter, Name, Label, FileSystem, DirtyBitSet, Capacity, FreeSpace
  }
} else {
  DW-Skip 'filesystem.win_dirty' 'not-admin'
}
