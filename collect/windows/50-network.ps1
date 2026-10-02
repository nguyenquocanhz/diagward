# ---- network: physical adapters, link state, error counters, NIC teams
# (LBFO and Hyper-V SET), which adapters carry an IP. Owner: system domain.
# Enums are written as strings so the analysis does not depend on numbering.

if (DW-Has 'Get-NetAdapter') {
  DW-Json 'network.win_adapter' {
    Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        Name                 = $_.Name
        InterfaceDescription = $_.InterfaceDescription
        InterfaceIndex       = $_.InterfaceIndex
        Status               = "$($_.Status)"
        MediaConnectionState = "$($_.MediaConnectionState)"
        LinkSpeed            = "$($_.LinkSpeed)"
        ReceiveLinkSpeed     = $_.ReceiveLinkSpeed
        TransmitLinkSpeed    = $_.TransmitLinkSpeed
        FullDuplex           = $_.FullDuplex
        MacAddress           = $_.MacAddress
        DriverProvider       = $_.DriverProvider
        DriverVersionString  = $_.DriverVersionString
        DriverDate           = "$($_.DriverDate)"
        NdisPhysicalMedium   = $_.NdisPhysicalMedium
        PnPDeviceID          = $_.PnPDeviceID
      }
    }
  }
  DW-Json 'network.win_adapter_stats' {
    Get-NetAdapterStatistics -ErrorAction Stop |
      Select-Object Name, ReceivedUnicastPackets, ReceivedMulticastPackets, ReceivedBroadcastPackets,
        SentUnicastPackets, SentMulticastPackets, SentBroadcastPackets,
        ReceivedPacketErrors, OutboundPacketErrors, ReceivedDiscardedPackets, OutboundDiscardedPackets
  }
  # *SpeedDuplex (NDIS standardised keyword): the valid values give the
  # fastest mode the adapter supports; a non-zero current value means the
  # speed was forced instead of auto-negotiated.
  DW-Json 'network.win_speedduplex' {
    Get-NetAdapterAdvancedProperty -Name * -RegistryKeyword '*SpeedDuplex' -ErrorAction SilentlyContinue | ForEach-Object {
      [pscustomobject]@{
        Name                = $_.Name
        RegistryValue       = @($_.RegistryValue) -join ','
        ValidRegistryValues = @($_.ValidRegistryValues)
        DisplayValue        = $_.DisplayValue
      }
    }
  }
  # Adapters bound to a Hyper-V external switch ("Hyper-V Extensible Virtual
  # Switch" protocol, component vms_pp). Unlike Get-VMSwitch this needs no
  # elevation, so an uplink without an IP is still known to be in use.
  if (DW-Has 'Get-NetAdapterBinding') {
    DW-Json 'network.win_vmswitch_bound' {
      Get-NetAdapterBinding -ComponentID vms_pp -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } |
        Select-Object Name, InterfaceDescription
    }
  }
} else {
  DW-Missing 'network.win_adapter' 'Get-NetAdapter'
}

if (DW-Has 'Get-NetIPAddress') {
  DW-Json 'network.win_ip' {
    Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        InterfaceIndex = $_.InterfaceIndex
        InterfaceAlias = $_.InterfaceAlias
        IPAddress      = $_.IPAddress
        PrefixLength   = $_.PrefixLength
        AddressFamily  = "$($_.AddressFamily)"
        AddressState   = "$($_.AddressState)"
      }
    }
  }
}

# LBFO teams (Windows Server 2012-2022; deprecated for Hyper-V in 2022).
if (DW-Has 'Get-NetLbfoTeam') {
  DW-Json 'network.win_lbfo_team' {
    Get-NetLbfoTeam -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        Name                   = $_.Name
        Status                 = "$($_.Status)"
        TeamingMode            = "$($_.TeamingMode)"
        LoadBalancingAlgorithm = "$($_.LoadBalancingAlgorithm)"
        Members                = @($_.Members)
      }
    }
  }
  DW-Json 'network.win_lbfo_member' {
    Get-NetLbfoTeamMember -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        Name                 = $_.Name
        Team                 = $_.Team
        InterfaceDescription = $_.InterfaceDescription
        AdministrativeMode   = "$($_.AdministrativeMode)"
        OperationalStatus    = "$($_.OperationalStatus)"
        FailureReason        = "$($_.FailureReason)"
        ReceiveLinkSpeed     = $_.ReceiveLinkSpeed
      }
    }
  }
}

# Hyper-V external switches (and Switch Embedded Teaming): the physical
# adapters bound to them carry the host's traffic but have no IP themselves.
if ((DW-Has 'Get-VMSwitch') -and -not $DW_ADMIN) {
  DW-Skip 'network.win_vmswitch' 'not-admin'
} elseif (DW-Has 'Get-VMSwitch') {
  DW-Json 'network.win_vmswitch' {
    Get-VMSwitch -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        Name                            = $_.Name
        SwitchType                      = "$($_.SwitchType)"
        EmbeddedTeamingEnabled          = $_.EmbeddedTeamingEnabled
        NetAdapterInterfaceDescriptions = @($_.NetAdapterInterfaceDescriptions)
      }
    }
  }
}
