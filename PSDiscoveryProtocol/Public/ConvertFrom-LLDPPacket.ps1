function ConvertFrom-LLDPPacket {

    <#

.SYNOPSIS

    Parse LLDP packet.

.DESCRIPTION

    Parse LLDP packet to get port, description, device, model, ipaddress and vlan.

.PARAMETER Packet

    Raw LLDP packet as byte array.

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type LLDP
    PS C:\> ConvertFrom-LLDPPacket -Packet $Packet.Fragment

    Model       : WS-C2960-48TT-L
    Description : HR Workstation
    VLAN        : 10
    Port        : Fa0/1
    Device      : SWITCH1.domain.example
    IPAddress   : 192.0.2.10

#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0,
            Mandatory = $true)]
        [byte[]]$Packet
    )

    $Protocol = 'LLDP'
    $EthernetHeaderLength = 14
    $TlvHeaderLength = 2
    $TlvLengthMask = 0x01FF
    if ((Get-DiscoveryFrameType $Packet) -ne $Protocol) { Throw-PacketError $Protocol 0 'Invalid Ethernet header.' }
    $Offset = $EthernetHeaderLength
    $Properties = @{}
    $TextTypes = @{ 4 = 'PortDescription'; 5 = 'Device'; 6 = 'SystemDescription' }
    $Terminated = $false
    while ($Offset -lt $Packet.Length) {
        $Header = Read-NetworkInteger $Packet $Offset $TlvHeaderLength $Protocol
        $TlvType = [int]($Header -shr 9)
        $TlvLength = $Header -band $TlvLengthMask
        $ValueOffset = $Offset + $TlvHeaderLength
        $Value = Read-PacketBytes $Packet $ValueOffset $TlvLength $Protocol
        Write-TlvDiagnostic $Protocol $Offset $TlvType $Value
        if ($TlvType -eq 0) {
            if ($TlvLength -ne 0) { Throw-PacketError $Protocol $Offset 'EndOfLLDPDU must have an empty value.' }
            $Terminated = $true
            break
        }
        try {
            if ($TextTypes.ContainsKey($TlvType)) { Add-PacketProperty $Properties $TextTypes[$TlvType] ([Text.Encoding]::ASCII.GetString($Value)) }
            else {
                switch ($TlvType) {
                    1 { $Id = Convert-LldpIdentifier $Value; if ($null -ne $Id) { Add-PacketProperty $Properties 'ChassisId' $Id } }
                    2 { $Id = Convert-LldpIdentifier $Value -Port; if ($null -ne $Id) { Add-PacketProperty $Properties 'Port' $Id } }
                    3 {
                        if ($TlvLength -ne 2) { Throw-PacketError $Protocol 0 'Invalid TTL length.' }
                        Add-PacketProperty $Properties 'TimeToLive' ([uint16](Read-NetworkInteger $Value 0 2 $Protocol))
                    }
                    8 {
                        $AddressLength = Read-NetworkInteger $Value 0 1 $Protocol
                        if ($AddressLength -lt 1) { Throw-PacketError $Protocol 0 'Invalid management address length.' }
                        $Family = Read-NetworkInteger $Value 1 1 $Protocol
                        $Bytes = Read-PacketBytes $Value 2 ($AddressLength - 1) $Protocol
                        $InterfaceOffset = 1 + $AddressLength
                        $null = Read-PacketBytes $Value $InterfaceOffset 6 $Protocol
                        $OidLength = Read-NetworkInteger $Value ($InterfaceOffset + 5) 1 $Protocol
                        $null = Read-PacketBytes $Value ($InterfaceOffset + 6) $OidLength $Protocol
                        if ($Family -in 1,2) {
                            if (-not $Properties.ContainsKey('IPAddress')) { $Properties.IPAddress = New-Object 'System.Collections.Generic.List[string]' }
                            $Properties.IPAddress.Add((Convert-PacketAddress $Bytes $Family $Protocol 2))
                        }
                    }
                    127 { Convert-LldpOrganization $Value $Properties }
                }
            }
        } catch [System.IO.InvalidDataException] { Throw-PacketError $Protocol $Offset $_.Exception.Message }
        $Offset = $ValueOffset + $TlvLength
    }
    if (-not $Terminated) { Throw-PacketError $Protocol $Offset 'Missing EndOfLLDPDU.' }
    [pscustomobject]$Properties
}
