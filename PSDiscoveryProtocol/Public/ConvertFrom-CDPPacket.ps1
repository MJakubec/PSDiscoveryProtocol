function ConvertFrom-CDPPacket {

    <#

.SYNOPSIS

    Parse CDP packet.

.DESCRIPTION

    Parse CDP packet to get port, device, model, ipaddress, vlan and capabilities.
    Capabilities contains Supported (uint32), Enabled (null for CDP) and IsSwitch (bool).

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.PARAMETER Packet

    Raw CDP packet as byte array.

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP
    PS C:\> ConvertFrom-CDPPacket -Packet $Packet.Fragment

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10

#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0,
            Mandatory = $true)]
        [byte[]]$Packet
    )

    $Protocol = 'CDP'
    $EthernetHeaderLength = 14
    $CdpHeaderOffset = 22
    $TlvHeaderLength = 4
    if ((Get-DiscoveryFrameType $Packet) -ne $Protocol) { Throw-PacketError $Protocol 0 'Invalid Ethernet/LLC header.' }
    $PayloadLength = Read-NetworkInteger $Packet 12 2 $Protocol
    $Payload = Read-PacketBytes $Packet $EthernetHeaderLength $PayloadLength $Protocol
    if ($Payload.Length -lt 12) { Throw-PacketError $Protocol $CdpHeaderOffset 'Truncated CDP header.' }
    $Offset = $CdpHeaderOffset + 4
    $End = $EthernetHeaderLength + $PayloadLength
    $Properties = @{}
    $TextTypes = @{ 1 = 'Device'; 3 = 'Port'; 6 = 'Model' }
    while ($Offset -lt $End) {
        if ($End - $Offset -lt $TlvHeaderLength) { Throw-PacketError $Protocol $Offset 'Truncated TLV header.' }
        $TlvType = [int](Read-NetworkInteger $Packet $Offset 2 $Protocol)
        $TlvLength = Read-NetworkInteger $Packet ($Offset + 2) 2 $Protocol
        if ($TlvLength -lt $TlvHeaderLength -or $TlvLength -gt $End - $Offset) { Throw-PacketError $Protocol $Offset 'Invalid TLV length.' }
        $Value = Read-PacketBytes $Packet ($Offset + $TlvHeaderLength) ($TlvLength - $TlvHeaderLength) $Protocol
        Write-TlvDiagnostic $Protocol $Offset $TlvType $Value
        try {
            if ($TextTypes.ContainsKey($TlvType)) { Add-PacketProperty $Properties $TextTypes[$TlvType] ([Text.Encoding]::UTF8.GetString($Value)) }
            elseif ($TlvType -in 2,22) {
                $Name = if ($TlvType -eq 2) { 'IPAddress' } else { 'Management' }
                Convert-CdpAddresses $Value $Properties $Name
            } elseif ($TlvType -eq 4) {
                if ($Value.Length -ne 4) { Throw-PacketError $Protocol 0 'Invalid Capabilities length.' }
                $Supported = [uint32](Read-NetworkInteger $Value 0 4 $Protocol)
                $SwitchMask = 0x00000008
                Add-PacketProperty $Properties 'Capabilities' ([pscustomobject]@{
                    Supported = $Supported
                    Enabled = $null
                    IsSwitch = [bool](($Supported -band $SwitchMask) -ne 0)
                })
            } elseif ($TlvType -eq 10) {
                if ($Value.Length -ne 2) { Throw-PacketError $Protocol 0 'Invalid VLAN length.' }
                Add-PacketProperty $Properties 'VLAN' ([uint16](Read-NetworkInteger $Value 0 2 $Protocol))
            }
        } catch [System.IO.InvalidDataException] { Throw-PacketError $Protocol $Offset $_.Exception.Message }
        $Offset += $TlvLength
    }
    [pscustomobject]$Properties
}
