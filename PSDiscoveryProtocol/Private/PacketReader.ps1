function Throw-PacketError {
    param([string]$Protocol, [int]$Offset, [string]$Reason)
    throw [System.IO.InvalidDataException]::new("${Protocol}: offset ${Offset}: $Reason")
}

function Read-PacketBytes {
    param([byte[]]$Packet, [int]$Offset, [int]$Count, [string]$Protocol)
    if ($Offset -lt 0 -or $Count -lt 0 -or $Offset -gt $Packet.Length - $Count) {
        Throw-PacketError $Protocol $Offset "Requested $Count bytes outside payload ($($Packet.Length) bytes)."
    }
    $Value = New-Object byte[] $Count
    [Array]::Copy($Packet, $Offset, $Value, 0, $Count)
    return ,$Value
}

function Read-NetworkInteger {
    param([byte[]]$Packet, [int]$Offset, [int]$Count, [string]$Protocol)
    $Bytes = Read-PacketBytes $Packet $Offset $Count $Protocol
    [long]$Value = 0
    foreach ($Byte in $Bytes) { $Value = ($Value -shl 8) -bor $Byte }
    return $Value
}

function Get-DiscoveryFrameType {
    param([byte[]]$Packet)
    if ($Packet.Length -ge 14 -and $Packet[12] -eq 0x88 -and $Packet[13] -eq 0xCC) { return 'LLDP' }
    if ($Packet.Length -ge 26 -and (Read-NetworkInteger $Packet 12 2 'CDP') -le 1500 -and
        [BitConverter]::ToString($Packet, 14, 8) -eq 'AA-AA-03-00-00-0C-20-00') { return 'CDP' }
    return [string]::Empty
}

function Add-PacketProperty {
    param([hashtable]$Properties, [string]$Name, $Value)
    if ($Properties.ContainsKey($Name)) { Write-Verbose "Duplicate $Name ignored." }
    else { $Properties[$Name] = $Value }
}

function Write-TlvDiagnostic {
    param([string]$Protocol, [int]$Offset, [int]$TlvType, [byte[]]$Value)
    Write-Verbose "$Protocol offset=$Offset type=$TlvType length=$($Value.Length) hex=$([BitConverter]::ToString($Value))"
}

function Convert-PacketAddress {
    param([byte[]]$Bytes, [int]$Family, [string]$Protocol, [int]$Offset)
    $Expected = if ($Family -eq 1) { 4 } else { 16 }
    if ($Bytes.Length -ne $Expected) { Throw-PacketError $Protocol $Offset 'Invalid IP address length.' }
    return [System.Net.IPAddress]::new($Bytes).IPAddressToString
}
