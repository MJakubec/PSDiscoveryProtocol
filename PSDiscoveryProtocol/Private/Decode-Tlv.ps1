function Convert-CdpAddresses {
    param([byte[]]$Value, [hashtable]$Properties, [string]$Name)
    $Count = Read-NetworkInteger $Value 0 4 'CDP'
    $Offset = 4
    if (-not $Properties.ContainsKey($Name)) { $Properties[$Name] = New-Object 'System.Collections.Generic.List[string]' }
    for ($Index = 0; $Index -lt $Count; $Index++) {
        $ProtocolType = Read-NetworkInteger $Value $Offset 1 'CDP'
        $ProtocolLength = Read-NetworkInteger $Value ($Offset + 1) 1 'CDP'
        $Offset += 2
        $Identifier = Read-PacketBytes $Value $Offset $ProtocolLength 'CDP'
        $Offset += $ProtocolLength
        $AddressLength = Read-NetworkInteger $Value $Offset 2 'CDP'
        $Offset += 2
        $Address = Read-PacketBytes $Value $Offset $AddressLength 'CDP'
        $Offset += $AddressLength
        $Hex = [BitConverter]::ToString($Identifier)
        if ($ProtocolType -eq 1 -and $Hex -eq 'CC') {
            $Properties[$Name].Add((Convert-PacketAddress $Address 1 'CDP' $Offset))
        } elseif ($ProtocolType -eq 2 -and $Hex -eq 'AA-AA-03-00-00-00-86-DD') {
            $Properties[$Name].Add((Convert-PacketAddress $Address 2 'CDP' $Offset))
        }
    }
    if ($Properties[$Name].Count -eq 0) { $Properties.Remove($Name) }
}

function Convert-LldpIdentifier {
    param([byte[]]$Value, [switch]$Port)
    $Subtype = Read-NetworkInteger $Value 0 1 'LLDP'
    $Bytes = Read-PacketBytes $Value 1 ($Value.Length - 1) 'LLDP'
    $MacSubtype = if ($Port) { 3 } else { 4 }
    $IpSubtype = if ($Port) { 4 } else { 5 }
    if ($Subtype -eq $MacSubtype) {
        if ($Bytes.Length -ne 6) { Throw-PacketError 'LLDP' 1 'Invalid MAC address length.' }
        return [System.Net.NetworkInformation.PhysicalAddress]::new($Bytes)
    }
    if ($Subtype -eq $IpSubtype) {
        $Family = Read-NetworkInteger $Bytes 0 1 'LLDP'
        if ($Family -in 1,2) {
            $Address = Read-PacketBytes $Bytes 1 ($Bytes.Length - 1) 'LLDP'
            return [System.Net.IPAddress]::Parse((Convert-PacketAddress $Address $Family 'LLDP' 2))
        }
        return
    }
    if ($Subtype -in 1,2,3,5,6,7) { return [Text.Encoding]::ASCII.GetString($Bytes) }
}

function Convert-DcbxValue {
    param([byte[]]$Value, [string]$Branch, [string]$Kind)
    $Cee = $Branch -eq 'CEE'
    $FlagsOffset = if ($Cee) { 2 } else { 0 }
    $Flags = Read-NetworkInteger $Value $FlagsOffset 1 'LLDP'
    $Result = [ordered]@{ Willing = ($Flags -band 0x40) -ne 0 }
    if (-not $Cee) { $Result.Willing = ($Flags -band 0x80) -ne 0 }
    if ($Cee) { $Result.Enabled = ($Flags -band 0x80) -ne 0 }
    if ($Kind -eq 'PFC') {
        $Offset = if ($Cee) { 4 } else { 1 }
        $Bits = Read-NetworkInteger $Value $Offset 1 'LLDP'
        $Result.FlowControl = @(0..7 | ForEach-Object { [pscustomobject]@{ Priority = $_; Enabled = ($Bits -band (1 -shl $_)) -ne 0 } })
    } else {
        $Offset = if ($Cee) { 4 } else { 1 }
        $Priorities = Read-PacketBytes $Value $Offset 4 'LLDP'
        $Bandwidth = Read-PacketBytes $Value ($Offset + 4) 8 'LLDP'
        $Result.PriorityAssignmentTable = @(for ($Index = 0; $Index -lt 8; $Index++) {
            $Shift = if ($Index % 2 -eq 0) { 4 } else { 0 }
            [pscustomobject]@{ Priority = $Index; TrafficClass = ($Priorities[[int][Math]::Floor($Index / 2)] -shr $Shift) -band 15 }
        })
        $Result.BandwidthAssignmentTable = @(0..7 | ForEach-Object { [pscustomobject]@{ Priority = $_; Bandwidth = $Bandwidth[$_] } })
    }
    return [pscustomobject]$Result
}

function Add-DcbxProperty {
    param([hashtable]$Properties, [string]$Branch, [string]$Kind, $Value)
    if (-not $Properties.ContainsKey('DCBX')) { $Properties.DCBX = [pscustomobject]@{} }
    if (-not $Properties.DCBX.PSObject.Properties[$Branch]) { $Properties.DCBX | Add-Member -NotePropertyName $Branch -NotePropertyValue ([pscustomobject]@{}) }
    if (-not $Properties.DCBX.$Branch.PSObject.Properties[$Kind]) { $Properties.DCBX.$Branch | Add-Member -NotePropertyName $Kind -NotePropertyValue $Value }
    else { Write-Verbose "Duplicate DCBX $Branch $Kind ignored." }
}

function Convert-LldpOrganization {
    param([byte[]]$Value, [hashtable]$Properties)
    $MedOui = '00-12-BB'
    $IeeeOui = '00-80-C2'
    $CeeOui = '00-1B-21'
    $Header = Read-PacketBytes $Value 0 4 'LLDP'
    $Oui = [BitConverter]::ToString($Header, 0, 3)
    $Subtype = $Header[3]
    $Payload = Read-PacketBytes $Value 4 ($Value.Length - 4) 'LLDP'
    if ($Oui -eq $MedOui -and $Subtype -eq 10) { Add-PacketProperty $Properties 'Model' ([Text.Encoding]::ASCII.GetString($Payload)) }
    if ($Oui -eq $IeeeOui) {
        switch ($Subtype) {
            1 { Add-PacketProperty $Properties 'VLAN' ([uint16](Read-NetworkInteger $Payload 0 2 'LLDP')) }
            9 { Add-DcbxProperty $Properties 'IEEE' 'ETS' (Convert-DcbxValue $Payload 'IEEE' 'ETS') }
            11 { Add-DcbxProperty $Properties 'IEEE' 'PFC' (Convert-DcbxValue $Payload 'IEEE' 'PFC') }
        }
    }
    if ($Oui -eq $CeeOui -and $Subtype -eq 2) {
        $Offset = 0
        while ($Offset -lt $Payload.Length) {
            $Header = Read-NetworkInteger $Payload $Offset 2 'LLDP'
            $TlvType = $Header -shr 9
            $TlvLength = $Header -band 511
            $Nested = Read-PacketBytes $Payload ($Offset + 2) $TlvLength 'LLDP'
            if ($TlvType -in 2,3) {
                $Kind = if ($TlvType -eq 2) { 'ETS' } else { 'PFC' }
                Add-DcbxProperty $Properties 'CEE' $Kind (Convert-DcbxValue $Nested 'CEE' $Kind)
            }
            $Offset += 2 + $TlvLength
        }
    }
}
