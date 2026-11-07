Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force
. "$PSScriptRoot/Fixtures.ps1"

Describe 'Public contract and valid frames' {
    It 'exports only the five functions and four aliases' {
        @(Get-Command -Module PSDiscoveryProtocol -CommandType Function).Count | Should Be 5
        @(Get-Command -Module PSDiscoveryProtocol -CommandType Alias).Count | Should Be 4
    }
    It 'preserves CDP property names and types and ignores Ethernet padding' {
        $Tlvs = (New-CdpTlv 1 ([Text.Encoding]::UTF8.GetBytes('switch'))) + (New-CdpTlv 3 ([byte[]]@(70,97,48))) + (New-CdpTlv 6 ([byte[]]@(77))) + (New-CdpTlv 10 ([byte[]]@(0,10)))
        $Result = ConvertFrom-CDPPacket ((New-CdpFrame $Tlvs) + [byte[]]@(0,0,0))
        $Result.Device | Should Be 'switch'
        $Result.Port | Should Be 'Fa0'
        $Result.Model | Should Be 'M'
        ($Result.VLAN -is [uint16]) | Should Be $true
        $Result.VLAN | Should Be 10
    }
    It 'preserves LLDP identifiers TTL and text properties' {
        $Tlvs = (New-LldpTlv 1 ([byte[]]@(4,0,17,34,51,68,85))) + (New-LldpTlv 2 ([byte[]]@(5,70,97,48))) + (New-LldpTlv 3 ([byte[]]@(0,120))) + (New-LldpTlv 4 ([byte[]]@(80))) + (New-LldpTlv 5 ([byte[]]@(83))) + (New-LldpTlv 6 ([byte[]]@(68)))
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs)
        ($Result.ChassisId -is [System.Net.NetworkInformation.PhysicalAddress]) | Should Be $true
        $Result.Port | Should Be 'Fa0'
        ($Result.TimeToLive -is [uint16]) | Should Be $true
        $Result.TimeToLive | Should Be 120
        $Result.PortDescription | Should Be 'P'
        $Result.Device | Should Be 'S'
        $Result.SystemDescription | Should Be 'D'
    }
    It 'keeps dynamic packet properties and enriches parsed output' {
        $Packet = New-PacketObject (New-LldpFrame (New-LldpTlv 5 ([byte[]]@(83))))
        $Packet.IsDiscoveryProtocolPacket | Should Be $true
        $Packet.SourceAddress | Should Be '001122334455'
        $Result = $Packet | Get-DiscoveryProtocolData
        $Result.Computer | Should Be 'client'
        $Result.Connection | Should Be 'Ethernet'
        $Result.Interface | Should Be 'Adapter'
        $Result.Type | Should Be 'LLDP'
        $Packet.Fragment = [byte[]]@(1)
        $Packet.IsDiscoveryProtocolPacket | Should Be $false
        $Packet.SourceAddress | Should Be ''
    }
    It 'preserves first scalar values and accepts empty text and unknown TLVs' {
        $Tlvs = (New-LldpTlv 5 ([byte[]]@(65))) + (New-LldpTlv 5 ([byte[]]@(66))) + (New-LldpTlv 4) + (New-LldpTlv 99)
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs)
        $Result.Device | Should Be 'A'
        $Result.PortDescription | Should Be ''
        $Cdp = ConvertFrom-CDPPacket (New-CdpFrame ((New-CdpTlv 1) + (New-CdpTlv 1 ([byte[]]@(66))) + (New-CdpTlv 99)))
        $Cdp.Device | Should Be ''
    }
    It 'stops at LLDP terminator before arbitrary padding' {
        $Result = ConvertFrom-LLDPPacket ((New-LldpFrame (New-LldpTlv 5 ([byte[]]@(65)))) + [byte[]]@(255,255,255))
        $Result.Device | Should Be 'A'
    }
    It 'reads CDP IPv4 IPv6 and arbitrary protocol lengths without losing alignment' {
        $Unknown = [byte[]]@(9,3,1,2,3,0,1,99)
        $Ipv4 = [byte[]]@(1,1,204,0,4,192,0,2,1)
        $Ipv6 = [byte[]]@(2,8,170,170,3,0,0,0,134,221,0,16) + [System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes()
        $Value = [byte[]]@(0,0,0,3) + $Unknown + $Ipv4 + $Ipv6
        $Result = ConvertFrom-CDPPacket (New-CdpFrame ((New-CdpTlv 2 $Value) + (New-CdpTlv 2 ([byte[]]@(0,0,0,1) + $Ipv4))))
        ($Result.IPAddress -is [System.Collections.Generic.List[string]]) | Should Be $true
        $Result.IPAddress.Count | Should Be 3
        $Result.IPAddress[0] | Should Be '192.0.2.1'
        $Result.IPAddress[1] | Should Be '2001:db8::1'
    }
    It 'aggregates LLDP management addresses' {
        $V4 = [byte[]]@(5,1,192,0,2,1,2,0,0,0,1,0)
        $V6 = [byte[]]@(17,2) + [System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes() + [byte[]]@(2,0,0,0,1,0)
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame ((New-LldpTlv 8 $V4) + (New-LldpTlv 8 $V6)))
        $Result.IPAddress.Count | Should Be 2
        $Result.IPAddress[1] | Should Be '2001:db8::1'
    }
    It 'preserves LLDP IP identifier types and organization properties' {
        $Chassis = New-LldpTlv 1 ([byte[]]@(5,1,192,0,2,1))
        $Port = New-LldpTlv 2 ([byte[]]@(4,2) + [System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes())
        $Model = New-LldpTlv 127 ([byte[]]@(0,18,187,10,77))
        $Vlan = New-LldpTlv 127 ([byte[]]@(0,128,194,1,0,10))
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame ($Chassis + $Port + $Model + $Vlan))
        ($Result.ChassisId -is [System.Net.IPAddress]) | Should Be $true
        ($Result.Port -is [System.Net.IPAddress]) | Should Be $true
        $Result.Port.IPAddressToString | Should Be '2001:db8::1'
        $Result.Model | Should Be 'M'
        ($Result.VLAN -is [uint16]) | Should Be $true
        $Result.VLAN | Should Be 10
    }
    It 'preserves the CDP management address collection and UTF8 text boundaries' {
        $Device = New-CdpTlv 1 ([Text.Encoding]::UTF8.GetBytes('sw' + [char]0x010D))
        $Management = New-CdpTlv 22 ([byte[]]@(0,0,0,1,1,1,204,0,4,192,0,2,1))
        $Result = ConvertFrom-CDPPacket (New-CdpFrame ($Device + $Management + (New-CdpTlv 3 ([byte[]]@(80)))))
        $Result.Device | Should Be ('sw' + [char]0x010D)
        $Result.Port | Should Be 'P'
        ($Result.Management -is [System.Collections.Generic.List[string]]) | Should Be $true
        $Result.Management[0] | Should Be '192.0.2.1'
    }
}

Describe 'Malformed frames' {
    It 'rejects CDP lookalikes with an invalid LLC header' {
        $Bytes = New-CdpFrame
        $Bytes[14] = 0
        (New-PacketObject $Bytes).IsDiscoveryProtocolPacket | Should Be $false
        { ConvertFrom-CDPPacket $Bytes } | Should Throw 'CDP: offset'
    }
    It 'rejects truncated headers and values' {
        { ConvertFrom-CDPPacket ([byte[]]@(0)) } | Should Throw 'CDP: offset'
        { ConvertFrom-LLDPPacket ([byte[]]@(0)) } | Should Throw 'LLDP: offset'
        { ConvertFrom-CDPPacket (New-CdpFrame ([byte[]]@(0,1,0))) } | Should Throw 'CDP: offset'
        { ConvertFrom-CDPPacket (New-CdpFrame ([byte[]]@(0,1,0,3))) } | Should Throw 'CDP: offset'
        { ConvertFrom-CDPPacket (New-CdpFrame ([byte[]]@(0,1,0,20))) } | Should Throw 'CDP: offset'
        { ConvertFrom-LLDPPacket ((New-LldpFrame)[0..13] + [byte[]]@(2)) } | Should Throw 'LLDP: offset'
        { ConvertFrom-LLDPPacket ((New-LldpFrame)[0..13] + [byte[]]@(10,20,65)) } | Should Throw 'LLDP: offset'
    }
    It 'rejects invalid fixed and nested lengths and missing terminators' {
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 3)) } | Should Throw 'LLDP: offset'
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 127 ([byte[]]@(0,128,194)))) } | Should Throw
        { ConvertFrom-LLDPPacket ((New-LldpFrame)[0..13]) } | Should Throw 'Missing EndOfLLDPDU'
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 0 ([byte[]]@(1)))) } | Should Throw
    }
    It 'does not emit a partial result before failure' {
        $Result = @()
        try { ConvertFrom-CDPPacket (New-CdpFrame ((New-CdpTlv 1 ([byte[]]@(65))) + [byte[]]@(0,2,0,3))) | ForEach-Object { $Result += $_ } } catch {}
        $Result.Count | Should Be 0
    }
    It 'rejects invalid address lengths and truncated organizational payloads' {
        { ConvertFrom-CDPPacket (New-CdpFrame (New-CdpTlv 2 ([byte[]]@(0,0,0,1,1,1,204,0,3,192,0,2)))) } | Should Throw 'Invalid IP address length'
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 1 ([byte[]]@(4,1)))) } | Should Throw
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 127 ([byte[]]@(0,128,194,9)))) } | Should Throw
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 127 ([byte[]]@(0,27,33,2,4,20,0)))) } | Should Throw
    }
}

Describe 'DCBX organization decoding' {
    It 'supports IEEE and CEE in either order with all eight priorities' {
        $Priorities = [byte[]]@(1,35,69,103)
        $Bandwidth = [byte[]]@(10,11,12,13,14,15,16,17)
        $Ieee = New-LldpTlv 127 ([byte[]]@(0,128,194,9,128) + $Priorities + $Bandwidth)
        $CeeEts = New-LldpTlv 2 ([byte[]]@(0,0,192,0) + $Priorities + $Bandwidth)
        $CeePfc = New-LldpTlv 3 ([byte[]]@(0,0,192,0,129))
        $Cee = New-LldpTlv 127 ([byte[]]@(0,27,33,2) + $CeeEts + $CeePfc)
        $Pfc = New-LldpTlv 127 ([byte[]]@(0,128,194,11,128,129))
        foreach ($Tlvs in @(@{ Bytes = $Ieee + $Cee + $Pfc }, @{ Bytes = $Cee + $Pfc + $Ieee })) {
            $Result = ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs.Bytes)
            foreach ($Branch in 'IEEE','CEE') {
                $Result.DCBX.$Branch.ETS.PriorityAssignmentTable.Count | Should Be 8
                for ($Index = 0; $Index -lt 8; $Index++) {
                    $Result.DCBX.$Branch.ETS.PriorityAssignmentTable[$Index].TrafficClass | Should Be $Index
                    $Result.DCBX.$Branch.ETS.BandwidthAssignmentTable[$Index].Bandwidth | Should Be (10 + $Index)
                }
                $Result.DCBX.$Branch.PFC.FlowControl[0].Enabled | Should Be $true
                $Result.DCBX.$Branch.PFC.FlowControl[1].Enabled | Should Be $false
                $Result.DCBX.$Branch.PFC.FlowControl[7].Enabled | Should Be $true
            }
        }
    }
}

Describe 'PCAP export' {
    It 'writes microseconds and captured versus original lengths in both parameter sets' {
        $Timestamp = ([datetime]'2026-01-01T00:00:00Z').AddTicks(1234567)
        Export-Pcap -Bytes ([byte[]]@(1,2,3)) -DateTime $Timestamp -Path "$TestDrive/bytes.pcap"
        $Bytes = [IO.File]::ReadAllBytes("$TestDrive/bytes.pcap")
        [BitConverter]::ToUInt32($Bytes, 28) | Should Be 123456
        [BitConverter]::ToUInt32($Bytes, 32) | Should Be 3
        $Bytes.Length | Should Be 43
        $Packet = New-PacketObject (New-LldpFrame)
        $Packet.TimeCreated = $Timestamp
        $Packet.FragmentSize = 100
        @($Packet,$Packet) | Export-Pcap -Path "$TestDrive/packets.pcap"
        $Bytes = [IO.File]::ReadAllBytes("$TestDrive/packets.pcap")
        [BitConverter]::ToUInt32($Bytes, 28) | Should Be 123456
        [BitConverter]::ToUInt32($Bytes, 32) | Should Be $Packet.Fragment.Length
        [BitConverter]::ToUInt32($Bytes, 36) | Should Be 100
        $Bytes.Length | Should Be (24 + 2 * (16 + $Packet.Fragment.Length))
    }
}
