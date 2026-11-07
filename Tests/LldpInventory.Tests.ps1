Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force
. "$PSScriptRoot/Fixtures.ps1"

function New-MedInventoryTlv {
    param([int]$Subtype, [string]$Text)
    New-LldpTlv 127 ([byte[]]@(0,18,187,$Subtype) + [Text.Encoding]::UTF8.GetBytes($Text))
}

Describe 'LLDP EdgeSwitch inventory and IEEE extensions' {
    It 'decodes the screenshot fields from synthetic TLVs' {
        $Description = 'EdgeSwitch 8 150W, 1.12.2, Linux 3.6.5-03329b4a, 1.2.0.5192732'
        $Tlvs = (New-LldpTlv 1 ([byte[]]@(4,216,179,112,78,121,186))) +
            (New-LldpTlv 2 ([byte[]]@(7,48,47,56))) +
            (New-LldpTlv 3 ([byte[]]@(0,120))) +
            (New-LldpTlv 4 ([Text.Encoding]::UTF8.GetBytes('0/8'))) +
            (New-LldpTlv 5 ([Text.Encoding]::UTF8.GetBytes('sw-hasta-it-kral'))) +
            (New-LldpTlv 6 ([Text.Encoding]::UTF8.GetBytes($Description))) +
            (New-LldpTlv 7 ([byte[]]@(0,4,0,4))) +
            (New-LldpTlv 127 ([byte[]]@(0,128,194,1,0,10))) +
            (New-LldpTlv 127 ([byte[]]@(0,18,15,1,3,128,1,0,30))) +
            (New-LldpTlv 127 ([byte[]]@(0,18,15,4,35,40))) +
            (New-LldpTlv 127 ([byte[]]@(0,18,187,1,0,33,4))) +
            (New-MedInventoryTlv 5 'hardware-test') +
            (New-MedInventoryTlv 6 'firmware-test') +
            (New-MedInventoryTlv 7 '1.12.2') +
            (New-MedInventoryTlv 8 'serial-test') +
            (New-MedInventoryTlv 9 'Ubiquiti') +
            (New-MedInventoryTlv 10 'EdgeSwitch 8 150W') +
            (New-MedInventoryTlv 11 'asset-test')
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs)
        $Result.ChassisId.ToString() | Should Be 'D8B3704E79BA'
        $Result.ChassisIdSubtype | Should Be 4
        $Result.PortSubtype | Should Be 7
        $Result.Port | Should Be '0/8'
        $Result.PortDescription | Should Be '0/8'
        $Result.TimeToLive | Should Be 120
        $Result.SystemName | Should Be 'sw-hasta-it-kral'
        $Result.Device | Should Be $Result.SystemName
        $Result.SystemDescription | Should Be $Description
        $Result.Capabilities.IsSwitch | Should Be $true
        $Result.VLAN | Should Be 10
        $Result.MacPhy.AutoNegotiationSupported | Should Be $true
        $Result.MacPhy.AutoNegotiationEnabled | Should Be $true
        $Result.MacPhy.AutoNegotiationAdvertised | Should Be 32769
        $Result.MacPhy.OperationalMauType | Should Be 30
        $Result.MaximumFrameSize | Should Be 9000
        $Result.MediaCapabilities.Supported | Should Be 33
        $Result.MediaCapabilities.DeviceClass | Should Be 4
        $Result.HardwareRevision | Should Be 'hardware-test'
        $Result.FirmwareRevision | Should Be 'firmware-test'
        $Result.SoftwareVersion | Should Be '1.12.2'
        $Result.SerialNumber | Should Be 'serial-test'
        $Result.Manufacturer | Should Be 'Ubiquiti'
        $Result.Model | Should Be 'EdgeSwitch 8 150W'
        $Result.AssetId | Should Be 'asset-test'
    }
    It 'keeps the first inventory value and handles empty UTF8 values' {
        $Tlvs = (New-MedInventoryTlv 7 'first') + (New-MedInventoryTlv 7 'second') +
            (New-MedInventoryTlv 5 '') + (New-MedInventoryTlv 9 ('vendor-' + [char]0x010D))
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs)
        $Result.SoftwareVersion | Should Be 'first'
        $Result.HardwareRevision | Should Be ''
        $Result.Manufacturer | Should Be ('vendor-' + [char]0x010D)
    }
    It 'rejects truncated and oversized fixed extension payloads' {
        foreach ($Case in @(
            @{ Header = [byte[]]@(0,18,15,1); Length = 5 },
            @{ Header = [byte[]]@(0,18,15,4); Length = 2 },
            @{ Header = [byte[]]@(0,18,187,1); Length = 3 },
            @{ Header = [byte[]]@(0,128,194,1); Length = 2 }
        )) {
            foreach ($Length in 0,($Case.Length - 1),($Case.Length + 1)) {
                $Value = $Case.Header + (New-Object byte[] $Length)
                { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 127 $Value)) } | Should Throw 'LLDP: offset'
            }
        }
    }
    It 'does not infer software version or model from a system description' {
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 6 ([Text.Encoding]::UTF8.GetBytes('EdgeSwitch 1.12.2'))))
        ($null -eq $Result.SoftwareVersion) | Should Be $true
        ($null -eq $Result.Model) | Should Be $true
    }
}
