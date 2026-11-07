Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force
. "$PSScriptRoot/Fixtures.ps1"

Describe 'Discovery capabilities' {
    It 'decodes CDP switch router-switch router host and zero masks' {
        foreach ($Case in @(
            @{ Bytes = [byte[]]@(0,0,0,8); Mask = 8; IsSwitch = $true },
            @{ Bytes = [byte[]]@(0,0,0,9); Mask = 9; IsSwitch = $true },
            @{ Bytes = [byte[]]@(0,0,0,1); Mask = 1; IsSwitch = $false },
            @{ Bytes = [byte[]]@(0,0,0,16); Mask = 16; IsSwitch = $false },
            @{ Bytes = [byte[]]@(0,0,0,0); Mask = 0; IsSwitch = $false },
            @{ Bytes = [byte[]]@(128,0,0,8); Mask = 2147483656L; IsSwitch = $true }
        )) {
            $Result = ConvertFrom-CDPPacket (New-CdpFrame (New-CdpTlv 4 $Case.Bytes))
            $Result.Capabilities.Supported | Should Be $Case.Mask
            ($Result.Capabilities.Supported -is [uint32]) | Should Be $true
            ($null -eq $Result.Capabilities.Enabled) | Should Be $true
            ($Result.Capabilities.IsSwitch -is [bool]) | Should Be $true
            $Result.Capabilities.IsSwitch | Should Be $Case.IsSwitch
        }
    }
    It 'uses enabled rather than supported LLDP Bridge capabilities' {
        foreach ($Case in @(
            @{ Bytes = [byte[]]@(0,4,0,4); Supported = 4; Enabled = 4; IsSwitch = $true },
            @{ Bytes = [byte[]]@(0,20,0,20); Supported = 20; Enabled = 20; IsSwitch = $true },
            @{ Bytes = [byte[]]@(0,20,0,16); Supported = 20; Enabled = 16; IsSwitch = $false },
            @{ Bytes = [byte[]]@(0,16,0,16); Supported = 16; Enabled = 16; IsSwitch = $false },
            @{ Bytes = [byte[]]@(0,128,0,128); Supported = 128; Enabled = 128; IsSwitch = $false },
            @{ Bytes = [byte[]]@(0,0,0,0); Supported = 0; Enabled = 0; IsSwitch = $false },
            @{ Bytes = [byte[]]@(128,4,128,4); Supported = 32772; Enabled = 32772; IsSwitch = $true }
        )) {
            $Result = ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 7 $Case.Bytes))
            $Result.Capabilities.Supported | Should Be $Case.Supported
            $Result.Capabilities.Enabled | Should Be $Case.Enabled
            ($Result.Capabilities.Supported -is [uint32]) | Should Be $true
            ($Result.Capabilities.Enabled -is [uint32]) | Should Be $true
            ($Result.Capabilities.IsSwitch -is [bool]) | Should Be $true
            $Result.Capabilities.IsSwitch | Should Be $Case.IsSwitch
        }
    }
    It 'omits the property when no capabilities TLV is present' {
        $Cdp = ConvertFrom-CDPPacket (New-CdpFrame)
        $Lldp = ConvertFrom-LLDPPacket (New-LldpFrame)
        @($Cdp.PSObject.Properties.Name) -contains 'Capabilities' | Should Be $false
        @($Lldp.PSObject.Properties.Name) -contains 'Capabilities' | Should Be $false
    }
    It 'preserves the first capabilities TLV and diagnoses duplicates' {
        $Result = ConvertFrom-CDPPacket (New-CdpFrame ((New-CdpTlv 4 ([byte[]]@(0,0,0,1))) + (New-CdpTlv 4 ([byte[]]@(0,0,0,8))))) -Verbose 4>&1
        @($Result | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match 'Duplicate Capabilities' }).Count | Should Be 1
        ($Result | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }).Capabilities.IsSwitch | Should Be $false
        $Result = ConvertFrom-LLDPPacket (New-LldpFrame ((New-LldpTlv 7 ([byte[]]@(0,4,0,4))) + (New-LldpTlv 7 ([byte[]]@(0,0,0,0)))))
        $Result.Capabilities.IsSwitch | Should Be $true
    }
    It 'rejects non-four-byte capabilities payloads for both protocols' {
        foreach ($Length in 0,1,2,3,5) {
            $Value = New-Object byte[] $Length
            { ConvertFrom-CDPPacket (New-CdpFrame (New-CdpTlv 4 $Value)) } | Should Throw 'CDP: offset'
            { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 7 $Value)) } | Should Throw 'LLDP: offset'
        }
    }
    It 'rejects enabled bits not present in the LLDP supported mask' {
        { ConvertFrom-LLDPPacket (New-LldpFrame (New-LldpTlv 7 ([byte[]]@(0,4,0,20)))) } | Should Throw 'Enabled capabilities include unsupported bits'
    }
    It 'includes capabilities in enriched output without changing packet objects' {
        $Packet = New-PacketObject (New-LldpFrame (New-LldpTlv 7 ([byte[]]@(0,4,0,4))))
        $Result = $Packet | Get-DiscoveryProtocolData
        $Result.Capabilities.IsSwitch | Should Be $true
        $Result.Type | Should Be 'LLDP'
        $Packet.GetType().Name | Should Be 'DiscoveryProtocolPacket'
    }
}
