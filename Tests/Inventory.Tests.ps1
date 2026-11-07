# Extract pure helpers without executing capture or Active Directory writes.
$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../Invoke-ComputerInventory.ps1'), [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw 'Invoke-ComputerInventory.ps1 has syntax errors.' }
foreach ($Name in 'Select-InventorySwitch', 'ConvertTo-InventoryCapabilities', 'Get-InventorySwitchAttributes') {
    $Definition = $Ast.Find({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $Name }, $true)
    . ([scriptblock]::Create($Definition.Extent.Text))
}

Describe 'Inventory switch selection' {
    It 'prefers LLDP for the same advertised device name' {
        $Cdp = [pscustomobject]@{ Type = 'CDP'; Device = 'switch.example.'; SourceAddress = '001122334455' }
        $Lldp = [pscustomobject]@{ Type = 'LLDP'; Device = 'SWITCH.EXAMPLE'; SourceAddress = '001122334466' }
        (Select-InventorySwitch @($Lldp,$Cdp)).Type | Should Be 'LLDP'
    }
    It 'prefers LLDP when advertised names differ' {
        $Cdp = [pscustomobject]@{ Type = 'CDP'; Device = 'switch'; SourceAddress = '001122334455' }
        $Lldp = [pscustomobject]@{ Type = 'LLDP'; Device = 'switch.example'; SourceAddress = '001122334455' }
        (Select-InventorySwitch @($Lldp,$Cdp)).Type | Should Be 'LLDP'
    }
    It 'uses LLDP without CDP and returns nothing without announcements' {
        $Lldp = [pscustomobject]@{ Type = 'LLDP'; Device = 'switch'; SourceAddress = '001122334455' }
        (Select-InventorySwitch @($Lldp)).Type | Should Be 'LLDP'
        ($null -eq (Select-InventorySwitch @())) | Should Be $true
    }
    It 'uses LLDP even with conflicting or multiple CDP neighbors' {
        $Cdp = [pscustomobject]@{ Type = 'CDP'; Device = 'switch1'; SourceAddress = '001122334455' }
        $Lldp = [pscustomobject]@{ Type = 'LLDP'; Device = 'switch2'; SourceAddress = '001122334466' }
        (Select-InventorySwitch @($Cdp,$Lldp)).Type | Should Be 'LLDP'
        (Select-InventorySwitch @($Cdp,$Cdp,$Lldp)).Type | Should Be 'LLDP'
    }
    It 'uses CDP only when LLDP is absent and unambiguous' {
        $Cdp = [pscustomobject]@{ Type = 'CDP'; Device = 'switch'; SourceAddress = '001122334455' }
        (Select-InventorySwitch @($Cdp)).Type | Should Be 'CDP'
        ($null -eq (Select-InventorySwitch @($Cdp,$Cdp) -WarningAction SilentlyContinue)) | Should Be $true
    }
    It 'does not fall back to CDP when LLDP is ambiguous' {
        $Cdp = [pscustomobject]@{ Type = 'CDP'; Device = 'switch'; SourceAddress = '001122334455' }
        $Lldp = [pscustomobject]@{ Type = 'LLDP'; Device = 'other'; SourceAddress = '001122334466' }
        ($null -eq (Select-InventorySwitch @($Lldp,$Lldp,$Cdp) -WarningAction SilentlyContinue)) | Should Be $true
        ($null -eq (Select-InventorySwitch @($Lldp,$Lldp) -WarningAction SilentlyContinue)) | Should Be $true
    }
}

Describe 'Inventory attribute synchronization' {
    It 'normalizes Switch and Router roles across CDP and enabled LLDP capabilities' {
        (ConvertTo-InventoryCapabilities 'CDP' ([pscustomobject]@{ Supported = [uint32]9 })) | Should Be 'Switch, Router'
        (ConvertTo-InventoryCapabilities 'LLDP' ([pscustomobject]@{ Supported = [uint32]20; Enabled = [uint32]20 })) | Should Be 'Switch, Router'
        (ConvertTo-InventoryCapabilities 'LLDP' ([pscustomobject]@{ Supported = [uint32]20; Enabled = [uint32]16 })) | Should Be 'Router'
    }
    It 'distinguishes missing capabilities from zero and preserves unknown bits' {
        ($null -eq (ConvertTo-InventoryCapabilities 'LLDP' $null)) | Should Be $true
        (ConvertTo-InventoryCapabilities 'LLDP' ([pscustomobject]@{ Supported = [uint32]4; Enabled = [uint32]0 })) | Should Be 'None'
        (ConvertTo-InventoryCapabilities 'CDP' ([pscustomobject]@{ Supported = [uint32]2147483656L })) | Should Be 'Switch, Unknown(0x80000000)'
    }
    It 'uses a distinct SystemName for SwitchName and preserves Device for SwitchDevice' {
        $Attributes = Get-InventorySwitchAttributes ([pscustomobject]@{ SystemName = 'friendly-name'; Device = 'original-device-id' })
        $Attributes['msDS-cloudExtensionAttribute1'] | Should Be 'friendly-name'
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'original-device-id'
    }
    It 'exposes CDP Device ID as SystemName and populates both existing inventory fields' {
        Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force
        . "$PSScriptRoot/Fixtures.ps1"
        $Data = ConvertFrom-CDPPacket (New-CdpFrame (New-CdpTlv 1 ([Text.Encoding]::UTF8.GetBytes('cdp-switch'))))
        $Data.SystemName | Should Be 'cdp-switch'
        $Attributes = Get-InventorySwitchAttributes $Data
        $Attributes['msDS-cloudExtensionAttribute1'] | Should Be 'cdp-switch'
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'cdp-switch'
    }
    It 'maps supported fields and serializes addresses and readable roles' {
        $Item = [pscustomobject]@{
            Type = 'CDP'; Port = 'Gi1/1'; VLAN = 10; Model = 'Switch'; Device = 'switch.example'
            IPAddress = @('192.0.2.1','2001:db8::1'); Capabilities = [pscustomobject]@{ Supported = [uint32]8 }
        }
        $Attributes = Get-InventorySwitchAttributes $Item
        $Attributes['msDS-cloudExtensionAttribute2'] | Should Be 'Gi1/1'
        $Attributes['msDS-cloudExtensionAttribute3'] | Should Be '10'
        $Attributes['msDS-cloudExtensionAttribute4'] | Should Be '192.0.2.1; 2001:db8::1'
        $Attributes['msDS-cloudExtensionAttribute5'] | Should Be 'Switch'
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'switch.example'
        $Attributes['msDS-cloudExtensionAttribute1'] | Should Be 'switch.example'
        $Attributes['msDS-cloudExtensionAttribute8'] | Should Be 'Switch'
        $Attributes.Count | Should Be 11
    }
    It 'explicitly clears missing optional values and unsupported fields' {
        $Attributes = Get-InventorySwitchAttributes ([pscustomobject]@{ Device = 'switch'; Model = ' '; IPAddress = @() })
        $Attributes.Count | Should Be 11
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'switch'
        $Attributes['msDS-cloudExtensionAttribute1'] | Should Be 'switch'
        foreach ($Index in 2,3,4,5,7,8,9,10,11) {
            $Attributes.Contains("msDS-cloudExtensionAttribute$Index") | Should Be $true
            ($null -eq $Attributes["msDS-cloudExtensionAttribute$Index"]) | Should Be $true
        }
    }
    It 'preserves zero values instead of treating them as missing' {
        $Attributes = Get-InventorySwitchAttributes ([pscustomobject]@{
            Type = 'CDP'; VLAN = 0; UntrustedPortCoS = 0; Capabilities = [pscustomobject]@{ Supported = [uint32]0 }
        })
        $Attributes['msDS-cloudExtensionAttribute3'] | Should Be '0'
        $Attributes['msDS-cloudExtensionAttribute8'] | Should Be 'None'
        $Attributes['msDS-cloudExtensionAttribute10'] | Should Be '0'
    }
    It 'maps LLDP system name and MED software and model to the existing LDAP attributes' {
        Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force
        . "$PSScriptRoot/Fixtures.ps1"
        $Tlvs = (New-LldpTlv 5 ([Text.Encoding]::UTF8.GetBytes('sw-edge'))) +
            (New-LldpTlv 127 ([byte[]]@(0,18,187,7) + [Text.Encoding]::UTF8.GetBytes('1.12.2'))) +
            (New-LldpTlv 127 ([byte[]]@(0,18,187,10) + [Text.Encoding]::UTF8.GetBytes('EdgeSwitch')))
        $Attributes = Get-InventorySwitchAttributes (ConvertFrom-LLDPPacket (New-LldpFrame $Tlvs))
        $Attributes['msDS-cloudExtensionAttribute1'] | Should Be 'sw-edge'
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'sw-edge'
        $Attributes['msDS-cloudExtensionAttribute7'] | Should Be '1.12.2'
        $Attributes['msDS-cloudExtensionAttribute5'] | Should Be 'EdgeSwitch'
        ($null -eq $Attributes['msDS-cloudExtensionAttribute9']) | Should Be $true
    }
}
