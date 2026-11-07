# Extract pure helpers without executing capture or Active Directory writes.
$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '../Invoke-ComputerInventory.ps1'), [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw 'Invoke-ComputerInventory.ps1 has syntax errors.' }
foreach ($Name in 'Select-InventorySwitch', 'Get-InventorySwitchAttributes') {
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

Describe 'Inventory attribute preservation' {
    It 'maps supported fields and serializes addresses and the numeric mask' {
        $Item = [pscustomobject]@{
            Port = 'Gi1/1'; VLAN = 10; Model = 'Switch'; Device = 'switch.example'
            IPAddress = @('192.0.2.1','2001:db8::1'); Capabilities = [pscustomobject]@{ Supported = [uint32]8 }
        }
        $Attributes = Get-InventorySwitchAttributes $Item
        $Attributes['msDS-cloudExtensionAttribute2'] | Should Be 'Gi1/1'
        $Attributes['msDS-cloudExtensionAttribute3'] | Should Be '10'
        $Attributes['msDS-cloudExtensionAttribute4'] | Should Be '192.0.2.1; 2001:db8::1'
        $Attributes['msDS-cloudExtensionAttribute5'] | Should Be 'Switch'
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'switch.example'
        $Attributes['msDS-cloudExtensionAttribute8'] | Should Be '8'
        $Attributes.Count | Should Be 6
    }
    It 'omits missing optional values and unsupported fields' {
        $Attributes = Get-InventorySwitchAttributes ([pscustomobject]@{ Device = 'switch'; Model = ' '; IPAddress = @() })
        $Attributes.Count | Should Be 1
        $Attributes['msDS-cloudExtensionAttribute6'] | Should Be 'switch'
        foreach ($Index in 1,2,3,4,5,7,8,9,10,11) {
            $Attributes.Contains("msDS-cloudExtensionAttribute$Index") | Should Be $false
        }
    }
}
