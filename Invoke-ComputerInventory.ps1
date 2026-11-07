#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Updates Active Directory hardware, OS, network and switch inventory for this computer.
.DESCRIPTION
Run elevated under an identity allowed to update the computer's inventory attributes.
Deploy the complete PSDiscoveryProtocol folder beside this script. Discovery captures
CDP and LLDP for 62 seconds. A selected neighbor's missing fields clear their LDAP
attributes; failed discovery or ambiguous neighbors leave switch inventory unchanged.
#>

$ComputerName = $env:COMPUTERNAME
$DomainName = $env:USERDOMAIN
$DomainSuffix = (Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Domain)
$ModulePath = (Join-Path $PSScriptRoot -ChildPath 'PSDiscoveryProtocol\PSDiscoveryProtocol.psd1')
$StartTime = (Get-Date -Format 'MM\/dd\/yyyy HH:mm:ss')

Write-Output "Starting an inventory process for computer ""$ComputerName"" on ""$StartTime""..."

function Set-AttributeValue
{
    param(
        [System.DirectoryServices.DirectoryEntry]$Computer,
        [string]$AttributeName,
        [string]$AttributeValue
    )

    $CurrentValue = if ([string]::IsNullOrWhiteSpace($AttributeValue)) { $null } else { $AttributeValue }
    $OriginalValue = $Computer.Properties[$AttributeName].Value

    if ($OriginalValue -ne $CurrentValue)
    {
        Write-Output "Updating attribute ""$AttributeName"" to ""$AttributeValue""..."
        if ($null -eq $CurrentValue)
        {
            $Computer.Properties[$AttributeName].Clear()
        }
        else
        {
            $Computer.Properties[$AttributeName].Value = $CurrentValue
        }
    }
    else
    {
        Write-Output "Attribute ""$AttributeName"" does not need to be updated."
    }
}

# Prefer LLDP: forwarded CDP announcements may identify switches on other ports.
function Select-InventorySwitch
{
    [CmdletBinding()]
    param([object[]]$Announcements)

    $Cdp = @($Announcements | Where-Object { $_.Type -eq 'CDP' })
    $Lldp = @($Announcements | Where-Object { $_.Type -eq 'LLDP' })
    if ($Lldp.Count -eq 1) { return $Lldp[0] }
    if ($Lldp.Count -gt 1)
    {
        Write-Warning 'Multiple LLDP switch neighbors were found on the primary adapter. Inventory is unchanged.'
        return
    }
    # Use CDP only when LLDP is absent, and only for one unambiguous neighbor.
    if ($Cdp.Count -gt 1)
    {
        Write-Warning 'Multiple CDP switch neighbors were found without LLDP. Inventory is unchanged.'
        return
    }
    if ($Cdp.Count -eq 1) { return $Cdp[0] }
}

function Get-InventorySwitchAttributes
{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Item)

    $Attributes = [ordered]@{}
    # Include every managed switch attribute so missing values explicitly clear old data.
    foreach ($Index in 1..11) { $Attributes["msDS-cloudExtensionAttribute$Index"] = $null }
    $Mapping = [ordered]@{
        'msDS-cloudExtensionAttribute1' = 'SystemName'
        'msDS-cloudExtensionAttribute2' = 'Port'
        'msDS-cloudExtensionAttribute3' = 'VLAN'
        'msDS-cloudExtensionAttribute5' = 'Model'
        'msDS-cloudExtensionAttribute6' = 'Device'
        'msDS-cloudExtensionAttribute7' = 'SoftwareVersion'
        'msDS-cloudExtensionAttribute9' = 'Duplex'
        'msDS-cloudExtensionAttribute10' = 'UntrustedPortCoS'
        'msDS-cloudExtensionAttribute11' = 'TrustBitmap'
    }
    foreach ($Name in $Mapping.Keys)
    {
        $Value = $Item.($Mapping[$Name])
        if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value))
        {
            $Attributes[$Name] = [string]$Value
        }
    }
    $Addresses = @($Item.IPAddress | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($Addresses.Count -gt 0)
    {
        $Attributes['msDS-cloudExtensionAttribute4'] = $Addresses -join '; '
    }
    if ($null -ne $Item.Capabilities.Supported)
    {
        # Preserve numeric storage; bit definitions depend on the source protocol logged above.
        $Attributes['msDS-cloudExtensionAttribute8'] = [string]$Item.Capabilities.Supported
    }
    # Unsupported fields remain null and clear stale values, without inventing replacements.
    return $Attributes
}

$Machine = Get-CimInstance Win32_ComputerSystem -Property Manufacturer, Model, TotalPhysicalMemory
$Board = Get-CimInstance Win32_Baseboard -Property Manufacturer, Product, Version
$Processor = Get-CimInstance Win32_Processor -Property Name, NumberOfEnabledCore, NumberOfLogicalProcessors
$Bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion, ReleaseDate, SerialNumber
$System = Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
    | Select-Object -Property ProductName, ReleaseId, DisplayVersion, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentBuildNumber, UBR

try
{
    Write-Output "Searching computer object $ComputerName in $DomainName domain..."

    $Root = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DomainName")

    $Searcher = [System.DirectoryServices.DirectorySearcher]::new(
        $Root,
        "(name=$ComputerName)",
        @(),
        [System.DirectoryServices.SearchScope]::Subtree
    )

    $Result = $Searcher.FindOne()

    if ($Result -eq $null)
    {
        throw [System.ObjectNotFoundException]::new("Computer object with name $ComputerName was not found.")
    }

    $Computer = $Result.GetDirectoryEntry()

    Write-Output "Assigning values to inventory attributes..."

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute1" -AttributeValue "$($Machine.Manufacturer)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute2" -AttributeValue "$($Machine.Model)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute3" -AttributeValue "$([Math]::Round($Machine.TotalPhysicalMemory / 1024 / 1024 / 1024)) GiB RAM"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute4" -AttributeValue "$($Board.Manufacturer)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute5" -AttributeValue "$($Board.Product)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute6" -AttributeValue "$($Board.Version)"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute7" -AttributeValue "$($Processor.Name -replace '[ ]{2,}', ' ')"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute8" -AttributeValue "$($Processor.NumberOfEnabledCore) cores, $($Processor.NumberOfLogicalProcessors) threads"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute9" -AttributeValue "$($Bios.SMBIOSBIOSVersion)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute10" -AttributeValue "$($Bios.ReleaseDate)"
    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute11" -AttributeValue "$($Bios.SerialNumber)"
    Set-AttributeValue -Computer $Computer -AttributeName "serialNumber" -AttributeValue "$($Bios.SerialNumber)"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute12" -AttributeValue "$($System.ProductName)"
    Set-AttributeValue -Computer $Computer -AttributeName "operatingSystem" -AttributeValue "$($System.ProductName)"

    if ($null -ne $System.DisplayVersion)
    {
        Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute13" -AttributeValue "$($System.DisplayVersion)"
        Set-AttributeValue -Computer $Computer -AttributeName "operatingSystemServicePack" -AttributeValue "$($System.DisplayVersion)"
    }
    else
    {
        Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute13" -AttributeValue "$($System.ReleaseId)"
        Set-AttributeValue -Computer $Computer -AttributeName "operatingSystemServicePack" -AttributeValue "$($System.ReleaseId)"
    }

    $VersionText = "$($System.CurrentMajorVersionNumber).$($System.CurrentMinorVersionNumber) ($($System.CurrentBuildNumber))"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute14" -AttributeValue "$VersionText"
    Set-AttributeValue -Computer $Computer -AttributeName "operatingSystemVersion" -AttributeValue "$VersionText"

    Set-AttributeValue -Computer $Computer -AttributeName "extensionAttribute15" -AttributeValue "$($System.UBR)"
    Set-AttributeValue -Computer $Computer -AttributeName "operatingSystemHotfix" -AttributeValue "$($System.UBR)"

    Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute16" -AttributeValue "$(Get-Date -Format "MM\/dd\/yyyy HH:mm:ss")"

    Write-Output "Writing changes to computer object $ComputerName in $DomainName domain..."
    $Computer.CommitChanges()

######################################################################################################################
    
    Write-Output "Looking up for a primary network adapter..."
    $DnsClientSet = Get-DnsClient -ConnectionSpecificSuffix $DomainSuffix -RegisterThisConnectionsAddress $True -ErrorAction SilentlyContinue

    $IsDnsClientFound = (@($DnsClientSet).Count -gt 0)

    if ($IsDnsClientFound)
    {
        $InterfaceAlias = $DnsClientSet[0].InterfaceAlias

        Write-Output "DNS client with domain connection suffix ""$DomainSuffix"" has been found. Name of the corresponding network adapter is ""$InterfaceAlias""."

        $Adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop
        $MacAddress = $Adapter.MacAddress -replace '-', ':'

        Write-Output "MAC address of network adapter ""$InterfaceAlias"" is ""$MacAddress""."

        Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute13" -AttributeValue "$MacAddress"

        $IpAddressSet = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -Type Unicast -AddressFamily IPv4
        $HasIpAddress = (@($IpAddressSet).Count -gt 0)

        if ($HasIpAddress)
        {
            $Item = $IpAddressSet[0]
            $IpAddress = $Item.IPv4Address
            $AssignmentType = $Item.PrefixOrigin

            Write-Output "IP address of network adapter ""$InterfaceAlias"" is ""$IpAddress"" assigned by ""$AssignmentType""."
            Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute14" -AttributeValue "$IpAddress"
            Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute15" -AttributeValue "$AssignmentType"
        }
        else
        {
            Write-Output "No IP address has been found as assigned to the network adapter ""$InterfaceAlias""."
            Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute14" -AttributeValue $null
            Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute15" -AttributeValue $null
        }
    }
    else
    {
        Write-Output "No primary network interface with domain connection suffix ""$DomainSuffix"" has been found. Network addresses can't be identified."
        Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute13" -AttributeValue $null
        Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute14" -AttributeValue $null
        Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute15" -AttributeValue $null
    }

    Set-AttributeValue -Computer $Computer -AttributeName "msDS-cloudExtensionAttribute17" -AttributeValue "$(Get-Date -Format "MM\/dd\/yyyy HH:mm:ss")"

    Write-Output "Writing changes to computer object $ComputerName in $DomainName domain..."
    $Computer.CommitChanges()

######################################################################################################################

    # No selected neighbor means no switch updates; missing fields on a selected neighbor are cleared.
    if ($IsDnsClientFound)
    {
        $Item = $null
        try
        {
            Write-Output "Importing PSDiscoveryProtocol module at '$ModulePath'..."
            Import-Module $ModulePath -ErrorAction Stop

            Write-Output "Capturing CDP and LLDP switch announcements for '$InterfaceAlias'..."
            $Announcements = @(
                foreach ($Packet in (Invoke-DiscoveryProtocolCapture -SwitchOnly -ErrorAction Stop))
                {
                    if ($Packet.MiniportIfIndex -ne $Adapter.InterfaceIndex) { continue }
                    $Data = $Packet | Get-DiscoveryProtocolData -ErrorAction Stop
                    $Data | Add-Member -NotePropertyName SourceAddress -NotePropertyValue $Packet.SourceAddress
                    $Data
                }
            )

            $Item = Select-InventorySwitch -Announcements $Announcements
        }
        catch
        {
            Write-Warning "Switch discovery failed. Retaining current switch attribute values: $_"
        }
        if ($null -ne $Item)
        {
            Write-Output "Using $($Item.Type) announcement from '$($Item.Device)' on '$InterfaceAlias'."
            $Attributes = Get-InventorySwitchAttributes -Item $Item
            foreach ($Name in $Attributes.Keys)
            {
                Set-AttributeValue -Computer $Computer -AttributeName $Name -AttributeValue $Attributes[$Name]
            }
            Set-AttributeValue -Computer $Computer -AttributeName 'msDS-cloudExtensionAttribute12' -AttributeValue (Get-Date -Format 'MM/dd/yyyy HH:mm:ss')
        }
        else
        {
            Write-Output 'No unambiguous switch announcement found. Retaining current switch attribute values.'
        }
    }
    else
    {
        Write-Output 'Primary adapter was not found. Retaining current switch attribute values.'
    }

    Write-Output "Writing changes to computer object $ComputerName in $DomainName domain..."
    $Computer.CommitChanges()

    $EndTime = (Get-Date -Format 'MM\/dd\/yyyy HH:mm:ss')
    Write-Output "Inventory process for computer ""$ComputerName"" finished on ""$EndTime""!"
}
finally
{
    if ($null -ne $Computer)
    {
        $Computer.Close()
    }
    if ($null -ne $Searcher)
    {
        $Searcher.Dispose()
    }
    if ($null -ne $Root)
    {
        $Root.Close()
    }
}
