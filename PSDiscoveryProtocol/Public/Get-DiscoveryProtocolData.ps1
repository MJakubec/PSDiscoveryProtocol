function Get-DiscoveryProtocolData {

    <#

.SYNOPSIS

    Parse CDP or LLDP packets captured by Invoke-DiscoveryProtocolCapture

.DESCRIPTION

    Gets computername, type and packet details from a DiscoveryProtocolPacket.

    Calls ConvertFrom-CDPPacket or ConvertFrom-LLDPPacket to extract packet details
    from a byte array.

.PARAMETER Packet

    Specifies an object of type DiscoveryProtocolPacket.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
    PS C:\> Get-DiscoveryProtocolData -Packet $Packet

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> Invoke-DiscoveryProtocolCapture -Computer COMPUTER1 | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

    Port      : FastEthernet0/2
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 20
    Computer  : COMPUTER2
    Type      : CDP

#>

    [CmdletBinding()]
    [Alias('Parse-CDPPacket', 'Parse-LLDPPacket')]
    param(
        [Parameter(Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [DiscoveryProtocolPacket[]]
        $Packet
    )

    begin {
        if ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
            $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
            Write-Warning $Warning
        }
    }

    process {
        foreach ($Item in $Packet) {
            switch ($Item.DiscoveryProtocolType) {
                'CDP' { $PacketData = ConvertFrom-CDPPacket -Packet $Item.Fragment }
                'LLDP' { $PacketData = ConvertFrom-LLDPPacket -Packet $Item.Fragment }
                Default { throw 'Packet does not contain a supported CDP or LLDP Ethernet frame.' }
            }

            $Properties = [ordered]@{}
            foreach ($Property in $PacketData.PSObject.Properties) { $Properties[$Property.Name] = $Property.Value }
            $Properties.Computer = $Item.MachineName
            $Properties.Connection = $Item.Connection
            $Properties.Interface = $Item.Interface
            $Properties.Type = $Item.DiscoveryProtocolType
            [pscustomobject]$Properties
        }
    }

}
