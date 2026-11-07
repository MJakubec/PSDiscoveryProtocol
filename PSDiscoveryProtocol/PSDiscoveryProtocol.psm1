#region classes
class DiscoveryProtocolPacket {
    [string]$MachineName
    [datetime]$TimeCreated
    [int]$FragmentSize
    [byte[]]$Fragment
    [int]$MiniportIfIndex
    [string]$Connection
    [string]$Interface

    DiscoveryProtocolPacket([PSCustomObject]$WinEvent) {
        $this.MachineName = $WinEvent.MachineName
        $this.TimeCreated = $WinEvent.TimeCreated
        $this.FragmentSize = $WinEvent.FragmentSize
        $this.Fragment = $WinEvent.Fragment
        $this.MiniportIfIndex = $WinEvent.MiniportIfIndex
        $this.Connection = $WinEvent.Connection
        $this.Interface = $WinEvent.Interface

        Add-Member -InputObject $this -MemberType ScriptProperty -Name IsDiscoveryProtocolPacket -Value {
            return [bool]($this.DiscoveryProtocolType -ne [string]::Empty)
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name DiscoveryProtocolType -Value {
            return Get-DiscoveryFrameType -Packet $this.Fragment
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name SourceAddress -Value {
            if ($this.Fragment.Length -lt 12) { return [string]::Empty }
            [System.Net.NetworkInformation.PhysicalAddress]::new($this.Fragment[6..11]).ToString()
        }
    }
}
#endregion

# Load in dependency order. Only manifest-listed commands are exported.
. "$PSScriptRoot/Private/PacketReader.ps1"
. "$PSScriptRoot/Private/Decode-Tlv.ps1"
. "$PSScriptRoot/Private/Pcap.ps1"
. "$PSScriptRoot/Public/Invoke-DiscoveryProtocolCapture.ps1"
. "$PSScriptRoot/Public/Get-DiscoveryProtocolData.ps1"
. "$PSScriptRoot/Public/ConvertFrom-CDPPacket.ps1"
. "$PSScriptRoot/Public/ConvertFrom-LLDPPacket.ps1"
. "$PSScriptRoot/Public/Export-Pcap.ps1"

# Also keep helpers private when callers import the .psm1 directly.
Export-ModuleMember -Function @(
    'Invoke-DiscoveryProtocolCapture', 'Get-DiscoveryProtocolData',
    'ConvertFrom-CDPPacket', 'ConvertFrom-LLDPPacket', 'Export-Pcap'
) -Alias @('Capture-CDPPacket', 'Capture-LLDPPacket', 'Parse-CDPPacket', 'Parse-LLDPPacket')

# Also keep helpers private when callers import the .psm1 directly.
Export-ModuleMember -Function @(
    'Invoke-DiscoveryProtocolCapture', 'Get-DiscoveryProtocolData',
    'ConvertFrom-CDPPacket', 'ConvertFrom-LLDPPacket', 'Export-Pcap'
) -Alias @('Capture-CDPPacket', 'Capture-LLDPPacket', 'Parse-CDPPacket', 'Parse-LLDPPacket')
