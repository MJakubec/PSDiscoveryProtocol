Import-Module "$PSScriptRoot/../../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force

Describe 'Live capture on a discovery-enabled wired network' {
    It 'captures and parses CDP on each returned interface' -Skip:($env:PSDISCOVERY_LIVE_CAPTURE -ne '1') {
        $Packets = @(Invoke-DiscoveryProtocolCapture -Type CDP -ErrorAction Stop)
        $Packets.Count | Should BeGreaterThan 0
        @($Packets | Get-DiscoveryProtocolData -ErrorAction Stop).Count | Should Be $Packets.Count
    }
    It 'captures and parses LLDP on each returned interface' -Skip:($env:PSDISCOVERY_LIVE_CAPTURE -ne '1') {
        $Packets = @(Invoke-DiscoveryProtocolCapture -Type LLDP -ErrorAction Stop)
        $Packets.Count | Should BeGreaterThan 0
        @($Packets | Get-DiscoveryProtocolData -ErrorAction Stop).Count | Should Be $Packets.Count
    }
}
