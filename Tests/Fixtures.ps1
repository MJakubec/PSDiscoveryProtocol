function New-LldpTlv {
    param([int]$Type, [byte[]]$Value = @())
    $Header = ($Type -shl 9) -bor $Value.Length
    return ,([byte[]]@(($Header -shr 8), ($Header -band 255)) + $Value)
}
function New-LldpFrame {
    param([byte[]]$Tlvs = @())
    return ,([byte[]]@(1,128,194,0,0,14,0,17,34,51,68,85,136,204) + $Tlvs + [byte[]]@(0,0))
}
function New-CdpTlv {
    param([int]$Type, [byte[]]$Value = @())
    $Length = $Value.Length + 4
    return ,([byte[]]@(($Type -shr 8), ($Type -band 255), ($Length -shr 8), ($Length -band 255)) + $Value)
}
function New-CdpFrame {
    param([byte[]]$Tlvs = @())
    $Length = 12 + $Tlvs.Length
    return ,([byte[]]@(1,0,12,204,204,204,0,17,34,51,68,85,($Length -shr 8),($Length -band 255),170,170,3,0,0,12,32,0,2,60,0,0) + $Tlvs)
}
function New-PacketObject {
    param([byte[]]$Bytes)
    & (Get-Module PSDiscoveryProtocol) {
        param($Bytes)
        [DiscoveryProtocolPacket]::new([pscustomobject]@{
            MachineName = 'client'; TimeCreated = [datetime]'2026-01-01T00:00:00Z'
            FragmentSize = $Bytes.Length; Fragment = $Bytes; MiniportIfIndex = 1
            Connection = 'Ethernet'; Interface = 'Adapter'
        })
    } $Bytes
}
