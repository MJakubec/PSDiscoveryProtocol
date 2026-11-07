function Export-Pcap {

    <#

.SYNOPSIS

    Export packets to pcap

.DESCRIPTION

    Export packets, captured using Invoke-DiscoveryProtocolCapture, to pcap format.

.PARAMETER Packet

    Specifies one or more objects of type DiscoveryProtocolPacket.

.PARAMETER Path

    Relative or absolute path to pcap file.

.PARAMETER Invoke

    If Invoke is set, exported file is opened in the program associated with pcap files.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
    PS C:\> Export-Pcap -Packet $Packet -Path C:\Windows\Temp\captures.pcap -Invoke

    Export captured packet to C:\Windows\Temp\captures.pcap and open file in
    the program associated with pcap files.

.EXAMPLE

    PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Export-Pcap -Path captures.pcap

    Export captured packets to captures.pcap in current directory. Export-Pcap supports input from pipeline.

#>

    [CmdletBinding(DefaultParameterSetName = 'DiscoveryProtocolPacket')]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'DiscoveryProtocolPacket')]
        [DiscoveryProtocolPacket[]]$Packet,

        [Parameter(Mandatory = $true,
            ParameterSetName = 'BytesAndDateTime')]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $false,
            ParameterSetName = 'BytesAndDateTime')]
        [datetime]$DateTime = (Get-Date),

        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                if ([System.IO.Path]::IsPathRooted($_)) {
                    $AbsolutePath = $_
                }
                else {
                    $AbsolutePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
                }
                if (-not(Test-Path (Split-Path $AbsolutePath -Parent))) {
                    throw "Folder does not exist"
                }
                if ($_ -notmatch '\.pcap$') {
                    throw "Extension must be pcap"
                }
                return $true
            })]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$Invoke
    )

    begin {
        $Records = New-Object 'System.Collections.Generic.List[byte[]]'
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'DiscoveryProtocolPacket') {
            foreach ($Item in $Packet) {
                $Records.Add((New-PcapRecord -Bytes $Item.Fragment -Timestamp $Item.TimeCreated -OriginalLength $Item.FragmentSize))
            }
        } else {
            $Records.Add((New-PcapRecord -Bytes $Bytes -Timestamp $DateTime -OriginalLength $Bytes.Length))
        }
    }

    end {
        $Stream = [System.IO.MemoryStream]::new()
        $Writer = $null
        try {
            $Writer = [System.IO.BinaryWriter]::new($Stream)
            $Writer.Write([uint32]0xa1b2c3d4L)
            $Writer.Write([uint16]2)
            $Writer.Write([uint16]4)
            $Writer.Write([int32]0)
            $Writer.Write([uint32]0)
            $Writer.Write([uint32]65536)
            $Writer.Write([uint32]1)
            foreach ($Record in $Records) { $Writer.Write($Record) }
            $AbsolutePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
            [System.IO.File]::WriteAllBytes($AbsolutePath, $Stream.ToArray())
        } finally {
            if ($null -ne $Writer) { $Writer.Dispose() }
            $Stream.Dispose()
        }
        if ($Invoke) { Invoke-Item -LiteralPath $AbsolutePath }
    }
}
