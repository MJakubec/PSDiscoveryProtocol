function New-PcapRecord {
    param([byte[]]$Bytes, [datetime]$Timestamp, [int]$OriginalLength)
    if ($OriginalLength -lt $Bytes.Length) { throw 'Original packet length is smaller than captured data.' }
    $Stream = [System.IO.MemoryStream]::new()
    $Writer = $null
    try {
        $Writer = [System.IO.BinaryWriter]::new($Stream)
        $Writer.Write([uint32]([DateTimeOffset]$Timestamp).ToUnixTimeSeconds())
        $Writer.Write([uint32][Math]::Floor(($Timestamp.Ticks % [TimeSpan]::TicksPerSecond) / 10))
        $Writer.Write([uint32]$Bytes.Length)
        $Writer.Write([uint32]$OriginalLength)
        $Writer.Write($Bytes)
        return ,$Stream.ToArray()
    } finally {
        if ($null -ne $Writer) { $Writer.Dispose() }
        $Stream.Dispose()
    }
}
