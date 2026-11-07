function Invoke-DiscoveryProtocolCapture {

    <#

.SYNOPSIS

    Capture CDP or LLDP packets on local or remote computers

.DESCRIPTION

    Capture discovery protocol packets on local or remote computers. This function will start a packet capture and save the
    captured packets in a temporary ETL file. The first matching discovery protocol packet on each interface will be returned.
    With SwitchOnly, the first matching frame per interface, protocol and source MAC address is returned instead.

    Cisco devices will by default send CDP announcements every 60 seconds. Default interval for LLDP packets is 30 seconds.

    Requires elevation (Run as Administrator) for local capture.
    WinRM and PowerShell remoting must be enabled on target computer for remote capture.

.PARAMETER ComputerName

    Specifies one or more computers on which to capture packets. Defaults to $env:COMPUTERNAME.

    If specified, remote capture is assumed and therefore WinRM must be enabled on target.

.PARAMETER Duration

    Specifies the duration for which the discovery protocol packets are captured, in seconds.

    If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

.PARAMETER Type

    Specifies what type of packet to capture, CDP or LLDP. If omitted, both types will be captured,
    but only the first matching packet on each interface will be returned unless SwitchOnly is specified.

    If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

.PARAMETER NoCleanup

    If specified, the ETL file will not be deleted from %TEMP%.

.PARAMETER SwitchOnly

    Return only neighbors advertising CDP Switch or enabled LLDP Bridge capabilities.
    Frames without Capabilities are excluded. Malformed candidates are skipped with verbose diagnostics.
    Returns the first matching frame per interface, protocol and source MAC address.
    Omit Type to capture both protocols. Capabilities describe the advertised role; they do not
    prove physical topology or the identity of the access switch. Software bridges can also match.

.PARAMETER Force

    If specified, any existing NetEventSession will be removed.

.PARAMETER Credential

    Use this with remote capture if current user do not have administrative privileges on the target computer.

.OUTPUTS

    DiscoveryProtocolPacket

.EXAMPLE

    PS C:\> Invoke-DiscoveryProtocolCapture -SwitchOnly | Get-DiscoveryProtocolData

    Capture both CDP and LLDP announcements and return neighbors advertising switching.
    Repeated announcements are removed separately for each interface, protocol and source MAC address.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP -Duration 60
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

    [CmdletBinding(DefaultParametersetName = 'LocalCapture')]
    [OutputType('DiscoveryProtocolPacket')]
    [Alias('Capture-CDPPacket', 'Capture-LLDPPacket')]
    param(
        [Parameter(ParameterSetName = 'RemoteCapture',
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Computer')]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'LocalCapture',
            Position = 0)]
        [Parameter(ParameterSetName = 'RemoteCapture',
            Position = 1)]
        [ValidateRange(1, 32767)]
        [Int16]$Duration,

        [Parameter(ParameterSetName = 'LocalCapture',
            Position = 1)]
        [Parameter(ParameterSetName = 'RemoteCapture',
            Position = 2)]
        [ValidateSet('CDP', 'LLDP')]
        [String]$Type,

        [Parameter(ParameterSetName = 'RemoteCapture')]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [switch]$NoCleanup,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$SwitchOnly
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
            if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                throw 'Invoke-DiscoveryProtocolCapture requires elevation. Please run PowerShell as administrator.'
            }
        }

        if ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
            if ($MyInvocation.InvocationName -eq 'Capture-CDPPacket') { $Type = 'CDP' }
            if ($MyInvocation.InvocationName -eq 'Capture-LLDPPacket') { $Type = 'LLDP' }
            $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
            Write-Warning $Warning
        }
        if (-not $PSBoundParameters.ContainsKey('Duration')) { $Duration = if ($Type -eq 'LLDP') { 32 } else { 62 } }
    }

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)"
            Write-Verbose "TargetComputer: $Computer"

            $CimSession = @{}
            $PSSession = @{}
            $ETLFilePath = $null
            $SessionCreated = $false
            $SessionRunning = $false
            try {
                if ($PSCmdlet.ParameterSetName -eq 'RemoteCapture') {
                    $CredentialParameters = @{}
                    if ($PSBoundParameters.ContainsKey('Credential')) { $CredentialParameters.Credential = $Credential }
                    $CimSession.CimSession = New-CimSession -ComputerName $Computer @CredentialParameters -ErrorAction Stop
                    $PSSession.Session = New-PSSession -ComputerName $Computer @CredentialParameters -ErrorAction Stop
                }

                $ETLFilePath = Invoke-Command @PSSession -ErrorAction Stop -ScriptBlock {
                    Join-Path ([System.IO.Path]::GetTempPath()) ('Discovery-{0}.etl' -f [guid]::NewGuid())
                }

                Write-Verbose "ETLFilePath: $ETLFilePath"

                $Adapters = Get-NetAdapter @CimSession -ErrorAction Stop |
                Where-Object { $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 } |
                Select-Object Name, MacAddress, InterfaceDescription, InterfaceIndex

                if ($Adapters) {
                    $MACAddresses = $Adapters.MacAddress.ForEach({ [System.Net.NetworkInformation.PhysicalAddress]::Parse($_).ToString() })
                    $SessionName = 'Capture-{0}' -f [guid]::NewGuid()

                    if ($Force.IsPresent) {
                        Get-NetEventSession @CimSession -ErrorAction Stop | ForEach-Object {
                            if ($_.SessionStatus -eq 'Running') {
                                $_ | Stop-NetEventSession @CimSession -ErrorAction Stop
                            }
                            $_ | Remove-NetEventSession @CimSession -ErrorAction Stop
                        }
                    }

                    try {
                        New-NetEventSession -Name $SessionName -LocalFilePath $ETLFilePath -CaptureMode SaveToFile @CimSession -ErrorAction Stop | Out-Null
                        $SessionCreated = $true
                    }
                    catch [Microsoft.Management.Infrastructure.CimException] {
                        if ($_.Exception.NativeErrorCode -eq 'AlreadyExists') {
                            $Message = "Another NetEventSession already exists. Run Invoke-DiscoveryProtocolCapture with -Force switch to remove existing NetEventSessions."
                            Write-Error -Message $Message
                        }
                        else {
                            Write-Error -ErrorRecord $_
                        }
                        continue
                    }

                    $LinkLayerAddress = switch ($Type) {
                        'CDP' { '01-00-0c-cc-cc-cc' }
                        'LLDP' { '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                        Default { '01-00-0c-cc-cc-cc', '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                    }

                    $PacketCaptureParams = @{
                        SessionName      = $SessionName
                        TruncationLength = 0
                        CaptureType      = 'Physical'
                        LinkLayerAddress = $LinkLayerAddress
                    }

                    Add-NetEventPacketCaptureProvider @PacketCaptureParams @CimSession -ErrorAction Stop | Out-Null

                    foreach ($Adapter in $Adapters) {
                        Add-NetEventNetworkAdapter -Name $Adapter.Name -PromiscuousMode $True @CimSession -ErrorAction Stop | Out-Null
                    }

                    # A failed start may still have activated the session; attempt a stop in finally.
                    $SessionRunning = $true
                    Start-NetEventSession -Name $SessionName @CimSession -ErrorAction Stop

                    $Seconds = $Duration
                    $End = (Get-Date).AddSeconds($Seconds)
                    while ($End -gt (Get-Date)) {
                        $SecondsLeft = [Math]::Max(0, $End.Subtract((Get-Date)).TotalSeconds)
                        $Percent = ($Seconds - $SecondsLeft) / $Seconds * 100
                        Write-Progress -Activity "Discovery Protocol Packet Capture" -Status "Capturing on $Computer..." -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                        [System.Threading.Thread]::Sleep(500)
                    }

                    Stop-NetEventSession -Name $SessionName @CimSession -ErrorAction Stop
                    $SessionRunning = $false

                    $Events = Invoke-Command @PSSession -ErrorAction Stop -ScriptBlock {
                        param(
                            $ETLFilePath
                        )

                        try {
                            $Events = Get-WinEvent -Path $ETLFilePath -Oldest -FilterXPath "*[System[EventID=1001]]" -ErrorAction Stop
                        }
                        catch {
                            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                                throw
                            }
                        }

                        [string[]]$XpathQueries = @(
                            "Event/EventData/Data[@Name='FragmentSize']"
                            "Event/EventData/Data[@Name='Fragment']"
                            "Event/EventData/Data[@Name='MiniportIfIndex']"
                        )

                        $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($XpathQueries)

                        try {
                            $AdapterByIndex = @{}
                            foreach ($Adapter in (Get-NetAdapter -ErrorAction Stop)) { $AdapterByIndex[$Adapter.InterfaceIndex] = $Adapter }
                            foreach ($WinEvent in $Events) {
                                $FragmentSize, $Fragment, $MiniportIfIndex = $WinEvent.GetPropertyValues($PropertySelector)
                                $Adapter = $AdapterByIndex[[int]$MiniportIfIndex]
                                [pscustomobject]@{
                                    MachineName = $WinEvent.MachineName
                                    TimeCreated = $WinEvent.TimeCreated
                                    FragmentSize = $FragmentSize
                                    Fragment = $Fragment
                                    MiniportIfIndex = $MiniportIfIndex
                                    Connection = $Adapter.Name
                                    Interface = $Adapter.InterfaceDescription
                                }
                            }
                        } finally { $PropertySelector.Dispose() }
                    } -ArgumentList $ETLFilePath

                    $Candidates = $Events -as [DiscoveryProtocolPacket[]] | Where-Object {
                        $_.IsDiscoveryProtocolPacket -and $_.SourceAddress -notin $MACAddresses
                    }
                    if ($SwitchOnly) {
                        $MatchingPackets = foreach ($Candidate in $Candidates) {
                            if ($Type -and $Candidate.DiscoveryProtocolType -ne $Type) { continue }
                            try {
                                $Data = switch ($Candidate.DiscoveryProtocolType) {
                                    'CDP' { ConvertFrom-CDPPacket -Packet $Candidate.Fragment }
                                    'LLDP' { ConvertFrom-LLDPPacket -Packet $Candidate.Fragment }
                                }
                                if ($Data.Capabilities.IsSwitch) { $Candidate }
                            } catch [System.IO.InvalidDataException] {
                                Write-Verbose "Skipping malformed $($Candidate.DiscoveryProtocolType) frame from $($Candidate.SourceAddress) on interface $($Candidate.MiniportIfIndex): $($_.Exception.Message)"
                            }
                        }
                        $FoundPackets = $MatchingPackets | Group-Object MiniportIfIndex, DiscoveryProtocolType, SourceAddress | ForEach-Object {
                            $_.Group | Select-Object -First 1
                        }
                    } else {
                        $FoundPackets = $Candidates | Group-Object MiniportIfIndex | ForEach-Object {
                            $_.Group | Select-Object -First 1
                        }
                    }

                    if ($FoundPackets) {
                        $FoundPackets
                    }
                    else {
                        if ($SwitchOnly) {
                            Write-Warning "No discovery protocol packets matching SwitchOnly captured on $Computer in $Seconds seconds."
                        } else {
                            Write-Warning "No discovery protocol packets captured on $Computer in $Seconds seconds."
                        }
                        continue
                    }
                }
                else {
                    Write-Warning "Unable to find a connected wired adapter on $Computer."
                    continue
                }
            } catch {
                Write-Error -ErrorRecord $_
            } finally {
                Write-Progress -Activity 'Discovery Protocol Packet Capture' -Completed
                if ($SessionRunning) {
                    try { Stop-NetEventSession -Name $SessionName @CimSession -ErrorAction Stop }
                    catch { Write-Warning "Capture stop failed on ${Computer}: $_" }
                }
                if ($SessionCreated) {
                    try { Remove-NetEventSession -Name $SessionName @CimSession -ErrorAction Stop }
                    catch { Write-Warning "Capture cleanup failed on ${Computer}: $_" }
                }
                if ($ETLFilePath -and -not $NoCleanup) {
                    try {
                        Invoke-Command @PSSession -ErrorAction Stop -ScriptBlock {
                            param($Path)
                            if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop }
                        } -ArgumentList $ETLFilePath
                    } catch { Write-Warning "ETL cleanup failed on ${Computer}: $_" }
                }
                if ($PSSession.ContainsKey('Session')) {
                    try { Remove-PSSession @PSSession -ErrorAction Stop }
                    catch { Write-Warning "PSSession cleanup failed on ${Computer}: $_" }
                }
                if ($CimSession.ContainsKey('CimSession')) {
                    try { Remove-CimSession @CimSession -ErrorAction Stop }
                    catch { Write-Warning "CimSession cleanup failed on ${Computer}: $_" }
                }
            }
        }
    }

}
