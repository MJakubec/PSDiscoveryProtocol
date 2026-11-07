Import-Module "$PSScriptRoot/../PSDiscoveryProtocol/PSDiscoveryProtocol.psd1" -Force

InModuleScope PSDiscoveryProtocol {
    Describe 'Capture resource ownership' {
        BeforeEach {
            $script:FailAt = ''
            $script:Clock = 0
            $script:CleanupCount = 0
            $script:NoAdapters = $false
            $script:CapturedEvents = @()
            # Typed but disconnected objects satisfy the original cmdlet parameter validators.
            $script:FakeCim = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([Microsoft.Management.Infrastructure.CimSession])
            $script:FakePS = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([System.Management.Automation.Runspaces.PSSession])
            Mock New-CimSession { if ($script:FailAt -eq 'Cim') { throw 'Cim failure' }; $script:FakeCim }
            Mock New-PSSession { if ($script:FailAt -eq 'PS') { throw 'PS failure' }; $script:FakePS }
            Mock Remove-CimSession {}
            Mock Remove-PSSession {}
            Mock Get-NetAdapter {
                if ($script:FailAt -eq 'Adapters') { throw 'Adapter failure' }
                if (-not $script:NoAdapters) {
                    [pscustomobject]@{ Status = 'Up'; InterfaceType = 6; Name = 'Ethernet'; MacAddress = '00-11-22-33-44-55'; InterfaceDescription = 'Adapter'; InterfaceIndex = 1 }
                }
            }
            Mock New-NetEventSession { if ($script:FailAt -eq 'Create') { throw 'Create failure' } }
            Mock Add-NetEventPacketCaptureProvider { if ($script:FailAt -eq 'Provider') { throw 'Provider failure' } }
            Mock Add-NetEventNetworkAdapter { if ($script:FailAt -eq 'Adapter') { throw 'Adapter configuration failure' } }
            Mock Start-NetEventSession { if ($script:FailAt -eq 'Start') { throw 'Start failure' } }
            Mock Stop-NetEventSession { if ($script:FailAt -eq 'Stop') { throw 'Stop failure' } }
            Mock Remove-NetEventSession { if ($script:FailAt -eq 'Cleanup') { throw 'Cleanup failure' } }
            Mock Write-Progress {}
            Mock Get-Date { $script:Clock++; ([datetime]'2026-01-01').AddDays($script:Clock) }
            Mock Invoke-Command {
                if ($ScriptBlock.ToString() -match 'GetTempPath') {
                    if ($script:FailAt -eq 'Temp') { throw 'Temp failure' }
                    return 'capture.etl'
                }
                if ($ScriptBlock.ToString() -match 'Get-WinEvent') {
                    if ($script:FailAt -eq 'Read') { throw 'Read failure' }
                    return $script:CapturedEvents
                }
                $script:CleanupCount++
                if ($script:FailAt -eq 'Delete') { throw 'Delete failure' }
            }
        }

        It 'closes a CIM session when PSSession creation fails' {
            $script:FailAt = 'PS'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 0 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 0 -Exactly
        }
        It 'does not remove resources that were never acquired' {
            $script:FailAt = 'Cim'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-CimSession -Times 0 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 0 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 0 -Exactly
        }
        It 'closes remote sessions when temporary path creation fails' {
            $script:FailAt = 'Temp'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 0
        }
        It 'cleans the ETL path when adapter discovery fails' {
            $script:FailAt = 'Adapters'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            $script:CleanupCount | Should Be 1
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 0 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
        }
        It 'does not remove another capture session after creation fails' {
            $script:FailAt = 'Create'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 0 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'removes its session when provider configuration fails' {
            $script:FailAt = 'Provider'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Stop-NetEventSession -Times 0 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'removes its session when adapter configuration fails' {
            $script:FailAt = 'Adapter'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'attempts to stop a session even when starting fails' {
            $script:FailAt = 'Start'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Stop-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
        }
        It 'retries stopping in finally and still removes other resources' {
            $script:FailAt = 'Stop'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Assert-MockCalled -Scope It Stop-NetEventSession -Times 2 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
        }
        It 'cleans up when ETL reading fails' {
            $script:FailAt = 'Read'
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It Stop-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'continues cleanup when session removal fails' {
            $script:FailAt = 'Cleanup'
            Invoke-DiscoveryProtocolCapture -ComputerName server -WarningAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'continues cleanup when ETL deletion fails' {
            $script:FailAt = 'Delete'
            Invoke-DiscoveryProtocolCapture -ComputerName server -WarningAction SilentlyContinue
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
        }
        It 'retains the ETL file with NoCleanup while closing sessions' {
            Invoke-DiscoveryProtocolCapture -ComputerName server -NoCleanup -WarningAction SilentlyContinue
            $script:CleanupCount | Should Be 0
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
        }
        It 'continues after a computer has no connected adapters' {
            $script:NoAdapters = $true
            Invoke-DiscoveryProtocolCapture -ComputerName first,second -WarningAction SilentlyContinue
            Assert-MockCalled -Scope It New-CimSession -Times 2 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 2 -Exactly
            $script:CleanupCount | Should Be 2
        }
        It 'continues after no packets were found and completes progress' {
            Invoke-DiscoveryProtocolCapture -ComputerName first,second -WarningAction SilentlyContinue
            Assert-MockCalled -Scope It New-CimSession -Times 2 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 2 -Exactly
            Assert-MockCalled -Scope It Write-Progress -Times 2 -Exactly -ParameterFilter { $Completed }
        }
        It 'excludes local source addresses and selects the first neighbor per interface' {
            $Frame = [byte[]]@(1,128,194,0,0,14,0,17,34,51,68,85,136,204,0,0)
            $Local = [pscustomobject]@{ MachineName = 'server'; TimeCreated = [datetime]'2026-01-01'; FragmentSize = 16; Fragment = $Frame.Clone(); MiniportIfIndex = 1; Connection = 'Ethernet'; Interface = 'Adapter' }
            $Frame[11] = 102
            $First = [pscustomobject]@{ MachineName = 'server'; TimeCreated = [datetime]'2026-01-01'; FragmentSize = 16; Fragment = $Frame.Clone(); MiniportIfIndex = 1; Connection = 'Ethernet'; Interface = 'Adapter' }
            $Frame[11] = 103
            $Second = [pscustomobject]@{ MachineName = 'server'; TimeCreated = [datetime]'2026-01-01'; FragmentSize = 16; Fragment = $Frame.Clone(); MiniportIfIndex = 1; Connection = 'Ethernet'; Interface = 'Adapter' }
            $Other = [pscustomobject]@{ MachineName = 'server'; TimeCreated = [datetime]'2026-01-01'; FragmentSize = 16; Fragment = $Frame.Clone(); MiniportIfIndex = 2; Connection = 'Ethernet2'; Interface = 'Adapter2' }
            $script:CapturedEvents = @($Local, $First, $Second, $Other)
            $Packets = @(Invoke-DiscoveryProtocolCapture -ComputerName server)
            $Packets.Count | Should Be 2
            $Packets[0].SourceAddress | Should Be '001122334466'
            $Packets[1].MiniportIfIndex | Should Be 2
        }
        It 'reports cleanup failure separately from the original error' {
            $script:FailAt = 'Provider'
            Mock Remove-NetEventSession { throw 'Cleanup also failed' }
            Invoke-DiscoveryProtocolCapture -ComputerName server -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -ErrorVariable CaptureErrors -WarningVariable CleanupWarnings
            @($CaptureErrors | Where-Object { $_.Exception.Message -eq 'Provider failure' }).Count | Should BeGreaterThan 0
            ($CleanupWarnings -join ' ') | Should Match 'Cleanup also failed'
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
        }
        It 'continues after a per-computer failure' {
            $script:FailAt = 'Provider'
            Invoke-DiscoveryProtocolCapture -ComputerName first,second -ErrorAction SilentlyContinue
            Assert-MockCalled -Scope It New-CimSession -Times 2 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 2 -Exactly
        }
        It 'honors ErrorAction Stop after cleaning owned resources' {
            $script:FailAt = 'Provider'
            { Invoke-DiscoveryProtocolCapture -ComputerName first,second -ErrorAction Stop } | Should Throw 'Provider failure'
            Assert-MockCalled -Scope It New-CimSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-NetEventSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-PSSession -Times 1 -Exactly
            Assert-MockCalled -Scope It Remove-CimSession -Times 1 -Exactly
            $script:CleanupCount | Should Be 1
        }
        It 'uses the LLDP alias default after resolving the alias' {
            Capture-LLDPPacket -ComputerName server -WarningVariable Warnings -WarningAction SilentlyContinue
            ($Warnings -join ' ') | Should Match 'in 32 seconds'
            Assert-MockCalled -Scope It Add-NetEventPacketCaptureProvider -Times 1 -ParameterFilter { $LinkLayerAddress.Count -eq 3 }
        }
        It 'preserves explicit alias duration and CDP default duration' {
            Capture-LLDPPacket -ComputerName server -Duration 9 -WarningVariable Warnings -WarningAction SilentlyContinue
            ($Warnings -join ' ') | Should Match 'in 9 seconds'
            Invoke-DiscoveryProtocolCapture -ComputerName server -WarningVariable Warnings -WarningAction SilentlyContinue
            ($Warnings -join ' ') | Should Match 'in 62 seconds'
        }
        It 'rejects nonpositive durations before acquiring resources' {
            { Invoke-DiscoveryProtocolCapture -ComputerName server -Duration 0 } | Should Throw
            { Invoke-DiscoveryProtocolCapture -ComputerName server -Duration -1 } | Should Throw
            Assert-MockCalled -Scope It New-CimSession -Times 0 -Exactly
        }
    }
}
