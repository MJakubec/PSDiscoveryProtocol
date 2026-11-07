#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Runs live CDP and LLDP integration tests.
.DESCRIPTION
Requires Pester 3.4 or 4.x and a wired network advertising both protocols.
Captures CDP for 62 seconds and LLDP for 32 seconds. Restores the original
PSDISCOVERY_LIVE_CAPTURE environment variable even if the tests fail.
.EXAMPLE
    .\Run-IntegrationTests.ps1
#>
[CmdletBinding()]
param()

Import-Module Pester -MinimumVersion 3.4 -MaximumVersion 4.99 -ErrorAction Stop

$OriginalLiveCapture = $env:PSDISCOVERY_LIVE_CAPTURE
try {
    $env:PSDISCOVERY_LIVE_CAPTURE = '1'
    $Result = Invoke-Pester -Script (Join-Path $PSScriptRoot 'Tests/Integration') -PassThru
    $Result
    if ($Result.FailedCount -gt 0) {
        throw "Live integration tests failed: $($Result.FailedCount) failed test(s)."
    }
}
finally {
    if ($null -eq $OriginalLiveCapture) {
        Remove-Item Env:\PSDISCOVERY_LIVE_CAPTURE -ErrorAction SilentlyContinue
    }
    else {
        $env:PSDISCOVERY_LIVE_CAPTURE = $OriginalLiveCapture
    }
}
