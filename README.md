![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/PSDiscoveryProtocol?color=808000&logo=powershell&logoColor=lightgrey&style=flat-square)
![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSDiscoveryProtocol?color=808000&style=flat-square)
![GitHub](https://img.shields.io/github/license/lahell/PSDiscoveryProtocol?color=808000&style=flat-square)
## PSDiscoveryProtocol

Capture and parse CDP and LLDP packets on local or remote computers

Capture returns the first matching neighbor frame on each connected wired interface, excluding frames sent by the capturing computer. With `-SwitchOnly`, it returns the first matching frame per interface, protocol and source MAC address instead. A failed computer does not prevent processing later computers unless `-ErrorAction Stop` is requested. `-NoCleanup` retains the ETL file, whose path is shown with `-Verbose`.

### Discover neighbors advertising switching

```PowerShell
Invoke-DiscoveryProtocolCapture -SwitchOnly | Get-DiscoveryProtocolData
```

Omitting `-Type` captures CDP and LLDP simultaneously for 62 seconds. `-SwitchOnly` requires the CDP Switch flag (`0x00000008`) or the enabled LLDP Bridge flag (`0x0004`). Announcements without Capabilities are excluded; malformed candidates are skipped with `-Verbose` diagnostics. Both protocols remain separate, and repeated announcements are removed per interface, protocol and source MAC address. Use `-Type CDP` or `-Type LLDP` to restrict the protocol.

The parsed output includes `Capabilities` when the corresponding TLV is present:

| Property | Meaning |
| --- | --- |
| `Supported` | Advertised capability mask as `uint32`, using the originating protocol's bit definitions. |
| `Enabled` | Active LLDP capability mask as `uint32`; `$null` for CDP. |
| `IsSwitch` | Boolean indicating the CDP Switch flag or enabled LLDP Bridge flag. |

Capabilities describe the sender's advertised role. They do not prove physical topology or identify a particular access switch; software bridges and other devices advertising switching can also match. CDP and LLDP results are not merged into one device.

### Development and tests

The root module defines `DiscoveryProtocolPacket` and explicitly loads commands from `Public` and helpers from `Private`. The manifest defines the public exports. Runtime compatibility remains Windows PowerShell 5.1 and PowerShell 7 on Windows.

Run `Invoke-Pester ./Tests` from the repository root with Pester 3.4 or 4.x in each PowerShell edition. Unit tests construct Ethernet frames and mock capture operations; they do not require elevation or a discovery-enabled network. The live capture tests are skipped by default.

To run the live CDP and LLDP tests, use an elevated PowerShell on a wired network advertising both protocols and run `./Run-IntegrationTests.ps1`. The script enables live capture, runs the tests using Pester 3.4 or 4.x, and restores the original environment variable afterward, including on failure. The tests use the normal 62/32 second capture durations. A separate `SwitchOnly` test captures for 62 seconds and requires at least one neighbor advertising switching through either protocol; it does not require both protocols to be present. The script reports an error if any test fails. See [CHANGELOG.md](CHANGELOG.md) for parsing and error-handling changes.

### CDP and LLDP
PSDiscoveryProtocol does not return all information available in CDP and LLDP packets. If you want to know what information is available use `Export-Pcap` and open the pcap file in Wireshark or another tool with a more complete implementation.

### Installation

```PowerShell
Install-Module -Name PSDiscoveryProtocol
```

### Active Directory inventory

The standalone `Invoke-ComputerInventory.ps1` script updates the computer object's Active Directory inventory attributes. Run it elevated under an account with the required AD write permissions, with the complete `PSDiscoveryProtocol` folder beside the script. It captures both protocols with `-SwitchOnly`, limits results to the selected primary adapter, prefers LLDP and ignores CDP neighbors when LLDP is present. CDP is used only when LLDP is absent and identifies exactly one neighbor. Multiple LLDP neighbors or, without LLDP, multiple CDP neighbors leave existing switch attributes unchanged. This avoids forwarded CDP announcements overriding the local LLDP neighbor. Once a neighbor is selected, missing, empty or unsupported values explicitly clear the corresponding managed switch LDAP attributes (1-11). Discovery failure or ambiguous neighbors still leave the switch inventory unchanged. Switch address lists are stored separated by `; `, and attribute 8 stores the numeric capability mask of the selected protocol. The source protocol is logged. Review these attribute mappings before deploying the scheduled task.

### SCCM Hardware Inventory
PSDiscoveryProtocol can add port information to SCCM Hardware Inventory on your Windows 10 clients.

Take a look here for details: [PSDiscoveryProtocol-SCCM-HWInventory](https://github.com/lahell/PSDiscoveryProtocol-SCCM-HWInventory)

### Usage
On this page you will find a few examples of how to use this module.

For more examples please read help:
```PowerShell
Get-Help -Name Invoke-DiscoveryProtocolCapture -Full
Get-Help -Name Get-DiscoveryProtocolData -Full
Get-Help -Name Export-Pcap -Full
```

### Capture and parse LLDP on local computer

```PowerShell
$Packet = Invoke-DiscoveryProtocolCapture -Type LLDP
Get-DiscoveryProtocolData -Packet $Packet
```

#### Output
```
Model       : WS-C2960-48TT-L
Description : HR Workstation
VLAN        : 10
Port        : Fa0/1
Device      : SWITCH1.domain.example
IPAddress   : 192.0.2.10
Computer    : COMPUTER1.domain.example
Type        : LLDP
```

### Capture and parse CDP on remote computers

```PowerShell
'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture -Type CDP | Get-DiscoveryProtocolData
```

#### Output
```
Port      : FastEthernet0/1
Device    : SWITCH1.domain.example
Model     : cisco WS-C2960-48TT-L
IPAddress : 192.0.2.10
VLAN      : 10
Computer  : COMPUTER1.domain.example
Type      : CDP

Port      : FastEthernet0/2
Device    : SWITCH1.domain.example
Model     : cisco WS-C2960-48TT-L
IPAddress : 192.0.2.10
VLAN      : 20
Computer  : COMPUTER2.domain.example
Type      : CDP
```

### Capture on remote computers and export to pcap

```PowerShell
'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Export-Pcap -Path packets.pcap
```

### Speed up capturing in PowerShell 7

By leveraging the new `-Parallel` parameter on `ForEach-Object` we can capture simultaneously on multiple computers.

```PowerShell
#Requires -Version 7
'COMPUTER1', 'COMPUTER2', 'COMPUTER3' | ForEach-Object -Parallel {
    Invoke-DiscoveryProtocolCapture -ComputerName $_ | Get-DiscoveryProtocolData
}
```
