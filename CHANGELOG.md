# Unreleased

- Add optional `Invoke-DiscoveryProtocolCapture -SwitchOnly` filtering by advertised CDP Switch or enabled LLDP Bridge capabilities. Omit `-Type` to capture both protocols; return the first matching announcement per interface, protocol and source MAC address. The default selection without the switch remains unchanged.
- Parse CDP Capabilities and LLDP System Capabilities into `Capabilities.Supported`, `Enabled` (null for CDP) and `IsSwitch`. Reject incorrect lengths and LLDP enabled bits absent from the supported mask; preserve the first duplicate value. Frames without Capabilities are excluded by `SwitchOnly`, and malformed candidates are skipped with verbose diagnostics.
- Add an opt-in live `SwitchOnly` integration test. Capability filtering reflects advertised roles and does not verify physical topology or access-switch identity.

- Preserve the public commands, aliases, packet class and supported output properties while separating public commands from private binary readers and TLV decoders.
- Reject malformed or truncated frames with an `InvalidDataException` containing the protocol, TLV offset and reason. Parsers emit no partial results. LLDP requires an empty EndOfLLDPDU terminator and ignores subsequent padding; CDP honors the Ethernet payload length.
- Preserve the first repeated scalar value and log duplicates with `-Verbose`. Aggregate repeated address values. Decode CDP address protocol identifiers using their declared lengths.
- Decode IEEE and CEE DCBX independently of their order, including all eight priority assignments.
- Clean up owned capture sessions, ETL files and remote connections after failures. Continue to later computers after a per-computer error, missing adapters or missing packets. `-ErrorAction Stop` still stops processing after cleanup.
- Resolve capture aliases before selecting the default duration. Require a duration of 1–32767 seconds; return the first matching frame per interface.
- Write PCAP timestamps in microseconds, use the actual captured byte count for included length, and retain FragmentSize as original length. Reject an original length smaller than the captured data.

VLAN-tagged Ethernet frames, additional TLV types and checksum validation remain outside the supported scope.
