# Unauthorized Network Scanning Tool Execution

| | |
|---|---|
| **Platform** | Microsoft Defender XDR / Microsoft Sentinel |
| **Data source** | `DeviceProcessEvents` |
| **Severity** | High |
| **MITRE ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) |

## Objective

Detect execution of network reconnaissance and scanning tools on endpoints outside approved scanning systems. Network discovery and port-scanning tools such as Nmap are commonly used by administrators and security teams, but they may also be leveraged by threat actors during the reconnaissance phase of an attack to identify hosts, open ports and available services.

## Description

This detection identifies execution of common network scanning tools on endpoints that are not part of approved scanning systems.

Execution of network discovery tools outside approved systems may indicate unauthorized security testing, network reconnaissance or malicious discovery behavior, and should therefore be investigated.

### Design decisions

During development, multiple behavior-based approaches were evaluated, including identifying hosts that communicated with unusually high numbers of unique IP addresses or destination ports within short time intervals. Validation testing showed that these threshold-based approaches generated a high number of benign matches and excessive alert volume.

The final detection is therefore based on execution of known scanning tools outside approved scanning systems, which gives significantly better precision and a higher expected true-positive ratio.

## Query

```kql
let ScannerNames = dynamic([                    // Common network discovery and scanning tools
    // Windows
    "nmap.exe",
    "masscan.exe",
    "advanced_ip_scanner.exe",
    "angryipscanner.exe",
    "rustscan.exe",
    "netscan.exe",                              // SoftPerfect Network Scanner
    "nbtscan.exe",
    // Linux / macOS
    "nmap",
    "masscan",
    "rustscan",
    "ipscan",                                   // Angry IP Scanner
    "zmap",
    "arp-scan",
    "netdiscover",
    "nbtscan"
]);
DeviceProcessEvents
| where Timestamp > ago(30d)                    // Last 30 days
| where FileName in~ (ScannerNames)
    or ProcessVersionInfoOriginalFileName in~ (ScannerNames)  // Also catch renamed Windows binaries
| where DeviceName !in~ (
    "<EXCLUDE APPROVED SYSTEMS HERE>"
  )                                             // Exclude approved scanning and testing systems
| project
    Timestamp,
    ReportId,                                   // Required for custom detection rules
    DeviceId,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessVersionInfoOriginalFileName,
    ProcessCommandLine,
    FolderPath,
    SHA1                                        // Investigation context
```

> **Placeholder:** replace `<EXCLUDE APPROVED SYSTEMS HERE>` with the device names of your approved scanning systems.

## Additional hunting queries

These queries reuse the same `ScannerNames` list (copy the `let` statement above the query) and are meant for hunting, not for alerting.

### Scanning activity across multiple devices

Finds accounts that have run scanning tools on more than one device, which may indicate an attacker moving laterally and repeating reconnaissance.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (ScannerNames)
    or ProcessVersionInfoOriginalFileName in~ (ScannerNames)
| summarize
    DeviceCount = dcount(DeviceId),
    Devices = make_set(DeviceName, 50),
    Tools = make_set(FileName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by InitiatingProcessAccountName
| where DeviceCount > 1                         // Same account, several devices
| order by DeviceCount desc
```

### Scanning activity trend over time

Shows how often scanning tools are executed per day, which helps establish a baseline and spot unusual spikes.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (ScannerNames)
    or ProcessVersionInfoOriginalFileName in~ (ScannerNames)
| summarize Executions = count() by bin(Timestamp, 1d), Tool = tolower(FileName)
| render timechart
```

## Watchlist recommendation

Consider replacing the hardcoded exclusions with a Watchlist to improve maintainability and scalability.

## Investigation guidance

- Verify whether the device belongs to an approved scanning system.
- Validate the initiating user and process chain.
- Confirm whether an authorized assessment was scheduled.

## Known limitations

- Renamed binaries are caught through `ProcessVersionInfoOriginalFileName`, but that field only exists for Windows executables with version information. Renamed binaries on Linux and macOS are not detected.
- Linux and macOS coverage requires those endpoints to be onboarded to Microsoft Defender for Endpoint, since process events are only collected from onboarded devices.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery |

## Results

Validation testing showed that restricting alerts to scanning tool executions outside approved scanning systems significantly reduced noise compared to behavior-based network activity detections.

This approach gives reliable detection of potentially unauthorized network reconnaissance while keeping a high expected signal-to-noise ratio and minimizing benign alerts.

## Future enhancements

- Replace static exclusions with a Watchlist.
- Correlate scanning activity with authentication, process and network telemetry.
- Build reporting and dashboards for network reconnaissance detections.
- Add risk-based enrichment using device exposure and asset criticality.
- Integrate automated response actions for unauthorized scanning activity.

### Implemented

- ~~Detect renamed binaries by also matching `ProcessVersionInfoOriginalFileName`.~~
- ~~Expand coverage to additional network discovery and enumeration tools~~ (Linux/macOS, SoftPerfect Network Scanner, nbtscan).
- ~~Identify repeated scanning activity across multiple devices~~ (see Additional hunting queries).
- ~~Track scanning activity trends and frequency over time~~ (see Additional hunting queries).
