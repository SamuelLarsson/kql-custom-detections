# Suspicious Scheduled Task Creation Using PowerShell

| | |
|---|---|
| **Platform** | Microsoft Defender XDR / Microsoft Sentinel |
| **Data source** | `DeviceProcessEvents` |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |

## Objective

Detect the creation of scheduled tasks that execute PowerShell with parameters commonly associated with stealthy or malicious behavior. Scheduled tasks are frequently abused by threat actors to establish persistence and automatically execute payloads after a reboot or at predefined times.

## Description

This detection identifies newly created scheduled tasks that launch PowerShell using parameters often seen in malicious activity, such as hidden execution, encoded commands, or bypassing PowerShell execution policies.

System accounts are excluded to reduce false positives and focus on user-initiated activity.

## Query

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)                                  // Last 30 days
| where FileName =~ "schtasks.exe"                            // Scheduled Task creation utility
| where ProcessCommandLine has "/create"                      // New scheduled task is being created
| where ProcessCommandLine has_any ("powershell", "pwsh")     // Task executes PowerShell
| where ProcessCommandLine has_any (
    "ExecutionPolicy Bypass",
    "-enc",
    "-EncodedCommand",
    "WindowStyle Hidden",
    "-w hidden"
  )                                                           // Suspicious PowerShell arguments
| where AccountName !in~ (
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE"
  )                                                           // Exclude service accounts
| project
    Timestamp,
    ReportId,                                                 // Required for custom detection rules
    DeviceId,
    DeviceName,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessParentFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    FolderPath,
    SHA1                                                      // Investigation context
```

## Investigation context

The query returns the initiating account, parent process and full command line to support analyst investigations.

## Investigation guidance

- Verify whether the account is authorized to create scheduled tasks.
- Review the parent process chain.
- Investigate (decode) any encoded PowerShell arguments.
- Determine whether the task could be used for persistence.

## Known limitations

- `SYSTEM`, `LOCAL SERVICE` and `NETWORK SERVICE` are excluded to reduce noise, so tasks created under SYSTEM (for example after privilege escalation) are not covered.
- Tasks created through the `Register-ScheduledTask` cmdlet or the Task Scheduler COM API are not covered. A complementary detection is recommended.
- Only the listed argument variants are matched. Short forms such as `-ep bypass` or `-nop` are not covered and could be added to the list.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell |

## Results

Testing demonstrated that the detection successfully identifies scheduled task creation events that invoke PowerShell using high-risk execution parameters. The results provide useful visibility into behaviors commonly associated with persistence mechanisms and automated script execution.
