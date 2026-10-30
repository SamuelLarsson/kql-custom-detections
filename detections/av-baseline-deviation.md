# Endpoint Antivirus Baseline Deviation Detected

| | |
|---|---|
| **Platform** | Microsoft Defender for Endpoint / Microsoft Sentinel |
| **Data sources** | `DeviceInfo`, `DeviceTvmInfoGathering` |
| **MITRE ATT&CK** | [T1562](https://attack.mitre.org/techniques/T1562/) · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |

## Objective

Detect managed servers operating outside an approved Microsoft Defender Antivirus configuration baseline.

Endpoints are expected to run in approved antivirus modes defined by organizational security policy. Any deviation may indicate configuration drift, unauthorized changes, deployment issues, loss of telemetry or impairment of endpoint protection controls.

This detection continuously monitors antivirus operational state and helps identify devices that no longer comply with the required security baseline.

Potential causes include:

- Unauthorized configuration changes
- Configuration drift
- Accidental policy deployment
- Security tooling misconfiguration
- Loss of endpoint telemetry
- Security control tampering

## Description

This detection continuously validates the current Microsoft Defender Antivirus operating mode on monitored devices.

Rather than detecting a state transition, it evaluates the latest reported antivirus state and compares it against an approved baseline. Devices reporting a state outside the baseline generate an alert for investigation.

Device inventory information is joined in to give context and improve investigation quality.

## Detection logic

**Expected state:** the device reports an approved antivirus operating mode according to the defined security baseline.

**Alert when:**

- the device reports a non-approved antivirus operating mode
- antivirus is disabled
- telemetry is incomplete or unavailable
- an unexpected antivirus state is observed

Primary telemetry source: `parse_json(AdditionalFields).AvMode`

| AvMode | Meaning |
|---|---|
| `0` | Active AV |
| `1` | Passive AV |
| `2` | Disabled |
| `4` | EDR Block Mode |
| `5` | Passive Audit |
| *(empty)* | Unknown |

## Query

```kql
let ExcludedDevices = dynamic([
    "<EXCLUDED DEVICE>"
]);                                                     // Excluded devices
let DeviceInventory =
    DeviceInfo
    | where MachineGroup == "<SERVER-GROUP>"            // Target server group
    | summarize arg_max(Timestamp, *) by DeviceId
    | project
        DeviceId,
        MachineGroup,
        RegistryDeviceTag,
        OSPlatform,
        OSVersion,
        PublicIP,
        ExposureLevel,
        OnboardingStatus,
        SensorHealthState,
        ClientVersion,
        LoggedOnUsers,
        ReportId;                                       // Required for custom detection rules
DeviceTvmInfoGathering
| summarize arg_max(Timestamp, *) by DeviceId           // Latest AV status
| extend AF = parse_json(AdditionalFields)
| extend AvMode = tostring(AF.AvMode)                   // Extract AV mode
| where DeviceId !in (ExcludedDevices)                  // Exclusions
| join kind=inner DeviceInventory on DeviceId           // Device enrichment
| extend LastLoggedOnUser = tostring(parse_json(LoggedOnUsers)[0].UserName)  // Latest logged on user
| extend AvModeDescription =
    case(
        AvMode == "0", "Active AV",
        AvMode == "1", "Passive AV",
        AvMode == "2", "Disabled",
        AvMode == "4", "EDR Block Mode",
        AvMode == "5", "Passive Audit",
        isempty(AvMode), "Unknown",
        "Unexpected value"
    )
| where AvMode !in ("<APPROVED-MODES>") or isempty(AvMode)  // Approved modes
| project
    Timestamp,
    ReportId,
    DeviceId,
    DeviceName,
    AvMode,
    AvModeDescription,
    LastLoggedOnUser,
    SensorHealthState,
    MachineGroup,
    RegistryDeviceTag,
    OSPlatform,
    OSVersion,
    PublicIP,
    ClientVersion,
    ExposureLevel,
    OnboardingStatus
| order by Timestamp desc
```

> **Placeholders:**
> - `<SERVER-GROUP>`: the device group to monitor
> - `<EXCLUDED DEVICE>`: device IDs to exclude
> - `<APPROVED-MODES>`: the AvMode values your baseline allows, e.g. `"0", "4"`

## Investigation context

The query returns device name and ID, current antivirus mode and description, last logged-on user, sensor health, device group, OS platform and version, public IP address, Defender client version, exposure level and onboarding status, so analysts can quickly identify devices outside the expected baseline.

The detection can be applied to server and workstation environments, Windows and Linux devices, and newly onboarded environments.

## Investigation guidance

1. Verify that the device is within the intended monitoring scope.
2. Open the device record in Microsoft Defender.
3. Review device health and current antivirus status.
4. Determine whether recent maintenance could explain the deviation.
5. Review endpoint security configuration.
6. Investigate recent policy deployments.
7. Validate expected antivirus behavior.
8. Confirm telemetry is being reported correctly.
9. Engage device owners if configuration drift is identified.
10. Determine whether the deviation could indicate tampering with security controls.

## Known limitations

- The inner join means devices that have no record in `DeviceTvmInfoGathering` at all are not evaluated. Telemetry that is completely missing is therefore not detected, only an empty `AvMode` value.
- AvMode values not listed in the table are labelled `Unexpected value` and alert unless they are added to the approved modes.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Security Tools |

**Rationale:** Threat actors may attempt to alter, disable or interfere with endpoint security controls to reduce visibility and evade detection. Changes to antivirus operating state can affect monitoring, protection and overall security posture.

## Results

Devices operating outside the approved antivirus baseline are identified and enriched with additional device telemetry to support investigation and response.

## Future enhancements

1. Expand monitoring coverage to additional device groups.
2. Add compliance reporting and a baseline compliance dashboard showing approved versus non-approved AV modes, including long-term trends.
3. Correlate deviations with configuration change events and policy deployment telemetry.
4. Improve exception and exclusion management.
5. Monitor newly onboarded device populations.
6. Add automated remediation opportunities.
