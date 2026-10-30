# Server Sensor Health State Changed From Active

| | |
|---|---|
| **Rule ID** | `alert-defenderEndpoint-sensorStateChange` |
| **Platform** | Microsoft Defender for Endpoint / Microsoft Sentinel |
| **Data source** | `DeviceInfo` |
| **MITRE ATT&CK** | [T1562](https://attack.mitre.org/techniques/T1562/) · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |

## Objective

Detect managed servers that transition from a healthy Microsoft Defender for Endpoint sensor state (`Active`) to a degraded state and have not recovered.

The purpose is to give the SOC visibility when monitoring coverage for critical assets is lost and remains unavailable. Alerts are generated only for devices whose sensor health has degraded **and is still degraded** at the time of evaluation.

This prevents alerts for devices that temporarily lose health but recover, which reduces alert fatigue and improves incident quality.

## Description

This detection identifies managed servers that transitioned from a healthy sensor state (`Active`) to any degraded sensor state and remain in that degraded state.

The detection performs two validations:

1. A historical transition from `Active` to a non-`Active` sensor state.
2. Verification that the current sensor state is still non-`Active`.

Unlike an earlier version of the rule, this logic eliminates historical transitions that have already recovered and focuses only on active monitoring visibility issues that require investigation.

Alerts are enriched with device health, operating system, onboarding state, connectivity, exposure level, public IP address, Defender client version and duration of impact.

## Detection logic

```
Sensor health changed from Active → non-Active (within lookback window)
  AND current sensor health is still non-Active
  = ALERT
```

Devices that have recovered are not alerted. The monitored server group is defined in the query and can be extended to other protected environments.

## Query

```kql
// Identify devices that transitioned from Active to a degraded state
let Transitions =
    DeviceInfo
    | where MachineGroup == "<SERVER-GROUP>"        // Target server group
    | where Timestamp > ago(1d)                     // Transition history
    | sort by DeviceName asc, Timestamp asc
    | serialize                                     // Preserve event order
    | extend PreviousState = prev(SensorHealthState),
             PreviousDevice = prev(DeviceName)
    | where DeviceName == PreviousDevice            // Same device
    | where PreviousState == "Active"               // Previously healthy
    | where SensorHealthState != "Active"           // Transition occurred
    | summarize arg_min(Timestamp, *) by DeviceId
    | project
        DeviceId,
        DeviceName,
        TransitionTime = Timestamp,
        PreviousState,
        TransitionState = SensorHealthState;
// Retrieve current device status
let CurrentStatus =
    DeviceInfo
    | where MachineGroup == "<SERVER-GROUP>"        // Target server group
    | summarize arg_max(Timestamp, *) by DeviceId
    | project
        DeviceId,
        ReportId,                                   // Required for custom detection rules
        CurrentTimestamp = Timestamp,
        CurrentState = SensorHealthState,
        MachineGroup,
        RegistryDeviceTag,
        OSPlatform,
        OSVersion,
        PublicIP,
        ClientVersion,
        ExposureLevel,
        ConnectivityType,
        OnboardingStatus;
// Only alert if device is STILL not Active
Transitions
| join kind=inner CurrentStatus on DeviceId
| where CurrentState != "Active"                    // Still unhealthy
| extend HoursImpacted = round((now() - TransitionTime) / 1h, 1)
| project
    Timestamp = CurrentTimestamp,                   // Required for custom detection rules
    ReportId,
    TransitionTime,
    CurrentTimestamp,
    DeviceId,
    DeviceName,
    PreviousState,
    CurrentState,
    HoursImpacted,
    MachineGroup,
    RegistryDeviceTag,
    OSPlatform,
    OSVersion,
    PublicIP,
    ClientVersion,
    ExposureLevel,
    ConnectivityType,
    OnboardingStatus
| order by TransitionTime desc
```

> **Placeholder:** replace `<SERVER-GROUP>` with the name of the device group you want to monitor.

## Investigation context

The query returns device name, current and previous sensor health state, timestamps, public IP address and other device metadata, so analysts can see when monitoring visibility was lost and which device was affected.

## Investigation guidance

- Verify whether the server is expected to be online.
- Confirm whether the outage is related to planned maintenance or decommissioning.
- Review the device page in Microsoft Defender for Endpoint.
- Check the device's latest communication timestamp.
- Verify that the MDE sensor service is still running.
- Review firewall, proxy or network changes that may prevent communication with Microsoft Defender.
- Determine whether the sensor interruption could be related to security tool tampering or unauthorized changes.
- Identify whether monitoring visibility for the asset has been partially or completely lost.

## Known limitations

- Transitions are only evaluated within the 1-day lookback, so the rule should run at least once per day to avoid missing a transition.
- Devices that never reported an `Active` state within the lookback window are not covered.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Security Tools |

**Rationale:** A malicious actor may attempt to disable, interfere with or otherwise impair endpoint security tooling to reduce visibility and evade detection.

## Results

During testing, the earlier version identified both active and previously recovered sensor health incidents.

The updated detection successfully excludes devices that have recovered and generates alerts only for devices that remain degraded at the time of evaluation. Validation was performed on historical sample data to verify that recovered transitions are correctly suppressed.

This significantly reduces alert noise and keeps SOC analysts focused on current monitoring visibility gaps rather than historical events.

## Future enhancements

- Expand monitoring to additional protected environments.
- Maintain approved device exclusion lists.
- Investigate EDR mode monitoring opportunities.
- Build compliance and dashboard reporting.
- Correlate AV mode deviations with Defender policy changes.
