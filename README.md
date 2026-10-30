# KQL Custom Detections

A collection of custom detection rules written in **KQL** for **Microsoft Defender XDR** and **Microsoft Sentinel**.

The rules were built and validated during an internship in a SecOps team. All organization-specific details (device groups, device names, thresholds, approved values) have been replaced with generic placeholders such as `<SERVER-GROUP>`, so the rules can be adapted to any environment.

## Detections

| Detection | Data sources | Severity | MITRE ATT&CK |
|---|---|---|---|
| [Suspicious Scheduled Task Creation Using PowerShell](detections/suspicious-powershell-scheduled-task.md) | DeviceProcessEvents | Medium | T1053.005, T1059.001 |
| [Unauthorized Network Scanning Tool Execution](detections/unauthorized-network-scanner.md) | DeviceProcessEvents | High | T1046 |
| [Mass Upload of Business Documents to Unsanctioned AI Services](detections/mass-upload-unsanctioned-ai.md) | CloudAppEvents, IdentityInfo, DeviceFileEvents | Medium | T1567, T1020 |
| [Server Sensor Health State Changed From Active](detections/server-sensor-health-state.md) | DeviceInfo | – | T1562, T1562.001 |
| [Endpoint Antivirus Baseline Deviation Detected](detections/av-baseline-deviation.md) | DeviceInfo, DeviceTvmInfoGathering | – | T1562, T1562.001 |

## Structure of each rule

Each detection file follows the same format, with sections included where applicable:

- **Objective**: what the rule is meant to catch and why it matters
- **Description**: how it works
- **Query**: the KQL, commented line by line
- **Investigation guidance**: what an analyst should check when it fires
- **Known limitations**: what the rule does not cover
- **MITRE ATT&CK**: mapped techniques
- **Results**: what validation testing showed
- **Future enhancements**: planned improvements

## How to use

1. Open **Advanced hunting** in Microsoft Defender XDR (or Logs in Microsoft Sentinel).
2. Paste the query and replace the `<PLACEHOLDERS>` with values from your environment.
3. Run it as a hunting query first and tune it against your own baseline.
4. When the results look right, save it as a **custom detection rule** and choose frequency, severity and response actions.

> Table and column availability can differ depending on licensing and which Defender products are deployed. Always validate in your own tenant before production use.

## Disclaimer

These rules are provided as-is for educational and portfolio purposes. Test and tune them before using them in a production environment.
