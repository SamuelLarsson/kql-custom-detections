# Mass Upload of Business Documents to Unsanctioned AI Services

| | |
|---|---|
| **Platform** | Microsoft Defender XDR / Microsoft Sentinel |
| **Data sources** | `CloudAppEvents`, `IdentityInfo`, `DeviceFileEvents` (add-on hunt) |
| **Severity** | Medium |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) · [T1020](https://attack.mitre.org/techniques/T1020/) |

## Objective

Detect users who upload an unusually high number of business documents to external generative AI services within a short period of time.

Generative AI platforms such as ChatGPT, Gemini, Claude and DeepSeek allow users to upload documents for analysis and content generation. While these services can improve productivity, they can also introduce data leakage risks if employees upload large quantities of internal company information.

This detection aims to identify potential exfiltration of corporate data through unsanctioned AI services by detecting excessive document upload activity that deviates from normal user behavior.

It is especially valuable if Microsoft Purview controls are not yet fully deployed, or if the organization has previously experienced Shadow AI related incidents.

## Description

This detection identifies users who upload an unusually high number of business-related documents to unsanctioned generative AI services within a one-hour period.

Rather than alerting on individual uploads, the detection focuses on bulk upload behavior, which may indicate accidental data exposure, misuse of AI services, insider threats or attempts to exfiltrate corporate information.

## Query

```kql
let TimeWindow = 1h;                    // Time window being analysed
let Threshold = <UPLOAD THRESHOLD>;     // Least amount of files to generate an alert
let AIDomains = dynamic([               // List of AI services being monitored
    "chat.openai.com",
    "chatgpt.com",
    "openai.com",
    "gemini.google.com",
    "claude.ai",
    "claude.com",
    "deepseek.com",
    "deepseekv3.com",
    "deep-seek.chat",
    "deep-seek.ai",
    "chat.qwen.ai",
    "qwen.ai",
    "qwenlm.ai"
]);
CloudAppEvents
| where Timestamp > ago(TimeWindow)                                   // Only look at events in this time window
| where ActionType in ("FileUploadedToCloud", "FileUploaded", "FileUpload", "UploadFile")  // File upload related activities
| extend Raw = parse_json(RawEventData)                               // Extract upload target from raw data
| extend TargetDomain = tostring(Raw.TargetDomain)
| extend TargetUrl = tostring(Raw.TargetURL)
| extend FileName = tostring(Raw.ObjectId)                            // Extract file name
| where TargetDomain has_any (AIDomains)
    or TargetUrl has_any (AIDomains)                                  // Uploads to known AI services
| summarize                                                           // Summarize per user
    UploadCount = count(),
    UploadedFiles = make_set(FileName, 100),
    ReportId = take_any(ReportId)                                     // Required for custom detection rules
    by AccountDisplayName, AccountObjectId, bin(Timestamp, 1h)
| where UploadCount >= Threshold                                      // Alert if threshold is reached
| join kind=leftouter (                                               // Add identifying data
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId              // Latest identity record per user (avoids duplicate rows)
    | project AccountObjectId, Department, Manager, AccountUpn
  ) on AccountObjectId
| project
    Timestamp,
    ReportId,
    AccountObjectId,                                                  // Entity column for the alert
    AccountDisplayName,
    AccountUpn,
    Department,
    Manager,
    UploadCount,
    UploadedFiles
```

> **Placeholder:** replace `<UPLOAD THRESHOLD>` with a number based on your own baseline of normal upload activity.

## Add-on: sensitive file name hunt

A separate hunting query, **not** correlated with the upload query above. It looks for business documents whose file names contain keywords often found in sensitive files.

```kql
// Keywords often found in sensitive file names
let SensitiveWords = dynamic([
    "salary",
    "payroll",
    "budget",
    "forecast",
    "employee",
    "hr",
    "personal",
    "customer",
    "finance",
    "invoice",
    "confidential"
]);
DeviceFileEvents
| where FileName has_any (SensitiveWords)       // Files whose names include sensitive words
| where FileName endswith ".xlsx"               // Limit to business document formats
    or FileName endswith ".xls"
    or FileName endswith ".csv"
    or FileName endswith ".docx"
    or FileName endswith ".pptx"
    or FileName endswith ".pdf"
| project                                       // Relevant fields for further analysis
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    FileName,
    FolderPath,
    SHA1
```

## Prerequisites

`CloudAppEvents` may originate from Microsoft Defender for Cloud Apps or Microsoft Defender Data Lake. Availability, retention and licensing requirements should be validated before production deployment.

## Watchlist recommendation

Maintain AI domains in a Watchlist (for example `Monitored_AI_Domains`) instead of hardcoding them in the query.

## Investigation guidance

- Determine whether the AI service is approved.
- Review uploaded file names and the business justification.
- Assess potential exposure of sensitive corporate information.

## Known limitations

- All domains in the list are treated as unsanctioned, so services approved by the organization should be excluded (for example through a Watchlist).
- Uploads are counted in fixed one-hour bins. A burst that spans an hour boundary can be split into two bins that each stay below the threshold. A longer lookback or a sliding window reduces this.
- The add-on query is a separate hunt for sensitive-looking file names. It is not joined to the upload events and will be noisy unless it is correlated by user, device and time window.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration |
