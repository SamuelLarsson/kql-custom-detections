# Potentially Sensitive File Uploaded to External AI Service

| | |
|---|---|
| **Rule ID** | `alert-defenderCloudApps-sensitiveFileUploadToAI` |
| **Platform** | Microsoft Defender XDR / Microsoft Sentinel |
| **Data sources** | `CloudAppEvents`, `IdentityInfo` |
| **Frequency** | Every hour (1-hour lookback) |
| **MITRE ATT&CK** | [T1567](https://attack.mitre.org/techniques/T1567/) |
| **Related rule** | [Mass Upload of Business Documents to Unsanctioned AI Services](mass-upload-unsanctioned-ai.md) |

## Objective

Detect potentially sensitive files uploaded to external generative AI services, based on file names and available Microsoft Defender for Cloud Apps telemetry.

The purpose is to give the SOC visibility when a user uploads a file whose name indicates that it may contain sensitive company information, such as:

- Payroll or salary information
- Employee or HR data
- Personal information
- Customer datasets
- Credentials or secrets
- Security documentation
- Confidential commercial or strategic information

A single potentially sensitive file upload is enough to generate a detection result. Multiple matching files uploaded by the same account within the same hour are grouped into one result, which enriches the alert while reducing duplicates.

This rule complements the [mass upload rule](mass-upload-unsanctioned-ai.md): that rule looks at **how many** files are uploaded, this one looks at **what** is uploaded.

## Description

This detection identifies file uploads to monitored external AI services and compares the file name against a curated list of sensitive keywords and phrases.

The detection performs three validations:

1. The event represents a file upload.
2. The destination matches a monitored external AI service.
3. The file name contains a configured sensitive keyword.

Each result is enriched with account, department, manager, file names, matched keywords, AI services, risk tier and upload period.

### Risk tiers

Keywords are divided into two tiers. The highest matching tier decides the `RiskTier` of the result.

| Tier | Strong or potential indication of |
|---|---|
| **High** | Credentials or secrets, payroll or salary information, employee or HR data, personal identification information, customer lists or registers, detailed security information |
| **Medium** | Business plans, budgets and forecasts, pricing information, strategic documents, board material, risk assessments, specific business agreements |

## Detection logic

```
File upload event
  AND destination matches a monitored AI service
  AND file name contains a configured sensitive keyword
  = ALERT (one matching file is enough)
```

**Monitored upload activities:** `FileUploadedToCloud`, `FileUploaded`, `FileUpload`, `UploadFile`

**Monitored AI services:** OpenAI ChatGPT, Anthropic Claude, Google Gemini, DeepSeek, Qwen, Ollama

## Query

```kql
let TimeWindow = 1h;                    // Rule runs hourly. Use e.g. 30d for historical hunting/validation.
let AIDomains = dynamic([               // Monitored external AI services
    "chat.openai.com",
    "chatgpt.com",
    "openai.com",
    "api.openai.com",
    "platform.openai.com",
    "claude.ai",
    "claude.com",
    "api.anthropic.com",
    "gemini.google.com",
    "gemini.google",
    "deepseek.com",
    "deepseekv3.com",
    "deep-seek.chat",
    "deep-seek.ai",
    "chat.qwen.ai",
    "qwen.ai",
    "qwenlm.ai",
    "ollama.com"
]);
let KeywordRules = dynamic([            // Sensitive keywords with risk tier
    // NOTE: these are examples only. Replace or extend them with the terms that are
    // sensitive in your organization, in the languages your users write file names in.
    // High: credentials and secrets
    {"Keyword":"password", "RiskTier":"High"},
    {"Keyword":"api_key", "RiskTier":"High"},
    {"Keyword":"lösenord", "RiskTier":"High"},
    // High: HR, payroll and personal data
    {"Keyword":"salary", "RiskTier":"High"},
    {"Keyword":"payroll", "RiskTier":"High"},
    {"Keyword":"lön", "RiskTier":"High"},
    // High: identity and customer datasets
    {"Keyword":"passport copy", "RiskTier":"High"},
    {"Keyword":"customer list", "RiskTier":"High"},
    {"Keyword":"kundregister", "RiskTier":"High"},
    // High: detailed security information
    {"Keyword":"pentest", "RiskTier":"High"},
    {"Keyword":"vulnerability report", "RiskTier":"High"},
    {"Keyword":"firewall rules", "RiskTier":"High"},
    // Medium: confidential business information
    {"Keyword":"business plan", "RiskTier":"Medium"},
    {"Keyword":"board material", "RiskTier":"Medium"},
    {"Keyword":"budget", "RiskTier":"Medium"},
    // Medium: specific business agreements
    {"Keyword":"customer agreement", "RiskTier":"Medium"},
    {"Keyword":"supplier agreement", "RiskTier":"Medium"},
    {"Keyword":"data processing agreement", "RiskTier":"Medium"}
]);
CloudAppEvents
| where Timestamp > ago(TimeWindow)
| where ActionType in (
    "FileUploadedToCloud",
    "FileUploaded",
    "FileUpload",
    "UploadFile"
  )                                                     // File upload related activities
| extend Raw = parse_json(RawEventData)                 // Extract upload target from raw data
| extend
    TargetDomain = tolower(tostring(Raw.TargetDomain)),
    TargetUrl = tolower(tostring(Raw.TargetURL)),
    FullFilePath = tostring(Raw.ObjectId)
| extend FileName = extract(@"[^\\/]+$", 0, FullFilePath)  // File name without path
| extend FileNameLower = tolower(FileName)
| where TargetDomain has_any (AIDomains)
    or TargetUrl has_any (AIDomains)                    // Uploads to monitored AI services
| mv-apply Rule = KeywordRules to typeof(dynamic) on (  // Test the file name against every keyword
    extend
        MatchedKeyword = tostring(Rule.Keyword),
        MatchedRiskTier = tostring(Rule.RiskTier)
    | where FileNameLower contains MatchedKeyword
  )
| extend RiskRank = case(
    MatchedRiskTier == "High", 2,
    MatchedRiskTier == "Medium", 1,
    0
  )
| extend TimeBucket = bin(Timestamp, 1h)                // Group uploads per hour
| summarize
    Timestamp = max(Timestamp),
    ReportId = take_any(ReportId),                      // Required for custom detection rules
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SensitiveUploadCount = dcount(strcat(FileName, "|", TargetDomain)),
    SensitiveFiles = make_set(FileName, 100),
    MatchedKeywords = make_set(MatchedKeyword, 50),
    AIServices = make_set(TargetDomain, 20),
    ActionTypes = make_set(ActionType, 10),
    HighestRiskRank = max(RiskRank)
    by AccountObjectId, AccountDisplayName, TimeBucket
| extend RiskTier = case(
    HighestRiskRank == 2, "High",
    HighestRiskRank == 1, "Medium",
    "Unknown"
  )
| join kind=leftouter (                                 // Add identifying data
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId  // Latest identity record per user
    | project AccountObjectId, AccountUpn, Department, Manager
  ) on AccountObjectId
| sort by HighestRiskRank desc, Timestamp desc
| project
    Timestamp,
    ReportId,
    AccountObjectId,
    AccountDisplayName,
    AccountUpn,
    Department,
    Manager,
    RiskTier,
    FirstSeen,
    LastSeen,
    SensitiveUploadCount,
    SensitiveFiles,
    MatchedKeywords,
    AIServices,
    ActionTypes
```

## Investigation context

The query returns user and account information, department and manager, first and last observed upload time, number of unique sensitive files, uploaded file names, matched keywords, AI services and the highest identified risk tier.

This helps analysts see what triggered the detection, where the file was uploaded and whether the activity seems related to the user's business responsibilities.

## Investigation guidance

1. Review the file names in `SensitiveFiles`.
2. Review `MatchedKeywords` and `RiskTier`.
3. Identify the external service in `AIServices`.
4. Determine whether the file name indicates company business information or private information.
5. Review the user's department and business role.
6. Check for additional uploads by the same account.
7. Review related Microsoft Defender for Cloud Apps, Purview or DLP activity.
8. Determine whether the document is public, internal or confidential.
9. Escalate to the relevant information owner or privacy function when appropriate.
10. Do not conclude that sensitive information was exposed based only on the file name.

## Prerequisites

`CloudAppEvents` may originate from Microsoft Defender for Cloud Apps or Microsoft Defender Data Lake. Availability, retention and licensing requirements should be validated before production deployment.

## Known limitations

- The detection evaluates file names and metadata, not file contents.
- Generic file names such as `data.xlsx` may contain sensitive information without triggering the rule.
- Sensitive files may be renamed before upload.
- Information pasted directly into an AI prompt is not detected.
- A file name match does not confirm malicious activity or a policy violation.
- AI services and upload actions not included in the query are not detected.
- Keywords are matched as substrings (`contains`), so short keywords such as `lön` can also match unrelated words (for example `lönsamhet`). Review short keywords when tuning.
- The keyword list in the query is a short example list. It must be adapted to the organization's own sensitive terms and languages before use.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service |

**Rationale:** An attacker, insider or compromised user may upload company information to an external web service to move data outside the organization's controlled environment. External generative AI services can be used as upload destinations. A matching event does not establish malicious intent, but potentially sensitive files uploaded to these services require investigation.

## Results

Historical validation was performed over a 30-day review period.

The initial keyword list generated **34 grouped results**. Review showed that several were caused by:

- Private CVs and résumés
- Cover letters
- Personal travel documents
- Private housing, garage and vehicle agreements
- Incorrect substring matches from short terms such as `nda` and `dpa`

The keyword list was then tuned by removing broad terms and replacing them with more specific phrases. (The full tuned list of around 100 Swedish and English terms is not published here; the query contains a shortened example list.) The updated detection generated **8 grouped results** over the same period, a **76 % reduction**.

The remaining results were technically valid file name matches, mainly HR- and payroll-related documents and business documents such as price lists and agreements. The HR and payroll matches were clear high-interest indicators, while the business documents required contextual review to determine their actual sensitivity.

The tuning reduced alert noise while keeping the most relevant findings.

## Future enhancements

- Add relevant Norwegian, Danish and Finnish keywords.
- Continue tuning keywords using observed file names.
- Consider separate High and Medium severity rules.
- Correlate results with Purview DLP and sensitivity labels.
- Add approved services or documented workflow exceptions.
- Move the keyword list to a Watchlist if it grows large or requires shared maintenance.
- Build reporting for repeated users, departments and AI services.
