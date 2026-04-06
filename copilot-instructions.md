---
name: secure-boot-analysis
description: Analyze Secure Boot adoption, certificate rollout, and OEM compliance using the PI_SB_CensusExAgg_Weekly Kusto table. Use this skill when asked about Secure Boot enablement, SB certificate adoption (DB/KEK 2023 keys), OEM action needed, Copilot+ PC compliance, device census data, or any question about which OEMs or models need firmware updates. For executive summary generation, see the repeatable process at C:\AIMaker\vault\how-to\sb-exec-summary-process.md. Trigger phrases include "Secure Boot", "SB enabled", "certificate adoption", "DB 1P 2023", "KEK 1P 2023", "OEM action", "which OEMs", "which models", "Copilot+ PC", "firmware update", "PK update", "device census", "executive summary", "SB exec summary".
---

# Secure Boot Census Analysis

This skill enables natural language querying of Secure Boot device census data via Kusto (KQL).

## CRITICAL: How to Use This Skill

Translate the user's natural language question into a KQL query against the table below, execute it using the `kusto-execute_query` tool, and present results with insights.

## Cluster and Table

- **Cluster:** `https://ossec.kusto.windows.net`
- **Database:** `PI_DA300`
- **Table:** `PI_SB_CensusExAgg_Weekly`

```
database('PI_DA300').PI_SB_CensusExAgg_Weekly
```

Always use cluster `https://ossec.kusto.windows.net` and prefix the table with `database('PI_DA300').` when querying.

## Canvas

When I say "put this on the canvas," "show me a visual," "make a slide," or "visualize this," build an HTML file and open it as a borderless app window.

**Workflow:**
1. Generate the HTML. Save to `C:\Users\<your-alias>\Desktop\canvas\` (or any folder you prefer).
2. Open it: `Start-Process "msedge.exe" -ArgumentList "--app=file:///C:/Users/<your-alias>/Desktop/canvas/filename.html", "--window-size=1400,900"`
3. Tell me the file path.

**Design defaults:**
- Font: Segoe UI, system-ui, sans-serif
- Light theme: background `#F1F5F9`, cards white, text `#1E293B`
- Tables: clean, compact, 12-13px font, tabular-nums for numbers
- Always mobile-responsive. Always tab-navigable.
- Use color purposefully: red for urgency/risk, green for progress, blue for informational, gray for secondary.
- Max width 1300px.

**When iterating:**
- Save versioned backups (e.g., filename-v1.html, filename-v2.html) when making significant changes so I can reference older versions.
- Make edits directly to the HTML without asking for permission on simple changes.

## Query Types

There are TWO main query patterns. Choose based on what the user is asking:

### Query Type 1: Certificate Adoption (2023 Keys)

Use when asking about DB/KEK certificate rollout, which devices have new keys, cert adoption percentages.

**Standard filters (always apply):**
```kql
| where SB_Enabled
| where SV_Encoded_Length > 0
| where not(IsVirtualDevice)
```

**Common pattern:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled
| where SV_Encoded_Length > 0
| where not(IsVirtualDevice)
| summarize
    TotalDevices = sum(Devices),
    DB_Has_1P_23 = sumif(Devices, SV_Has_DB1P23),
    KEK_Has_1P_23 = sumif(Devices, SV_Has_KEK1P23)
    by Make, Model
| extend
    DB_1P_2023_Pct = round(DB_Has_1P_23 * 100.0 / TotalDevices, 1),
    KEK_1P_2023_Pct = round(KEK_Has_1P_23 * 100.0 / TotalDevices, 1)
| where TotalDevices > 100
| sort by TotalDevices desc
```

### Query Type 2: Secure Boot Enablement (Factory / OKR Tracking)

Use when asking about whether devices have Secure Boot turned on, SB capable vs enabled, factory defaults, or OKR progress against an enablement target.

**CRITICAL: Do NOT use `SV_Encoded_Length > 0` for enablement queries.** That filter limits to devices with cert variable data, which biases results to ~100% SB (survivorship bias). For true enablement rates, only filter on `not(IsVirtualDevice)`.

**Standard filters:**
```kql
| where not(IsVirtualDevice)
```

**Common pattern — monthly factory enablement rate (OKR tracking):**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where not(IsVirtualDevice)
| where MfgYear >= 2025
| summarize
    TotalDevices = sum(Devices),
    SB_Enabled = sumif(Devices, SB_Enabled),
    SB_Capable = sumif(Devices, SB_Capable)
    by MfgYear, MfgMonth
| extend
    SB_Enabled_Pct = round(SB_Enabled * 100.0 / TotalDevices, 1),
    SB_Capable_Pct = round(SB_Capable * 100.0 / TotalDevices, 1)
| sort by MfgYear asc, MfgMonth asc
```

**Per-OEM monthly breakdown:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where not(IsVirtualDevice)
| where MfgYear >= 2025
| summarize
    TotalDevices = sum(Devices),
    SB_Enabled = sumif(Devices, SB_Enabled)
    by Make, MfgYear, MfgMonth
| extend SB_Pct = round(SB_Enabled * 100.0 / TotalDevices, 1)
| sort by Make asc, MfgYear asc, MfgMonth asc
```

**Historical pattern (for deeper analysis using EverCapable/EverEnabled):**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where isnotempty(SB_EverCapable) and isnotempty(SB_EverEnabled) and isnotempty(MfgYear)
| where MfgOsType == "FullOS"
| summarize
    Devices = sum(Devices),
    SB_EverCapable = sumif(Devices, SB_EverCapable),
    SB_EverEnabled = sumif(Devices, SB_EverEnabled)
    by Make, Model
| extend
    Capable_Pct = round(SB_EverCapable * 100.0 / Devices, 0.01),
    Enabled_Pct = round(SB_EverEnabled * 100.0 / Devices, 0.01)
```

Common additional filters: MfgOsPlatform (e.g., "16_Ga" for 24H2), MfgYear, MfgMonth, Make.

#### ⚠️ Data Lag Warning for Recent Manufacturing Months
Devices manufactured in the last 2–3 months report to telemetry with a lag. When monthly volume drops below ~1M (vs 6-8M at steady state), the rates are unreliable and skewed toward early-reporting device types. Flag these months as provisional and avoid drawing conclusions from them.

**How to find the most recent reliable month:** Query monthly volume first, then pick the latest month with 1M+ devices:
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where not(IsVirtualDevice) and SB_Enabled and SV_Encoded_Length > 0
| where MfgYear == 2025
| where Make in ("Lenovo", "HP", "Dell", "Asus", "Microsoft", "Acer", "Samsung")
| summarize TotalDevices = sum(Devices) by MfgMonth
| sort by MfgMonth asc
```

### OEM Action Queries

Use when asking who needs to take action, what action is needed, update PK / provide KEK / resolve skip.

```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled
| where SV_Encoded_Length > 0
| where not(IsVirtualDevice)
| where NeedsOemAction == true
| summarize Devices = sum(Devices) by Make, Model, OemAction
| sort by Devices desc
```

### Block/Skip Analysis (Combined View)

Use when asking about all reasons devices are blocked from receiving Secure Boot updates — combines UpdateSkipped and OemAction reasons.

**IMPORTANT: Exclude "Provide KEK" devices that already have KEK 1P 2023** — if the device already has the 2023 KEK, the OEM does not need to submit a PK-signed KEK. These are effectively unblocked.

```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled
| where SV_Encoded_Length > 0
| where not(IsVirtualDevice)
| where SbUpdateAudience == "InScope"
| where UpdateSkipped == true or NeedsOemAction == true
// Exclude Provide KEK devices that already have the 2023 KEK — they're unblocked
| where not(OemAction has "Provide KEK" and SV_Has_KEK1P23 == true)
| extend BlockReason = case(
    UpdateSkipped == true and isnotempty(UpdateSkippedReason), UpdateSkippedReason,
    NeedsOemAction == true and isnotempty(OemAction), strcat("OemAction: ", OemAction),
    "Unknown"
  )
| summarize Devices = sum(Devices) by Make, BlockReason
| sort by Devices desc
```

### Lost PK Analysis

Use when asking about devices with a confirmed lost Platform Key. The definitive source is `SV_ORCSubjectNames` which contains "LOST_PK" with detailed OEM status (Updating/Pending/Not updating + reason). Use `SV_Encoded_PK` to identify specific PK lineages per OEM. Use `DeviceAgeYear` (not `MfgYear`) for device age — MfgYear is null for 70-80% of devices. Priority cutoff for OEM action is 2021+.

**IMPORTANT:** When reporting to WECE LT, always scope to supported OS only: `OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")`

**Lost PK by OEM with status:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SV_ORCSubjectNames has "LOST_PK"
| where OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")
| extend Status = case(
    SV_ORCSubjectNames has "Not updating", "Not Updating",
    SV_ORCSubjectNames has "Pending", "Pending",
    SV_ORCSubjectNames has "Updating", "Updating",
    "Other"
  )
| summarize Devices = sum(Devices) by Status, Make, SV_ORCSubjectNames
| sort by Devices desc
```

**Lost PK by OEM with priority tier (2021+ vs older):**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SV_ORCSubjectNames has "LOST_PK"
| where OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")
| where isnotnull(DeviceAgeYear)
| summarize
    Total = sum(Devices),
    Priority = sumif(Devices, DeviceAgeYear >= 2021),
    Older = sumif(Devices, DeviceAgeYear < 2021)
    by Make
| sort by Total desc
```

**Device age distribution for lost PK devices:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SV_ORCSubjectNames has "LOST_PK"
| where isnotnull(DeviceAgeYear) and DeviceAgeYear >= 2018
| summarize Devices = sum(Devices) by DeviceAgeYear
| sort by DeviceAgeYear asc
```

**Model-level lost PK for a specific OEM (swap Make filter as needed):**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SV_ORCSubjectNames has "LOST_PK"
| where OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")
| where Make == "Acer"
| where isnotnull(DeviceAgeYear) and DeviceAgeYear >= 2021
| summarize TotalDevices = sum(Devices) by Model
| sort by TotalDevices desc
| take 50
```

**New device factory rate — monthly trend of lost PK on new shipments:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where Make == "Acer"
| where isnotnull(DeviceAgeYear) and DeviceAgeYear >= 2024
| summarize
    Total = sum(Devices),
    LostPK = sumif(Devices, SV_ORCSubjectNames has "LOST_PK")
    by DeviceAgeYear, DeviceAgeMonth
| extend LostPK_Pct = round(LostPK * 100.0 / Total, 1)
| sort by DeviceAgeYear asc, DeviceAgeMonth asc
```

**PK lineage per OEM — identifies how many distinct lost keys are in play:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SV_ORCSubjectNames has "LOST_PK"
| where OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")
| where Make == "Acer"
| summarize Devices = sum(Devices) by SV_Encoded_PK, FirmwareManufacturer
| sort by Devices desc
```

**Unmatched PKs — devices that need KEK but aren't yet classified as LOST_PK:**
```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SbUpdateAudience == "InScope"
| where NeedsOemAction == true and OemAction has "Provide KEK"
| where SV_Has_KEK1P23 == false
| where OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")
| where not(SV_ORCSubjectNames has "LOST_PK")
| summarize Devices = sum(Devices) by Make
| sort by Devices desc
```

### Provide KEK Analysis (Truly Blocked Only)

Use when asking about OEMs that need to submit a PK-signed KEK. Exclude devices that already have KEK 1P 2023.

```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where SB_Enabled and SV_Encoded_Length > 0 and not(IsVirtualDevice)
| where SbUpdateAudience == "InScope"
| where NeedsOemAction == true and OemAction has "Provide KEK"
| where SV_Has_KEK1P23 == false
| summarize Devices = sum(Devices) by Make, Model, SV_Encoded_PK, FirmwareManufacturer
| sort by Devices desc
```

## Make Field — Canonical Values

The Make field is user-reported and messy. Always use the canonical value from the list below.

### Top 50 OEMs by Volume (canonical Make values)

| Rank | Canonical Make | Devices |
|------|---------------|---------|
| 1 | `"HP"` | 178M |
| 2 | `"Lenovo"` | 163M |
| 3 | `"Dell"` | 120M |
| 4 | `"Asus"` | 82M |
| 5 | `"Acer"` | 51M |
| 6 | `"MSI"` | 30M |
| 7 | `"Huawei"` | 22M |
| 8 | `"Microsoft"` | 21M |
| 9 | `"Samsung"` | 13M |
| 10 | `"FUJITSU CLIENT COMPUTING LIMITED"` | 7.0M |
| 11 | `"Dynabook Inc"` | 6.9M |
| 12 | `"NEC"` | 6.7M |
| 13 | `"Xiaomi"` | 4.2M |
| 14 | `"MECHREVO"` | 4.2M |
| 15 | `"LG"` | 4.1M |
| 16 | `"Gigabyte"` | 4.1M |
| 17 | `"HONOR"` | 4.0M |
| 18 | `"Fujitsu"` | 2.6M |
| 19 | `"MCJ"` | 2.6M |
| 20 | `"Positivo"` | 2.3M |
| 21 | `"Intel Client Systems"` | 1.7M |
| 22 | `"WORTMANN AG"` | 1.7M |
| 23 | `"Thirdwave Corporation"` | 1.5M |
| 24 | `"Panasonic"` | 1.3M |
| 25 | `"Colorful Technology And Development Co., LTD"` | 1.0M |
| 26 | `"VAIO"` | 912K |
| 27 | `"Gigabyte Communications Inc."` | 825K |
| 28 | `"ASRock"` | 810K |
| 29 | `"Panasonic Connect Co., Ltd."` | 692K |
| 30 | `"COLORFUL"` | 679K |
| 31 | `"CASPER BILGISAYAR SISTEMLERI"` | 607K |
| 32 | `"THUNDEROBOT"` | 553K |
| 33 | `"iBUYPOWER"` | 503K |
| 34 | `"CyberPowerPC"` | 500K |
| 35 | `"EPSON DIRECT CORPORATION"` | 475K |
| 36 | `"Sony Corporation"` | 460K |
| 37 | `"Razer"` | 451K |
| 38 | `"MONSTER"` | 415K |
| 39 | `"Apple"` | 380K |
| 40 | `"MicroElectronics"` | 342K |
| 41 | `"PCSpecialist"` | 317K |
| 42 | `"Lecoo"` | 300K |
| 43 | `"Micro Computer  Tech Limited"` | 282K |
| 44 | `"MACHENIKE"` | 280K |
| 45 | `"Multilaser Industrial"` | 265K |
| 46 | `"TECNO Mobile Limited"` | 263K |

### Common gotchas

| Canonical Value | NOT this |
|---|---|
| `"Asus"` | "ASUS", "ASUSTeK" |
| `"FUJITSU CLIENT COMPUTING LIMITED"` | "Fujitsu" (note: both exist as separate Make values) |
| `"Dynabook Inc"` | "Dynabook", "dynabook" |
| `"Panasonic Connect Co., Ltd."` | "Panasonic" (note: both exist as separate Make values) |
| `"Gigabyte Communications Inc."` | confusable with `"Gigabyte"` (different entities) |

When unsure, use `Make contains "nec"` first to discover the exact value, then switch to `==` for the real query.

## Column Reference

### Device Identity
- **Make** (string): OEM manufacturer — see canonical values above
- **Model** (string): Device model name
- **MfgYear** (int): Manufacturing year (e.g., 2024, 2025)
- **MfgMonth** (int): Manufacturing month (1–12)
- **DeviceAgeYear** (int): **Manufacture year (despite the name, this is NOT age-in-years)**. Use for vintage analysis: `DeviceAgeYear >= 2024` means manufactured 2024+. May differ from MfgYear; MfgYear can be null while DeviceAgeYear is populated.
- **DeviceFamily** (string): e.g., "Windows.Desktop"

### OS Info
- **OsPlatform** (string): OS platform codename ("Ga" = 24H2, "Ni" = 23H2, "Vb" = older)
- **OsPlatformIndexed** (string): Indexed version (e.g., "16_Ga")
- **MfgOsType** (string): "FullOS" for standard Windows installations
- **MfgOsPlatform** (string): OS platform at manufacture (e.g., "16_Ga" for 24H2)
- **OsSKU** (string): Windows SKU ("PROFESSIONAL", "CORE", "ENTERPRISE")
- **OSSkuGroupTargeting** (string): SKU group ("Pro", "Home", "Enterprise")

### Device Flags
- **IsCopilotPlusPC** (bool): Whether device is a Copilot+ PC
- **SB_Enabled** (bool): Secure Boot currently enabled
- **SB_Capable** (bool): Device is Secure Boot capable
- **SB_EverCapable** (bool): Device was ever SB capable
- **SB_EverEnabled** (bool): Device ever had SB enabled
- **SB_EverDisabled** (bool): Device ever had SB disabled (if true + SB_EverEnabled false → shipped SB-off from factory)
- **IsVirtualDevice** (bool): Is a virtual machine
- **HasSecuredCoreUefi** (bool): Has Secured-core UEFI

### Secure Boot Certificate Flags (2023 era)
- **SV_Has_DB1P23** (bool): Has 1st-party DB certificate (2023)
- **SV_Has_DB3P23** (bool): Has 3rd-party DB certificate (2023)
- **SV_Has_DBOR23** (bool): Has DB OEM Revocation cert (2023)
- **SV_Has_KEK1P23** (bool): Has 1st-party KEK certificate (2023)

### Secure Boot Certificate Flags (2011 era)
- **SV_Has_DB1P11** (bool): Has 1st-party DB certificate (2011)
- **SV_Has_DB3P11** (bool): Has 3rd-party DB certificate (2011)
- **SV_Has_KEK1P11** (bool): Has 1st-party KEK certificate (2011)

### Secure Boot Variable Info
- **SV_Encoded_Type** (string): "Present" or "NA"
- **SV_Encoded_Length** (int): Length of encoded SV (>0 means data present)
- **SV_Encoded_PK** (string): Platform Key identifier
- **SV_RequiredUpdates** (string): Comma-separated list of required updates

### OEM Action / Update Status
- **NeedsOemAction** (bool): OEM action is required
- **OemAction** (string): "Update PK", "Provide KEK", "Resolve Skip", or combinations
- **InScopeForOemAction** (bool): In scope for OEM action
- **SbUpdateAudience** (string): Update audience — **"InScope"** (active/supported, updates would apply), **"OutOfSupport"** (older OS/HW, lower urgency), **"ReqOptIn"** (eligible but not opted in yet), **"Excluded"** (explicitly excluded — VMs, cloud, etc.). Use "InScope" to scope to actionable devices.
- **SbUpdateRolloutPhase** (int): Rollout phase number
- **UpdateSkipped** (bool): Whether update was skipped
- **UpdateSkippedReason** (string): Why skipped. Known values: "HPCommercialBIOS", "SystemFamily103C_NotSBKPFV3", "InsydeBadBaseBoardProduct", "HPBadBaseBoardProductDBX", "ShouldSecurebootSkipAnyUpdateFailed", "ProcessorArchitectureARM64_UefiSecAppVersionRT_NotFound", "AppleBadBaseBoardProduct", "SamsungBadSKU", "BaseBoardProductRegistryFailed", "IsHPFeatureEnabledOEMStringArray", "FujitsuBadBaseBoardProduct", "SurfaceHub", "AsusBadBaseBoardProduct", "Invalid Reason"

### Firmware Info
- **FirmwareTypeName** (string): "UEFI" or "BIOS"
- **FirmwareManufacturer** (string): Firmware manufacturer (e.g., "Insyde Corp.", "American Megatrends Inc.", "Dell Inc.", "HUAWEI", "LENOVO", "Microsoft Corporation"). Useful for identifying firmware lineages behind skip/block reasons.
- **FirmwareVersion** (string): Firmware version string
- **FirmwareReleaseDate** (string): Firmware release date

### Metrics
- **Devices** (long): **Weighted device count — ALWAYS use sum(Devices), never count()**
- **Rolling28** (real): 28-day rolling average
- **StreamDate** (datetime): Data stream date

## Analysis Patterns

### Gap-to-target analysis
When asked "what would it take to reach X%", calculate the gap and show which models close it cumulatively:
```kql
| extend Disabled = Devices - SB_EverEnabled
| sort by Disabled desc
| extend CumulativeDisabled = row_cumsum(Disabled)
```

### Month-over-month trends
Add MfgYear, MfgMonth to the grouping to show trends:
```kql
| summarize ... by Make, Model, MfgYear, MfgMonth
| sort by MfgYear asc, MfgMonth asc
```

### Device vintage / age analysis
Use DeviceAgeYear (manufacture year) to bucket devices by era. Combine with MfgMonth for finer granularity:
```kql
| extend Vintage = case(
    DeviceAgeYear >= 2024, "2024+",
    DeviceAgeYear >= 2022, "2022-23",
    DeviceAgeYear >= 2020, "2020-21",
    DeviceAgeYear >= 2018, "2018-19",
    DeviceAgeYear < 2018 and isnotnull(DeviceAgeYear), "Pre-2018",
    "Unknown"
  )
| summarize Devices = sum(Devices) by Make, Vintage
| evaluate pivot(Vintage, sum(Devices), Make)
```

For weighted average vintage:
```kql
| where isnotnull(DeviceAgeYear)
| summarize Devices = sum(Devices), WeightedYear = sum(Devices * DeviceAgeYear) by Make
| extend AvgVintage = round(1.0 * WeightedYear / Devices, 1)
```

### OEM tier analysis
Categorize OEMs into tiers **by device volume** (not SB performance) for impact-oriented analysis:

**Tier thresholds (adjust based on time window):**
- **Tier 1 — Major OEMs:** >10M devices (Lenovo, HP, Dell)
- **Tier 2 — Large OEMs:** 1M–10M (Asus, Acer, Microsoft, Samsung, MECHREVO, MSI, Fujitsu, Dynabook)
- **Tier 3 — Mid-size:** 100K–1M
- **Tier 4 — Small:** <100K

```kql
| extend OemTier = case(
    Make in ("Lenovo", "HP", "Dell"), "Tier 1 (>10M)",
    Make in ("Asus", "Acer", "Microsoft", "Samsung", "MECHREVO", "MSI", "FUJITSU CLIENT COMPUTING LIMITED", "Dynabook Inc"), "Tier 2 (1-10M)",
    "Tier 3/4"
)
```

Present each tier separately with its own subtotal. This helps identify whether the gap to target is driven by a few large OEMs (addressable) or a long tail of small ones (harder).

### Copilot+ PC segment analysis
Copilot+ PCs consistently run 98%+ SB enablement. Breaking out Copilot+ vs non-Copilot+ reveals the structural tailwind from new hardware:

```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where not(IsVirtualDevice)
| where MfgYear >= 2025
| summarize
    TotalDevices = sum(Devices),
    SB_Enabled = sumif(Devices, SB_Enabled)
    by IsCopilotPlusPC, MfgYear, MfgMonth
| extend SB_Pct = round(SB_Enabled * 100.0 / TotalDevices, 1)
| sort by IsCopilotPlusPC asc, MfgYear asc, MfgMonth asc
```

### Factory default forensics (for OEM outreach)
When investigating why an OEM's devices ship with SB off, use these columns to distinguish factory defaults from post-purchase changes:

- **`SB_Capable = true` + `SB_Enabled = false`** → SB-capable but currently off (fixable)
- **`SB_EverEnabled = false` + `SB_EverDisabled = true`** → Shipped SB-off from the factory (OEM's fault, not enterprise IT)
- **`SB_EverEnabled = true` + `SB_Enabled = false`** → Was once enabled, then disabled (likely enterprise IT or user action)

```kql
database('PI_DA300').PI_SB_CensusExAgg_Weekly
| where not(IsVirtualDevice)
| where Make == "<OEM>"
| where MfgYear == 2025
| where not(SB_Enabled) and SB_Capable
| summarize Devices = sum(Devices) by Model, SB_EverEnabled, SB_EverDisabled, FirmwareManufacturer, FirmwareVersion
| sort by Devices desc
```

This data is powerful for OEM outreach — it proves devices left the factory with SB off and identifies the specific firmware versions involved.

## Terminology
- **DB** = Secure Boot Signature Database (holds allowed boot signatures)
- **KEK** = Key Exchange Key (authorizes DB updates)
- **PK** = Platform Key (root of trust, OEM-owned)
- **1P** = First-party (Microsoft)
- **3P** = Third-party
- **2023 / 23** = 2023-era certificates (the new ones being rolled out)
- **2011 / 11** = 2011-era certificates (the old ones)
- **ORC** = OEM Root Certificate
- **"Update PK" (Lost PK)** = The device's PK is not a Microsoft 1P key. Microsoft cannot push KEK/DB updates via WU. The OEM must issue a BIOS update to re-provision the PK. This is the most severe block — it prevents all downstream cert updates.
- **"Provide KEK"** = The OEM owns a valid PK but has not submitted a PK-signed KEK capsule to Microsoft for WU distribution. **However**, if the device already has SV_Has_KEK1P23 == true (e.g., OEM pre-loaded it in firmware), the OEM does NOT need to submit a capsule — exclude these from action-needed counts.
- **"Resolve Skip"** = Devices are blocked from update by an UpdateSkippedReason; OEM must fix the blocking condition
- **Copilot+ PC** = Devices with IsCopilotPlusPC == true
- **24H2 / Ga** = Windows 11 24H2 (OsPlatform == "Ga" or MfgOsPlatform == "16_Ga")
- **SV_Encoded_PK** = Hash identifying the specific Platform Key on a device. Useful for grouping devices by PK lineage — devices sharing the same PK hash share the same root of trust and can be addressed with a single capsule.

## PK/Skip Analysis Methodology

This section captures the methodology for producing Lost PK and Update Skip reports for OEM engagement. Follow these guardrails to avoid known pitfalls.

### The Three Populations (Core Mental Model)

"Lost PK" is actually three overlapping populations. Confusing them produces inconsistent headlines.

| Population | How to Find | What It Means |
|---|---|---|
| **1. Confirmed Lost PK** | `SV_ORCSubjectNames has "LOST_PK"` | Definitive. ORC has status notes: "Updating", "Pending", "Not updating" + reason. Report this as the confirmed number. |
| **2. Unmatched – need KEK, not yet classified** | `NeedsOemAction == true AND OemAction has "Provide KEK" AND SV_Has_KEK1P23 == false AND NOT(SV_ORCSubjectNames has "LOST_PK")` | OEM needs to submit KEK but we haven't confirmed if PK is lost or just not enrolled. These are the "do you have your PK?" conversations. |
| **3. OemAction "Provide KEK"** | `NeedsOemAction == true AND OemAction has "Provide KEK" AND SV_Has_KEK1P23 == false` | Superset of 1+2. Was our first approach – caused inconsistency because partially remediated LOST_PK devices drop out of this view but keep the tag. |

**Rule: Don't mix these query approaches in the same report.** Pick one lens:
- For **confirmed exposure** → Population 1 (LOST_PK tag)
- For **actionable OEM work** → Population 3 (NeedsOemAction)
- For **full risk surface** → both, clearly labeled

### What Lost PK Devices Can and Cannot Receive

| Update Type | Can Receive? | Why |
|---|---|---|
| New 2023 DB certificates | ✅ YES | Delivered via Windows Update – no PK needed |
| New 2023 KEK certificate | ❌ NO | Requires PK-signed capsule – if PK is lost, OEM can't sign it |
| DBX blocklist updates | ❌ NO | Signed with KEK – stuck on 2011 KEK = no new DBX |
| Emergency bootloader revocation | ❌ NO | **The real risk** – if we need to revoke a compromised bootloader, these devices are the gap |

**Executive framing:** "These devices get most security updates. But if we discover a compromised bootloader and need emergency revocation, these are the devices we can't protect."

### Scoping Rules (Learned the Hard Way)

| Rule | Filter | Why It Exists |
|---|---|---|
| Always apply base filters | `SB_Enabled`, `SV_Encoded_Length > 0`, `not(IsVirtualDevice)` | Without these you count devices with no visibility or inflate OEM counts with VMs |
| Supported OS for external reports | `OsPlatformIndexed in ("16_Ga", "17_Dt", "18_Br", "19_Kr", "13_Ni")` | Robin asked for in-support only. Omitting inflates numbers 10-15% with devices we aren't updating |
| Use DeviceAgeYear, NOT MfgYear | `isnotnull(DeviceAgeYear) and DeviceAgeYear >= 2021` | MfgYear is null 70-80% of the time. DeviceAgeYear fills the gap (only ~1.6% null). Despite the name, it IS the manufacture year. |
| Priority cutoff | `DeviceAgeYear >= 2021` | Agreed threshold – 5 years old or less, within useful life |
| InScope audience for actionable work | `SbUpdateAudience == "InScope"` | Focuses on devices where updates would actually apply |

### Quality Checks (Run Before Sharing Anything)

| Check | How | Why |
|---|---|---|
| Model totals = OEM total | Sum model table, compare to headline | We shipped a report where models summed to 18.3M but headline said 21.8M – different query scopes |
| Supported OS scoping confirmed | Verify `OsPlatformIndexed in (...)` in every query | One missing filter changes numbers by 10-15% |
| No mixed query approaches | All numbers from same population definition | Don't mix LOST_PK tag counts with OemAction counts in one report |
| Priority + Older = Total | Arithmetic check on tier split | DeviceAgeYear nulls cause a gap if not handled |
| Copilot+ PC flags verified | Web search each flagged model | Data flags aren't always reliable – one wrong flag and OEM questions everything |
| Data date stated | Note the StreamDate | Numbers change weekly – always state when data was pulled |

### Iteration History (Mistakes to Avoid)

| What Went Wrong | Correction |
|---|---|
| Used `MfgYear` for device age | Switch to `DeviceAgeYear` – MfgYear is null 70-80% |
| Said devices "will receive new KEK via OS-side fix" | Wrong. They get DB via OS, but KEK requires PK-signed capsule |
| Inferred lost PK from `OemAction == "Provide KEK"` | `SV_ORCSubjectNames has "LOST_PK"` is the definitive source |
| Mixed two query approaches in same report | Headlines (21.8M) didn't match model tables (18.3M) – pick one approach |
| Reported without supported OS filter | Robin asked for in-support only – numbers dropped ~10% |
| Scope too narrow – only counted tagged LOST_PK | Unmatched PKs are also customer risk – add as separate category |
| Included "new device factory issue" in OEM report | Raise verbally – don't put "you're shipping broken firmware" in writing |
| One sort order for model prioritization | Run volume, recency, AND premium sorts separately – different lenses surface different priorities |

### OEM Report Workflow (12 Steps)

1. "How many [OEM] devices have a lost PK on supported Windows 11?"
2. "Break that down by remediation status – updating, pending, declined"
3. "How many are 2021 or newer?"
4. "Show me the device age distribution"
5. "Top 50 models by device count, 2021+, supported OS"
6. "Is [OEM] still shipping new devices with the lost PK? Monthly since 2024"
7. "How many distinct lost PKs does [OEM] have?"
8. "Any [OEM] devices needing KEK that aren't classified as lost PK yet?"
9. "Put this on the canvas – prioritization report for [OEM]"
10. Iterate – adjust framing, grouping, sort order
11. Run quality checks (above) – every time, no exceptions
12. Decide framing: internal vs OEM-facing (see below)

### Report Structure

**Internal (WECE LT):** Executive summary → OEM status breakdown → Priority tier (2021+) → Device age distribution → Factory trend → PK lineage → Actions/owners. Always note: "Scoped to supported Windows 11. Telemetry-visible only."

**OEM-facing:** Partnership tone ("playbook to succeed"). Situation → Their exposure → Top models → Recommended waves → What "done" looks like → How Microsoft helps. Do NOT include: other OEMs' data, unmatched PK populations (internal investigation), soft commitments not yet secured, factory issue language.

### Unmatched PK Remediation Process

OEMs with unmatched PKs need to submit a PK-signed KEK (not a capsule update). Process instructions: https://github.com/microsoft/secureboot_objects/wiki/OEM-Certificate-Key-Rolling#oem-contribution-prerequisites. Signed KEK repo: PostSignedObjects/KEK/ in the same repo.

## Response Guidelines

1. **Always show data in tables** for readability
2. **Include both absolute numbers and percentages** — rates can be misleading without volume context
3. **Call out insights** — don't just show data, interpret it (trends, anomalies, root causes)
4. **When comparing OEMs**, note that enterprise customers may disable SB (not the OEM's fault)
5. **For trend analysis**, look for inflection points that suggest process changes (fixes or regressions)
6. **Use sum(Devices)** — never use count(), the Devices column is already a weighted count
