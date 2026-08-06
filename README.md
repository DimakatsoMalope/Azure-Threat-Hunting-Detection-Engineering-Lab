# Azure Threat Hunting & Detection Engineering Lab
### Endpoint Threat Hunting | Detection Engineering | DFIR | MITRE ATT&CK | Microsoft Azure

---

## Project Overview

This project demonstrates the design, implementation, and operation of a cloud-hosted Endpoint Detection and Response (EDR) lab built within Microsoft Azure.

The lab simulates real-world adversary behaviour using Atomic Red Team and investigates the resulting endpoint telemetry using LimaCharlie EDR and Microsoft Sysinternals Sysmon.

Rather than simply executing attack simulations, the project follows a structured SOC investigation methodology that mirrors how Security Operations Centre (SOC) analysts, Threat Hunters, Incident Responders, and Digital Forensics investigators conduct investigations within enterprise environments.

Each attack simulation is treated as a separate incident investigation and includes:

- Attack execution
- Endpoint telemetry analysis
- Process tree reconstruction
- Timeline analysis
- Indicators of Compromise (IoCs)
- MITRE ATT&CK mapping
- Detection engineering
- Detection gap analysis
- Lessons learned

---

# Project Objectives

The objective of this project was to:

✔ Build a realistic Azure endpoint investigation lab

✔ Deploy and configure LimaCharlie EDR

✔ Configure Sysmon for advanced Windows telemetry

✔ Deploy Active Directory Domain Services

✔ Simulate adversary behaviour using Atomic Red Team

✔ Perform structured threat hunting investigations

✔ Develop custom detection rules

✔ Produce SOC-quality incident reports

✔ Build a professional DFIR portfolio demonstrating real investigative methodology

---

# Architecture

```
                        Microsoft Azure

                    Resource Group
                           │
                           │
                ┌────────────────────┐
                │ Windows Server 2022│
                │ Azure Edition      │
                │                    │
                │ Active Directory   │
                │ DNS                │
                │ Sysmon             │
                │ LimaCharlie Sensor │
                │ Atomic Red Team    │
                └─────────┬──────────┘
                          │
                   Endpoint Telemetry
                          │
                          ▼
                LimaCharlie Cloud EDR
                          │
             Threat Hunting Investigation
                          │
                          ▼
                  GitHub Documentation
```

📷 **Screenshot**

> Insert Azure architecture diagram or Azure Resource Group screenshot.

---

# Lab Environment

## Cloud Platform

Microsoft Azure

---

## Operating System

Windows Server 2022 Azure Edition

Hostname

```
WIN-SERV22-ENDPOINT-01
```

Domain

```
THREATHUNTING.LOCAL
```

Role

```
Domain Controller
DNS Server
```

📷 **Screenshot**

> Azure VM Overview

---

# Lab Components

| Component | Technology |
|------------|------------|
| Cloud Platform | Microsoft Azure |
| Operating System | Windows Server 2022 Azure Edition |
| Endpoint Detection | LimaCharlie |
| Logging | Sysmon |
| Attack Simulation | Atomic Red Team |
| Framework | MITRE ATT&CK |
| Reporting | GitHub |

---

# Initial Lab Build

The first phase of the project involved creating the Azure environment.

Tasks completed:

- Created Azure Resource Group
- Created Windows Server VM
- Configured NSGs
- Applied firewall rules
- Updated Windows Server
- Renamed server
- Created Active Directory Forest
- Promoted server to Domain Controller
- Installed DNS
- Created project directory
- Created VM Snapshot

📷 **Screenshot**

Azure Resource Group

📷 **Screenshot**

Virtual Machine Overview

📷 **Screenshot**

Windows Server Desktop

📷 **Screenshot**

Active Directory Installation

📷 **Screenshot**

Domain Controller Promotion

📷 **Screenshot**

Completed Domain Installation

---

# Sysmon Installation

Microsoft Sysinternals Sysmon was deployed to improve endpoint visibility.

Telemetry collected includes:

- Process Creation
- Process Termination
- Network Connections
- Registry Events
- File Creation
- File Streams
- Image Loading

Installation

```
Sysmon64.exe -i sysmonconfig.xml
```

Verification

```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational
```

📷 **Screenshot**

Sysmon installation

📷 **Screenshot**

Sysmon Event Viewer logs

---

# LimaCharlie Deployment

The LimaCharlie EDR sensor was deployed to the endpoint.

The deployment enables:

- Process telemetry
- Command-line logging
- Parent-child process relationships
- File activity
- Registry activity
- Detection rules
- Endpoint investigations

📷 **Screenshot**

Sensor installation

📷 **Screenshot**

Sensor Online

📷 **Screenshot**

LimaCharlie Dashboard

---

# Atomic Red Team

Atomic Red Team was selected to safely emulate attacker techniques.

Advantages:

- Safe
- Repeatable
- MITRE ATT&CK aligned
- Widely adopted by defenders

Repository

```
https://github.com/redcanaryco/atomic-red-team
```

Execution Framework

```
Invoke-AtomicRedTeam
```

📷 **Screenshot**

Atomic Red Team repository

📷 **Screenshot**

PowerShell installation

---

# Threat Hunting Methodology

Each investigation followed the same methodology.

```
Review Atomic Test

↓

Prepare Prerequisites

↓

Execute Atomic Test

↓

Collect Telemetry

↓

Threat Hunt

↓

Process Analysis

↓

Timeline Reconstruction

↓

MITRE Mapping

↓

Detection Analysis

↓

Recommendations

↓

Incident Report
```

---

# Incident Investigations

# Incident Report: INC-0001
## Encoded PowerShell Execution Investigation

---

## Incident Summary

| Field | Value |
|-------|-------|
| Incident ID | INC-0001 |
| Technique | T1059.001 – Command and Scripting Interpreter: PowerShell |
| MITRE ATT&CK | T1059.001 |
| Atomic Test | Test 17 – PowerShell Command Execution |
| Detection Source | LimaCharlie EDR, Sysmon, Windows Security Logs |
| Execution Time | 10:03:30 UTC |
| Executed By | `THREATHUNTING\azureuser` |
| Host | `WIN-SERV22-ENDPOINT-01` |

---

# Investigation Objective

The purpose of this investigation was to reconstruct the execution of an encoded PowerShell command generated by an Atomic Red Team simulation and determine:

- How execution began
- Which processes were spawned
- Whether persistence was established
- Whether registry modifications occurred
- Whether files were created
- Whether network communication occurred
- What Indicators of Compromise (IoCs) were present
- Whether the activity matched known MITRE ATT&CK techniques

---

# Investigation Timeline

| Time | Event |
|------|------|
| 10:03:30.595 | `hostname.exe` executed |
| 10:03:30.621 | `whoami.exe` executed |
| 10:03:30.xxx | Encoded PowerShell command launched |
| 10:03:30.xxx | Temporary PowerShell policy files created |
| 10:03:30.xxx | Atomic test completed successfully |

---

# Investigation Walkthrough

Rather than simply reviewing alerts, this investigation followed the methodology used by a Tier 2 SOC Analyst to reconstruct attacker behaviour using endpoint telemetry.

---

# Step 1 — What Happened First?

The first observable events were the execution of:

```
hostname.exe
```

followed by

```
whoami.exe
```

## Investigation Question

> **Why would the Atomic test execute these commands?**

Thinking from an attacker's perspective, one of the first objectives after gaining code execution is situational awareness.

Attackers commonly begin by answering two fundamental questions:

```
Who am I?
```

and

```
Which computer am I on?
```

To answer these questions they frequently execute:

```
whoami.exe
hostname.exe
```

These commands represent **Discovery** activity under the MITRE ATT&CK framework.

Analysis of the process lineage showed both commands were launched by:

```
powershell.exe
```

This allowed the first process tree to be reconstructed:

```text
powershell.exe
│
├── hostname.exe
└── whoami.exe
```

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 1 showing `hostname.exe`

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 1 showing `whoami.exe`

📷 **Screenshot Placeholder**

> Insert LimaCharlie process tree showing parent-child relationship

---

# Step 2 — Encoded PowerShell Execution

The next significant event was the execution of:

```
powershell.exe
```

Inspection of the command line revealed:

```text
powershell.exe -e JgAgACgAZwBjAG0A...
```

The following flag immediately stands out during investigation:

```
-e
```

This parameter indicates that PowerShell is executing a **Base64-encoded command**.

Encoded commands are commonly used by attackers to obscure command-line activity and evade simple inspection.

---

## Investigation Question 1

> **Was ExecutionPolicy Bypass used?**

The command line was examined for indicators such as:

```
-ExecutionPolicy Bypass
```

or

```
-ep bypass
```

Neither parameter was present.

### Finding

**No evidence of ExecutionPolicy Bypass was observed.**

This conclusion is based solely on the available evidence rather than assumption.

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 1 displaying the full PowerShell command line

📷 **Screenshot Placeholder**

> Insert LimaCharlie process details showing the encoded command

---

## Investigation Question 2

> **Was an encoded command used?**

Yes.

Evidence:

```text
powershell.exe -e
```

The `-e` switch confirms that the command executed encoded PowerShell content.

From an investigative perspective, this would warrant decoding the Base64 payload to determine its true behaviour.

---

# Step 3 — Who Started PowerShell?

Analysis of the parent process revealed:

```text
ParentImage

cmd.exe
```

The reconstructed process chain becomes:

```text
powershell.exe
        │
        ▼
cmd.exe
        │
        ▼
powershell.exe -e
```

This sequence aligns with the behaviour of the Atomic Red Team simulation, where an initial command shell launches a second PowerShell instance containing the encoded payload.

📷 **Screenshot Placeholder**

> Insert Sysmon process tree

📷 **Screenshot Placeholder**

> Insert LimaCharlie process ancestry

---

# Step 4 — What Was the Encoded Command?

The Base64 payload was decoded during investigation.

Decoded command:

```powershell
Write-Host "Hello, from PowerShell!"
```

This explains the console output generated during execution:

```
Hello, from PowerShell!
```

Although benign in this simulation, the technique itself is widely abused by adversaries.

The same execution method could just as easily be used to:

- Download malware
- Disable Microsoft Defender
- Create new local accounts
- Execute credential theft tools
- Launch ransomware

The investigation therefore focuses on the execution technique rather than the harmless payload itself.

---

# Step 5 — Did PowerShell Create Files?

Evidence showed creation of:

```
__PSScriptPolicyTest_*.ps1
```

These events were captured by:

```
Sysmon Event ID 11
```

## Investigation Question

> **Is this malicious?**

No.

PowerShell creates temporary policy test files while validating execution behaviour.

### Finding

These files represent expected PowerShell behaviour and are not considered malicious.

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 11 showing PowerShell temporary file creation

---

# Step 6 — Did the Command Communicate Over the Network?

The investigation searched for evidence of:

- Sysmon Event ID 3
- DNS queries
- LimaCharlie network telemetry
- Windows Firewall events

No supporting evidence was identified.

### Finding

**No network activity was observed during this investigation.**

It is important to note the wording used in professional investigations.

The conclusion is:

> **No evidence of network communication was observed.**

rather than

> "The command never accessed the network."

This distinction ensures conclusions remain evidence-based.

📷 **Screenshot Placeholder**

> Insert LimaCharlie network timeline (showing no network events)

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 3 search results (if applicable)

---

# Step 7 — Were Registry Modifications Observed?

The investigation searched for:

- Sysmon Event ID 12
- Sysmon Event ID 13
- Sysmon Event ID 14

No registry modification events were identified.

### Finding

**No evidence of registry modification or persistence was observed.**

📷 **Screenshot Placeholder**

> Insert Sysmon registry event search results

---

# Step 8 — Correlating Multiple Data Sources

One of the objectives of this investigation was to compare telemetry collected by different logging sources.

## Sysmon

Sysmon provided detailed forensic context including:

- Process hashes
- Parent process
- Parent GUID
- Command line
- Integrity level
- Current directory
- File version metadata

## Windows Security Event ID 4688

Windows Security logs provided:

- Process creation
- User account
- Creator process

Although less detailed than Sysmon, these events remain valuable for auditing and correlation.

## LimaCharlie EDR

LimaCharlie provided:

- Endpoint telemetry
- Process ancestry
- Timeline reconstruction
- Interactive investigation
- Threat hunting visibility

The combination of all three telemetry sources provided a comprehensive view of endpoint activity.

📷 **Screenshot Placeholder**

> Insert Windows Security Event ID 4688

📷 **Screenshot Placeholder**

> Insert Sysmon Event ID 1

📷 **Screenshot Placeholder**

> Insert LimaCharlie investigation timeline

---

# Investigation Findings

| Investigation Question | Finding | Evidence |
|-------------------------|---------|----------|
| What process executed? | `powershell.exe` | Sysmon Event ID 1 |
| Who executed it? | `THREATHUNTING\azureuser` | User field |
| Parent process? | `cmd.exe` | ParentImage |
| ExecutionPolicy bypass? | No evidence observed | Command line analysis |
| Encoded command? | Yes | `-e` switch |
| Child processes? | `hostname.exe`, `whoami.exe` | Sysmon Event ID 1 |
| Files created? | Temporary PowerShell policy files | Sysmon Event ID 11 |
| Registry modified? | No evidence observed | No Sysmon Events 12–14 |
| Network communication? | No evidence observed | No network telemetry |

---

# Analyst Assessment

Although this Atomic Red Team simulation executed a harmless payload, the investigation demonstrates an execution technique frequently associated with malicious activity.

Encoded PowerShell commands are widely used by threat actors to conceal malicious intent and bypass simple command-line inspection. In this case, decoding the payload revealed only a benign `Write-Host` command; however, the investigative methodology would remain identical if the payload instead downloaded malware, established persistence, disabled security controls, or initiated credential theft.

The investigation emphasizes the importance of validating conclusions using multiple telemetry sources rather than relying on a single alert. Correlating Sysmon logs, Windows Security Events, and LimaCharlie EDR telemetry provided a complete understanding of the execution chain and enabled accurate reconstruction of the attack timeline.

---

# Detection Opportunities

The investigation identified several opportunities to strengthen endpoint detection:

- Alert on PowerShell executions containing the `-e` or `-EncodedCommand` parameter.
- Correlate encoded PowerShell with child process creation such as `whoami.exe` and `hostname.exe`.
- Monitor for suspicious parent-child relationships involving `cmd.exe` spawning encoded PowerShell.
- Enhance detections by automatically decoding Base64 PowerShell payloads where possible.
- Continue correlating Sysmon, Windows Security Logs, and LimaCharlie telemetry to improve investigation fidelity.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1059.001 | PowerShell |
| TA0002 | Execution |
| TA0007 | Discovery |
---

## Incident 0002

Scheduled Task Persistence

MITRE

```
T1053.005
```

Investigation

- Task creation
- Registry modifications
- Process creation
- Parent process
- Timeline

📷 **Screenshots**

---

## Incident 0003

Ingress Tool Transfer

MITRE

```
T1105
```

Focus

- Certutil execution
- Download activity
- Network connections
- File creation

📷 **Screenshots**

---

## Incident 0004

Credential Access Simulation

MITRE

```
T1003
```

Focus

- LSASS access
- Memory access
- Privileges
- Process execution

📷 **Screenshots**

---

## Incident 0005

Remote Services

MITRE

```
T1021
```

Focus

- Remote execution
- Authentication
- Network activity
- Endpoint telemetry

📷 **Screenshots**

---

## Incident 0006

Registry / Startup Persistence

MITRE

```
T1547
```

Focus

- Registry autoruns
- Startup folder
- Persistence artifacts

📷 **Screenshots**

---

# Detection Engineering

During the project several custom detections were created.

Examples include

- Encoded PowerShell
- Certutil Abuse
- Scheduled Tasks
- Registry Persistence
- LOLBins
- Suspicious Parent Child Processes

Detection rules are available under

```
detections/
```

---

# Indicators of Compromise

Examples collected throughout the investigations

- Process Names
- File Paths
- Parent Processes
- Child Processes
- Command Lines
- Registry Keys
- Scheduled Tasks
- DNS Requests
- Network Connections
- File Hashes

Location

```
iocs/
```

---

# MITRE ATT&CK Coverage

| Technique | Description |
|------------|-------------|
| T1059.001 | PowerShell |
| T1053.005 | Scheduled Tasks |
| T1105 | Ingress Tool Transfer |
| T1003 | Credential Access |
| T1021 | Remote Services |
| T1547 | Registry Persistence |

📷 **Screenshot**

MITRE ATT&CK Navigator Heatmap

---

# Detection Gap Analysis

The investigations identified several areas where detection visibility could be improved.

Examples

- Additional PowerShell logging
- Registry auditing improvements
- DNS telemetry enrichment
- Sigma rule implementation
- Additional Sysmon tuning
- Network segmentation
- Alert tuning

---

# Lessons Learned

Key lessons from this project include:

- Endpoint telemetry is foundational to effective threat hunting.
- Atomic Red Team provides safe and repeatable adversary simulations.
- Process lineage is critical for reconstructing attacker behaviour.
- MITRE ATT&CK offers a standardized framework for documenting investigations.
- Detection engineering is an iterative process that evolves as new techniques are observed.

---

# Future Improvements

Planned enhancements include:

- Microsoft Sentinel integration
- Wazuh SIEM integration
- Sigma rule development
- SOAR automation
- Threat Intelligence enrichment
- YARA rule development
- Multi-endpoint Active Directory environment
- Automated ATT&CK heatmap generation
- Windows 11 workstation joined to the domain for realistic lateral movement scenarios

---

# Repository Structure

```
Azure-Threat-Hunting-Detection-Engineering-Lab/

├── README.md
├── architecture/
├── screenshots/
│   ├── azure/
│   ├── limacharlie/
│   ├── sysmon/
│   ├── atomic/
│   └── incidents/
├── detections/
├── hunt-reports/
├── incident-reports/
├── iocs/
├── attack-simulations/
├── mitre/
├── timelines/
└── evidence/
```

---

# Disclaimer

This project was performed exclusively within an isolated Microsoft Azure laboratory environment.

All attack simulations were executed using Atomic Red Team for defensive research, detection engineering, and educational purposes.

No production systems, third-party infrastructure, or unauthorized targets were involved.
