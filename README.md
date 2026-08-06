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

## Incident 0001

Encoded PowerShell Execution

MITRE

```
T1059.001
```

Objectives

- Investigate encoded PowerShell
- Analyse parent-child relationships
- Review command-line arguments
- Validate Sysmon events
- Review LimaCharlie telemetry

Artifacts

- Screenshots
- Timeline
- IoCs
- Process Tree
- Detection Rule

📷 **Screenshot**

Atomic Test Execution

📷 **Screenshot**

LimaCharlie Timeline

📷 **Screenshot**

Process Tree

📷 **Screenshot**

Sysmon Event

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
