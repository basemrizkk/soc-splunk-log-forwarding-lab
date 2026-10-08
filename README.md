# SOC Log Forwarding Lab: Apache, Active Directory, Sysmon and PowerShell Logs to Splunk

A hands-on SOC engineering lab covering log collection, forwarding and detection in Splunk Enterprise. It has two parts: web server telemetry from a Linux host, and endpoint and identity telemetry from a Windows Server domain controller.

Step-by-step walkthroughs with screenshots:

- [Task 1: Apache access logs to Splunk](docs/Task_1_Apache_Access_Logs_to_Splunk.pdf)
- [Task 2: AD, Sysmon and PowerShell logs to Splunk](docs/Task_2_AD_Sysmon_and_PowerShell_Logs_to_Splunk.pdf)

## Lab environment

| Role | System | Notes |
|---|---|---|
| SIEM | Splunk Enterprise | Dedicated indexes: `web_applications`, `linux`, `win_server` |
| Web server | Ubuntu with Apache 2.4.58 | Splunk Universal Forwarder on Linux |
| Attacker | Kali Linux with Nmap 7.95 | Used to generate scan traffic |
| Domain controller | Windows Server (`PCD22.admin.local`) | Sysmon, PowerShell logging, Splunk Universal Forwarder |

## Task 1: Linux and Apache access logs to Splunk

**Objective:** monitor web server traffic, forward the access log to Splunk and detect suspicious requests.

1. Installed Apache2 and confirmed the service is active and enabled.
2. Created the `web_applications` events index in Splunk.
3. Added `/var/log/apache2/access.log` as a monitored input on the Universal Forwarder and routed it to that index.
4. Generated normal browser traffic, then ran Nmap scans (SYN scan and a full TCP connect scan with service and OS detection) from Kali.
5. Confirmed the scan is visible in Splunk. Requests such as `/HNAP1` and `POST /sdk` carry the Nmap Scripting Engine user agent.
6. Created an alert named `Nmap Scanning`, real-time with a per-result trigger. It triggered twice, five seconds apart, with Medium severity.

Search used to review the data:

```
index="web_applications"
```

Forwarder configuration: [`task1-apache/inputs.conf`](task1-apache/inputs.conf)

## Task 2: Windows Active Directory, PowerShell and Sysmon logs to Splunk

**Objective:** collect endpoint telemetry and domain controller events for threat hunting.

1. Installed Sysmon (v15.22) on the domain controller and verified that the `Sysmon64` service is running and that events appear in the `Microsoft-Windows-Sysmon/Operational` log.
2. Enabled PowerShell Module Logging, Script Block Logging and Transcription through Group Policy, then applied the policy with `gpupdate /force`.
3. Ran `Get-Date` in an elevated PowerShell session and confirmed Event ID 4104 (script block) in Event Viewer.
4. Installed OpenSSH on the server, copied the Splunk Universal Forwarder installer over SFTP and installed it.
5. Created the `win_server` index and configured the forwarder to send the Application, Security, System, PowerShell, Windows PowerShell, Windows Defender and Sysmon logs to it. The Security, PowerShell Operational and Sysmon inputs use `renderXml = 1`, so those events arrive in Splunk as XML.
6. Verified ingestion in Splunk and ran searches against the PowerShell and Sysmon data. A search-time `EventCode` field was extracted from the Sysmon XML events.

Searches used:

```
index="win_server"
index="win_server" EventCode=4104 Message="*Get-Date*"
index="win_server" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Forwarder configuration: [`task2-windows/inputs.conf`](task2-windows/inputs.conf)

## Results

| Area | Outcome |
|---|---|
| Apache access log | Forwarded to `web_applications`, scan activity identifiable by user agent and request pattern |
| Detection | Real-time alert triggered on Nmap scanning activity |
| Windows telemetry | About 15,000 events in `win_server` from seven log sources, led by Security, System, Sysmon and PowerShell Operational |
| PowerShell | Script block content (Event ID 4104) searchable in Splunk |
| Sysmon | About 2,100 events ingested, mainly Process Create (1) and Process Terminated (5) |

## What I learned

- How a Universal Forwarder maps log sources to indexes through `inputs.conf`.
- Why separate indexes per data source make searching and access control simpler.
- How Group Policy controls PowerShell logging and how Event ID 4104 exposes executed script content.
- How scanner activity shows up in web logs and how to turn that into a detection.

## Next steps

- Apply a tuned Sysmon configuration to capture network connections (Event ID 3) and more detail on process activity.
- Build searches and alerts for Active Directory authentication events such as 4624, 4625 and account changes.
- Add field extractions and a dashboard for the Sysmon and PowerShell data.

## Repository structure

```
.
├── README.md
├── docs/
│   ├── Task_1_Apache_Access_Logs_to_Splunk.pdf
│   └── Task_2_AD_Sysmon_and_PowerShell_Logs_to_Splunk.pdf
├── task1-apache/
│   └── inputs.conf
└── task2-windows/
    ├── inputs.conf
    └── inputs-conf-screenshot.png
```
