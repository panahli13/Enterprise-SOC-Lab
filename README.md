Enterprise SOC Laboratory & Purple Team Ecosystem
Domain: Cybersecurity | Role: SOC Analyst / Detection Engineer | Framework: MITRE ATT&CK | Architecture: Zero Trust | Defense-in-Depth

Project Overview
This project showcases an end-to-end, enterprise-grade SOC (Security Operations Center) Laboratory built from scratch. Designed with Zero Trust and Defense-in-Depth principles, this environment seamlessly integrates perimeter security, network segmentation, identity hardening, centralized telemetry, SIEM correlation, PAM, and threat hunting.
To validate the defense capabilities, Atomic Red Team was utilized to simulate real-world adversarial TTPs mapped to the MITRE ATT&CK framework, enabling a complete Purple Team feedback loop.

Infrastructure & Core Components
Network & Perimeter Security:
Palo Alto Networks NGFW: Configured L3 network interfaces, Zone Protection policies, Source NAT, and strict inter-zone firewall rules.
SafeLine WAF & DVWA: Protected web applications using reverse proxy architecture, actively mitigating SQL Injection (SQLi) and Cross-Site Scripting (XSS).
Cloudflare Tunnel & Email Security: Enforced Anti-DDoS protection via Cloudflare Tunnels, alongside Proxmox ESG and Postfix with SPF, DKIM, and DMARC enforcement.
Identity & Access Management (IAM) Hardening:
Active Directory Hardening: Implemented 25 critical Group Policy Objects (GPOs), including LSASS process protection, mandatory NTLMv2, SMB Signing, and CMD/Registry access restriction.
JumpServer PAM: Deployed Privileged Access Management enforcing mandatory 2FA/MFA, session recording, and credential vaulting for RDP/SSH access.
SIEM, XDR & Telemetry:
Wazuh XDR: Deployed agents across all endpoints in "Detect-Only" mode for full visibility, enabling File Integrity Monitoring (FIM), Security Configuration Assessment (SCA), and vulnerability evaluation.
Splunk Enterprise SIEM: Centralized log collection across Windows Event Logs, Syslog, Firewall, and WAF logs. Designed custom dashboards and SPL queries for threat detection.
Vulnerability & Disaster Recovery:
Nessus Scanner: Conducted credentialed vulnerability scans to identify and remediate host-level misconfigurations.
Disaster Recovery: Created automated PowerShell scripts for Active Directory System State backups and routine data archiving.

MITRE ATT&CK Mapping & Threat Hunting
10 core adversary TTPs were simulated using Atomic Red Team to test and refine detection rules in Splunk and Wazuh:
| Technique ID | Technique Name | Detection Source | Mitigation / Hardening |
| :--- | :--- | :--- | :--- |
| **T1003.001** | OS Credential Dumping: LSASS Memory | Sysmon / Splunk (SPL) | Enabled RunAsPPL & LSA Protection via GPO |
| **T1110.001** | Brute Force: Password Guessing | Windows Auth / Splunk | Account Lockout Threshold & PAM MFA |
| **T1070.001** | Indicator Removal: Clear Windows Event Logs | Event ID 1102 / Wazuh | Log Forwarding & Real-time Alerting |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Sysmon Event ID 1 | Script Block Logging & Constrained Language Mode |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Network Logs / Palo Alto | Enforced SMB Signing & Blocked Administrative Shares |
| **T1190** | Exploit Public-Facing Application | SafeLine WAF / Web Logs | WAF Rules & Input Sanitization |
| **T1087.002** | Account Discovery: Domain Account | Active Directory Audit | Restricted Domain Enumeration via Security Group |
| **T1562.001** | Impair Defenses: Disable Windows Defender | Registry / Sysmon | Restricted Local Admin Rights & Registry Modification GPO |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Sysmon Event ID 106 | System Task Creation Audit |
| **T1046** | Network Service Discovery | Palo Alto / Firewall Logs | Micro-segmentation & Zone Protection |
## Sample Detection Rules (Splunk SPL)

### 1. Detection of LSASS Memory Dumping Attempt (Splunk SPL)

<pre><code>index=win_logs EventCode=10 TargetImage="*lsass.exe*"
| stats count by SourceImage, TargetImage, GrantedAccess, Computer
| where GrantedAccess="0x1010" OR GrantedAccess="0x1F0FFF"</code></pre>

### 2. Brute-Force Attack Detection (Splunk SPL)

<pre><code>index=win_logs EventCode=4625
| stats count by TargetUserName, WorkstationName, Source_Network_Address
| where count > 5</code></pre>

---

## Repository Structure

<pre><code>.
├── docs/                   # Architecture diagrams & Full SOC Report (PDF)
├── splunk-queries/         # Custom SPL rules for detection engineering
├── wazuh-rules/            # Custom XML rules for Wazuh XDR
├── scripts/                # PowerShell backup scripts & Hardening automation
└── README.md               # Main project documentation</code></pre>

---

## Author

<b>Pənah Pənahlı</b><br>
<i>Cybersecurity Student / SOC Analyst</i><br>
<b>LinkedIn:</b> https://www.linkedin.com/in/panah-panahli<br>
<b>Email:</b> p.panahli13@gmail.com<br><br>

<i>Disclaimer: This laboratory environment was built strictly for educational and security research purposes. All attack simulations were executed within an isolated lab network.</i>
