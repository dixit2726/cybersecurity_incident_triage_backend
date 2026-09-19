# Playbook: Suspicious PowerShell Execution

## Incident Type
Execution / Defense Evasion / Suspicious Scripting / Living Off The Land (LotL) / PowerShell Abuse

## Purpose
Provide structured guidance for SOC analysts to investigate, validate, contain, and remediate suspicious, obfuscated, or unauthorized PowerShell activity detected on Windows endpoints and servers.

## Trigger Conditions
- EDR or SIEM alert for PowerShell execution with high-risk command-line switches:
  - Base64 encoded commands (`-e`, `-enc`, `-encodedcommand`).
  - Execution policy bypass (`-ep bypass`, `-executionpolicy bypass`, `-noprofile`, `-windowstyle hidden`).
  - In-memory download cradles (`DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`).
- Process creation alert where PowerShell is spawned by an unexpected parent process (e.g., `winword.exe`, `excel.exe`, `wmiprvse.exe`, `w3wp.exe`, `sqlservr.exe`, `svchost.exe`).
- Script block logging (Event ID 4104) containing known attack framework keywords (e.g., `Mimikatz`, `Invoke-Shellcode`, `BloodHound`, `Empire`, `Cobalt Strike`).
- Execution of commands manipulating system startup, services, scheduled tasks (`schtasks.exe`), or registry run keys via PowerShell.

## Initial Triage
1. Review the alert details: host name, user account context (user vs. SYSTEM / service account), parent process name, process ID, execution time, and full command line string.
2. Examine the parent-child process relationship:
   - Legitimate admin tool (e.g., SCCM, PDQ, InTune) vs. non-standard parent (e.g., Office application, web browser, external service).
3. Check for obfuscation:
   - If an encoded command (`-EncodedCommand`) is present, decode the Base64 Unicode string into readable ASCII text.
4. Determine whether the script was executed interactively by a logged-in user or automatically by a background process/service.
5. Verify if the activity corresponds to documented maintenance windows, IT scripts, or standard system administrator duties.

## Investigation Steps
1. Decode and analyze the script payload:
   - Decode Base64 strings, nested functions, or string concatenation routines.
   - Identify targets of the script: downloaded URLs, dropped files, registry modifications, API calls, or network sockets opened.
2. Review PowerShell Event Logs:
   - Event ID 4104 (Script Block Logging) to see the full, de-obfuscated script content that was executed.
   - Event ID 4103 (Module Logging) and Event ID 400 (Engine Lifecycle).
3. Investigate process actions:
   - Check what child processes were spawned by PowerShell (e.g., `cmd.exe`, `schtasks.exe`, `whoami.exe`, `net.exe`, `reg.exe`).
   - Identify any files created or modified in directories such as `C:\Windows\Temp\`, `C:\ProgramData\`, or user `%APPDATA%`.
4. Inspect network connections:
   - Correlate timestamps with firewall, EDR network events, or proxy logs to detect external outbound network connections initiated by the PowerShell PID.
   - Check destination IP/domain reputation against ThreatFox or URLhaus.
5. Check for persistence and credential access:
   - Look for commands modifying registry keys, registering scheduled tasks, dumping credentials from LSASS, or querying Active Directory.

## Containment Steps
1. Process Termination:
   - Kill the suspicious PowerShell process and all associated child process trees immediately.
2. Host Isolation:
   - If the script executed an unknown remote payload, downloaded a secondary binary, or initiated unauthorized network connections, isolate the host from the network via EDR.
3. Network Block:
   - Block any external IP addresses, domains, or download URLs referenced in the script at the perimeter firewall and web proxy.
4. Account Credential Protection:
   - If the PowerShell process ran under a privileged user or service account, immediately revoke active tokens and trigger an emergency password reset.

## Eradication Steps
1. Remove all files, staging directories, or scripts dropped to the file system during the PowerShell execution.
2. Remove any persistence mechanisms established:
   - Delete scheduled tasks created by the script (e.g., via `schtasks /delete /tn ...`).
   - Remove unauthorized registry entries created in Run/RunOnce or services.
3. Verify that any altered security settings (e.g., Windows Defender exclusions or disabled firewall profiles) are restored to hardened baseline standards.
4. Run an EDR and antivirus scan across the entire system.

## Recovery Steps
1. Validate system integrity by confirming no unauthorized background jobs or hidden processes remain active.
2. Remove the host from network isolation once the machine has been fully cleaned and verified.
3. If the script was part of legitimate administration that triggered false positive alerts, work with the systems engineering team to sign scripts with internal certificates and establish appropriate EDR tuning rules.
4. Monitor endpoint process execution logs for 7 days for recurring anomalous PowerShell sessions.

## Evidence to Collect
- Full command-line arguments and decoded Base64 script content.
- PowerShell Event Logs (Event IDs 4104, 4103, 400, 800) covering the incident window.
- EDR process telemetry: parent process chain, spawned processes, file writes, and network connections.
- Hashes and file samples of any scripts or payloads written to disk.
- Memory dump of the host if in-memory-only reflective DLL injection or beaconing is suspected.

## Escalation Criteria
- PowerShell execution resulted in a successful in-memory Cobalt Strike / Meterpreter beacon or active C2 channel.
- Credential harvesting commands targeted `lsass.exe` or exported Active Directory ntds.dit.
- The script performed lateral movement across the network using WinRM, WMI, or PsExec.
- Execution occurred on high-value infrastructure (e.g., Active Directory Domain Controllers, PKI servers).

## Closure Criteria
- Suspicious PowerShell processes have been terminated and root-cause script or entry vector identified.
- All dropped files, persistence entries (scheduled tasks, services, registry keys), and network connections are eradicated.
- Enterprise-wide sweep confirms no other systems were impacted by the same script or download cradle.
- Post-remediation verification confirms normal operational status with no secondary alerts.
