# Playbook: Suspicious IP and Network Activity

## Incident Type
Network Security / Command and Control (C2) / Exfiltration / Malicious IP Communication & Scanning

## Purpose
Provide standardized response workflows for SOC analysts to investigate, triage, contain, and remediate alerts involving communications with suspicious, blacklisted, or anomalous external IP addresses, port scanning, data exfiltration, or external intrusion attempts.

## Trigger Conditions
- Network Intrusion Detection/Prevention System (NIDS/NIPS) alert indicating outbound connection to known Command and Control (C2) IP or botnet node.
- Firewall or NetFlow alert indicating abnormal outbound data volume transfer (potential data exfiltration) to an external IP.
- Threat intelligence match on external IP address against active threat feeds (e.g., ThreatFox, AbuseIPDB, internal threat intel).
- Internal or external port scanning, brute force sweeps, or vulnerability probing detected across network segments.
- Detection of beaconing behavior (periodic, regular interval communication) to an uncategorized external IP.

## Initial Triage
1. Identify communication endpoints: internal source IP/hostname, source port, external destination IP, destination port, transport protocol (TCP/UDP/ICMP), and total bytes transferred.
2. Determine directionality: inbound attack attempt vs. outbound connection from internal host.
3. Query threat intelligence platforms (ThreatFox, AbuseIPDB, VirusTotal, Shodan, WHOIS) to analyze destination IP:
   - Reputation score, known threat actor associations, malware family attribution, hosting provider (bulletproof host, cloud provider, Tor exit node, residential proxy).
4. Identify internal asset context: workstation, server, network appliance, or guest Wi-Fi device.
5. Identify the initiating internal process name and PID via EDR or network socket telemetry.

## Investigation Steps
1. Analyze network flow and firewall logs:
   - Determine connection history: first seen timestamp, connection frequency, duration, and volume of data sent vs. received.
   - Inspect communication patterns for beaconing intervals, jitter, or keep-alive pulses characteristic of C2 frameworks.
2. Inspect application layer data (if available via Proxy, TLS inspection, or PCAP):
   - Review HTTP/HTTPS request headers, user-agent strings, URI paths, and domain names (SNI / HTTP Host header).
   - Check if the traffic encapsulates unauthorized protocols (e.g., DNS tunneling, ICMP tunneling, SSH over non-standard ports).
3. Correlate with endpoint telemetry:
   - Identify which executable or service initiated the outbound socket connection on the host.
   - Check if the executable is a recognized system binary (`svchost.exe`, `powershell.exe`, `rundll32.exe`) or an unknown dropped binary in `%TEMP%` or `%APPDATA%`.
   - Inspect parent process and command line arguments.
4. Scope across the enterprise:
   - Search firewall, proxy, and DNS logs across all internal network segments to identify any other internal hosts communicating with the same external IP address or subnet.
5. Assess exfiltration risk:
   - Calculate total data egress volume to the destination IP.
   - Cross-reference with internal file access logs or archive creation utilities (`7z.exe`, `rar.exe`) executed shortly before the transfer.

## Containment Steps
1. Network Perimeter Blocking:
   - Immediately apply an egress and ingress block rule for the malicious external IP address and associated subnet on boundary firewalls and security gateways.
2. Proxy and DNS Sinkhole:
   - Add associated domain names or IP addresses to enterprise DNS sinkhole resolvers and web proxy blocklists.
3. Host Isolation:
   - If outbound C2 communication or active beaconing is confirmed from an internal endpoint, isolate the host from the network using EDR.
4. Routing / Null-Route:
   - In cases of heavy incoming DDoS or distributed scanning, coordinate with network engineering to null-route or blackhole traffic at border routers.

## Eradication Steps
1. Terminate any active network sessions, malicious processes, or unauthorized daemons on the affected internal host.
2. Remove dropped malware payloads, staging archives, or unauthorized tools identified during the endpoint investigation.
3. Eliminate any persistence mechanisms (scheduled tasks, services, startup registry entries) linked to the malicious process.
4. If a vulnerability on an exposed server was exploited to initiate the connection, apply vendor security patches or disable vulnerable services immediately.

## Recovery Steps
1. Validate network firewall and proxy policy changes to confirm the block rule is actively dropping traffic without disrupting legitimate business dependencies.
2. Reconnect the remediated internal host to the network after confirming clean EDR scans and absence of anomalous network connections.
3. Verify that all internal and external DNS resolutions for the affected host resolve strictly to legitimate authorized destinations.
4. Monitor perimeter firewall logs and host network telemetry for 14 days for repeated connection attempts to the blocked IP or related infrastructure.

## Evidence to Collect
- Packet captures (PCAP files) or NetFlow records capturing connection handshakes, timestamps, payloads, and volume.
- Firewall, proxy, and DNS log extracts documenting complete communication history with the external IP.
- Threat intelligence reports from ThreatFox, AbuseIPDB, and WHOIS records detailing the IP registration and historical threat records.
- EDR process telemetry linking network sockets to specific local processes, hashes, and command lines.
- List of internal files accessed or staged prior to any detected large outbound data transfers.

## Escalation Criteria
- Outbound network traffic is confirmed to be an active Command and Control (C2) channel for a known ransomware or APT group.
- Substantial data egress volume (gigabytes or terabytes) detected from sensitive file repositories or database servers to an untrusted external IP.
- The external IP address successfully exploited an externally facing critical enterprise system.
- Multiple internal systems across different subnets are simultaneously beaconing to the same external infrastructure, indicating widespread lateral spread.

## Closure Criteria
- Malicious external IP addresses and associated infrastructure are blocked across all perimeter security devices.
- All internal hosts communicating with the malicious IP have been identified, contained, investigated, and cleared of malware.
- Data exfiltration assessments are completed and findings reported to relevant incident stakeholders.
- Perimeter and internal network telemetry confirms complete cessation of communication to the malicious IP.
