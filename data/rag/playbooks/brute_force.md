# Playbook: Brute Force Attack

## Incident Type
Authentication Anomaly / Credential Access / Brute Force & Password Spraying

## Purpose
Provide security operations center (SOC) analysts with a standardized workflow to detect, investigate, contain, eradicate, and recover from automated or manual brute force authentication attempts against corporate accounts, endpoints, VPNs, and cloud services.

## Trigger Conditions
- High volume of failed authentication attempts within a short time window originating from single or distributed IP addresses.
- Account lockout alerts triggered across multiple user accounts simultaneously or sequentially.
- Sudden spike in failed logins followed by a successful authentication on an external service (SSH, RDP, VPN, Web Portal).
- SIEM, EDR, or Identity Provider (IdP) rule detections for Password Guessing, Password Spraying, or Dictionary Attacks.

## Initial Triage
1. Review the alert metadata to identify targeted usernames, source IP address(es), geographic origin, targeted protocols/applications, and timestamp interval.
2. Determine whether the attack is targeted at a single account (traditional brute force) or spread across many accounts using common passwords (password spraying).
3. Check authentication status: confirm if all attempts were failed or if any attempt succeeded during or immediately following the surge.
4. Verify if the targeted account is an active employee, service account, privileged administrator, or deactivated user.
5. Check if the source IP is known internal infrastructure, vulnerability scanner, or external public IP.

## Investigation Steps
1. Correlate authentication logs across Active Directory/IdP, VPN gateways, firewall logs, and single sign-on (SSO) systems for the same time frame.
2. Query threat intelligence sources (such as ThreatFox, AbuseIPDB, or internal blocklists) to check the reputation of the external source IP addresses.
3. If an authentication attempt succeeded:
   - Identify the specific account compromised.
   - Inspect post-authentication session telemetry: IP address, user-agent, MFA prompt response time, and MFA method used.
   - Check if the login occurred from an anomalous location or impossible travel scenario.
   - Examine subsequent endpoint and cloud activity for privilege escalation, reconnaissance, or data access within the authenticated session.
4. If password spraying is suspected, identify the full list of accounts targeted in the spray pattern.
5. Check for signs of MFA fatigue/push spamming where repeated prompts were pushed to force user approval.

## Containment Steps
1. If an account had a successful login during the attack:
   - Immediately disable or lock the compromised user account in the directory service.
   - Terminate all active sessions and revoke existing authentication tokens/refresh tokens.
   - Reset the account password and revoke/re-enroll MFA devices.
2. If the attack originates from discrete external IP addresses:
   - Temporarily block the offending source IP address(es) at the perimeter firewall or web application firewall (WAF).
3. If targeted against an exposed administrative port (such as external RDP/SSH):
   - Restrict access to authorized management networks or require VPN access.
4. If account lockout thresholds are not enforced, coordinate temporary lockout policy enforcement to prevent continuous password guessing.

## Eradication Steps
1. Remove any persistence mechanisms created during an authenticated session (e.g., newly registered MFA factors, OAuth app grants, inbox forwarding rules).
2. Scan endpoints accessed by the compromised user for dropped tools, webshells, or unauthorized software.
3. Validate that no secondary backdoor accounts were created during the compromise window.
4. Ensure all affected accounts have completed a verified out-of-band password change.

## Recovery Steps
1. Re-enable the user account following out-of-band identity verification with the account owner.
2. Confirm successful re-enrollment of Multi-Factor Authentication with phishing-resistant or authenticator app methods.
3. Restore any altered configurations or access controls to a verified baseline state.
4. Place enhanced monitoring and alerting on the affected user account for 7 to 14 days.

## Evidence to Collect
- Authentication log excerpts showing timestamp, username, source IP, user-agent, result code, and failure reason.
- Firewall and proxy session records associated with the attacker IP addresses.
- Threat intelligence reputation reports for offending IP addresses.
- MFA server logs showing push notifications, approvals, or denials.
- Post-compromise process execution logs and security event logs if access succeeded.

## Escalation Criteria
- An authentication attempt succeeded on an account with domain administrator or privileged access.
- Widespread password spraying succeeded across multiple enterprise accounts simultaneously.
- Host telemetry indicates successful lateral movement, credential dumping, or data exfiltration following authentication.
- Source IP infrastructure is attributed to a known Advanced Persistent Threat (APT) group or active ransomware campaign.

## Closure Criteria
- All authentication attempts from the attacker source have ceased or are effectively blocked.
- Confirmed that no unauthorized logins succeeded, or all compromised accounts were isolated, remediated, and verified.
- Persistence mechanisms and post-exploitation artifacts have been thoroughly identified and eliminated.
- Post-incident monitoring shows normal baseline authentication patterns for affected identities.
