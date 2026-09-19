# Playbook: Credential Compromise

## Incident Type
Identity & Access / Credential Access / Account Takeover (ATO) / Unauthorized Access

## Purpose
Provide a standardized procedure for SOC analysts to investigate, contain, remediate, and recover from confirmed or suspected user and service account compromises, unauthorized access sessions, and credential dumping events.

## Trigger Conditions
- Identity Provider (IdP) risk detection (e.g., Leaked Credentials, Atypical Travel, Impossible Travel, Anomalous Token, Suspicious Browser Session).
- EDR alert for credential dumping tools or memory access against `lsass.exe`, SAM registry hives, or browser credential databases.
- External threat intelligence or dark web breach intelligence reporting active enterprise credentials in credential leak dumps.
- Multiple successful logins from unfamiliar international geographic locations without registered business travel.
- Multiple failed MFA attempts followed by an unexpected MFA registration or successful login.

## Initial Triage
1. Identify the compromised account: username, user role, department, privilege level (standard user vs. local admin vs. domain admin vs. cloud global admin).
2. Gather initial authentication indicators: source IP, country, device ID, user-agent, authentication protocol, and timestamp of the alert.
3. Determine if the detection is based on:
   - External remote login (e.g., VPN, Microsoft 365, AWS Console, Okta).
   - Local endpoint credential harvesting (e.g., Mimikatz, ProcDump, secretsdump).
   - Third-party public breach notification.
4. Check if the user is actively working, traveling, or using an authorized enterprise VPN/proxy.

## Investigation Steps
1. Review Identity and Access Management (IAM) audit logs for the preceding 14 days:
   - Analyze logon history: list all source IP addresses, client applications, and operating systems used.
   - Look for changes to user account settings: secondary email additions, mobile number changes, or newly enrolled MFA devices / FIDO keys.
2. Check email activity (if email/cloud mailbox access occurred):
   - Review inbox rules for forwarding, redirection, or deletion rules (e.g., rules hiding emails containing words like "phish", "invoice", "payment", "alert").
   - Inspect sent items for outgoing phishing or fraudulent payment redirection messages sent from the compromised account.
3. Review cloud resource / application access:
   - Check file access logs (SharePoint, OneDrive, Google Drive, AWS S3) for bulk file downloads, permission modifications, or sensitive data exports.
   - Review administrative actions: role assignments, new user creations, or OAuth application consents.
4. Correlate with endpoint telemetry:
   - If internal host access occurred, examine process execution, network connections, and remote desktop (RDP) sessions initiated by the compromised identity.
   - Check if the account was used to execute commands on other endpoints (lateral movement).
5. Cross-reference source IP addresses against threat intelligence feeds (ThreatFox, AbuseIPDB) to identify proxies, VPN exit nodes, or known botnet infrastructure.

## Containment Steps
1. Account Disablement / Lockout:
   - Immediately disable or lock the compromised user account in Active Directory and cloud identity provider.
2. Session Invalidation:
   - Revoke all active user sessions, refresh tokens, browser cookies, and OAuth authorizations across all integrated services.
3. Password & Secret Reset:
   - Force an immediate password reset via administrative override.
4. MFA Quarantine:
   - Remove any newly added or unrecognized MFA authentication devices or phone numbers from the user profile.
5. IP Blocking:
   - Block malicious source IP addresses at perimeter firewalls and identity conditional access policies.

## Eradication Steps
1. Remove all persistence mechanisms added by the attacker:
   - Delete unauthorized inbox forwarding or redirection rules.
   - Remove newly created administrator roles, user accounts, or service principals.
   - Revoke any unauthorized enterprise applications or third-party OAuth app consents granted during the breach.
2. If credentials were dumped from an endpoint:
   - Re-image or completely clean the host where the dumping tool was executed.
   - Reset credentials for ALL accounts that had logged into that compromised host within the past 30 days.
3. Verify that no secondary backdoors or scheduled tasks were established under the user's context.

## Recovery Steps
1. Re-enable the account following direct out-of-band identity verification with the employee (via verified phone call or manager confirmation).
2. Assist user with re-enrolling a fresh MFA factor using an approved, phishing-resistant method.
3. Confirm that account privileges and group memberships accurately reflect the user's legitimate role.
4. Notify affected business units if sensitive documents or internal communications were accessed or altered.
5. Place the account under enhanced logging and monitoring for 30 days.

## Evidence to Collect
- IAM / IdP authentication and audit logs covering 14 days prior to the alert through containment.
- List of IP addresses, geolocation data, and user-agents utilized by the unauthorized actor.
- Export of mailbox rules, forwarded message logs, and modified cloud configurations.
- Audit trail of any files downloaded, accessed, or modified during the unauthorized session.
- EDR process and connection logs from endpoints accessed by the compromised account.

## Escalation Criteria
- Compromised account holds domain administrative, cloud global administrative, or root privileges.
- Attacker accessed confidential intellectual property, financial systems, or sensitive customer data (PII/PHI).
- Evidence of active lateral movement to high-value servers or domain controllers using the compromised credentials.
- Discovery of enterprise-wide credential exposure (e.g., NTDS.dit exfiltration, Kerberoasting on privileged service accounts).

## Closure Criteria
- Compromised credentials have been reset and all active sessions revoked.
- All attacker-added persistence factors (MFA devices, inbox rules, app grants) have been removed and verified.
- Confirmed that no ongoing unauthorized authentication attempts are succeeding.
- Blast radius has been fully scoped, documented, and remediated across on-premises and cloud environments.
