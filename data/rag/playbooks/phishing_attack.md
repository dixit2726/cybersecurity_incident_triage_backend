# Playbook: Phishing Attack

## Incident Type
Social Engineering / Phishing & Spear-Phishing / Credential Harvester & Malicious Attachment

## Purpose
Provide guidance for SOC analysts to evaluate, investigate, contain, and remediate reported phishing emails, credential harvesting landing pages, weaponized attachments, and downstream compromise resulting from social engineering.

## Trigger Conditions
- User-reported suspicious email submitted via phishing reporting plugin or dedicated mailbox.
- Email gateway (SEG) alert detecting spoofed domain, suspicious attachment, known phishing URL, or DKIM/SPF/DMARC failure.
- Web proxy alert indicating an internal employee visited a newly registered domain (NRD) or known phishing site from an email link.
- Threat intelligence feed matching malicious domains or URLs delivered via email (such as URLhaus).

## Initial Triage
1. Review email message headers:
   - Sender address (`From:`, `Return-Path:`).
   - Sending server IP address and reverse DNS lookup.
   - SPF, DKIM, and DMARC authentication verification results.
   - Recipient list (`To:`, `Cc:`, `Bcc:`).
2. Examine the email body and lures:
   - Urgency indicators (e.g., password expiration, overdue invoice, urgent wire transfer, HR notification).
   - Display name spoofing (e.g., executive or trusted vendor impersonation).
3. Identify embedded artifacts:
   - Hyperlinks/URLs (including URL redirection or obfuscation services).
   - Attachments (e.g., ISO, ZIP, HTML, EXE, macro-enabled DOCM/XLSM, PDF with links).
4. Determine interaction scope:
   - Did any recipient open the attachment, click the link, or submit credentials?

## Investigation Steps
1. Query Secure Email Gateway (SEG) logs to determine the blast radius:
   - Identify how many mailboxes received the identical or related phishing message across the organization.
2. Analyze links:
   - Check destination URLs using safe reputation sandboxes and URL analysis services (URLhaus, VirusTotal).
   - Check if the page is a credential harvesting portal (e.g., fake Microsoft 365, Okta, or Google login).
3. Analyze attachments:
   - Compute MD5/SHA256 hashes of attachments and check against MalwareBazaar / VirusTotal.
   - Run attachments in an isolated dynamic analysis sandbox to observe process execution and network callback behavior.
4. Check web proxy and DNS telemetry:
   - Search for internal proxy requests to the identified phishing URL.
   - Identify specific users who navigated to the page and inspect HTTP POST request body sizes (indicating potential credential submission).
5. Check identity provider logs:
   - Inspect authentication attempts from the clicking user within 0-4 hours of email receipt.
   - Look for successful logins from anomalous geolocations, unfamiliar user-agents, or session hijacking indicators.

## Containment Steps
1. Email Purge:
   - Search and delete (soft or hard purge) the phishing email across all recipient mailboxes via email gateway or Microsoft Graph/PowerShell cmdlets.
2. Network and URL Blocking:
   - Add malicious URLs and domains to boundary web proxies, secure DNS resolvers, and endpoint protection web filtering blocklists.
3. Sender Domain/IP Blacklist:
   - Block offending sender IP addresses and malicious domains at the email security gateway.
4. Account Remediation (if credentials entered or suspected):
   - Immediately force password reset for the compromised account.
   - Invalidate all active browser sessions, OAuth tokens, and refresh tokens.
   - Revoke and re-verify registered MFA devices.

## Eradication Steps
1. If malicious attachment executed:
   - Isolate affected endpoint from network immediately.
   - Follow the Malware Infection Playbook for complete process termination and file eradication.
2. Review mailbox configuration of compromised user:
   - Inspect and delete unauthorized mailbox forwarding rules, inbox sweep rules, or delegate permissions created by the attacker.
3. Check for unauthorized OAuth application consent grants in the cloud directory and revoke non-approved applications.

## Recovery Steps
1. Restore sanitized email communication channel for any business operations impacted by email blocking.
2. Re-establish user account access following confirmed identity verification.
3. Conduct direct outreach or security awareness briefing with users who engaged with the phishing lure.
4. Monitor targeted accounts and outbound email traffic for suspicious outbound spam or anomalous activity for 14 days.

## Evidence to Collect
- Original raw email message exported in `.eml` or `.msg` format with full diagnostic headers.
- Screenshots of the phishing landing page captured in a safe sandbox.
- File hashes and sandbox execution reports of any weaponized attachments.
- Proxy logs showing outbound connections, timestamps, IP addresses, and user-agents of visiting clients.
- Authentication logs and session identifiers for any affected user accounts.

## Escalation Criteria
- An executive (C-level), finance administrator, or high-privilege IT administrator entered credentials into a phishing portal.
- An attacker successfully authenticated using harvested credentials and accessed internal resources or email contents.
- Malware attachment executed with active C2 communication or ransomware deployment.
- High-volume targeted business email compromise (BEC) involving fraudulent invoice modification or wire transfer redirection.

## Closure Criteria
- All instances of the phishing email have been completely purged from all enterprise mailboxes.
- Malicious domains, URLs, and sender addresses are blocked across perimeter defenses.
- All users who clicked links or submitted data have been identified, remediated, and secured.
- Any secondary attacker actions (malware execution, forwarding rules, OAuth grants) have been eliminated.
