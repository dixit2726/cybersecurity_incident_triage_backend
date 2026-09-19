import re
from typing import Any, Dict, List, Optional, Set


class AlertParser:
    """
    Deterministic rule-based parser for cybersecurity incident alerts.
    Extracts structured alert metadata, network context, behavioral evidence,
    IOC evidence, situational context, and recommended initial actions.
    """

    def __init__(self):
        # Regex pattern for IPv4 addresses
        self._ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        # Regex for URLs
        self._url_pattern = re.compile(r"https?://[^\s<>\"',;()]+", re.IGNORECASE)

        # Regex for Emails
        self._email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )

        # Regex for Domains
        # Excludes standard file extensions, IPs, and common protocol names
        self._domain_pattern = re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|co|ai|info|biz|ru|cn|de|uk|jp|xyz|me|top|live|online|site)\b",
            re.IGNORECASE,
        )

    def parse(self, alert_text: str) -> Dict[str, Any]:
        """
        Parse raw alert text into a structured dictionary.
        """
        if not isinstance(alert_text, str):
            raise TypeError("Alert input must be a string.")

        if not alert_text or not alert_text.strip():
            raise ValueError("Alert input cannot be empty.")

        # 1. Parse Key-Value fields and multi-line sections
        fields = self._extract_key_values(alert_text)

        # 2. Extract Alert Metadata
        alert_metadata = {
            "alert_id": fields.get("alert_id") or fields.get("id"),
            "timestamp": fields.get("timestamp") or fields.get("time") or fields.get("date"),
            "severity": fields.get("severity") or fields.get("alert_severity"),
            "event_type": fields.get("event_type") or fields.get("event"),
            "attack_category": fields.get("attack_category") or fields.get("category"),
            "status": fields.get("status") or fields.get("alert_status"),
        }

        # 3. Extract Network Context
        network_context = {
            "source_ip": fields.get("source_ip") or fields.get("src_ip"),
            "destination_ip": fields.get("destination_ip") or fields.get("dst_ip"),
            "protocol": fields.get("protocol"),
            "destination_port": fields.get("destination_port") or fields.get("dst_port") or fields.get("port"),
        }

        # Fallback for destination port if missing from key-values
        if not network_context["destination_port"]:
            port_match = re.search(r"(?:Destination Port|Dst Port|Port)\s*:\s*(\d+)", alert_text, re.IGNORECASE)
            if port_match:
                network_context["destination_port"] = port_match.group(1).strip()

        # 4. Extract Situational Context
        context = {
            "target_service": fields.get("target_service") or fields.get("service"),
            "target_account": fields.get("target_account") or fields.get("account") or fields.get("user"),
            "failed_login_attempts": fields.get("failed_login_attempts") or fields.get("failed_logins") or fields.get("attempts"),
            "time_window": fields.get("time_window") or fields.get("window"),
        }

        # 5. Extract Recommended Initial Action
        recommended_action = fields.get("recommended_initial_action") or fields.get("recommended_action") or fields.get("initial_action")

        # 6. Extract Behavioral Evidence
        behavioral_evidence = self._extract_behavioral_evidence(alert_text, fields)

        # 7. Extract IOC Evidence
        ioc_evidence = self._extract_iocs(alert_text)

        return {
            "alert_metadata": alert_metadata,
            "network_context": network_context,
            "behavioral_evidence": behavioral_evidence,
            "ioc_evidence": ioc_evidence,
            "context": context,
            "recommended_initial_action": recommended_action,
        }

    def _extract_key_values(self, text: str) -> Dict[str, str]:
        """
        Extract labeled key-value lines and multi-line section values.
        """
        fields: Dict[str, str] = {}
        lines = [line.strip() for line in text.splitlines()]

        # Identify major known section headers that span multiple lines or paragraphs
        section_headers = [
            "Alert Description",
            "Recommended Initial Action",
            "Recommended Action",
            "Authentication Details",
            "Network Details",
            "Initial Action",
        ]

        # First pass: identify line-by-line key: value pairs
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line:
                i += 1
                continue

            # Check if line matches a multi-line section header
            matched_section = None
            for sh in section_headers:
                if re.match(rf"^(?:[-*]\s*)?{re.escape(sh)}\s*:\s*(.*)$", line, re.IGNORECASE):
                    matched_section = sh
                    break

            if matched_section:
                # Capture header value on the same line if present
                m = re.match(rf"^(?:[-*]\s*)?{re.escape(matched_section)}\s*:\s*(.*)$", line, re.IGNORECASE)
                first_part = m.group(1).strip() if m else ""
                section_lines = [first_part] if first_part else []

                # Accumulate following lines until next key: value header or empty line
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    if not next_line:
                        # Empty line might delimit section unless followed by continuation
                        i += 1
                        break
                    # If next line looks like a new "Header: Value", stop multi-line capture
                    if re.match(r"^[A-Z][A-Za-z0-9 _/-]+?\s*:\s*.+$", next_line):
                        break
                    section_lines.append(next_line)
                    i += 1

                normalized_key = matched_section.lower().replace(" ", "_")
                fields[normalized_key] = " ".join(section_lines).strip()
                continue

            # Standard Key: Value line
            kv_match = re.match(r"^(?:[-*]\s*)?([A-Za-z0-9 _/-]+?)\s*:\s*(.*)$", line)
            if kv_match:
                raw_key = kv_match.group(1).strip().lower().replace(" ", "_").replace("-", "_")
                val = kv_match.group(2).strip()
                fields[raw_key] = val

            i += 1

        return fields

    def _extract_behavioral_evidence(
        self, alert_text: str, fields: Dict[str, str]
    ) -> List[str]:
        """
        Extract sentences and statements describing adversary behavior and suspicious activity.
        """
        evidence: List[str] = []

        # 1. From Alert Description
        alert_desc = fields.get("alert_description", "")
        if alert_desc:
            # Split sentences ending with periods or semicolons
            sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", alert_desc) if s.strip()]
            for sentence in sentences:
                if len(sentence) > 10 and sentence not in evidence:
                    evidence.append(sentence)

        # 2. From bullet-pointed details (e.g. Authentication Details, Network Details)
        detail_lines = re.findall(r"^\s*[-*•]\s*(.+)$", alert_text, re.MULTILINE)
        for line in detail_lines:
            clean_line = line.strip()
            # Filter out non-behavioral bullets like key: value pairs
            if ":" not in clean_line or re.search(r"(detected|registered|login|activity|denies|transfer|beacon|attempt)", clean_line, re.I):
                if len(clean_line) > 5 and clean_line not in evidence:
                    evidence.append(clean_line)

        # 3. If still empty, search for descriptive sentences in the full text
        if not evidence:
            for line in alert_text.splitlines():
                line_clean = line.strip()
                if (
                    re.search(r"\b(failed|detected|attempt|compromis|suspicious|beacon|unusual|executed|downloaded)\b", line_clean, re.I)
                    and not line_clean.startswith("Recommended")
                    and not line_clean.startswith("Alert ID")
                    and not line_clean.startswith("Timestamp")
                ):
                    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", line_clean) if s.strip()]
                    for s in sentences:
                        if len(s) > 10 and s not in evidence:
                            evidence.append(s)

        return evidence

    def _extract_iocs(self, text: str) -> List[Dict[str, str]]:
        """
        Extract indicators of compromise: IPs, hashes, URLs, domains, emails.
        """
        iocs: List[Dict[str, str]] = []
        seen: Set[str] = set()

        def add_ioc(ioc_type: str, val: str):
            clean_val = val.strip().rstrip(".,;!?'\")>]")
            key = (ioc_type, clean_val.lower())
            if clean_val and key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": clean_val})

        # 1. Extract URLs
        for url in self._url_pattern.findall(text):
            add_ioc("url", url)

        # 2. Extract Emails
        for email in self._email_pattern.findall(text):
            add_ioc("email", email)

        # 3. Extract IPv4 Addresses (validating octet range 0-255)
        for ip in self._ip_pattern.findall(text):
            parts = ip.split(".")
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                add_ioc("ip", ip)

        # 4. Extract Hashes (MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex)
        # Tokenize by word boundaries
        hex_tokens = re.findall(r"\b[a-fA-F0-9]+\b", text)
        for token in hex_tokens:
            token_len = len(token)
            # Avoid matching pure numeric strings or small words
            if token.isdigit():
                continue
            if token_len == 64:
                add_ioc("hash", token.lower())
            elif token_len == 40:
                add_ioc("hash", token.lower())
            elif token_len == 32:
                add_ioc("hash", token.lower())

        # 5. Extract Domains (excluding matches that are part of extracted URLs or emails)
        for domain in self._domain_pattern.findall(text):
            domain_clean = domain.strip().lower()
            # Avoid matching IP-like or already captured URL hostnames
            if not self._ip_pattern.fullmatch(domain_clean):
                # Ensure it wasn't an email domain or part of an already extracted URL
                if not any(domain_clean in seen_item[1] for seen_item in seen if seen_item[0] in ("url", "email")):
                    add_ioc("domain", domain_clean)

        return iocs
