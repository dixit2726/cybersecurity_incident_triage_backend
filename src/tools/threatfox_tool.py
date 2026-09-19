
import os
import pandas as pd
from langchain.tools import tool


# Path to the local ThreatFox dataset
DATASET_PATH = os.path.join(
    "data",
    "external",
    "misp",
    "Threat Intelligence Dataset.csv"
)


@tool
def threatfox_lookup(ioc: str) -> str:
    """
    Search the local ThreatFox dataset for an IOC.

    Use this tool to check whether an IP, domain, URL,
    or hash appears in the ThreatFox dataset.
    """

    try:
        df = pd.read_csv(DATASET_PATH)

        matches = df[df["ioc_value"].astype(str).str.lower() == ioc.lower()]

        if matches.empty:
            return f"No matching ThreatFox record found for {ioc}."

        results = []

        for _, row in matches.iterrows():
            results.append(
                {
                    "ioc": row["ioc_value"],
                    "ioc_type": row["ioc_type"],
                    "threat_type": row["threat_type"],
                    "malware": row["malware_printable"],
                    "confidence_level": row["confidence_level"],
                    "is_compromised": row["is_compromised"],
                    "first_seen": row["first_seen_utc"],
                    "last_seen": row["last_seen_utc"],
                }
            )

        return str(results)

    except Exception as e:
        return f"ThreatFox lookup error: {str(e)}"