import os
import pandas as pd
from langchain.tools import tool


# Path to the local URLhaus dataset
DATASET_PATH = os.path.join(
    "data",
    "external",
    "misp",
    "Malicious URL Dataset.csv"
)


@tool
def urlhaus_lookup(url: str) -> str:
    """
    Search the local URLhaus dataset for a URL.

    Use this tool to check whether a URL appears
    in the available URLhaus malicious URL dataset.
    """

    try:
        df = pd.read_csv(DATASET_PATH)

        # Find the column containing the URL
        url_column = None

        for column in df.columns:
            if column.lower() in ["url", "ioc_value", "url_value"]:
                url_column = column
                break

        if url_column is None:
            return "URLhaus lookup error: URL column not found in dataset."

        # Exact URL match
        matches = df[
            df[url_column]
            .astype(str)
            .str.strip()
            .str.lower()
            == url.strip().lower()
        ]

        if matches.empty:
            return f"No matching URLhaus record found for {url}."

        results = []

        for _, row in matches.iterrows():

            result = {
                "url": row[url_column]
            }

            # Add available fields
            for field in [
                "url_status",
                "threat",
                "tags",
                "date_added",
                "last_online",
                "reporter",
                "reference"
            ]:
                if field in df.columns:
                    result[field] = row[field]

            results.append(result)

        return str(results)

    except Exception as e:
        return f"URLhaus lookup error: {str(e)}"