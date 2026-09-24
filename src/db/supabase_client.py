import logging
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("db.supabase_client")

_client = None


def _get_credentials():
    url = (os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL") or "").strip()
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
        or ""
    ).strip()
    return url, key


def is_supabase_configured() -> bool:
    """Check if both Supabase URL and Key are configured."""
    url, key = _get_credentials()
    return bool(url and key)


def get_supabase_client():
    """
    Lazy-initialize and return the Supabase client.
    Returns None safely if credentials are not configured or if initialization fails.
    """
    global _client
    if _client is not None:
        return _client

    url, key = _get_credentials()

    if not url or not key:
        logger.info("Supabase is not configured (URL or key missing). Persistence disabled.")
        return None

    try:
        from supabase import create_client, ClientOptions

        # Set reasonable timeout for DB calls to avoid stalling triage response
        options = ClientOptions(postgrest_client_timeout=10)
        _client = create_client(url, key, options=options)
        logger.info("Supabase client initialized successfully.")
        return _client
    except Exception as e:
        # Sanitize error to avoid leaking credentials
        logger.warning("Failed to initialize Supabase client: %s", str(e))
        return None
