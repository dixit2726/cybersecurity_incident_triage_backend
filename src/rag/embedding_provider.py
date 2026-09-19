import logging
import os
import re
import sys
import time
from typing import Any, List, Optional
import numpy as np
from dotenv import load_dotenv

load_dotenv()

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logger = logging.getLogger("rag.embedding_provider")

DEFAULT_EMBEDDING_MODEL = "models/gemini-embedding-001"
DEFAULT_EMBEDDING_DIMENSION = 768


def normalize_vectors(vectors: np.ndarray) -> np.ndarray:
    """Normalize vectors to unit length (L2 norm) for cosine similarity in IndexFlatIP."""
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return (vectors / norms).astype(np.float32)


def extract_retry_delay(error_str: str) -> float:
    """Extract recommended retry delay from Gemini rate limit error message, adding a safe buffer."""
    match = re.search(r"retry in (\d+(?:\.\d+)?)s", error_str, re.IGNORECASE)
    if match:
        return float(match.group(1)) + 5.0
    match2 = re.search(r"retryDelay':\s*'(\d+)s'", error_str)
    if match2:
        return float(match2.group(1)) + 5.0
    return 60.0


class GeminiEmbeddingProvider:
    """
    Lightweight, production-grade embedding provider utilizing Google Gemini.
    Eliminates local PyTorch and SentenceTransformers memory overhead, enabling
    the backend to operate well within 512 MB RAM on Render Free tier.
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        dimension: Optional[int] = None,
        api_key: Optional[str] = None,
    ):
        self.model_name = (
            model_name
            or os.getenv("RAG_EMBEDDING_MODEL", "").strip()
            or DEFAULT_EMBEDDING_MODEL
        )
        self.dimension = int(
            dimension
            or os.getenv("RAG_EMBEDDING_DIMENSION", "").strip()
            or DEFAULT_EMBEDDING_DIMENSION
        )
        api_key = api_key or os.getenv("GOOGLE_API_KEY", "").strip()
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found. Required for Gemini embeddings.")

        from google import genai
        self.client = genai.Client(api_key=api_key)
        logger.info(
            "Initialized GeminiEmbeddingProvider (model: %s, dimension: %d)",
            self.model_name,
            self.dimension,
        )

    def embed_text(self, text: str) -> np.ndarray:
        """
        Embed a single text string.
        Returns a normalized 2D numpy array of shape (1, dimension) with dtype float32.
        """
        if not text or not text.strip():
            raise ValueError("Input text for embedding cannot be empty.")

        max_retries = 2
        for attempt in range(max_retries):
            try:
                res = self.client.models.embed_content(
                    model=self.model_name,
                    contents=text.strip(),
                    config={"output_dimensionality": self.dimension},
                )
                if hasattr(res, "embedding") and res.embedding:
                    vec = res.embedding.values
                elif hasattr(res, "embeddings") and res.embeddings:
                    vec = res.embeddings[0].values
                else:
                    raise ValueError("No embedding returned by Gemini API.")

                arr = np.asarray([vec], dtype=np.float32)
                return normalize_vectors(arr)
            except Exception as e:
                err_str = str(e)
                if ("429" in err_str or "RESOURCE_EXHAUSTED" in err_str) and attempt < max_retries - 1:
                    delay = min(extract_retry_delay(err_str), 3.0)
                    logger.warning("Rate limit hit during single embedding. Quick retry in %.1fs...", delay)
                    time.sleep(delay)
                else:
                    raise

    def embed_documents(
        self,
        texts: List[str],
        batch_size: int = 25,
        show_progress: bool = True,
        rate_limit_pause: float = 1.0,
    ) -> np.ndarray:
        """
        Embed a list of text strings in batches with automatic rate-limit management.
        Returns a normalized 2D numpy array of shape (N, dimension) with dtype float32.
        """
        if not texts:
            raise ValueError("Texts list cannot be empty.")

        all_vectors = []
        total = len(texts)

        for i in range(0, total, batch_size):
            batch = texts[i : i + batch_size]
            max_retries = 30
            for attempt in range(max_retries):
                try:
                    res = self.client.models.embed_content(
                        model=self.model_name,
                        contents=batch,
                        config={"output_dimensionality": self.dimension},
                    )
                    batch_vecs = [e.values for e in res.embeddings]
                    all_vectors.extend(batch_vecs)
                    break
                except Exception as e:
                    err_str = str(e)
                    if ("429" in err_str or "RESOURCE_EXHAUSTED" in err_str) and attempt < max_retries - 1:
                        delay = max(extract_retry_delay(err_str), 60.0)
                        print(f"\n[Rate Limit] Gemini quota pause: sleeping {delay:.1f}s before resuming...", flush=True)
                        time.sleep(delay)
                    else:
                        raise
                        raise

            if show_progress:
                pct = min(100.0, ((i + len(batch)) / total) * 100.0)
                print(
                    f"Embedded {min(i + len(batch), total):,}/{total:,} chunks ({pct:.1f}%)...",
                    flush=True,
                )

            if rate_limit_pause > 0 and (i + batch_size < total):
                time.sleep(rate_limit_pause)

        arr = np.asarray(all_vectors, dtype=np.float32)
        return normalize_vectors(arr)


# Global singleton instance
_GLOBAL_PROVIDER: Optional[GeminiEmbeddingProvider] = None


def get_embedding_provider() -> GeminiEmbeddingProvider:
    """Return the application-level shared GeminiEmbeddingProvider instance."""
    global _GLOBAL_PROVIDER
    if _GLOBAL_PROVIDER is None:
        _GLOBAL_PROVIDER = GeminiEmbeddingProvider()
    return _GLOBAL_PROVIDER
