"""Block F: Text Embeddings (~105 features).

PCA-reduced sentence embeddings of CVE descriptions plus simple text features.
Uses all-MiniLM-L6-v2 (384-dim) reduced to 100 via PCA.
"""
import numpy as np
import pandas as pd


def extract_text_features(df: pd.DataFrame, use_embeddings: bool = True) -> pd.DataFrame:
    """Extract text features from CVE descriptions.

    Args:
        df: DataFrame with 'cve_description' column.
        use_embeddings: If True, compute sentence-transformer embeddings + PCA.
            If False, return only simple text features (faster).

    Returns:
        DataFrame with ~105 features (100 embeddings + 5 text stats).
    """
    features = pd.DataFrame(index=df.index)
    desc = df.get("cve_description", pd.Series("", index=df.index)).fillna("").astype(str)

    # Simple text features (always computed)
    features["description_length"] = desc.str.len()
    features["description_word_count"] = desc.str.split().str.len().fillna(0).astype(int)
    features["description_has_exploit_mention"] = desc.str.lower().str.contains("exploit", na=False).astype(int)
    features["description_has_rce_mention"] = (
        desc.str.lower().str.contains("remote code execution", na=False)
        | desc.str.lower().str.contains(r"\brce\b", na=False, regex=True)
    ).astype(int)
    features["description_has_dos_mention"] = (
        desc.str.lower().str.contains("denial of service", na=False)
        | desc.str.lower().str.contains(r"\bdos\b", na=False, regex=True)
    ).astype(int)

    if not use_embeddings:
        return features

    # Compute sentence embeddings
    try:
        from sentence_transformers import SentenceTransformer
        from sklearn.decomposition import PCA

        # Load model
        model = SentenceTransformer("all-MiniLM-L6-v2")

        # Encode descriptions
        descriptions = desc.tolist()
        embeddings = model.encode(descriptions, show_progress_bar=False, batch_size=64)

        # PCA reduction: 384 -> 100
        n_components = min(100, embeddings.shape[0], embeddings.shape[1])
        if n_components < 2:
            # Too few samples for PCA
            for i in range(100):
                features[f"text_embed_{i}"] = 0.0
        else:
            pca = PCA(n_components=n_components)
            reduced = pca.fit_transform(embeddings)

            for i in range(n_components):
                features[f"text_embed_{i}"] = reduced[:, i]
            # Pad remaining if n_components < 100
            for i in range(n_components, 100):
                features[f"text_embed_{i}"] = 0.0

    except ImportError:
        # sentence-transformers not installed — fill with zeros
        for i in range(100):
            features[f"text_embed_{i}"] = 0.0

    return features
