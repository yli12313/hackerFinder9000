"""
file-based fingerprinting system for detecting:
- similar content across requests (semantic similarity)
- fragment correlation (pieces of larger payloads)
- obfuscated duplicates (paraphrased malicious content)
- structural patterns (code, JSON, markup)
"""

import hashlib  # noqa: I001
import re
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional, Set  # noqa: F401
from enum import Enum
import threading
import time


class ContentType(str, Enum):
    """Detected content types."""

    TEXT = "text"
    CODE = "code"
    JSON = "json"
    MARKDOWN = "markdown"
    XML = "xml"
    MIXED = "mixed"
    BINARY = "binary"


@dataclass
class ContentFingerprint:
    """Multi-dimensional fingerprint of content."""

    # Primary identifiers
    exact_hash: str  # SHA-256 of normalized content
    structure_hash: str  # Hash of structural elements only
    semantic_hash: str  # Hash based on key terms/concepts

    # Similarity signatures
    minhash_signature: tuple[int, ...]  # MinHash for Jaccard similarity
    simhash: int  # SimHash for hamming distance similarity
    ngram_fingerprint: str  # Character n-gram based fingerprint

    # Content characteristics
    content_type: ContentType
    length: int
    entropy: float  # Shannon entropy (high = more random/encrypted)

    # Structural features
    line_count: int
    avg_line_length: float
    code_ratio: float  # Ratio of code-like characters
    special_char_ratio: float

    # Extracted features
    keywords: list[str]
    entities: list[str]  # URLs, IPs, emails, etc.
    language_indicators: list[str]

    # Metadata
    timestamp: float = field(default_factory=time.time)


@dataclass
class FingerprintMatch:
    """A match between two fingerprints."""

    fingerprint_a: str
    fingerprint_b: str
    similarity_score: float  # 0.0 to 1.0
    match_type: str  # "exact", "structural", "semantic", "similar"
    matching_features: list[str]


class AdvancedFingerprinter:
    """
    Advanced content fingerprinting engine.

    Uses multiple techniques:
    1. MinHash for set similarity (Jaccard)
    2. SimHash for near-duplicate detection
    3. N-gram analysis for substring matching
    4. Structural hashing for code/JSON patterns
    5. Semantic extraction for concept matching
    """

    # Number of hash functions for MinHash
    NUM_MINHASH_FUNCTIONS = 128

    # N-gram sizes for fingerprinting
    NGRAM_SIZES = [3, 4, 5]

    # SimHash bits
    SIMHASH_BITS = 64

    # Code-like patterns
    CODE_PATTERNS = [
        r"\b(def|function|class|import|from|return|if|else|for|while|try|catch)\b",
        r"[{}\[\]();]",
        r"[a-zA-Z_]\w*\s*\(",
        r"[a-zA-Z_]\w*\s*=",
    ]

    # Entity patterns
    ENTITY_PATTERNS = {
        "url": r'https?://[^\s<>"\']+',
        "ip": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "path": r"(?:/[\w.-]+)+(?:/|\.[a-zA-Z]+)?",
        "hash": r"\b[a-fA-F0-9]{32,64}\b",
        "api_key": r"\b(sk-|pk_|api[_-]?key)[a-zA-Z0-9_-]{20,}\b",
    }

    def __init__(self):
        # Pre-compute random coefficients for MinHash
        import random

        random.seed(42)  # Deterministic for consistency
        self._minhash_a = [
            random.randint(1, 2**31 - 1) for _ in range(self.NUM_MINHASH_FUNCTIONS)
        ]  # noqa: E501
        self._minhash_b = [
            random.randint(0, 2**31 - 1) for _ in range(self.NUM_MINHASH_FUNCTIONS)
        ]  # noqa: E501
        self._large_prime = 2**31 - 1

        # Compile patterns
        self._code_re = [re.compile(p) for p in self.CODE_PATTERNS]
        self._entity_re = {
            k: re.compile(v, re.IGNORECASE) for k, v in self.ENTITY_PATTERNS.items()
        }  # noqa: E501

        # Fingerprint storage for matching
        self._fingerprints: dict[str, ContentFingerprint] = {}
        self._minhash_index: dict[int, Set[str]] = defaultdict(set)  # LSH buckets
        self._lock = threading.RLock()

    def fingerprint(self, content: str) -> ContentFingerprint:
        """
        Generate a comprehensive fingerprint for content.
        """
        # Normalize content
        normalized = self._normalize(content)

        # Generate all hashes
        exact_hash = self._exact_hash(normalized)
        structure_hash = self._structure_hash(content)
        semantic_hash = self._semantic_hash(normalized)

        # Generate similarity signatures
        tokens = self._tokenize(normalized)
        minhash = self._compute_minhash(tokens)
        simhash = self._compute_simhash(tokens)
        ngram_fp = self._ngram_fingerprint(normalized)

        # Analyze content
        content_type = self._detect_content_type(content)
        entropy = self._compute_entropy(content)
        code_ratio = self._compute_code_ratio(content)

        # Extract features
        keywords = self._extract_keywords(normalized)
        entities = self._extract_entities(content)
        lang_indicators = self._detect_language_indicators(content)

        # Line statistics
        lines = content.split("\n")
        line_count = len(lines)
        avg_line_length = sum(len(l) for l in lines) / max(line_count, 1)  # noqa: E741

        # Special character ratio
        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        special_char_ratio = special_chars / max(len(content), 1)

        fp = ContentFingerprint(
            exact_hash=exact_hash,
            structure_hash=structure_hash,
            semantic_hash=semantic_hash,
            minhash_signature=minhash,
            simhash=simhash,
            ngram_fingerprint=ngram_fp,
            content_type=content_type,
            length=len(content),
            entropy=entropy,
            line_count=line_count,
            avg_line_length=avg_line_length,
            code_ratio=code_ratio,
            special_char_ratio=special_char_ratio,
            keywords=keywords,
            entities=entities,
            language_indicators=lang_indicators,
        )

        # Store for matching
        with self._lock:
            self._fingerprints[exact_hash] = fp
            # Add to LSH index (band-based)
            for band_idx in range(0, len(minhash), 8):
                band = minhash[band_idx : band_idx + 8]
                bucket_key = hash(band)
                self._minhash_index[bucket_key].add(exact_hash)

        return fp

    def find_similar(
        self,
        fingerprint: ContentFingerprint,
        min_similarity: float = 0.7,
        max_results: int = 10,
    ) -> list[FingerprintMatch]:
        """
        Find similar content based on fingerprint.
        """
        matches = []

        with self._lock:
            # Quick exact match check
            if fingerprint.exact_hash in self._fingerprints:
                other = self._fingerprints[fingerprint.exact_hash]
                if other.timestamp != fingerprint.timestamp:
                    matches.append(
                        FingerprintMatch(
                            fingerprint_a=fingerprint.exact_hash,
                            fingerprint_b=fingerprint.exact_hash,
                            similarity_score=1.0,
                            match_type="exact",
                            matching_features=["exact_hash"],
                        )
                    )

            # LSH-based candidate retrieval
            candidates = set()
            for band_idx in range(0, len(fingerprint.minhash_signature), 8):
                band = fingerprint.minhash_signature[band_idx : band_idx + 8]
                bucket_key = hash(band)
                candidates.update(self._minhash_index.get(bucket_key, set()))

            # Compute similarities for candidates
            for candidate_hash in candidates:
                if candidate_hash == fingerprint.exact_hash:
                    continue

                candidate = self._fingerprints.get(candidate_hash)
                if not candidate:
                    continue

                # Compute various similarity scores
                minhash_sim = self._minhash_similarity(
                    fingerprint.minhash_signature, candidate.minhash_signature
                )
                simhash_sim = self._simhash_similarity(
                    fingerprint.simhash, candidate.simhash
                )

                # Weighted combination
                combined_sim = (
                    minhash_sim * 0.5
                    + simhash_sim * 0.3
                    + (
                        1.0
                        if fingerprint.structure_hash == candidate.structure_hash
                        else 0.0
                    )
                    * 0.2
                )  # noqa: E501

                if combined_sim >= min_similarity:
                    matching_features = []
                    if minhash_sim >= 0.7:
                        matching_features.append("content_similarity")
                    if simhash_sim >= 0.8:
                        matching_features.append("near_duplicate")
                    if fingerprint.structure_hash == candidate.structure_hash:
                        matching_features.append("structural_match")
                    if fingerprint.semantic_hash == candidate.semantic_hash:
                        matching_features.append("semantic_match")

                    match_type = (
                        "exact"
                        if combined_sim > 0.95
                        else "structural"
                        if fingerprint.structure_hash == candidate.structure_hash
                        else "semantic"
                        if fingerprint.semantic_hash == candidate.semantic_hash
                        else "similar"
                    )  # noqa: E501

                    matches.append(
                        FingerprintMatch(
                            fingerprint_a=fingerprint.exact_hash,
                            fingerprint_b=candidate_hash,
                            similarity_score=combined_sim,
                            match_type=match_type,
                            matching_features=matching_features,
                        )
                    )

        # Sort by similarity and limit
        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        return matches[:max_results]

    def is_fragment_of(
        self,
        potential_fragment: ContentFingerprint,
        potential_parent: ContentFingerprint,
        threshold: float = 0.6,
    ) -> bool:
        """
        Check if one content is a fragment of another.
        Uses n-gram containment analysis.
        """
        # Fragment should be smaller
        if potential_fragment.length >= potential_parent.length:
            return False

        # Check keyword containment
        fragment_keywords = set(potential_fragment.keywords)
        parent_keywords = set(potential_parent.keywords)

        if not fragment_keywords:
            return False

        containment = len(fragment_keywords & parent_keywords) / len(fragment_keywords)
        return containment >= threshold

    def _normalize(self, content: str) -> str:
        """Normalize content for hashing."""
        # Lowercase
        text = content.lower()
        # Normalize whitespace
        text = " ".join(text.split())
        # Remove common punctuation variations
        text = re.sub(r"[^\w\s]", " ", text)
        return text

    def _exact_hash(self, normalized: str) -> str:
        """Compute exact content hash."""
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _structure_hash(self, content: str) -> str:
        """
        Hash structural elements only.
        Useful for detecting structurally similar content with different values.
        """
        # Extract structural skeleton
        skeleton = []

        # Replace strings with placeholder
        skeleton_content = re.sub(r'"[^"]*"', '"STR"', content)
        skeleton_content = re.sub(r"'[^']*'", "'STR'", skeleton_content)

        # Replace numbers with placeholder
        skeleton_content = re.sub(r"\b\d+\.?\d*\b", "NUM", skeleton_content)

        # Keep only structural characters and keywords
        structural_chars = re.findall(
            r"[{}\[\]():;,=<>]|\b(if|else|for|while|def|class|function|return|import)\b",
            skeleton_content,
        )  # noqa: E501
        skeleton = "".join(str(c) for c in structural_chars)

        return hashlib.md5(skeleton.encode()).hexdigest()[:12]

    def _semantic_hash(self, normalized: str) -> str:
        """
        Hash based on semantic content (key concepts).
        """
        # Extract significant words (longer words tend to be more meaningful)
        words = [w for w in normalized.split() if len(w) >= 4]

        # Get top frequent meaningful words
        word_counts = Counter(words)
        top_words = sorted(word_counts.keys())[:20]

        semantic_content = " ".join(top_words)
        return hashlib.md5(semantic_content.encode()).hexdigest()[:12]

    def _tokenize(self, text: str) -> set[str]:
        """Tokenize text into a set of tokens."""
        # Word tokens
        words = set(text.split())

        # Add character n-grams
        for n in self.NGRAM_SIZES:
            for i in range(len(text) - n + 1):
                words.add(text[i : i + n])

        return words

    def _compute_minhash(self, tokens: set[str]) -> tuple[int, ...]:
        """Compute MinHash signature for a set of tokens."""
        signature = []

        for i in range(self.NUM_MINHASH_FUNCTIONS):
            min_hash = float("inf")
            for token in tokens:
                token_hash = hash(token)
                # Apply hash function: (a * x + b) mod p
                h = (
                    self._minhash_a[i] * token_hash + self._minhash_b[i]
                ) % self._large_prime  # noqa: E501
                min_hash = min(min_hash, h)
            signature.append(min_hash if min_hash != float("inf") else 0)

        return tuple(signature)

    def _compute_simhash(self, tokens: set[str]) -> int:
        """Compute SimHash for near-duplicate detection."""
        v = [0] * self.SIMHASH_BITS

        for token in tokens:
            token_hash = int(hashlib.md5(token.encode()).hexdigest(), 16)

            for i in range(self.SIMHASH_BITS):
                bit = (token_hash >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1

        # Generate final hash
        simhash = 0
        for i in range(self.SIMHASH_BITS):
            if v[i] > 0:
                simhash |= 1 << i

        return simhash

    def _ngram_fingerprint(self, text: str) -> str:
        """Generate n-gram based fingerprint."""
        # Get 4-gram frequencies
        ngrams = Counter()
        for i in range(len(text) - 3):
            ngrams[text[i : i + 4]] += 1

        # Take top 20 most frequent
        top_ngrams = sorted(ngrams.keys(), key=lambda x: ngrams[x], reverse=True)[:20]
        return hashlib.md5("".join(top_ngrams).encode()).hexdigest()[:12]

    def _detect_content_type(self, content: str) -> ContentType:
        """Detect the type of content."""
        # Check for JSON
        try:
            json.loads(content)
            return ContentType.JSON
        except (json.JSONDecodeError, ValueError):
            pass

        # Check for XML/HTML
        if re.search(r"<[^>]+>", content):
            return ContentType.XML

        # Check for Markdown
        if re.search(r"^#{1,6}\s|\*\*|__|```", content, re.MULTILINE):
            return ContentType.MARKDOWN

        # Check for code
        code_matches = sum(1 for regex in self._code_re if regex.search(content))
        if code_matches >= 2:
            return ContentType.CODE

        return ContentType.TEXT

    def _compute_entropy(self, content: str) -> float:
        """Compute Shannon entropy of content."""
        if not content:
            return 0.0

        import math

        freq = Counter(content)
        length = len(content)

        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _compute_code_ratio(self, content: str) -> float:
        """Compute ratio of code-like characters."""
        if not content:
            return 0.0

        code_chars = sum(1 for c in content if c in "{}[]();=<>+-*/")
        return code_chars / len(content)

    def _extract_keywords(self, normalized: str, max_keywords: int = 20) -> list[str]:
        """Extract significant keywords from content."""
        # Common stop words to filter
        stop_words = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "from",
            "is",
            "are",
            "was",
            "were",
            "be",
            "been",
            "being",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "will",
            "would",
            "could",
            "should",
            "may",
            "might",
            "must",
            "shall",
            "can",
            "need",
            "this",
            "that",
            "these",
            "those",
            "i",
            "you",
            "he",
            "she",
            "it",
            "we",
            "they",
            "what",
            "which",
            "who",
            "when",
            "where",
            "why",
            "how",
            "all",
            "each",
            "every",
            "both",
            "few",
            "more",
            "most",
            "other",
            "some",
            "such",
            "no",
            "nor",
            "not",
            "only",
            "own",
            "same",
            "so",
            "than",
            "too",
            "very",
        }

        words = normalized.split()
        # Filter stop words and short words
        significant = [w for w in words if w not in stop_words and len(w) >= 3]

        # Get most frequent
        word_counts = Counter(significant)
        return [word for word, _ in word_counts.most_common(max_keywords)]

    def _extract_entities(self, content: str) -> list[str]:
        """Extract named entities (URLs, IPs, emails, etc.)."""
        entities = []

        for entity_type, pattern in self._entity_re.items():
            matches = pattern.findall(content)
            for match in matches[:5]:  # Limit per type
                entities.append(f"{entity_type}:{match[:50]}")

        return entities

    def _detect_language_indicators(self, content: str) -> list[str]:
        """Detect programming language indicators."""
        indicators = []

        lang_patterns = {
            "python": [r"\bdef\s+\w+\s*\(", r"\bimport\s+\w+", r":\s*$", r"self\."],
            "javascript": [r"\bfunction\s+\w+", r"\bconst\s+", r"\blet\s+", r"=>"],
            "java": [r"\bpublic\s+class", r"\bprivate\s+", r"\bvoid\s+"],
            "sql": [r"\bSELECT\b", r"\bFROM\b", r"\bWHERE\b", r"\bINSERT\b"],
            "shell": [r"^#!/", r"\becho\s+", r"\$\{?\w+\}?"],
        }

        for lang, patterns in lang_patterns.items():
            matches = sum(
                1
                for p in patterns
                if re.search(p, content, re.IGNORECASE | re.MULTILINE)
            )  # noqa: E501
            if matches >= 2:
                indicators.append(lang)

        return indicators

    def _minhash_similarity(
        self, sig1: tuple[int, ...], sig2: tuple[int, ...]
    ) -> float:  # noqa: E501
        """Compute Jaccard similarity estimate from MinHash signatures."""
        if len(sig1) != len(sig2):
            return 0.0

        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)  # noqa: B905
        return matches / len(sig1)

    def _simhash_similarity(self, hash1: int, hash2: int) -> float:
        """Compute similarity from SimHash hamming distance."""
        # XOR to find differing bits
        diff = hash1 ^ hash2

        # Count differing bits
        hamming_distance = bin(diff).count("1")

        # Convert to similarity (0 distance = 1.0 similarity)
        return 1.0 - (hamming_distance / self.SIMHASH_BITS)

    def get_stats(self) -> dict[str, Any]:
        """Get fingerprinting statistics."""
        with self._lock:
            return {
                "total_fingerprints": len(self._fingerprints),
                "lsh_buckets": len(self._minhash_index),
                "avg_bucket_size": sum(len(b) for b in self._minhash_index.values())
                / max(len(self._minhash_index), 1),  # noqa: E501
            }

    def clear_old(self, max_age_seconds: int = 3600) -> int:
        """Clear fingerprints older than max_age_seconds."""
        cutoff = time.time() - max_age_seconds
        removed = 0

        with self._lock:
            old_hashes = [
                h for h, fp in self._fingerprints.items() if fp.timestamp < cutoff
            ]  # noqa: E501
            for h in old_hashes:
                del self._fingerprints[h]
                removed += 1

            # Rebuild LSH index
            self._minhash_index.clear()
            for h, fp in self._fingerprints.items():
                for band_idx in range(0, len(fp.minhash_signature), 8):
                    band = fp.minhash_signature[band_idx : band_idx + 8]
                    bucket_key = hash(band)
                    self._minhash_index[bucket_key].add(h)

        return removed
