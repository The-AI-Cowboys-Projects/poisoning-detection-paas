"""
Vector Integrity Analysis Engine
================================

Detects RAG poisoning through vector-space anomaly detection.  The engine
maintains a running baseline distribution of *known-clean* embeddings and
flags new vectors that deviate from that baseline on multiple axes:

1. **Cosine dispersion** -- vectors whose pairwise similarity to the
   baseline centroid falls outside N sigma are flagged.
2. **DBSCAN clustering** -- density-based clustering reveals adversarial
   micro-clusters that an attacker might inject.
3. **Split-view detection** -- vectors that straddle two clusters (dual
   membership) indicate a sophisticated "split-view" poisoning attack
   where embeddings look benign in isolation but form a malicious
   subspace when combined.

All heavy math is NumPy/SciPy-backed and runs synchronously in a thread
pool when called from the async API.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.spatial.distance import cdist
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Severity level for individual findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    """Immutable configuration for the vector integrity analyzer.

    Attributes:
        cosine_similarity_threshold: Vectors with similarity to centroid below
            this value are flagged as outliers.
        dispersion_sigma: Z-score cutoff for the modified Z-score outlier test.
        min_baseline_samples: Minimum clean-baseline vectors required before
            the detector will emit a definitive verdict.
        dbscan_eps: DBSCAN neighbourhood radius in cosine distance space.
        dbscan_min_samples: DBSCAN minimum cluster size.
        split_view_overlap_threshold: Minimum fraction of distance overlap
            between two cluster centroids for a vector to be considered
            "split-view".
    """
    cosine_similarity_threshold: float = 0.85
    dispersion_sigma: float = 3.0
    min_baseline_samples: int = 100
    dbscan_eps: float = 0.15
    dbscan_min_samples: int = 5
    split_view_overlap_threshold: float = 0.60


@dataclass(slots=True)
class VectorAnomaly:
    """A single anomalous vector identified by the analyzer.

    Attributes:
        index: Position of the vector in the submitted batch.
        anomaly_score: Composite score in [0.0, 1.0] -- higher is more suspicious.
        cosine_deviation: Distance from baseline centroid (1 - cosine_similarity).
        z_score: Modified Z-score relative to the baseline distribution.
        cluster_label: DBSCAN cluster assignment (-1 = noise).
        reasons: Human-readable explanation strings.
    """
    index: int
    anomaly_score: float
    cosine_deviation: float
    z_score: float
    cluster_label: int
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SplitViewAnomaly:
    """A vector exhibiting dual-cluster membership indicative of split-view poisoning.

    Attributes:
        index: Position of the vector in the submitted batch.
        primary_cluster: Dominant cluster label.
        secondary_cluster: Secondary cluster label the vector is close to.
        overlap_ratio: Ratio expressing how equidistant the vector is between
            the two cluster centroids (1.0 = perfectly equidistant).
        severity: Assessed severity level.
    """
    index: int
    primary_cluster: int
    secondary_cluster: int
    overlap_ratio: float
    severity: Severity


@dataclass(slots=True)
class VectorAnalysisReport:
    """Complete report produced by a single ``analyze_batch`` invocation.

    Attributes:
        total_vectors: Number of vectors in the submitted batch.
        flagged_count: Number of vectors flagged as anomalous.
        dispersion_rate: Standard deviation of pairwise cosine similarities
            across the batch -- a high value suggests heterogeneous injection.
        anomalies: Individual vector-level findings.
        split_view_anomalies: Vectors exhibiting dual-cluster membership.
        cluster_count: Number of clusters discovered by DBSCAN (excl. noise).
        noise_ratio: Fraction of vectors classified as noise by DBSCAN.
        baseline_sufficient: Whether the baseline had enough samples for a
            definitive verdict.
        elapsed_ms: Wall-clock time for the analysis in milliseconds.
        metadata: Arbitrary caller-supplied metadata echoed back.
    """
    total_vectors: int
    flagged_count: int
    dispersion_rate: float
    anomalies: list[VectorAnomaly]
    split_view_anomalies: list[SplitViewAnomaly]
    cluster_count: int
    noise_ratio: float
    baseline_sufficient: bool
    elapsed_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class VectorIntegrityAnalyzer:
    """Detects RAG poisoning through vector-space anomaly detection.

    The analyzer is stateful: call :meth:`update_baseline` with verified-clean
    embeddings before running :meth:`analyze_batch`.  Without a sufficient
    baseline the report will carry ``baseline_sufficient=False`` and anomaly
    scores will be relative to the batch itself (less reliable).

    Thread safety: the mutable baseline arrays are replaced atomically via
    simple reference assignment -- no locks are needed for read-heavy
    workloads.  Concurrent baseline updates should be serialised by the
    caller.

    Example::

        config = AnalyzerConfig(cosine_similarity_threshold=0.80)
        analyzer = VectorIntegrityAnalyzer(config)
        await analyzer.update_baseline(clean_vectors)
        report = await analyzer.analyze_batch(new_vectors, {"source": "rag-index"})
    """

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self._config = config or AnalyzerConfig()
        # Baseline statistics -- None until update_baseline is called.
        self._baseline_centroid: NDArray[np.float64] | None = None
        self._baseline_mean_sim: float | None = None
        self._baseline_std_sim: float | None = None
        self._baseline_count: int = 0
        logger.info(
            "VectorIntegrityAnalyzer initialised  sigma=%.1f  cos_threshold=%.3f",
            self._config.dispersion_sigma,
            self._config.cosine_similarity_threshold,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_batch(
        self,
        vectors: NDArray[np.floating[Any]],
        metadata: dict[str, Any] | None = None,
    ) -> VectorAnalysisReport:
        """Analyze a batch of embedding vectors for poisoning indicators.

        Args:
            vectors: 2-D array of shape ``(n_vectors, embedding_dim)``.
                Must contain at least 2 vectors.
            metadata: Arbitrary caller-supplied metadata echoed in the report.

        Returns:
            A :class:`VectorAnalysisReport` with per-vector anomaly scores,
            cluster statistics, and split-view findings.

        Raises:
            ValueError: If *vectors* has fewer than 2 rows or is not 2-D.
        """
        if vectors.ndim != 2:
            raise ValueError(
                f"Expected 2-D array of shape (n, dim), got shape {vectors.shape}"
            )
        if vectors.shape[0] < 2:
            raise ValueError("At least 2 vectors are required for analysis.")

        t0 = time.perf_counter()
        metadata = metadata or {}

        vectors = vectors.astype(np.float64, copy=False)

        baseline_sufficient = self._baseline_count >= self._config.min_baseline_samples

        # Step 1 -- pairwise cosine similarity matrix
        sim_matrix = self._cosine_similarity_matrix(vectors)

        # Step 2 -- dispersion rate
        dispersion = self._compute_dispersion_rate(sim_matrix)

        # Step 3 -- per-vector similarity to reference centroid
        if baseline_sufficient and self._baseline_centroid is not None:
            centroid = self._baseline_centroid
        else:
            centroid = vectors.mean(axis=0)
        centroid_sims = self._cosine_similarity_to_centroid(vectors, centroid)

        # Step 4 -- outlier flagging (modified Z-score)
        if baseline_sufficient and self._baseline_mean_sim is not None and self._baseline_std_sim is not None:
            reference_mean = self._baseline_mean_sim
            reference_std = self._baseline_std_sim
        else:
            reference_mean = float(np.mean(centroid_sims))
            reference_std = float(np.std(centroid_sims))

        outlier_mask = self._flag_outliers(
            centroid_sims, self._config.dispersion_sigma,
            reference_mean, reference_std,
        )

        # Step 5 -- DBSCAN clustering
        labels = self._dbscan_cluster(vectors)
        unique_labels = set(labels)
        cluster_count = len(unique_labels - {-1})
        noise_count = int(np.sum(labels == -1))
        noise_ratio = noise_count / len(labels) if len(labels) > 0 else 0.0

        # Step 6 -- split-view detection
        split_views = self._detect_split_view(vectors, labels)

        # Step 7 -- assemble per-vector anomaly objects
        anomalies: list[VectorAnomaly] = []
        for i in range(vectors.shape[0]):
            reasons: list[str] = []
            cos_dev = 1.0 - centroid_sims[i]

            z = (centroid_sims[i] - reference_mean) / reference_std if reference_std > 1e-12 else 0.0

            if outlier_mask[i]:
                reasons.append(
                    f"Cosine deviation {cos_dev:.4f} exceeds "
                    f"{self._config.dispersion_sigma}-sigma threshold"
                )
            if centroid_sims[i] < self._config.cosine_similarity_threshold:
                reasons.append(
                    f"Similarity {centroid_sims[i]:.4f} below threshold "
                    f"{self._config.cosine_similarity_threshold}"
                )
            if labels[i] == -1:
                reasons.append("Classified as DBSCAN noise (potential outlier)")

            # Composite anomaly score: weighted combination
            score_components = [
                0.40 * min(cos_dev / 0.5, 1.0),           # cosine deviation contribution
                0.30 * min(abs(z) / 5.0, 1.0),            # z-score contribution
                0.20 * (1.0 if labels[i] == -1 else 0.0), # noise penalty
                0.10 * (1.0 if outlier_mask[i] else 0.0), # hard outlier flag
            ]
            anomaly_score = float(np.clip(sum(score_components), 0.0, 1.0))

            if reasons:
                anomalies.append(VectorAnomaly(
                    index=i,
                    anomaly_score=anomaly_score,
                    cosine_deviation=cos_dev,
                    z_score=z,
                    cluster_label=int(labels[i]),
                    reasons=reasons,
                ))

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return VectorAnalysisReport(
            total_vectors=vectors.shape[0],
            flagged_count=len(anomalies),
            dispersion_rate=dispersion,
            anomalies=anomalies,
            split_view_anomalies=split_views,
            cluster_count=cluster_count,
            noise_ratio=noise_ratio,
            baseline_sufficient=baseline_sufficient,
            elapsed_ms=elapsed_ms,
            metadata=metadata,
        )

    async def update_baseline(self, clean_vectors: NDArray[np.floating[Any]]) -> None:
        """Update the baseline distribution from verified clean data.

        The baseline centroid and similarity distribution statistics are
        recomputed from *clean_vectors* and atomically swapped in.

        Args:
            clean_vectors: 2-D array of shape ``(n, dim)`` containing only
                verified-clean embeddings.

        Raises:
            ValueError: If *clean_vectors* has fewer than 2 rows.
        """
        if clean_vectors.ndim != 2 or clean_vectors.shape[0] < 2:
            raise ValueError(
                "Baseline requires a 2-D array with at least 2 vectors."
            )

        clean_vectors = clean_vectors.astype(np.float64, copy=False)
        centroid = clean_vectors.mean(axis=0)
        sims = self._cosine_similarity_to_centroid(clean_vectors, centroid)

        # Atomic swap of baseline state
        self._baseline_centroid = centroid
        self._baseline_mean_sim = float(np.mean(sims))
        self._baseline_std_sim = float(np.std(sims))
        self._baseline_count = clean_vectors.shape[0]

        logger.info(
            "Baseline updated  n=%d  mean_sim=%.4f  std_sim=%.4f",
            self._baseline_count,
            self._baseline_mean_sim,
            self._baseline_std_sim,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cosine_similarity_matrix(
        self, vectors: NDArray[np.float64],
    ) -> NDArray[np.float64]:
        """Efficient batched cosine similarity computation.

        Uses ``scipy.spatial.distance.cdist`` with the cosine metric and
        converts from *distance* to *similarity* (``1 - distance``).

        Args:
            vectors: 2-D array of shape ``(n, dim)``.

        Returns:
            Symmetric similarity matrix of shape ``(n, n)`` with values in
            ``[0, 1]`` (self-similarity on the diagonal is 1.0).
        """
        # cdist returns cosine *distance*; similarity = 1 - distance
        dist = cdist(vectors, vectors, metric="cosine")
        # Guard against tiny floating-point artefacts
        np.clip(dist, 0.0, 2.0, out=dist)
        sim: NDArray[np.float64] = 1.0 - dist
        return sim

    @staticmethod
    def _cosine_similarity_to_centroid(
        vectors: NDArray[np.float64],
        centroid: NDArray[np.float64],
    ) -> NDArray[np.float64]:
        """Compute cosine similarity of each vector to a single centroid.

        Args:
            vectors: 2-D array of shape ``(n, dim)``.
            centroid: 1-D array of shape ``(dim,)``.

        Returns:
            1-D array of shape ``(n,)`` with similarity values.
        """
        centroid_2d = centroid.reshape(1, -1)
        dist = cdist(vectors, centroid_2d, metric="cosine").ravel()
        np.clip(dist, 0.0, 2.0, out=dist)
        return 1.0 - dist

    def _compute_dispersion_rate(
        self, similarities: NDArray[np.float64],
    ) -> float:
        """Calculate dispersion rate of cosine similarity distribution.

        The dispersion rate is the standard deviation of the upper-triangular
        entries (excluding the diagonal) of the similarity matrix.  A high
        value means the batch contains vectors spanning very different
        neighbourhoods -- a possible sign of heterogeneous injection.

        Args:
            similarities: Square similarity matrix of shape ``(n, n)``.

        Returns:
            Scalar dispersion rate (>= 0).
        """
        # Extract upper triangle without the diagonal
        triu_indices = np.triu_indices_from(similarities, k=1)
        upper_values = similarities[triu_indices]
        if upper_values.size == 0:
            return 0.0
        return float(np.std(upper_values))

    def _flag_outliers(
        self,
        scores: NDArray[np.float64],
        sigma: float,
        mean: float | None = None,
        std: float | None = None,
    ) -> NDArray[np.bool_]:
        """Flag vectors beyond *sigma* threshold using modified Z-score.

        Uses the Median Absolute Deviation (MAD) when no external
        ``mean``/``std`` are supplied from the baseline, which is more robust
        to outlier contamination than the standard Z-score.

        Args:
            scores: 1-D array of per-vector similarity scores.
            sigma: Number of standard deviations for the cutoff.
            mean: Optional pre-computed mean (from baseline).
            std: Optional pre-computed std (from baseline).

        Returns:
            Boolean mask -- ``True`` for outlier vectors.
        """
        if mean is not None and std is not None and std > 1e-12:
            z_scores = np.abs((scores - mean) / std)
            return z_scores > sigma

        # MAD-based modified Z-score (robust to outlier contamination)
        median = float(np.median(scores))
        mad = float(np.median(np.abs(scores - median)))
        if mad < 1e-12:
            # All values are nearly identical -- nothing is an outlier
            return np.zeros(len(scores), dtype=np.bool_)
        modified_z = 0.6745 * (scores - median) / mad
        return np.abs(modified_z) > sigma

    def _dbscan_cluster(
        self, vectors: NDArray[np.float64],
    ) -> NDArray[np.intp]:
        """Run DBSCAN clustering on the vectors using cosine metric.

        Args:
            vectors: 2-D array of shape ``(n, dim)``.

        Returns:
            1-D array of cluster labels; -1 indicates noise.
        """
        db = DBSCAN(
            eps=self._config.dbscan_eps,
            min_samples=self._config.dbscan_min_samples,
            metric="cosine",
        )
        labels: NDArray[np.intp] = db.fit_predict(vectors)
        return labels

    def _detect_split_view(
        self,
        vectors: NDArray[np.float64],
        labels: NDArray[np.intp],
    ) -> list[SplitViewAnomaly]:
        """Detect split-view poisoning where vectors appear normal individually
        but form adversarial clusters.

        A split-view vector is one that is nearly equidistant to two distinct
        cluster centroids -- it could be "read" by the model as belonging to
        either cluster depending on the query context, enabling an attacker to
        influence retrieval unpredictably.

        Args:
            vectors: 2-D array of shape ``(n, dim)``.
            labels: DBSCAN cluster labels of shape ``(n,)``.

        Returns:
            List of :class:`SplitViewAnomaly` objects for flagged vectors.
        """
        unique_labels = sorted(set(labels) - {-1})
        if len(unique_labels) < 2:
            return []

        # Compute cluster centroids
        centroids: dict[int, NDArray[np.float64]] = {}
        for lbl in unique_labels:
            mask = labels == lbl
            centroids[lbl] = vectors[mask].mean(axis=0)

        centroid_array = np.array([centroids[lbl] for lbl in unique_labels])

        # For each vector, compute distance to every centroid
        dists = cdist(vectors, centroid_array, metric="cosine")  # (n, k)

        anomalies: list[SplitViewAnomaly] = []
        threshold = self._config.split_view_overlap_threshold

        for i in range(vectors.shape[0]):
            sorted_indices = np.argsort(dists[i])
            if len(sorted_indices) < 2:
                continue

            closest_idx = int(sorted_indices[0])
            second_idx = int(sorted_indices[1])
            d1 = dists[i, closest_idx]
            d2 = dists[i, second_idx]

            if d2 < 1e-12:
                # Both distances are effectively zero -- degenerate case
                continue

            # Overlap ratio: 1.0 when equidistant, 0.0 when fully committed
            overlap = d1 / d2 if d2 > d1 else 1.0

            if overlap >= threshold:
                severity = Severity.CRITICAL if overlap > 0.90 else (
                    Severity.HIGH if overlap > 0.80 else Severity.MEDIUM
                )
                anomalies.append(SplitViewAnomaly(
                    index=i,
                    primary_cluster=unique_labels[closest_idx],
                    secondary_cluster=unique_labels[second_idx],
                    overlap_ratio=float(overlap),
                    severity=severity,
                ))

        return anomalies
