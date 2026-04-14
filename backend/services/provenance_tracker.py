"""
Synthetic Data Provenance Engine
=================================

Graph-based tracking of synthetic data lineage to prevent Virus Infection
Attacks -- a class of data poisoning where contaminated synthetic data is
laundered through multiple generation cycles until its provenance is obscured.

The engine uses Neo4j as its backing store, modelling datasets as nodes and
parent-child derivation relationships as edges.  Key capabilities:

- **Lineage registration** -- record every dataset and its parent chain.
- **Contamination propagation** -- when a dataset is flagged, warnings
  propagate to all descendants with configurable decay.
- **Circular provenance detection** -- catches data-laundering loops where
  dataset A -> B -> C -> A is used to obscure the origin.
- **Ancestry traversal** -- full lineage graph retrieval for visualisation
  and audit.

All public methods are ``async`` and use the Neo4j async driver.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class ContaminationLevel(str, Enum):
    """Contamination severity classification."""
    CLEAN = "clean"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    PROPAGATED = "propagated"


class SourceType(str, Enum):
    """Origin classification for a dataset."""
    HUMAN_CURATED = "human_curated"
    SYNTHETIC_LLM = "synthetic_llm"
    SYNTHETIC_DIFFUSION = "synthetic_diffusion"
    AUGMENTED = "augmented"
    SCRAPED = "scraped"
    MIXED = "mixed"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ProvenanceRecord:
    """A registered dataset node in the provenance graph.

    Attributes:
        dataset_id: Unique identifier for the dataset.
        parent_id: Identifier of the parent dataset (None for root nodes).
        source_type: How the dataset was generated.
        generation: Generation number (0 = original, increments per derivation).
        tenant_id: Owning tenant for data isolation.
        contamination_score: Current contamination score in [0.0, 1.0].
        contamination_level: Classification of contamination state.
        created_at: ISO-8601 timestamp of registration.
        metadata: Arbitrary metadata attached to the dataset node.
    """
    dataset_id: str
    parent_id: str | None
    source_type: SourceType
    generation: int
    tenant_id: str
    contamination_score: float = 0.0
    contamination_level: ContaminationLevel = ContaminationLevel.CLEAN
    created_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ContaminationPath:
    """A single path from a contaminated ancestor to the queried dataset.

    Attributes:
        ancestor_id: The contaminated ancestor dataset.
        ancestor_score: Contamination score of the ancestor.
        ancestor_reason: Reason the ancestor was flagged.
        path: List of dataset IDs from ancestor to the queried dataset.
        generations_removed: Number of derivation steps between them.
        decayed_score: Contamination score after applying generational decay.
    """
    ancestor_id: str
    ancestor_score: float
    ancestor_reason: str
    path: list[str]
    generations_removed: int
    decayed_score: float


@dataclass(slots=True)
class ContaminationReport:
    """Result of a contamination check for a single dataset.

    Attributes:
        dataset_id: The queried dataset.
        is_contaminated: Whether any ancestor path exceeds the threshold.
        max_decayed_score: Highest decayed score across all ancestor paths.
        contamination_paths: All paths from contaminated ancestors.
        total_ancestors_checked: Number of ancestor nodes traversed.
        elapsed_ms: Wall-clock time in milliseconds.
    """
    dataset_id: str
    is_contaminated: bool
    max_decayed_score: float
    contamination_paths: list[ContaminationPath]
    total_ancestors_checked: int
    elapsed_ms: float


@dataclass(slots=True)
class LineageNode:
    """A single node in the lineage visualisation graph.

    Attributes:
        dataset_id: Node identifier.
        source_type: Origin classification.
        generation: Derivation generation number.
        contamination_score: Current contamination score.
        contamination_level: Classification of contamination state.
    """
    dataset_id: str
    source_type: str
    generation: int
    contamination_score: float
    contamination_level: str


@dataclass(slots=True)
class LineageEdge:
    """A directed edge in the lineage graph.

    Attributes:
        parent_id: Source node (parent dataset).
        child_id: Target node (derived dataset).
    """
    parent_id: str
    child_id: str


@dataclass(slots=True)
class LineageGraph:
    """Complete ancestry and descendant graph for visualisation.

    Attributes:
        root_id: The queried dataset.
        nodes: All nodes in the graph.
        edges: All directed edges (parent -> child).
        max_depth_reached: Maximum traversal depth actually used.
    """
    root_id: str
    nodes: list[LineageNode]
    edges: list[LineageEdge]
    max_depth_reached: int


@dataclass(frozen=True, slots=True)
class ProvenanceConfig:
    """Configuration for the provenance tracker.

    Attributes:
        contamination_threshold: Decayed score above which a dataset is
            considered contaminated.
        decay_factor: Multiplicative decay applied per generation of
            derivation.  A factor of 0.7 means 70% of the parent's score
            is inherited by each child.
        max_traversal_depth: Maximum BFS/DFS depth for ancestry checks.
        propagation_batch_size: Number of descendant nodes to update per
            Cypher transaction when propagating contamination.
    """
    contamination_threshold: float = 0.3
    decay_factor: float = 0.7
    max_traversal_depth: int = 20
    propagation_batch_size: int = 100


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ProvenanceTracker:
    """Graph-based tracking of synthetic data lineage to prevent Virus Infection Attacks.

    Requires a Neo4j async driver instance.  The driver is injected via the
    constructor and is *not* owned by this class (the caller manages its
    lifecycle).

    Example::

        from neo4j import AsyncGraphDatabase
        driver = AsyncGraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
        tracker = ProvenanceTracker(driver)
        record = await tracker.register_dataset("ds-001", None, "human_curated", 0, "tenant-1")
        report = await tracker.check_contamination("ds-001")
        await driver.close()
    """

    def __init__(
        self,
        neo4j_driver: Any,
        config: ProvenanceConfig | None = None,
        database: str = "neo4j",
    ) -> None:
        """Initialise the provenance tracker.

        Args:
            neo4j_driver: An instance of ``neo4j.AsyncDriver``.
            config: Configuration overrides.
            database: Neo4j database name.
        """
        self._driver = neo4j_driver
        self._config = config or ProvenanceConfig()
        self._database = database
        logger.info(
            "ProvenanceTracker initialised  decay=%.2f  threshold=%.2f  db=%s",
            self._config.decay_factor,
            self._config.contamination_threshold,
            self._database,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register_dataset(
        self,
        dataset_id: str,
        parent_id: str | None,
        source_type: str,
        generation: int,
        tenant_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Register a new dataset node in the provenance graph.

        Creates a ``Dataset`` node and, if *parent_id* is provided, a
        ``DERIVED_FROM`` edge to the parent.

        Args:
            dataset_id: Unique identifier for the new dataset.
            parent_id: Parent dataset ID, or ``None`` for root nodes.
            source_type: How the dataset was generated (see :class:`SourceType`).
            generation: Derivation generation (0 for originals).
            tenant_id: Owning tenant.
            metadata: Arbitrary metadata to store on the node.

        Returns:
            A :class:`ProvenanceRecord` for the newly created node.

        Raises:
            ValueError: If *dataset_id* is empty.
        """
        if not dataset_id:
            raise ValueError("dataset_id must be a non-empty string.")

        now = datetime.now(timezone.utc).isoformat()
        meta_str = _safe_json(metadata or {})

        # Validate source type
        try:
            src = SourceType(source_type)
        except ValueError:
            src = SourceType.UNKNOWN

        async with self._driver.session(database=self._database) as session:
            # Create the dataset node
            await session.run(
                """
                MERGE (d:Dataset {dataset_id: $dataset_id})
                SET d.source_type = $source_type,
                    d.generation = $generation,
                    d.tenant_id = $tenant_id,
                    d.contamination_score = 0.0,
                    d.contamination_level = $level,
                    d.created_at = $created_at,
                    d.metadata = $metadata
                """,
                dataset_id=dataset_id,
                source_type=src.value,
                generation=generation,
                tenant_id=tenant_id,
                level=ContaminationLevel.CLEAN.value,
                created_at=now,
                metadata=meta_str,
            )

            # Create edge to parent if provided
            if parent_id:
                await session.run(
                    """
                    MATCH (child:Dataset {dataset_id: $child_id})
                    MATCH (parent:Dataset {dataset_id: $parent_id})
                    MERGE (child)-[:DERIVED_FROM]->(parent)
                    """,
                    child_id=dataset_id,
                    parent_id=parent_id,
                )

        logger.info(
            "Registered dataset %s  parent=%s  gen=%d  tenant=%s",
            dataset_id, parent_id, generation, tenant_id,
        )

        return ProvenanceRecord(
            dataset_id=dataset_id,
            parent_id=parent_id,
            source_type=src,
            generation=generation,
            tenant_id=tenant_id,
            contamination_score=0.0,
            contamination_level=ContaminationLevel.CLEAN,
            created_at=now,
            metadata=metadata or {},
        )

    async def check_contamination(
        self,
        dataset_id: str,
    ) -> ContaminationReport:
        """Traverse ancestry graph to detect contamination propagation.

        Performs a BFS traversal up through ``DERIVED_FROM`` edges, checking
        each ancestor for a non-zero contamination score.  Contamination
        decays by :attr:`ProvenanceConfig.decay_factor` per generation.

        Args:
            dataset_id: Dataset to check.

        Returns:
            A :class:`ContaminationReport` with all contamination paths found.
        """
        t0 = time.perf_counter()

        async with self._driver.session(database=self._database) as session:
            # Traverse ancestors up to max depth
            result = await session.run(
                """
                MATCH path = (d:Dataset {dataset_id: $dataset_id})-[:DERIVED_FROM*1..$max_depth]->(ancestor:Dataset)
                WHERE ancestor.contamination_score > 0
                RETURN ancestor.dataset_id AS ancestor_id,
                       ancestor.contamination_score AS score,
                       ancestor.contamination_level AS level,
                       [n IN nodes(path) | n.dataset_id] AS path_nodes,
                       length(path) AS depth
                ORDER BY depth ASC
                """,
                dataset_id=dataset_id,
                max_depth=self._config.max_traversal_depth,
            )

            records = [r async for r in result]

            # Also count total ancestors for reporting
            count_result = await session.run(
                """
                MATCH (d:Dataset {dataset_id: $dataset_id})-[:DERIVED_FROM*1..$max_depth]->(ancestor:Dataset)
                RETURN count(DISTINCT ancestor) AS total
                """,
                dataset_id=dataset_id,
                max_depth=self._config.max_traversal_depth,
            )
            count_record = await count_result.single()
            total_ancestors = count_record["total"] if count_record else 0

        contamination_paths: list[ContaminationPath] = []
        max_decayed = 0.0

        for record in records:
            ancestor_id = record["ancestor_id"]
            ancestor_score = float(record["score"])
            path_nodes = record["path_nodes"]
            depth = int(record["depth"])

            decayed = ancestor_score * (self._config.decay_factor ** depth)
            max_decayed = max(max_decayed, decayed)

            contamination_paths.append(ContaminationPath(
                ancestor_id=ancestor_id,
                ancestor_score=ancestor_score,
                ancestor_reason=record.get("level", "unknown"),
                path=path_nodes,
                generations_removed=depth,
                decayed_score=round(decayed, 6),
            ))

        is_contaminated = max_decayed > self._config.contamination_threshold
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return ContaminationReport(
            dataset_id=dataset_id,
            is_contaminated=is_contaminated,
            max_decayed_score=round(max_decayed, 6),
            contamination_paths=contamination_paths,
            total_ancestors_checked=total_ancestors,
            elapsed_ms=elapsed_ms,
        )

    async def flag_contaminated(
        self,
        dataset_id: str,
        score: float,
        reason: str,
    ) -> None:
        """Mark a dataset as contaminated and propagate warnings to descendants.

        The contamination score is set directly on the flagged node.
        Descendants receive a propagated warning with decay applied per
        generation of distance.

        Args:
            dataset_id: Dataset to flag.
            score: Contamination score in [0.0, 1.0].
            reason: Human-readable reason for the flag.

        Raises:
            ValueError: If *score* is outside [0.0, 1.0].
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"Contamination score must be in [0.0, 1.0], got {score}")

        level = (
            ContaminationLevel.CONFIRMED if score >= 0.7
            else ContaminationLevel.SUSPECTED
        )

        async with self._driver.session(database=self._database) as session:
            # Flag the source node
            await session.run(
                """
                MATCH (d:Dataset {dataset_id: $dataset_id})
                SET d.contamination_score = $score,
                    d.contamination_level = $level,
                    d.contamination_reason = $reason,
                    d.flagged_at = datetime()
                """,
                dataset_id=dataset_id,
                score=score,
                level=level.value,
                reason=reason,
            )

            # Propagate to descendants with decay
            await session.run(
                """
                MATCH (source:Dataset {dataset_id: $dataset_id})<-[:DERIVED_FROM*1..$max_depth]-(descendant:Dataset)
                WITH descendant, length(
                    shortestPath((descendant)-[:DERIVED_FROM*]->(source:Dataset {dataset_id: $dataset_id}))
                ) AS dist
                WHERE descendant.contamination_score < $score * $decay ^ dist
                SET descendant.contamination_score = $score * $decay ^ dist,
                    descendant.contamination_level = $propagated_level,
                    descendant.contamination_reason = 'Propagated from ' + $dataset_id
                """,
                dataset_id=dataset_id,
                score=score,
                decay=self._config.decay_factor,
                max_depth=self._config.max_traversal_depth,
                propagated_level=ContaminationLevel.PROPAGATED.value,
            )

        logger.warning(
            "Flagged dataset %s as contaminated  score=%.3f  reason=%s",
            dataset_id, score, reason,
        )

    async def get_lineage(
        self,
        dataset_id: str,
        max_depth: int = 10,
    ) -> LineageGraph:
        """Retrieve full ancestry and descendant graph for visualisation.

        Traverses both ``DERIVED_FROM`` (ancestors) and reverse
        ``DERIVED_FROM`` (descendants) edges up to *max_depth* hops.

        Args:
            dataset_id: Root dataset for the lineage query.
            max_depth: Maximum traversal depth in each direction.

        Returns:
            A :class:`LineageGraph` with all nodes and edges found.
        """
        nodes_map: dict[str, LineageNode] = {}
        edges_set: set[tuple[str, str]] = set()
        effective_max_depth = min(max_depth, self._config.max_traversal_depth)

        async with self._driver.session(database=self._database) as session:
            # Ancestors
            result = await session.run(
                """
                MATCH path = (d:Dataset {dataset_id: $dataset_id})-[:DERIVED_FROM*0..$max_depth]->(ancestor:Dataset)
                UNWIND nodes(path) AS n
                WITH DISTINCT n
                RETURN n.dataset_id AS id, n.source_type AS src, n.generation AS gen,
                       n.contamination_score AS score, n.contamination_level AS level
                """,
                dataset_id=dataset_id,
                max_depth=effective_max_depth,
            )
            async for record in result:
                nid = record["id"]
                nodes_map[nid] = LineageNode(
                    dataset_id=nid,
                    source_type=record["src"] or "unknown",
                    generation=record["gen"] or 0,
                    contamination_score=float(record["score"] or 0.0),
                    contamination_level=record["level"] or "clean",
                )

            # Ancestor edges
            edge_result = await session.run(
                """
                MATCH (d:Dataset {dataset_id: $dataset_id})-[:DERIVED_FROM*0..$max_depth]->(ancestor:Dataset)
                MATCH (ancestor)<-[:DERIVED_FROM]-(child:Dataset)
                WHERE (child)-[:DERIVED_FROM*0..$max_depth]->(d) OR child.dataset_id = $dataset_id
                   OR (d)-[:DERIVED_FROM*0..$max_depth]->(child)
                RETURN child.dataset_id AS child_id, ancestor.dataset_id AS parent_id
                """,
                dataset_id=dataset_id,
                max_depth=effective_max_depth,
            )
            async for record in edge_result:
                edges_set.add((record["parent_id"], record["child_id"]))

            # Descendants
            desc_result = await session.run(
                """
                MATCH path = (d:Dataset {dataset_id: $dataset_id})<-[:DERIVED_FROM*0..$max_depth]-(descendant:Dataset)
                UNWIND nodes(path) AS n
                WITH DISTINCT n
                RETURN n.dataset_id AS id, n.source_type AS src, n.generation AS gen,
                       n.contamination_score AS score, n.contamination_level AS level
                """,
                dataset_id=dataset_id,
                max_depth=effective_max_depth,
            )
            async for record in desc_result:
                nid = record["id"]
                if nid not in nodes_map:
                    nodes_map[nid] = LineageNode(
                        dataset_id=nid,
                        source_type=record["src"] or "unknown",
                        generation=record["gen"] or 0,
                        contamination_score=float(record["score"] or 0.0),
                        contamination_level=record["level"] or "clean",
                    )

            # Descendant edges
            desc_edge_result = await session.run(
                """
                MATCH (d:Dataset {dataset_id: $dataset_id})<-[:DERIVED_FROM*1..$max_depth]-(desc:Dataset)
                MATCH (desc)-[:DERIVED_FROM]->(parent:Dataset)
                RETURN desc.dataset_id AS child_id, parent.dataset_id AS parent_id
                """,
                dataset_id=dataset_id,
                max_depth=effective_max_depth,
            )
            async for record in desc_edge_result:
                edges_set.add((record["parent_id"], record["child_id"]))

        edges = [LineageEdge(parent_id=p, child_id=c) for p, c in edges_set]

        return LineageGraph(
            root_id=dataset_id,
            nodes=list(nodes_map.values()),
            edges=edges,
            max_depth_reached=effective_max_depth,
        )

    async def detect_circular_provenance(self, dataset_id: str) -> bool:
        """Detect circular references in provenance that indicate data laundering.

        Checks whether following ``DERIVED_FROM`` edges from *dataset_id*
        eventually leads back to *dataset_id* itself.

        Args:
            dataset_id: Dataset to check for circular provenance.

        Returns:
            ``True`` if a cycle is detected, ``False`` otherwise.
        """
        async with self._driver.session(database=self._database) as session:
            result = await session.run(
                """
                MATCH (d:Dataset {dataset_id: $dataset_id})
                MATCH path = (d)-[:DERIVED_FROM*1..]->(d)
                RETURN count(path) > 0 AS has_cycle
                """,
                dataset_id=dataset_id,
            )
            record = await result.single()
            if record is None:
                return False
            return bool(record["has_cycle"])


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _safe_json(obj: dict[str, Any]) -> str:
    """Serialise a dict to JSON, returning '{}' on failure."""
    try:
        import json
        return json.dumps(obj, default=str)
    except Exception:
        return "{}"
