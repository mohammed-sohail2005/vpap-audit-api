"""
Enrichment pipeline orchestration.

Coordinates enrichment of validated findings and persistence of the
resulting evidence.
"""

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from vpap.domain.finding import Finding
from vpap.enrichment.epss import EPSSResult, get_epss_batch
from vpap.enrichment.service import (
    ADAPTER_NAME,
    ADAPTER_VERSION,
    SCHEMA_VERSION,
    SOURCE_SYSTEM,
    enrich_finding,
)
from vpap.persistence.repositories import (
    AuditEventRepository,
    EnrichmentRunRepository,
    EPSSSnapshotRepository,
    FindingEvidenceRepository,
    KEVCatalogueRepository,
)


class EnrichmentPipeline:
    """
    Enrich a batch of validated findings and persist the evidence.

    A single enrichment run is created for the entire batch. Its ID is
    reused for every finding in that batch.
    """

    def __init__(
        self,
        enrichment_run_repository,
        finding_evidence_repository,
        kev_catalogue_repository,
        epss_snapshot_repository,
        audit_event_repository=None,
        epss_max_age: timedelta | None = None,
    ):
        self.enrichment_run_repository = enrichment_run_repository
        self.finding_evidence_repository = finding_evidence_repository
        self.kev_catalogue_repository = kev_catalogue_repository
        self.epss_snapshot_repository = epss_snapshot_repository
        self.audit_event_repository = audit_event_repository
        self.epss_max_age = epss_max_age

    def _resolve_epss(
        self,
        cve_ids: set[str],
    ) -> dict[str, EPSSResult]:
        """
        Resolve EPSS values using the durable snapshot cache first.

        Fresh cached values are reused directly. Missing or stale values are
        refreshed from FIRST in batches. If refresh fails, the previous
        cached value is retained as last-known-good.
        """

        if not cve_ids:
            return {}

        now = datetime.now(timezone.utc)

        cached_response = self.epss_snapshot_repository.get_latest(cve_ids)

        resolved: dict[str, EPSSResult] = {}
        stale_values: dict[str, EPSSResult] = {}
        missing_or_stale: set[str] = set()

        for value in cached_response.get("values", []):
            cve_id = value.get("cve_id")
            retrieved_at_raw = value.get("retrieved_at")

            if not isinstance(cve_id, str):
                continue

            if not isinstance(retrieved_at_raw, str):
                missing_or_stale.add(cve_id)
                continue

            try:
                retrieved_at = datetime.fromisoformat(
                    retrieved_at_raw.replace("Z", "+00:00")
                )
            except ValueError:
                missing_or_stale.add(cve_id)
                continue

            try:
                epss = float(value["epss_probability"])
                percentile = float(value["epss_percentile"])
            except (KeyError, TypeError, ValueError):
                missing_or_stale.add(cve_id)
                continue

            cached_result = EPSSResult(
                status="FOUND",
                epss=epss,
                percentile=percentile,
                source_timestamp=retrieved_at,
            )

            if (
                self.epss_max_age is not None
                and now - retrieved_at > self.epss_max_age
            ):
                stale_values[cve_id] = cached_result
                missing_or_stale.add(cve_id)
            else:
                resolved[cve_id] = cached_result

        # Anything not returned by the persistence API is missing.
        missing_or_stale.update(cve_ids - set(resolved) - set(stale_values))

        if missing_or_stale:
            fetched = get_epss_batch(missing_or_stale)

            snapshot_entries: dict[str, tuple[float, float]] = {}

            for cve_id in missing_or_stale:
                result = fetched.get(
                    cve_id,
                    EPSSResult(
                        status="ERROR",
                        reason_code="CONNECTOR_ERROR",
                    ),
                )

                if result.status == "FOUND":
                    resolved[cve_id] = result

                    if (
                        result.epss is not None
                        and result.percentile is not None
                    ):
                        snapshot_entries[cve_id] = (
                            result.epss,
                            result.percentile,
                        )

                elif result.status == "NOT_FOUND":
                    # If FIRST confirms that the CVE is not scored,
                    # that is authoritative for this retrieval.
                    resolved[cve_id] = result

                elif cve_id in stale_values:
                    # FIRST failed, so retain the previous trusted value.
                    resolved[cve_id] = stale_values[cve_id]

                else:
                    resolved[cve_id] = result

            if snapshot_entries:
                source_timestamps = [
                    result.source_timestamp
                    for result in fetched.values()
                    if result.status == "FOUND"
                    and result.source_timestamp is not None
                ]

                source_timestamp = max(
                    source_timestamps,
                    default=now,
                )

                self.epss_snapshot_repository.create(
                    source_timestamp=source_timestamp,
                    retrieved_at=now,
                    entries=snapshot_entries,
                )

        # Ensure every requested CVE has a result.
        for cve_id in cve_ids:
            resolved.setdefault(
                cve_id,
                EPSSResult(
                    status="ERROR",
                    reason_code="CONNECTOR_ERROR",
                ),
            )

        return resolved

    def process(
        self,
        findings: Iterable[Finding],
        tenant_id: str,
        source_instance_id: str,
        finding_instance_ids: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Enrich and persist all findings in a batch.

        Returns the persistence responses for each saved evidence record.
        """

        findings = list(findings)
        if finding_instance_ids is not None:
            finding_instance_ids = list(finding_instance_ids)

            if len(findings) != len(finding_instance_ids):
                raise ValueError(
                    "Number of findings must match number of finding instance IDs"
                )
            if any(
                not finding_instance_id
                for finding_instance_id in finding_instance_ids
            ):
                raise ValueError(
                    "Finding instance IDs must not be empty"
                )
        run_response = self.enrichment_run_repository.create(
            {
                "tenant_id": tenant_id,
                "source_system": SOURCE_SYSTEM,
                "adapter_name": ADAPTER_NAME,
                "adapter_version": ADAPTER_VERSION,
                "schema_version": SCHEMA_VERSION,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "RUNNING",
            }
        )

        enrichment_run_id = run_response.get("enrichment_run_id")

        if not enrichment_run_id:
            raise ValueError(
                "Enrichment run response did not contain enrichment_run_id"
            )
        self.enrichment_run_id = enrichment_run_id

        if finding_instance_ids is not None:
            finding_pairs = list(
                zip(
                    findings,
                    finding_instance_ids,
                    strict=True,
                )
            )
        else:
            finding_pairs = [
                (finding, None)
                for finding in findings
            ]

        try:
            # Emit enrichment_run.started for each finding so that every
            # finding gets its own correlation chain through the pipeline.
            for _, finding_instance_id in finding_pairs:
                if finding_instance_id is not None:
                    self.audit_event_repository.create(
                        {
                            "actor_type": "system",
                            "actor_id": "enrichment-service",
                            "action": "enrichment_run.started",
                            "entity_type": "enrichment_run",
                            "entity_id": enrichment_run_id,
                            "correlation_id": finding_instance_id,
                            "tenant_id": tenant_id,
                        }
                    )

            cve_ids = {
                finding.cve_id
                for finding in findings
                if finding.cve_id
            }

            epss_results = self._resolve_epss(cve_ids)

            results: list[dict[str, Any]] = []

            for finding, finding_instance_id in finding_pairs:
                evidence, refreshed_catalogue = enrich_finding(
                    finding,
                    enrichment_run_id=enrichment_run_id,
                    tenant_id=tenant_id,
                    source_instance_id=source_instance_id,
                    finding_instance_id=finding_instance_id,
                    epss_result=epss_results[finding.cve_id],
                )

                evidence_response = (
                    self.finding_evidence_repository.create(evidence)
                )

                results.append(evidence_response)

                if finding_instance_id is not None:
                    self.audit_event_repository.create(
                        {
                            "actor_type": "system",
                            "actor_id": "enrichment-service",
                            "action": "finding_evidence.recorded",
                            "entity_type": "finding_evidence",
                            "entity_id": evidence.evidence_snapshot_id,
                            "correlation_id": finding_instance_id,
                            "tenant_id": tenant_id,
                            "evidence_ref": evidence.evidence_snapshot_id,
                        }
                    )

                if refreshed_catalogue is not None:
                    self.kev_catalogue_repository.create(
                        refreshed_catalogue
                    )

            self.enrichment_run_repository.update(
                enrichment_run_id=enrichment_run_id,
                tenant_id=tenant_id,
                status="COMPLETED",
                completed_at=datetime.now(timezone.utc),
            )

            for _, finding_instance_id in finding_pairs:
                if finding_instance_id is not None:
                    self.audit_event_repository.create(
                        {
                            "actor_type": "system",
                            "actor_id": "enrichment-service",
                            "action": "enrichment_run.completed",
                            "entity_type": "enrichment_run",
                            "entity_id": enrichment_run_id,
                            "correlation_id": finding_instance_id,
                            "tenant_id": tenant_id,
                        }
                    )

            return results

        except Exception:
            self.enrichment_run_repository.update(
                enrichment_run_id=enrichment_run_id,
                tenant_id=tenant_id,
                status="FAILED",
                completed_at=datetime.now(timezone.utc),
            )

            for _, finding_instance_id in finding_pairs:
                if finding_instance_id is not None:
                    try:
                        self.audit_event_repository.create(
                            {
                                "actor_type": "system",
                                "actor_id": "enrichment-service",
                                "action": "enrichment_run.failed",
                                "entity_type": "enrichment_run",
                                "entity_id": enrichment_run_id,
                                "correlation_id": finding_instance_id,
                                "tenant_id": tenant_id,
                            }
                        )
                    except Exception:
                        # Preserve the original enrichment failure.
                        pass

            raise
