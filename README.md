# VPAP — Vulnerability Prioritisation and Automation Platform

## Overview

VPAP is a security engineering platform designed to process vulnerability findings, enrich them with trusted security evidence, prioritise risk deterministically, and automate downstream remediation workflows.

VPAP 4.1 uses a deterministic, evidence-first architecture with optional bounded AI assistance. The core prioritisation path does not depend on an autonomous AI agent.

## High-Level Processing Flow

1. **Ingestion** — Read vulnerability findings and asset context from scanner/source systems such as Wiz.
2. **Validation and normalisation** — Validate incoming data, normalise identifiers into the VPAP canonical format, establish provenance, and calculate an idempotency key.
3. **Threat-intelligence enrichment** — Enrich CVEs using trusted sources such as CISA KEV and FIRST EPSS.
4. **Context validation** — Evaluate applicability, exposure, attack path, compensating controls, and business-service context.
5. **Deterministic prioritisation** — Apply versioned SSVC policy rules and calculate the Vulnerability Priority Score (VPS).
6. **ITSM automation** — Create or update the appropriate ITSM record and begin the SLA process.
7. **Optional AI assistance** — Generate evidence summaries and remediation playbooks from an allowlisted subset of data.
8. **Human governance and audit** — Handle exceptions, approvals, metrics, and audit events.

## Core Design Principles

### Deterministic

The same input snapshot and policy version should produce the same prioritisation result.

### Evidence-first

Important decisions must be linked to their source, timestamp, freshness, confidence, and applied rules.

### Bounded AI

AI is optional and is restricted to tasks such as interpreting unstructured notes and drafting explanations or remediation playbooks. It must not determine authoritative threat facts or final policy outcomes.

### Safe Handling of Uncertainty

Unknown information must not silently become `false`, `0`, or a low-risk value. The design uses explicit states such as `KNOWN`, `UNKNOWN`, `STALE`, and `ERROR`.

### Human Governance

False-positive handling, exceptions, risk acceptance, and SLA extensions use explicit approval workflows.

## Canonical Finding

VPAP defines a canonical `Finding` model so that data from different source systems can be represented consistently.

The canonical finding contains:

- `source_system`
- `source_finding_id`
- `cve_id`
- `asset_id`
- `package_id`
- `cvss_base`
- `cvss_vector`
- `description`
- `business_service_id`
- `internet_exposed`
- `first_detected_at`

The `Finding` model also provides an `idempotency_key()` method based on the source system, source finding ID, asset ID, and package ID.

## Current Ingestion Work

The current ingestion implementation reads a supplied **Wiz Excel sample** and converts each source record into the canonical VPAP representation.

### Verified Wiz-to-VPAP Mapping

| VPAP field | Wiz field |
|---|---|
| `source_system` | `"WIZ"` |
| `source_finding_id` | `id` |
| `cve_id` | `vulnerabilityExternalId` |
| `asset_id` | `vulnerableAsset.id` |
| `cvss_base` | `score` |
| `description` | `description` |
| `first_detected_at` | `firstDetectedAt` |
| `package_id` | `None` |
| `cvss_vector` | `None` |
| `business_service_id` | `None` |
| `internet_exposed` | `None` |

The ingestion layer must not invent missing information or infer unsupported fields from unrelated source values.

For example:

- Do not parse `CVEDescription` for `cve_id` when `vulnerabilityExternalId` already supplies the CVE.
- Do not automatically use `version` or `fixedVersion` as `package_id`.
- Do not automatically use asset tags such as `Owner` as `business_service_id`.
- Do not infer `internet_exposed` from unrelated asset metadata.
- Do not manufacture a CVSS vector when the source does not provide one.

## Ingestion vs Validation

These are separate responsibilities.

**Ingestion** reads source data and produces the canonical representation.

**Validation** verifies that the resulting values satisfy required rules and that external facts can be trusted or confirmed.

Validation may check:

- CVE format
- CVSS range
- schema requirements
- external threat-intelligence presence
- data quality and provenance

Keeping these responsibilities separate makes the pipeline easier to test, maintain, and extend to additional source systems.

## Target Repository Architecture

The VPAP 4.1 build guide describes a Python project organised around:

```text
src/vpap/
├── api/
├── connectors/
├── domain/
├── enrichment/
├── policy/
├── workflow/
├── ai/
├── persistence/
└── observability/

tests/
├── unit/
├── integration/
├── security/
└── evals/
```

## Security and Scope

VPAP is intended to operate with controlled integrations and read-only scanner access. Scanner data may be incomplete or attacker-influenced, so schema validation, scoped access, TLS, rate limiting, and audit controls are important.

VPAP is not intended to replace the vulnerability scanner, CMDB, or authoritative asset-owner process. It is also not intended to autonomously execute production patches, firewall changes, or other infrastructure modifications.

## VPAP Audit API & Database Setup

### 1. Environment Configuration

Copy the example environment template and configure your PostgreSQL / Supabase connection:

```bash
cp .env.example .env
```

Ensure `VPAP_AUDIT_DSN` (or `DATABASE_URL`) and `VPAP_AUTH_SECRET` are configured in `.env`:

```ini
VPAP_AUDIT_DSN=postgresql://username:password@hostname:5432/dbname
VPAP_AUTH_SECRET=your-secure-secret-here
```

### 2. Database Migrations

Apply database migrations (idempotent, tracks applied migrations in `migration_history`):

```bash
python run_migrations.py
```

The migrations establish:
- `0001_baseline_schema.sql`: Core 16 tables across Ingestion, Enrichment, Policy, Exceptions, and Audit.
- `0002_add_batch_id_to_finding_instance.sql`: Batch relationship and index on `finding_instance`.
- `0003_add_asset_contexts.sql`: Asset Context Source (ACS) table and audit event constraint updates.

### 3. Service & Operator Token Generation

Generate signed JWT access tokens out-of-band for core services and operators:

```bash
# Generate tokens for all 3 core services (Ingestion, Enrichment, Policy Engine) + UI Operator:
python generate_token.py --services

# Or generate a custom token:
python generate_token.py --tenant vpap-pilot --scope "persistence:* audit:read" --subject custom-service
```

### 4. Running the Audit API

Launch the FastAPI backend server:

```bash
uvicorn audit_api:app --reload --port 8000
```

Interactive OpenAPI docs will be available at: `http://localhost:8000/docs`

### 5. Running Tests

Run the test suite:

```bash
python -m pytest tests/test_asset_context.py -v
```

