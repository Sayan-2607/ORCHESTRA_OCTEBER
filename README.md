# ORCHESTRA_OCTEBER

**AI-Powered Personal Data Deletion Verification Agent**

An intelligent data auditing system built for the HackerRank Orchestrate – October 2026 challenge.

## Overview

Ghost Data Still Exists addresses a critical problem in modern data privacy: a deletion request may be marked as complete even when the user's personal data continues to exist across databases, logs, backups, search indexes, exports, and other connected systems.

ORCHESTRA_OCTEBER aims to build an AI agent that investigates deletion requests using historical identity records, system activity, deletion policies, and supporting evidence.

For every request, the system determines whether deletion was actually requested, evaluates the available evidence, identifies remaining data and potential recreation risks, and generates an ordered set of remediation and verification steps.

## Problem Statement

A successful deletion workflow does not necessarily guarantee that personal data has been removed everywhere.

Data may persist because of:

- Incomplete deletion across distributed systems.
- Replication delays and inconsistent database replicas.
- Historical identity changes and account associations.
- Residual data in logs, exports, attachments, and archives.
- Search indexes and cached records.
- Backup retention and restoration processes.
- Synchronization workflows that recreate deleted records.

The system must evaluate the actual resource state at the specified audit timestamp rather than blindly trusting reported workflow statuses.

## Core Objectives

- Determine whether a deletion request was actually made.
- Resolve current and historical user identities.
- Inspect evidence across multiple data sources.
- Identify residual personal data.
- Detect synchronization and restoration risks.
- Apply the appropriate deletion rules.
- Generate ordered remediation actions.
- Provide evidence-backed verification steps.

## Deletion Statuses

Each request receives exactly one of three statuses:

| Status | Meaning |
|---|---|
| `COMPLETE` | Available evidence establishes that the authorized deletion has been completed. |
| `INCOMPLETE` | Data remains, deletion is incomplete, or recreation risks require remediation. |
| `NOT_APPLICABLE` | No applicable deletion request was made. |

For `NOT_APPLICABLE`, the `steps_json` field must contain an empty JSON array.

## Dataset

The challenge provides 518 deletion requests and supporting evidence files.

| File | Description |
|---|---|
| `deletion_requests.csv` | Main evaluation dataset containing 518 requests |
| `sample_deletion_requests.csv` | Sample requests |
| `sample_output.csv` | Reference output |
| `user_identities.csv` | Current user identity records |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activities across systems and data processes |
| `deletion_rules.csv` | Deletion policies for different data categories |
| `evidence_files.csv` | Evidence file manifest |
| `evidence/` | Supporting PDFs, images, logs, JSON, text, and SQL snapshots |

## Expected Output

The solution generates `output.csv` in the repository root.

Required columns:

```csv
case_id,deletion_status,steps_json
```

Requirements:

- Exactly 518 data rows.
- One prediction for every deletion request.
- Rows sorted by `case_id`.
- Valid JSON arrays in `steps_json`.
- Consecutive step numbers starting from 1.
- Evidence references for findings and completed verification.
- Empty evidence references for proposed future actions.
- Correct ordering of findings, remediation, and verification.

## Project Structure

```text
ORCHESTRA_OCTEBER/
│
├── dataset/
│   ├── deletion_requests.csv
│   ├── sample_deletion_requests.csv
│   ├── sample_output.csv
│   ├── user_identities.csv
│   ├── user_audit_log.csv
│   ├── system_activity.csv
│   ├── deletion_rules.csv
│   ├── evidence_files.csv
│   └── evidence/
│
├── code/
│   ├── main.py
│   └── evaluation/
│       ├── evaluation_report.md
│       └── usage_report.md
│
├── AGENTS.md
├── README.md
├── log.txt
└── output.csv
```

## Getting Started

### Prerequisites

- Python 3.
- Git.
- An AI coding assistant or development environment, if required by your implementation.

### Clone the Repository

```bash
git clone https://github.com/Sayan-2607/ORCHESTRA_OCTEBER.git
cd ORCHESTRA_OCTEBER
```

### Run the Solution

```bash
python3 code/main.py
```

On Windows:

```powershell
python code/main.py
```

The program reads the challenge data from `dataset/` and generates the final predictions in the root-level `output.csv`.

## Evaluation

The solution is evaluated against hidden canonical answers.

Evaluation considers:

1. Deletion assessment accuracy.
2. Current and historical identity resolution.
3. Discovery of residual data and recreation risks.
4. Correct application of deletion policies.
5. Evidence reference accuracy.
6. Completeness and ordering of remediation and verification steps.

The submission must include:

- `code/evaluation/evaluation_report.md`
- `code/evaluation/usage_report.md`

The evaluation report documents case, row, field, and sequence accuracy, custom test cases, identified failures, and improvements.

The usage report documents model providers, model names, model calls, token consumption, and estimated costs for the full-dataset run.

## Submission Requirements

The final HackerRank submission consists of three components:

| Artifact | Description |
|---|---|
| `code.zip` | Runnable implementation, README, prompts, configuration, and evaluation reports |
| `output.csv` | Predictions for all 518 requests |
| `chat_transcript` | Complete AI coding session transcript from `log.txt` |

The dataset, credentials, API keys, virtual environments, caches, and nested archives must not be included in `code.zip`.

## Important Design Principles

- Evidence-driven decisions instead of trusting workflow claims.
- Historical identity resolution.
- Timestamp-aware resource state assessment.
- Policy-compliant deletion.
- Detection of replication and restoration risks.
- Deterministic output generation.
- Traceable findings and remediation steps.

## Author

**Sayan Ghosh**

Computer Science & Engineering | KIIT (2027)

- GitHub: [Sayan-2607](https://github.com/Sayan-2607)
- LinkedIn: [Sayan Ghosh](https://linkedin.com/in/sayan-g-600ab5307)
- Portfolio: [sxynn.vercel.app](https://sxynn.vercel.app)

---

**ORCHESTRA_OCTEBER**  
*Because marking data as deleted doesn't mean it is actually gone.*
