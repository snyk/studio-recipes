---
name: ai-inventory
description: |
  Generate and analyze AI Bill of Materials (AIBOM) for Python projects using AI/ML components.
  Identifies AI models, datasets, tools, and frameworks for security and compliance tracking. 
  Use this skill when:
  - User asks to scan for AI components
  - User wants to know what AI models a project uses
  - User mentions "AI BOM", "AI inventory", or "ML security"
  - User is working with Python AI/ML projects (PyTorch, TensorFlow, HuggingFace)
  - User needs AI component compliance documentation
allowed-tools: "mcp_snyk_snyk_aibom Read Write Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Python projects only. Internet connection required for AIBOM analysis.
  Snyk experimental features must be enabled.
metadata:
  author: Snyk
  version: 1.0.0
---

# AI Component Inventory

Generate and analyze AI Bill of Materials (AIBOM) for Python projects to track AI models, datasets, and ML frameworks for security, compliance, and governance.

**Core Principle**: Know what AI components are in your software.

**Note**: This is an experimental feature. Currently supports Python projects only.

---

## Quick Start

```
# Step 1: Generate AIBOM for the project
mcp_snyk_snyk_aibom(path="/absolute/path/to/project")

# Step 2: (Optional) Save AIBOM to file for documentation
mcp_snyk_snyk_aibom(
  path="/absolute/path/to/project",
  json_file_output="/absolute/path/to/output/aibom.json"
)

# Step 3: Verify the returned JSON contains component entries before proceeding
# Step 4: Summarize findings and flag license/risk issues
```

---

## Prerequisites

- Python project with `requirements.txt`, `setup.py`, or `pyproject.toml`
- Internet connection (required for analysis)
- Snyk experimental features enabled

---

## Phase 1: Project Validation

**Goal**: Ensure the project is suitable for AI BOM generation.

### Step 1.1: Verify Python Project

Check for Python project indicators: `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`, or `.py` files.

> **Error — Not a Python Project**: If no Python indicators are found, stop and report:
> - Verify path contains Python files
> - Check for `requirements.txt` or `pyproject.toml`
> - This feature only supports Python projects

### Step 1.2: Check for AI/ML Indicators

Scan dependency files for known AI/ML packages — common examples include `torch`, `tensorflow`, `keras`, `transformers`, `datasets`, `scikit-learn`, `jax`, `openai`, `langchain`, `mlflow`, and `wandb`. This list is illustrative; use judgment for other AI/ML packages encountered.

### Step 1.3: Report if Not Applicable

If no AI components detected:

```
## AI Inventory Result
**Project**: /path/to/project
**Status**: No AI components detected
This project does not appear to use AI/ML frameworks. AI BOM generation is not applicable.
```

---

## Phase 2: Generate AIBOM

**Goal**: Create comprehensive AI Bill of Materials.

### Step 2.1: Run AIBOM Generation

Invoke the `mcp_snyk_snyk_aibom` tool with the absolute path to the Python project:

```
mcp_snyk_snyk_aibom(path="/absolute/path/to/project")
```

> **Error — Network Error**: If the tool cannot connect, report:
> - Check internet connection and firewall (HTTPS must be allowed)
> - Retry after a few minutes

> **Error — Experimental Feature Not Enabled**: If access is denied, report:
> - Contact Snyk support for experimental access
> - Check organization settings and verify CLI version supports AIBOM

### Step 2.2: Validate AIBOM Output

Before proceeding, verify the returned JSON is valid and contains at least one component entry. If the response is empty or malformed, report the error and do not continue to Phase 3.

### Step 2.3: Save Output (Optional)

To persist the AIBOM as a file for documentation or downstream tooling:

```
mcp_snyk_snyk_aibom(
  path="/absolute/path/to/project",
  json_file_output="/absolute/path/to/output/aibom.json"
)
```

---

## Phase 3: Analyze Components

**Goal**: Understand and categorize AI components from the validated AIBOM output.

### Step 3.1: Component Categories

AIBOM identifies five component types: **Models**, **Datasets**, **Frameworks**, **Tools**, and **Services**.

### Step 3.2: Generate Summary Report

Present findings using the structure below, populated with actual scan results:

```
## AI Component Inventory
**Project**: <project name>
**Scan Date**: <date>
**Format**: CycloneDX v1.6

### Component Summary
| Category  | Count |
|-----------|-------|
| AI Models | N     |
| Datasets  | N     |
| Frameworks| N     |
| Tools     | N     |
| **Total** | N     |

### AI Models Detected
| Model | Source | License | Risk |
|-------|--------|---------|------|
| <from scan results> | ... | ... | ... |

### Datasets Referenced
| Dataset | Source | License | PII Risk |
|---------|--------|---------|----------|
| <from scan results> | ... | ... | ... |

### Frameworks & Tools
| Component | Version | License |
|-----------|---------|---------|
| <from scan results> | ... | ... |
```

---

## Phase 4: Risk Assessment

**Goal**: Identify potential risks in AI components.

### Step 4.1: License Compliance

Flag components by risk level: **Low** (MIT, Apache), **Medium** (proprietary APIs — review terms of service), **High** (unknown/unclear licenses or research-only terms that may prohibit commercial use).

### Step 4.2: Data Privacy Concerns

Flag datasets or models where data provenance or PII handling is unclear. Recommend: documenting data sources, reviewing PII handling procedures, and verifying data retention policies.

### Step 4.3: Model Security

Assess model-specific risks: prompt injection (LLM-based models — mitigate with input validation), model extraction (custom/fine-tuned models — apply access controls), adversarial inputs (vision models — input validation), and bias/fairness (consider bias testing).

---

## Phase 5: Documentation

**Goal**: Create compliance-ready documentation.

### Step 5.1: Generate Compliance Report

```
## AI Compliance Report
**Project**: <project name>
**Generated**: <date>
**Standard**: EU AI Act / Internal Governance

### AI System Classification
- **Risk Level**: [High/Limited/Minimal]
- **Category**: [Classification based on use case]

### Component Inventory
[Summary from Phase 3]

### License Compliance
- All components licensed: Yes/No
- Commercial use permitted: Yes/No
- Attribution required: [list components]

### Data Governance
- Data sources documented: Yes/No
- PII handling reviewed: Yes/No
- Consent verified: Yes/No

### Model Governance
- Model cards available: Yes/No
- Bias testing completed: Yes/No
- Performance benchmarks: Yes/No

### Approval Status
- [ ] Technical review
- [ ] Legal review
- [ ] Ethics review
- [ ] Deployment approved
```

---

## Use Cases

- **Pre-Deployment Audit**: Generate AIBOM → review licenses → check data/PII handling → document for audit trail
- **Regulatory Compliance (EU AI Act)**: Generate AIBOM → classify AI system risk level → document capabilities/limitations → create compliance checklist
- **Third-Party AI Review**: Generate AIBOM → analyze licenses → assess data handling → document risks and mitigations

---

## Constraints

1. **Python only**: Currently only supports Python projects
2. **Experimental**: Feature may change or have limitations
3. **Network required**: Needs internet for analysis
4. **CycloneDX output**: Generates CycloneDX v1.6 format only
5. **Point-in-time**: Reflects current state — regenerate on updates
