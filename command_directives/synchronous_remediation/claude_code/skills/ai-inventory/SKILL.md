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
---

# AI Component Inventory

Generate and analyze AI Bill of Materials (AIBOM) for Python projects to track AI models, datasets, and ML frameworks for security, compliance, and governance.

**Core Principle**: Know what AI components are in your software.

**Note**: This is an experimental feature. Currently supports Python projects only.

---

## Quick Start

```
1. Verify Python project with AI/ML dependencies
2. Run snyk_aibom on project directory
3. Review identified AI components
4. Document findings for compliance/governance
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

Check for Python project indicators:
- `requirements.txt`
- `setup.py`
- `pyproject.toml`
- `Pipfile`
- `.py` files

### Step 1.2: Check for AI/ML Indicators

Look for common AI/ML dependencies:

| Framework | Package Names |
|-----------|---------------|
| **PyTorch** | `torch`, `torchvision`, `torchaudio` |
| **TensorFlow** | `tensorflow`, `tensorflow-gpu`, `keras` |
| **HuggingFace** | `transformers`, `datasets`, `tokenizers` |
| **Scikit-learn** | `scikit-learn`, `sklearn` |
| **JAX** | `jax`, `jaxlib`, `flax` |
| **MLflow** | `mlflow` |
| **Weights & Biases** | `wandb` |
| **OpenAI** | `openai` |
| **LangChain** | `langchain`, `langchain-core` |

### Step 1.3: Report if Not Applicable

If no AI components detected:

```
## AI Inventory Result

**Project**: /path/to/project
**Status**: No AI components detected

This project does not appear to use AI/ML frameworks.
AI BOM generation is not applicable.
```

---

## Phase 2: Generate AIBOM

**Goal**: Create comprehensive AI Bill of Materials.

### Step 2.1: Run AIBOM Generation

```
Run snyk_aibom with:
- path: <absolute path to Python project>
```

### Step 2.2: Save Output (Optional)

To save the AIBOM for documentation:

```
Run snyk_aibom with:
- path: <project path>
- json_file_output: <output file path>
```

---

## Phase 3: Analyze Components

**Goal**: Understand and categorize AI components.

### Step 3.1: Component Categories

AIBOM identifies several types of AI components:

| Category | Description | Examples |
|----------|-------------|----------|
| **Models** | Pre-trained ML models | GPT-4, BERT, ResNet |
| **Datasets** | Training/evaluation data | ImageNet, COCO, GLUE |
| **Frameworks** | ML/AI libraries | PyTorch, TensorFlow |
| **Tools** | AI development tools | MLflow, Weights & Biases |
| **Services** | AI API services | OpenAI API, Anthropic API |

### Step 3.2: Generate Summary Report

```
## AI Component Inventory

**Project**: my-ai-project
**Scan Date**: 2024-01-15
**Format**: CycloneDX v1.6

### Component Summary
| Category | Count |
|----------|-------|
| AI Models | 3 |
| Datasets | 2 |
| Frameworks | 4 |
| Tools | 2 |
| **Total** | 11 |

### AI Models Detected

| Model | Source | License | Risk |
|-------|--------|---------|------|
| gpt-4 | OpenAI API | Proprietary | Review ToS |
| bert-base-uncased | HuggingFace | Apache 2.0 | Low |
| resnet50 | torchvision | BSD | Low |

### Datasets Referenced

| Dataset | Source | License | PII Risk |
|---------|--------|---------|----------|
| COCO | cocodataset.org | CC BY 4.0 | Low |
| custom-training | Internal | N/A | Review |

### Frameworks & Tools

| Component | Version | License |
|-----------|---------|---------|
| torch | 2.1.0 | BSD |
| transformers | 4.35.0 | Apache 2.0 |
| openai | 1.3.0 | MIT |
| mlflow | 2.9.0 | Apache 2.0 |
```

---

## Phase 4: Risk Assessment

**Goal**: Identify potential risks in AI components.

### Step 4.1: License Compliance

Check AI component licenses:

| License Type | Risk Level | Notes |
|--------------|------------|-------|
| Open source (MIT, Apache) | Low | Standard compliance |
| Proprietary API | Medium | Review terms of service |
| Unknown/Unclear | High | Investigate before use |
| Research-only | High | May not allow commercial use |

### Step 4.2: Data Privacy Concerns

Flag potential PII or sensitive data:

```
## Data Privacy Assessment

### Potential Concerns

| Dataset/Model | Concern | Recommendation |
|---------------|---------|----------------|
| custom-training | Unknown data source | Document data provenance |
| user-embeddings | May contain PII | Review data handling |
| fine-tuned-bert | Training data unknown | Verify no PII in fine-tuning |

### Recommendations
1. Document data sources for all custom datasets
2. Review PII handling for user-related data
3. Implement data retention policies
```

### Step 4.3: Model Security

Assess model-specific risks:

```
## Model Security Assessment

### Risk Factors

| Risk | Affected Models | Mitigation |
|------|-----------------|------------|
| Prompt injection | GPT-4 | Input validation |
| Model extraction | Custom models | Access controls |
| Adversarial inputs | ResNet50 | Input validation |
| Bias/fairness | BERT, GPT-4 | Bias testing |

### Recommendations
1. Implement input validation for all model inputs
2. Monitor for unusual query patterns
3. Conduct bias testing before deployment
```

---

## Phase 5: Documentation

**Goal**: Create compliance-ready documentation.

### Step 5.1: Generate Compliance Report

```
## AI Compliance Report

**Project**: my-ai-project
**Generated**: 2024-01-15
**Standard**: EU AI Act / Internal Governance

### AI System Classification
- **Risk Level**: [High/Limited/Minimal]
- **Category**: [Classification based on use case]

### Component Inventory
[Summary from Phase 3]

### License Compliance
- All components licensed: Yes/No
- Commercial use permitted: Yes/No
- Attribution required: List components

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

### Use Case 1: Pre-Deployment Audit

```
User: We need to audit AI components before production

Process:
1. Generate AIBOM for project
2. Review all AI models and their licenses
3. Check data sources and PII handling
4. Document findings for audit trail
```

### Use Case 2: Regulatory Compliance

```
User: Prepare AI inventory for EU AI Act compliance

Process:
1. Generate comprehensive AIBOM
2. Classify AI system risk level
3. Document model capabilities and limitations
4. Create compliance checklist
```

### Use Case 3: Third-Party AI Review

```
User: Review AI components in a vendor's software

Process:
1. Request AIBOM from vendor (or generate if source available)
2. Analyze models for license compliance
3. Assess data handling practices
4. Document risks and mitigations
```

---

## Common AI/ML Packages

### Deep Learning Frameworks

| Package | Use Case | License |
|---------|----------|---------|
| `torch` | PyTorch deep learning | BSD |
| `tensorflow` | TensorFlow deep learning | Apache 2.0 |
| `jax` | Differentiable computing | Apache 2.0 |
| `keras` | High-level neural networks | Apache 2.0 |

### NLP & LLMs

| Package | Use Case | License |
|---------|----------|---------|
| `transformers` | Pre-trained NLP models | Apache 2.0 |
| `openai` | OpenAI API client | MIT |
| `anthropic` | Anthropic API client | MIT |
| `langchain` | LLM application framework | MIT |
| `sentence-transformers` | Sentence embeddings | Apache 2.0 |

### Computer Vision

| Package | Use Case | License |
|---------|----------|---------|
| `torchvision` | Computer vision models | BSD |
| `opencv-python` | Image processing | Apache 2.0 |
| `pillow` | Image handling | HPND |
| `ultralytics` | YOLO object detection | AGPL-3.0 |

### ML Operations

| Package | Use Case | License |
|---------|----------|---------|
| `mlflow` | ML lifecycle management | Apache 2.0 |
| `wandb` | Experiment tracking | MIT |
| `dvc` | Data version control | Apache 2.0 |
| `ray` | Distributed computing | Apache 2.0 |

---

## Error Handling

### Not a Python Project

```
Error: No Python project found

Solutions:
1. Verify path contains Python files
2. Check for requirements.txt or pyproject.toml
3. This feature only supports Python projects
```

### Network Error

```
Error: Could not connect to analysis service

Solutions:
1. Check internet connection
2. Verify firewall allows HTTPS
3. Retry after a few minutes
```

### Experimental Feature Not Enabled

```
Error: AIBOM feature requires experimental access

Solutions:
1. Contact Snyk support for access
2. Check organization settings
3. Verify CLI version supports AIBOM
```

---

## Constraints

1. **Python only**: Currently only supports Python projects
2. **Experimental**: Feature may change or have limitations
3. **Network required**: Needs internet for analysis
4. **CycloneDX output**: Generates CycloneDX v1.6 format only
5. **Point-in-time**: Reflects current state - regenerate on updates
