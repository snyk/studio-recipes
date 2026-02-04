---
name: drift-detector
description: |
  Detect infrastructure drift between Terraform state and actual cloud resources. Identifies
  unmanaged resources, manual changes, and configuration drift. Use this skill when:
  - User asks to check for infrastructure drift
  - User wants to find unmanaged cloud resources
  - User mentions "drift detection" or "Terraform drift"
  - User asks to compare cloud state to IaC
  - User wants to audit infrastructure changes
---

# Infrastructure Drift Detector

Detect, track, and resolve infrastructure drift between Terraform state and actual cloud resources to maintain Infrastructure as Code integrity.

**Core Principle**: Your cloud should match your code.

**Note**: This skill uses `snyk iac describe` CLI command (requires shell execution).

---

## Quick Start

```
1. Configure cloud provider credentials
2. Run drift detection against Terraform state
3. Analyze unmanaged and changed resources
4. Generate remediation plan
5. Update Terraform or remove drift
```

---

## Prerequisites

- Terraform project with state file (local or remote)
- Cloud provider credentials configured
- `snyk` CLI installed
- Network access to cloud APIs

### Supported Cloud Providers

| Provider | Setup |
|----------|-------|
| **AWS** | AWS credentials (profile, env vars, or IAM role) |
| **Azure** | Azure CLI login or service principal |
| **GCP** | Application default credentials or service account |

---

## Phase 1: Setup

**Goal**: Configure drift detection environment.

### Step 1.1: Verify Terraform State

Check for Terraform state:

**Local state**:
```bash
ls terraform.tfstate
```

**Remote state** (S3 backend):
```hcl
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "state/terraform.tfstate"
    region = "us-east-1"
  }
}
```

### Step 1.2: Verify Cloud Credentials

**AWS**:
```bash
aws sts get-caller-identity
```

**Azure**:
```bash
az account show
```

**GCP**:
```bash
gcloud auth application-default print-access-token
```

---

## Phase 2: Run Drift Detection

**Goal**: Identify differences between IaC and actual cloud state.

### Step 2.1: Basic Drift Scan

```bash
snyk iac describe --from=tfstate://terraform.tfstate
```

### Step 2.2: Remote State Scan

For S3 backend:
```bash
snyk iac describe --from=tfstate+s3://my-bucket/state.tfstate
```

For Terraform Cloud:
```bash
snyk iac describe \
  --from=tfstate+tfcloud://organization/workspace \
  --tfc-token=$TFC_TOKEN
```

### Step 2.3: Specific Service Scan

To focus on specific AWS services:
```bash
snyk iac describe \
  --from=tfstate://terraform.tfstate \
  --service=aws_s3,aws_ec2,aws_rds
```

### Step 2.4: JSON Output for Analysis

```bash
snyk iac describe \
  --from=tfstate://terraform.tfstate \
  --json > drift-report.json
```

---

## Phase 3: Analyze Results

**Goal**: Understand and categorize drift.

### Step 3.1: Drift Categories

| Category | Description | Risk Level |
|----------|-------------|------------|
| **Unmanaged** | Resources not in Terraform | High - shadow IT |
| **Changed** | Resources modified outside Terraform | Medium - config drift |
| **Missing** | Resources in state but deleted | Low - usually intentional |

### Step 3.2: Generate Report

```
## Infrastructure Drift Report

**Scan Date**: 2024-01-15
**Terraform State**: s3://my-bucket/prod.tfstate
**Cloud Provider**: AWS (us-east-1)

### Summary
| Category | Count | Risk |
|----------|-------|------|
| Unmanaged Resources | 12 | High |
| Changed Resources | 5 | Medium |
| Missing Resources | 2 | Low |
| **Total Drift** | 19 | - |

### Unmanaged Resources (Not in Terraform)

| Resource Type | Resource ID | Risk | Action |
|---------------|-------------|------|--------|
| aws_s3_bucket | prod-logs-manual | High | Import or delete |
| aws_security_group | sg-temp-access | Critical | Review and remove |
| aws_iam_user | admin-john | High | Import or remove |
| aws_ec2_instance | i-temp-server | Medium | Import or terminate |

### Changed Resources (Modified Outside Terraform)

| Resource | Terraform Value | Actual Value | Risk |
|----------|-----------------|--------------|------|
| aws_security_group.web | ingress: [443] | ingress: [443, 22] | High |
| aws_s3_bucket.data | versioning: true | versioning: false | Medium |
| aws_rds_instance.main | multi_az: true | multi_az: false | Critical |

### Missing Resources (Deleted Outside Terraform)

| Resource | Last State | Notes |
|----------|------------|-------|
| aws_lambda_function.old | v1.0.0 | May be intentional |
| aws_sns_topic.alerts | Created 2023 | Verify if needed |
```

### Step 3.3: Risk Assessment

```
## Risk Assessment

### Critical Issues (Immediate Action)

1. **Security Group Modified**: Port 22 (SSH) opened to 0.0.0.0/0
   - Resource: aws_security_group.web
   - Risk: Unauthorized access
   - Action: Revert change immediately

2. **RDS Multi-AZ Disabled**: Production database no longer HA
   - Resource: aws_rds_instance.main
   - Risk: Single point of failure
   - Action: Re-enable via Terraform

### High Risk Issues

1. **Unmanaged Admin User**: IAM user not in Terraform
   - Resource: aws_iam_user.admin-john
   - Risk: Uncontrolled access
   - Action: Import to Terraform or remove

2. **Unmanaged Security Group**: Temporary access group
   - Resource: aws_security_group.temp-access
   - Risk: Potential security hole
   - Action: Review and remove
```

---

## Phase 4: Remediation

**Goal**: Resolve drift and restore IaC integrity.

### Step 4.1: Import Unmanaged Resources

For resources that should be in Terraform:

```bash
# Generate import block
terraform import aws_s3_bucket.manual_bucket prod-logs-manual

# Or use import block (Terraform 1.5+)
```

```hcl
import {
  to = aws_s3_bucket.manual_bucket
  id = "prod-logs-manual"
}
```

### Step 4.2: Remove Unauthorized Resources

For resources that shouldn't exist:

```bash
# After verification, delete unmanaged resources
aws s3 rb s3://unauthorized-bucket --force
aws ec2 terminate-instances --instance-ids i-temp-server
```

### Step 4.3: Revert Changes

For resources modified outside Terraform:

```bash
# Re-apply Terraform to restore intended state
terraform apply
```

### Step 4.4: Update Terraform (Adopt Changes)

If the manual change should be kept:

```hcl
# Update Terraform to match new reality
resource "aws_security_group" "web" {
  # Add the new rule
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restrict if keeping
  }
}
```

---

## Phase 5: Prevention

**Goal**: Prevent future drift.

### Step 5.1: Generate Exclude Policy

For expected drift (auto-scaling, etc.):

```bash
snyk iac update-exclude-policy \
  --exclude-unmanaged \
  --exclude-changed
```

This creates a `.snyk` policy file:

```yaml
exclude:
  iac-drift:
    - aws_autoscaling_group.*
    - aws_ecs_service.*:desiredCount
```

### Step 5.2: CI/CD Integration

Add drift detection to CI/CD:

```yaml
# GitHub Actions example
- name: Check for Infrastructure Drift
  run: |
    snyk iac describe \
      --from=tfstate+s3://my-bucket/prod.tfstate \
      --json > drift.json
    
    # Fail if unmanaged resources found
    if [ $(jq '.summary.total_unmanaged' drift.json) -gt 0 ]; then
      echo "Drift detected!"
      exit 1
    fi
```

### Step 5.3: Regular Audits

Schedule regular drift audits:

| Frequency | Scope | Purpose |
|-----------|-------|---------|
| Daily | Critical resources | Security monitoring |
| Weekly | All production | Configuration audit |
| Monthly | All environments | Comprehensive review |

---

## Common Scenarios

### Scenario 1: Post-Incident Audit

```
User: Check what changed after the security incident

Process:
1. Run drift detection with JSON output
2. Filter for security-related resources
3. Identify unauthorized changes
4. Generate incident report
5. Remediate and document
```

### Scenario 2: Pre-Deployment Check

```
User: Verify no drift before deploying changes

Process:
1. Run drift detection
2. Fail deployment if drift exists
3. Resolve drift first
4. Then proceed with deployment
```

### Scenario 3: Shadow IT Discovery

```
User: Find all resources not managed by Terraform

Process:
1. Run drift detection
2. Filter to unmanaged resources
3. Categorize by owner/purpose
4. Import or remove as appropriate
```

---

## Supported Services

### AWS Services

| Service | Resource Types |
|---------|----------------|
| EC2 | instances, security groups, EBS, AMIs |
| S3 | buckets, policies, configurations |
| IAM | users, roles, policies, groups |
| RDS | instances, clusters, snapshots |
| Lambda | functions, layers, aliases |
| VPC | VPCs, subnets, route tables, NAT gateways |
| EKS | clusters, node groups |
| DynamoDB | tables, global tables |
| CloudFront | distributions |
| Route53 | zones, records |

### Azure Services

| Service | Resource Types |
|---------|----------------|
| Compute | VMs, scale sets, disks |
| Storage | accounts, containers |
| Network | VNets, NSGs, load balancers |
| AKS | clusters, node pools |

### GCP Services

| Service | Resource Types |
|---------|----------------|
| Compute | instances, disks, images |
| Storage | buckets, IAM |
| GKE | clusters, node pools |
| IAM | service accounts, policies |

---

## Error Handling

### State Access Error

```
Error: Could not read Terraform state

Solutions:
1. Verify state file path
2. Check S3/backend permissions
3. Ensure terraform init has been run
```

### Cloud Credential Error

```
Error: Authentication failed

Solutions:
1. Verify cloud credentials
2. Check IAM permissions for describe/list
3. Ensure credentials not expired
```

### Service Not Supported

```
Warning: Service X not supported

Solutions:
1. Check supported services list
2. Use Terraform plan comparison instead
3. Report to Snyk for feature request
```

---

## Constraints

1. **Read-only**: This skill only detects drift, doesn't modify resources
2. **Credentials required**: Needs cloud provider access
3. **Service coverage**: Not all resource types supported
4. **State required**: Must have Terraform state to compare
5. **Network required**: Needs access to cloud APIs
