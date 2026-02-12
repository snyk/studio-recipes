---
name: iac-security
description: |
  Infrastructure as Code security scanning for Terraform, Kubernetes, CloudFormation, and Azure ARM.
  Detects misconfigurations, security risks, and compliance violations before deployment. Use this skill when:
  - User asks to scan Terraform files or modules
  - User mentions "infrastructure security" or "IaC scan"
  - User is working with Kubernetes manifests
  - User asks about CloudFormation or ARM template security
  - Agent is generating or modifying infrastructure code
allowed-tools:
  - mcp_snyk_snyk_iac_scan
  - Read
  - Write
  - Edit
  - Bash
  - Grep
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Supports Terraform (.tf), Kubernetes (YAML), AWS CloudFormation, and Azure ARM templates.
  Optional: Terraform CLI for plan-based scanning.
metadata:
  author: Snyk
  version: 1.0.0
---

# Infrastructure as Code Security

Comprehensive security scanning for Infrastructure as Code to catch misconfigurations before they become production vulnerabilities.

**Core Principle**: Security issues are cheaper to fix in code than in production.

---

## Quick Start

```
1. Identify IaC files (Terraform, K8s, CloudFormation, ARM)
2. Run snyk_iac_scan on the directory
3. Analyze misconfigurations by severity
4. Provide secure configuration alternatives
```

---

## Supported IaC Formats

| Platform | File Types | Detection Method |
|----------|-----------|------------------|
| **Terraform** | `.tf`, `.tf.json` | HCL syntax |
| **Terraform Plan** | JSON plan output | `terraform plan -out=plan && terraform show -json plan` |
| **Terraform Variables** | `.tfvars` | Variable definitions |
| **Kubernetes** | `.yaml`, `.yml` | `apiVersion` + `kind` fields |
| **Helm** | Chart templates | `Chart.yaml` presence |
| **AWS CloudFormation** | `.json`, `.yaml` | `AWSTemplateFormatVersion` |
| **Azure ARM** | `.json` | `$schema` with ARM URL |
| **Serverless Framework** | `serverless.yml` | Serverless structure |

---

## Phase 1: Discovery

**Goal**: Identify all IaC files that need scanning.

### Step 1.1: Detect IaC Type

Look for indicators:

**Terraform**:
- Files with `.tf` extension
- `terraform.tfstate` or `terraform.tfvars`
- `provider` blocks in files

**Kubernetes**:
- YAML with `apiVersion` and `kind`
- Directories named `k8s`, `kubernetes`, `manifests`
- `Deployment`, `Service`, `ConfigMap` resources

**CloudFormation**:
- `AWSTemplateFormatVersion` in YAML/JSON
- `template.yaml` or `template.json`
- `Resources` section with AWS types

**Azure ARM**:
- `$schema` containing `deploymentTemplate`
- `resources` array with ARM types

### Step 1.2: Scope the Scan

Determine scan boundaries:
- Single file: Scan just that file
- Directory: Scan all IaC in directory
- Recursive: Scan directory and subdirectories

---

## Phase 2: Execute Scan

**Goal**: Run appropriate IaC security scan.

### Step 2.1: Basic Scan

```
Run snyk_iac_scan with:
- path: <directory or file path>
```

### Step 2.2: Terraform-Specific Options

For Terraform configurations:

```
Run snyk_iac_scan with:
- path: <terraform directory>
- var_file: <path to .tfvars if using variables>
```

For Terraform plan analysis (more accurate):

```
# First generate plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Then scan the plan
Run snyk_iac_scan with:
- path: tfplan.json
- scan: "planned-values"  # or "resource-changes"
```

### Step 2.3: Custom Rules

If organization has custom policies:

```
Run snyk_iac_scan with:
- path: <directory>
- rules: <path to custom rules bundle>
```

---

## Phase 3: Analyze Results

**Goal**: Understand and categorize misconfigurations.

### Step 3.1: Severity Assessment

| Severity | Risk Level | Examples |
|----------|------------|----------|
| **Critical** | Immediate risk | Public S3, open security groups |
| **High** | Significant risk | Missing encryption, excessive perms |
| **Medium** | Moderate risk | Missing logging, broad IAM |
| **Low** | Best practice | Missing tags, suboptimal config |

### Step 3.2: Generate Summary

```
## IaC Security Scan Results

### Overview
| Severity | Count | Status |
|----------|-------|--------|
| Critical | X | 🔴 Block |
| High | Y | 🟠 Fix Required |
| Medium | Z | 🟡 Recommended |
| Low | W | 🔵 Optional |

### Critical Issues
| Resource | Issue | Location |
|----------|-------|----------|
| aws_s3_bucket.data | Public access enabled | main.tf:45 |
| aws_security_group.web | Open to 0.0.0.0/0 on port 22 | network.tf:23 |

### High Issues
| Resource | Issue | Location |
|----------|-------|----------|
| aws_rds_instance.db | Encryption not enabled | database.tf:12 |
```

### Step 3.3: Categorize by Domain

Group issues for easier remediation:

**Network Security**:
- Security groups
- Network ACLs
- Load balancer config
- VPC settings

**Data Protection**:
- Encryption at rest
- Encryption in transit
- Backup configuration
- Key management

**Access Control**:
- IAM policies
- Service accounts
- RBAC settings
- API permissions

**Logging & Monitoring**:
- CloudTrail/audit logs
- Access logging
- Alerting config

---

## Phase 4: Remediation

**Goal**: Provide secure configuration fixes.

### Terraform Fixes

#### S3 Bucket - Block Public Access

```hcl
# Insecure
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

# Secure
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

#### Security Group - Restrict Access

```hcl
# Insecure - open to world
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD
  }
}

# Secure - restricted to VPN
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
}
```

#### RDS - Enable Encryption

```hcl
# Insecure
resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
}

# Secure
resource "aws_db_instance" "main" {
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.rds.arn
  deletion_protection  = true
}
```

### Kubernetes Fixes

#### Pod Security - Non-Root User

```yaml
# Insecure
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp

# Secure
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

#### Resource Limits

```yaml
# Insecure - no limits
containers:
- name: app
  image: myapp

# Secure - with limits
containers:
- name: app
  image: myapp
  resources:
    limits:
      cpu: "500m"
      memory: "512Mi"
    requests:
      cpu: "200m"
      memory: "256Mi"
```

#### Network Policy

```yaml
# Add network policy to restrict traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: allowed-namespace
```

### CloudFormation Fixes

#### S3 Bucket Encryption

```yaml
# Insecure
Resources:
  DataBucket:
    Type: AWS::S3::Bucket

# Secure
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !Ref DataBucketKey
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```

---

## Phase 5: Verification

**Goal**: Confirm fixes are effective.

### Step 5.1: Re-scan After Changes

After applying fixes:

```
Run snyk_iac_scan with:
- path: <same directory>
```

### Step 5.2: Terraform Plan Scan

For Terraform, scan the plan after changes:

```bash
terraform plan -out=tfplan.new
terraform show -json tfplan.new > tfplan.new.json

# Scan the new plan
```

### Step 5.3: Report Improvements

```
## Fix Verification

| Severity | Before | After | Change |
|----------|--------|-------|--------|
| Critical | 2 | 0 | -2 ✅ |
| High | 5 | 1 | -4 ✅ |
| Medium | 8 | 6 | -2 ✅ |

### Remaining Issues
- 1 High: Third-party module - opened issue
- 6 Medium: Accepted risk (documented)
```

---

## Common Misconfigurations by Platform

### AWS (Terraform/CloudFormation)

| Issue | Risk | Fix |
|-------|------|-----|
| S3 public access | Data leak | Block public access |
| Unencrypted EBS | Data at rest | Enable encryption |
| Open security groups | Network attack | Restrict CIDR |
| Missing CloudTrail | No audit | Enable logging |
| Excessive IAM | Privilege escalation | Least privilege |

### Kubernetes

| Issue | Risk | Fix |
|-------|------|-----|
| Running as root | Container escape | runAsNonRoot |
| No resource limits | Denial of service | Set limits |
| Privileged containers | Host access | Remove privileged |
| No network policy | Lateral movement | Add network policy |
| Secrets in env | Exposure | Use secrets mount |

### Azure (ARM)

| Issue | Risk | Fix |
|-------|------|-----|
| Storage public access | Data leak | Disable public |
| SQL no TDE | Data at rest | Enable TDE |
| No NSG rules | Network attack | Add NSG |
| Missing diagnostics | No visibility | Enable logging |

---

## Best Practices

### Prevention

1. **Scan in CI/CD**: Fail builds with critical issues
2. **Pre-commit hooks**: Catch issues before commit
3. **Module security**: Scan reusable modules
4. **Policy as code**: Define custom rules for org standards

### Policy File Usage

Create `.snyk` to manage exceptions:

```yaml
ignore:
  SNYK-CC-TF-123:
    - '*':
        reason: 'Accepted risk - internal development environment'
        expires: 2025-06-01
        created: 2024-01-15
```

### Custom Rules

For organization-specific requirements:

1. Write rules in Rego (OPA) format
2. Bundle as `.tar.gz`
3. Pass to scan with `--rules` option

---

## Error Handling

### Terraform State Issues

```
Error: Could not read Terraform state

Solutions:
1. Ensure terraform init has been run
2. Check state backend is accessible
3. Scan .tf files directly instead of plan
```

### Invalid HCL

```
Error: Invalid HCL syntax

Solutions:
1. Run terraform validate first
2. Check for syntax errors
3. Ensure all variables are defined
```

### Plan File Issues

```
Error: Could not parse plan file

Solutions:
1. Regenerate plan with terraform show -json
2. Ensure Terraform version compatibility
3. Check plan file is valid JSON
```

---

## Constraints

1. **Scan before apply**: Never apply unscanned IaC
2. **Block on critical**: Critical issues must be fixed
3. **Document exceptions**: Use `.snyk` policy for accepted risks
4. **Validate plans**: Prefer plan scanning over file scanning for Terraform
5. **Continuous monitoring**: Re-scan when dependencies update
