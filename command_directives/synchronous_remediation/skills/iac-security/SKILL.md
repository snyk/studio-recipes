---
name: iac-security
description: |
  Infrastructure as Code security scanning for Terraform, Kubernetes, CloudFormation, and Azure ARM.
  Detects misconfigurations, security risks, and compliance violations before deployment. Use when:
  - User asks to scan Terraform files or modules
  - User mentions "infrastructure security" or "IaC scan"
  - User is working with Kubernetes manifests
  - User asks about CloudFormation or ARM template security
  - Agent is generating or modifying infrastructure code
allowed-tools: "mcp_snyk_snyk_iac_scan Read Write Edit Bash Grep"
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

| Platform | File Types |
|----------|-----------|
| **Terraform** | `.tf`, `.tf.json`, `.tfvars` |
| **Terraform Plan** | JSON plan output (`terraform show -json`) |
| **Kubernetes** | `.yaml` / `.yml` with `apiVersion` + `kind` |
| **Helm** | Chart templates (requires `Chart.yaml`) |
| **AWS CloudFormation** | `.json` / `.yaml` with `AWSTemplateFormatVersion` |
| **Azure ARM** | `.json` with `$schema` ARM URL |
| **Serverless Framework** | `serverless.yml` |

---

## Phase 1: Discovery

**Goal**: Identify all IaC files that need scanning.

Check for these indicators to confirm IaC type:

- **Terraform**: `.tf` files, `terraform.tfstate`, `provider` blocks
- **Kubernetes**: YAML with `apiVersion`/`kind`, directories named `k8s`, `manifests`
- **CloudFormation**: `AWSTemplateFormatVersion` key, `Resources` section with AWS types
- **Azure ARM**: `$schema` containing `deploymentTemplate`

Then determine scan scope: single file, directory, or recursive.

---

## Phase 2: Execute Scan

**Goal**: Run appropriate IaC security scan.

### Basic Scan

```
Run snyk_iac_scan with:
- path: <directory or file path>
```

### Terraform with Variables

```
Run snyk_iac_scan with:
- path: <terraform directory>
- var_file: <path to .tfvars if using variables>
```

### Terraform Plan (more accurate)

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

```
Run snyk_iac_scan with:
- path: tfplan.json
- scan: "planned-values"  # or "resource-changes"
```

### Custom Rules

```
Run snyk_iac_scan with:
- path: <directory>
- rules: <path to custom rules bundle>
```

---

## Phase 3: Analyze Results

**Goal**: Understand and categorize misconfigurations.

### Severity Assessment

| Severity | Risk Level | Examples |
|----------|------------|----------|
| **Critical** | Immediate risk | Public S3, open security groups |
| **High** | Significant risk | Missing encryption, excessive perms |
| **Medium** | Moderate risk | Missing logging, broad IAM |
| **Low** | Best practice | Missing tags, suboptimal config |

### Generate Summary

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

### Categorize by Domain

Group issues for easier remediation:

- **Network Security**: Security groups, Network ACLs, Load balancer config, VPC settings
- **Data Protection**: Encryption at rest/in transit, Backup configuration, Key management
- **Access Control**: IAM policies, Service accounts, RBAC settings, API permissions
- **Logging & Monitoring**: CloudTrail/audit logs, Access logging, Alerting config

---

## Phase 4: Remediation

**Goal**: Provide secure configuration fixes. Apply the pattern below to each finding; representative examples follow.

### Terraform Fixes

#### S3 Bucket — Block Public Access

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

#### Security Group — Restrict Access

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

# Secure - restricted to VPN/internal range
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

#### RDS — Enable Encryption

```hcl
# Secure
resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds.arn
  deletion_protection = true
}
```

### Kubernetes Fixes

#### Pod Security — Non-Root User & Resource Limits

```yaml
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
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "200m"
        memory: "256Mi"
```

#### Network Policy — Restrict Traffic

```yaml
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

#### S3 Bucket — Encryption & Public Access Block

```yaml
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

### Re-scan After Changes

```
Run snyk_iac_scan with:
- path: <same directory>
```

For Terraform, regenerate and scan the plan:

```bash
terraform plan -out=tfplan.new
terraform show -json tfplan.new > tfplan.new.json
```

### Report Improvements

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

| Error | Solutions |
|-------|-----------|
| **Could not read Terraform state** | Run `terraform init`; check state backend; scan `.tf` files directly |
| **Invalid HCL syntax** | Run `terraform validate`; check syntax; ensure all variables are defined |
| **Could not parse plan file** | Regenerate with `terraform show -json`; check Terraform version compatibility; verify JSON validity |

---

## Constraints

1. **Scan before apply**: Never apply unscanned IaC
2. **Block on critical**: Critical issues must be fixed
3. **Document exceptions**: Use `.snyk` policy for accepted risks
4. **Validate plans**: Prefer plan scanning over file scanning for Terraform
5. **Continuous monitoring**: Re-scan when dependencies update
