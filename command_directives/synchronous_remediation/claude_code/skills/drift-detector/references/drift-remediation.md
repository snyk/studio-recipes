# Drift Remediation Strategies

Guide for resolving different types of infrastructure drift.

## Decision Framework

### When to Import

**Import resources to Terraform when**:
- Resource is legitimate and should be managed
- Resource was created for valid business reasons
- Resource will need ongoing management
- Resource represents permanent infrastructure

**Process**:
1. Create Terraform resource block
2. Run `terraform import`
3. Verify imported state matches reality
4. Adjust Terraform config as needed
5. Run `terraform plan` to verify no changes

### When to Delete

**Delete resources when**:
- Resource is unauthorized (shadow IT)
- Resource is temporary/forgotten
- Resource poses security risk
- Resource is costing money unnecessarily

**Process**:
1. Verify resource is not in use
2. Document the resource and reason for deletion
3. Delete via cloud console or CLI
4. Run drift detection to confirm removal

### When to Accept

**Accept drift when**:
- Drift is expected (auto-scaling, dynamic resources)
- Manual intervention was necessary (incident response)
- Resource is managed by another team/system

**Process**:
1. Document the drift and reason for acceptance
2. Add to exclude policy if permanent
3. Update runbooks if this is expected pattern
4. Schedule review if temporary

---

## Import Patterns

### AWS Resources

```bash
# S3 Bucket
terraform import aws_s3_bucket.example bucket-name

# EC2 Instance
terraform import aws_instance.example i-1234567890abcdef0

# Security Group
terraform import aws_security_group.example sg-1234567890abcdef0

# IAM User
terraform import aws_iam_user.example user-name

# IAM Role
terraform import aws_iam_role.example role-name

# RDS Instance
terraform import aws_db_instance.example my-db-instance

# VPC
terraform import aws_vpc.example vpc-1234567890abcdef0

# Subnet
terraform import aws_subnet.example subnet-1234567890abcdef0

# Lambda Function
terraform import aws_lambda_function.example function-name
```

### Terraform Import Blocks (1.5+)

```hcl
# More declarative approach
import {
  to = aws_s3_bucket.example
  id = "bucket-name"
}

import {
  to = aws_instance.example
  id = "i-1234567890abcdef0"
}
```

### Azure Resources

```bash
# Resource Group
terraform import azurerm_resource_group.example /subscriptions/{sub-id}/resourceGroups/{name}

# Storage Account
terraform import azurerm_storage_account.example /subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}

# Virtual Machine
terraform import azurerm_virtual_machine.example /subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}
```

### GCP Resources

```bash
# Project
terraform import google_project.example project-id

# Compute Instance
terraform import google_compute_instance.example projects/{project}/zones/{zone}/instances/{name}

# Storage Bucket
terraform import google_storage_bucket.example bucket-name
```

---

## Revert Patterns

### Revert Security Group Changes

```bash
# View current Terraform state
terraform show

# Apply to revert to Terraform state
terraform apply -target=aws_security_group.web
```

### Revert S3 Configuration

```bash
# Force revert bucket configuration
terraform apply -target=aws_s3_bucket.data -replace=aws_s3_bucket.data
```

### Revert IAM Changes

```bash
# Careful with IAM - verify before applying
terraform plan -target=aws_iam_role.app
terraform apply -target=aws_iam_role.app
```

---

## Exclude Policies

### Snyk Policy File (.snyk)

```yaml
# Exclude auto-scaling resources (expected drift)
exclude:
  iac-drift:
    - aws_autoscaling_group.*
    - aws_ecs_service.*:desiredCount
    - aws_ecs_task_definition.*
    
    # Exclude specific resources
    - aws_s3_bucket.logs:lifecycle_rule
    
    # Exclude changed attributes
    - aws_rds_instance.main:latest_restorable_time

# Exclude entire resource types
exclude:
  iac-drift:
    - aws_cloudwatch_log_group.*
```

### Generate Policy from Current Drift

```bash
# Exclude all currently unmanaged resources
snyk iac update-exclude-policy --exclude-unmanaged

# Exclude all currently changed resources  
snyk iac update-exclude-policy --exclude-changed

# Combined
snyk iac update-exclude-policy \
  --exclude-unmanaged \
  --exclude-changed
```

---

## Common Drift Scenarios

### Scenario: Unauthorized Security Group Rule

**Drift**: Port 22 opened to 0.0.0.0/0
**Risk**: Critical - SSH exposed to internet

**Resolution**:
1. Document who made the change and why
2. If needed, add restricted rule to Terraform:
   ```hcl
   ingress {
     from_port   = 22
     to_port     = 22
     protocol    = "tcp"
     cidr_blocks = ["10.0.0.0/8"]  # VPN only
   }
   ```
3. Apply Terraform to enforce
4. Add monitoring for future changes

### Scenario: RDS Backup Retention Changed

**Drift**: Backup retention reduced from 30 to 7 days
**Risk**: Medium - compliance violation

**Resolution**:
1. Determine if change was intentional
2. If not, run `terraform apply` to revert
3. If intentional, update Terraform to match
4. Document compliance implications

### Scenario: Unmanaged Lambda Function

**Drift**: Lambda function not in Terraform
**Risk**: Medium - untracked code deployment

**Resolution**:
1. Identify owner and purpose
2. If legitimate, import to Terraform:
   ```hcl
   import {
     to = aws_lambda_function.new_function
     id = "function-name"
   }
   
   resource "aws_lambda_function" "new_function" {
     function_name = "function-name"
     # ... configuration
   }
   ```
3. If unauthorized, delete after verification

### Scenario: S3 Versioning Disabled

**Drift**: Versioning turned off
**Risk**: High - data loss risk

**Resolution**:
1. This may have been intentional (cost)
2. If required, run `terraform apply`
3. Check if data was lost during drift
4. Consider S3 Object Lock for compliance

---

## Prevention Best Practices

### CI/CD Gates

```yaml
# Block deployments with drift
- name: Check Drift
  run: |
    snyk iac describe --json > drift.json
    UNMANAGED=$(jq '.summary.total_unmanaged' drift.json)
    CHANGED=$(jq '.summary.total_changed' drift.json)
    
    if [ "$UNMANAGED" -gt 0 ] || [ "$CHANGED" -gt 0 ]; then
      echo "Drift detected: $UNMANAGED unmanaged, $CHANGED changed"
      exit 1
    fi
```

### Monitoring Alerts

Set up alerts for:
- Security group modifications
- IAM policy changes
- S3 bucket policy changes
- Encryption disabled events

### Access Controls

- Restrict console access
- Use SCPs to prevent certain changes
- Implement approval workflows
- Audit CloudTrail regularly

---

## Automation Templates

### Daily Drift Check Script

```bash
#!/bin/bash
# drift-check.sh

SLACK_WEBHOOK=$1
STATE_PATH=$2

# Run drift detection
snyk iac describe \
  --from=tfstate+s3://$STATE_PATH \
  --json > drift.json

UNMANAGED=$(jq '.summary.total_unmanaged' drift.json)
CHANGED=$(jq '.summary.total_changed' drift.json)

# Alert if drift found
if [ "$UNMANAGED" -gt 0 ] || [ "$CHANGED" -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠️ Infrastructure drift detected: $UNMANAGED unmanaged, $CHANGED changed resources\"}" \
    $SLACK_WEBHOOK
fi
```

### Weekly Report Generation

```bash
#!/bin/bash
# weekly-drift-report.sh

# Generate comprehensive report
snyk iac describe \
  --from=tfstate+s3://prod-state/terraform.tfstate \
  --html > drift-report.html

# Email report
mail -s "Weekly Drift Report" team@company.com < drift-report.html
```
