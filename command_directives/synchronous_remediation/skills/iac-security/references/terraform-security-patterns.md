# Terraform Security Patterns

Secure configuration patterns for common Terraform resources.

## AWS Resources

### S3 Bucket (Secure)

```hcl
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable access logging
resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

# Lifecycle rules for cost and security
resource "aws_s3_bucket_lifecycle_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
```

### RDS Instance (Secure)

```hcl
resource "aws_db_instance" "secure" {
  identifier        = "my-secure-db"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  # Security settings
  storage_encrypted        = true
  kms_key_id              = aws_kms_key.rds.arn
  deletion_protection      = true
  skip_final_snapshot      = false
  final_snapshot_identifier = "my-db-final-snapshot"

  # Network security
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Backup settings
  backup_retention_period = 30
  backup_window          = "03:00-04:00"

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true
  monitoring_interval             = 60
  monitoring_role_arn            = aws_iam_role.rds_monitoring.arn

  # Maintenance
  auto_minor_version_upgrade = true
  maintenance_window         = "Mon:04:00-Mon:05:00"
}
```

### Security Group (Secure)

```hcl
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  # Ingress - only required ports
  ingress {
    description = "HTTPS from load balancer"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.alb.id]  # SG reference, not CIDR
  }

  # No SSH from internet - use Session Manager instead
  # ingress {
  #   from_port   = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]  # NEVER DO THIS
  # }

  # Egress - restrict outbound
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Or prefix list for AWS services
  }

  tags = {
    Name = "web-sg"
  }
}
```

### IAM Role (Least Privilege)

```hcl
# Assume role policy - specific principal
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
    
    # Optional: Add conditions
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "app-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Minimal permissions policy
data "aws_iam_policy_document" "app" {
  # Specific S3 bucket access
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.app_data.arn}/*"
    ]
  }

  # Specific DynamoDB table access
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query"
    ]
    resources = [
      aws_dynamodb_table.app.arn
    ]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "app-policy"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}
```

### KMS Key (Secure)

```hcl
resource "aws_kms_key" "secure" {
  description             = "KMS key for data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  # Key policy - least privilege
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow service to use key"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "secure" {
  name          = "alias/my-key"
  target_key_id = aws_kms_key.secure.key_id
}
```

---

## Anti-Patterns to Avoid

### Never Do This

```hcl
# ❌ Wildcard IAM permissions
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}

# ❌ Open security group
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ❌ Unencrypted storage
resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # Should be true
}

# ❌ Public RDS
resource "aws_db_instance" "bad" {
  publicly_accessible = true  # Should be false
}

# ❌ Hardcoded secrets
resource "aws_db_instance" "bad" {
  password = "SuperSecret123!"  # Use aws_secretsmanager_secret
}
```

---

## Module Security

### Using Modules Securely

```hcl
# Pin module version
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"  # Always pin
  
  # ... configuration
}

# Verify module source
module "custom" {
  source = "git::https://github.com/org/module.git?ref=v1.0.0"
  # Use commit hash for maximum security
  # source = "git::https://github.com/org/module.git?ref=abc123def"
}
```

---

## Variables and Secrets

### Secure Variable Handling

```hcl
# Use sensitive flag
variable "database_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

# Don't default sensitive values
variable "api_key" {
  description = "API key"
  type        = string
  sensitive   = true
  # No default - must be provided
}

# Use data sources for secrets
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db.id
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
}
```
