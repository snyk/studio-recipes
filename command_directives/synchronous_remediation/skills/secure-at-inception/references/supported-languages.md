# Supported Languages and File Types

Quick reference for Snyk scanning capabilities.

## SAST (Static Code Analysis) - snyk_code_scan

### Fully Supported Languages

| Language | Extensions | Notes |
|----------|------------|-------|
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | ES6+, JSX |
| TypeScript | `.ts`, `.tsx` | Including JSX |
| Python | `.py` | Python 2.7+ and 3.x |
| Java | `.java` | Java 8+ |
| Kotlin | `.kt`, `.kts` | JVM Kotlin |
| Go | `.go` | Go 1.11+ with modules |
| Ruby | `.rb` | Ruby 2.4+ |
| PHP | `.php` | PHP 7+ |
| C# | `.cs` | .NET Core and Framework |
| VB.NET | `.vb` | Visual Basic .NET |
| Swift | `.swift` | Swift 4+ |
| Objective-C | `.m`, `.mm` | iOS/macOS |
| Scala | `.scala` | Scala 2.x |
| Rust | `.rs` | Cargo projects |
| C/C++ | `.c`, `.cpp`, `.cc`, `.h`, `.hpp` | With compilation database |
| Apex | `.cls`, `.trigger` | Salesforce Apex |
| Elixir | `.ex`, `.exs` | Elixir/Phoenix |
| Groovy | `.groovy` | Jenkins pipelines, Gradle |
| Dart | `.dart` | Flutter/Dart projects |

### Vulnerability Types Detected

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Code Injection
- LDAP Injection
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- Insecure Deserialization
- Hardcoded Secrets
- Sensitive Data Exposure
- Security Misconfiguration
- Cryptographic Issues
- Authentication/Authorization Flaws

---

## SCA (Software Composition Analysis) - snyk_sca_scan

### Package Managers

| Ecosystem | Manifest Files | Lock Files |
|-----------|---------------|------------|
| npm | `package.json` | `package-lock.json`, `npm-shrinkwrap.json` |
| Yarn | `package.json` | `yarn.lock` |
| pnpm | `package.json` | `pnpm-lock.yaml` |
| pip | `requirements.txt`, `setup.py`, `pyproject.toml` | `Pipfile.lock` |
| Poetry | `pyproject.toml` | `poetry.lock` |
| Maven | `pom.xml` | - |
| Gradle | `build.gradle`, `build.gradle.kts` | `gradle.lockfile` |
| RubyGems | `Gemfile` | `Gemfile.lock` |
| Go modules | `go.mod` | `go.sum` |
| Cargo | `Cargo.toml` | `Cargo.lock` |
| NuGet | `*.csproj`, `packages.config` | `packages.lock.json` |
| Composer | `composer.json` | `composer.lock` |
| CocoaPods | `Podfile` | `Podfile.lock` |
| Swift PM | `Package.swift` | `Package.resolved` |
| Hex | `mix.exs` | `mix.lock` |
| Pub | `pubspec.yaml` | `pubspec.lock` |

### What SCA Detects

- Known vulnerabilities (CVEs) in dependencies
- License compliance issues
- Outdated packages
- Deprecated packages
- Malicious packages (supply chain attacks)

---

## IaC (Infrastructure as Code) - snyk_iac_scan

### Supported IaC Formats

| Platform | File Types | Detection |
|----------|-----------|-----------|
| Terraform | `.tf`, `.tf.json` | HCL syntax |
| Terraform Plan | `.json` | Plan output |
| Terraform Variables | `.tfvars` | Variable files |
| Kubernetes | `.yaml`, `.yml` | `apiVersion` + `kind` fields |
| Helm | `Chart.yaml`, templates | Helm chart structure |
| AWS CloudFormation | `.json`, `.yaml` | `AWSTemplateFormatVersion` |
| Azure ARM | `.json` | `$schema` with ARM URL |
| Serverless | `serverless.yml` | Serverless Framework |

### What IaC Detects

- Overly permissive security groups
- Missing encryption (at rest, in transit)
- Public exposure of resources
- Missing logging/monitoring
- Excessive IAM permissions
- Missing resource limits
- Insecure default configurations
- Network security issues

---

## Files to Skip

### Never Scan

- Binary files (images, compiled code, archives)
- Documentation (`.md`, `.rst`, `.txt`)
- Configuration that isn't IaC (`.json`, `.yaml` without IaC markers)
- Test fixtures and mock data
- Generated files (minified JS, compiled CSS)
- Lock files without manifests
- IDE configuration (`.vscode/`, `.idea/`)

### Conditional Skip

- Test files (`*_test.go`, `*.spec.ts`) - scan for security, but lower priority
- Vendor directories (`vendor/`, `node_modules/`) - typically skip, scan via SCA instead
- Build output (`dist/`, `build/`, `target/`) - skip generated code
