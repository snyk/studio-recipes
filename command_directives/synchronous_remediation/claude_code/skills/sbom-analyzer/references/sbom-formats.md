# SBOM Format Reference

Quick reference for CycloneDX and SPDX SBOM formats.

## CycloneDX

### Supported Versions

- CycloneDX 1.4
- CycloneDX 1.5
- CycloneDX 1.6

### Basic Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z",
    "tools": [
      {
        "vendor": "Snyk",
        "name": "snyk-cli",
        "version": "1.1200.0"
      }
    ],
    "component": {
      "name": "my-application",
      "version": "1.0.0",
      "type": "application"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "abc123..."
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/my-app@1.0.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    }
  ]
}
```

### Key Fields

| Field | Description | Required |
|-------|-------------|----------|
| `bomFormat` | Must be "CycloneDX" | Yes |
| `specVersion` | Version of spec (1.4, 1.5, 1.6) | Yes |
| `components` | List of software components | Yes |
| `components[].purl` | Package URL for identification | Yes* |
| `components[].licenses` | License information | Recommended |
| `components[].hashes` | Checksums for integrity | Recommended |
| `dependencies` | Dependency relationships | Recommended |

**\*** Required for Snyk vulnerability scanning.

### Package URL (purl) Format

```
pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

Examples:
- npm: pkg:npm/lodash@4.17.21
- pip: pkg:pypi/requests@2.28.0
- maven: pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1
- go: pkg:golang/github.com/gorilla/mux@1.8.0
```

---

## SPDX

### Supported Version

- SPDX 2.3

### Basic Structure

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-application-sbom",
  "documentNamespace": "https://example.com/my-app-sbom-1.0",
  "creationInfo": {
    "created": "2024-01-15T10:00:00Z",
    "creators": [
      "Tool: snyk-cli-1.1200.0"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-lodash",
      "name": "lodash",
      "versionInfo": "4.17.21",
      "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright JS Foundation",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/lodash@4.17.21"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "abc123..."
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-lodash",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

### Key Fields

| Field | Description | Required |
|-------|-------------|----------|
| `spdxVersion` | Must be "SPDX-2.3" | Yes |
| `SPDXID` | Unique identifier | Yes |
| `packages` | List of software packages | Yes |
| `packages[].externalRefs` | External references (purl) | Yes* |
| `packages[].licenseConcluded` | Concluded license | Recommended |
| `packages[].checksums` | Checksums for integrity | Recommended |
| `relationships` | Dependency relationships | Recommended |

**\*** Required for Snyk vulnerability scanning (purl in externalRefs).

---

## Format Comparison

| Feature | CycloneDX | SPDX |
|---------|-----------|------|
| Primary use | DevSecOps | Legal compliance |
| Component types | Detailed taxonomy | Basic categories |
| Vulnerability refs | Native support | External extension |
| Licensing | Per-component | Detailed model |
| Relationships | Simple deps | Rich relationship types |
| Tool support | Growing | Mature |

### When to Use Each

**CycloneDX**:
- Security-focused workflows
- DevSecOps pipelines
- Vulnerability tracking
- Modern tooling integration

**SPDX**:
- License compliance
- Legal requirements
- Open source audits
- Government contracts

---

## NTIA Minimum Elements

Both formats should include these NTIA-required elements:

| Element | CycloneDX Location | SPDX Location |
|---------|-------------------|---------------|
| Supplier Name | `component.publisher` | `packages[].supplier` |
| Component Name | `component.name` | `packages[].name` |
| Version | `component.version` | `packages[].versionInfo` |
| Unique ID | `component.purl` | `externalRefs[].purl` |
| Dependency | `dependencies` | `relationships` |
| SBOM Author | `metadata.authors` | `creationInfo.creators` |
| Timestamp | `metadata.timestamp` | `creationInfo.created` |

---

## Validation

### CycloneDX Schema Validation

```bash
# Using cyclonedx-cli
cyclonedx validate --input-file sbom.json --input-format json

# Using npm package
npx @cyclonedx/cyclonedx-library validate sbom.json
```

### SPDX Validation

```bash
# Using spdx-tools
java -jar spdx-tools.jar Verify sbom.json

# Using pyspdxtools
pyspdxtools -i sbom.json --validate
```

---

## Converting Between Formats

### CycloneDX to SPDX

```bash
# Using cyclonedx-cli
cyclonedx convert \
  --input-file cyclonedx.json \
  --output-file spdx.json \
  --output-format spdxjson
```

### SPDX to CycloneDX

```bash
# Using cdx-spdx (experimental)
# Note: Some data may be lost in conversion
```

---

## Common Issues

### Missing purl

**Problem**: Components lack Package URL
**Impact**: Cannot identify vulnerabilities
**Solution**: Ensure tool generates purls, or add manually

### Invalid Version Format

**Problem**: Version doesn't follow semver
**Impact**: May affect vulnerability matching
**Solution**: Normalize versions where possible

### Missing Dependency Info

**Problem**: No dependency relationships
**Impact**: Can't trace vulnerability path
**Solution**: Use tools that capture full dep graph
