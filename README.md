# DriftControl GitHub Action

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub Release](https://img.shields.io/github/release/raulgsh/driftcontrol-action-public.svg)](https://github.com/raulgsh/driftcontrol-action-public/releases)
[![Node.js CI](https://github.com/raulgsh/driftcontrol-action-public/workflows/Node.js%20CI/badge.svg)](https://github.com/raulgsh/driftcontrol-action-public/actions)

**DriftControl** is a comprehensive GitHub Action that automatically detects and analyzes drift across your entire stack - APIs, databases, dependencies, infrastructure, and configuration. It helps prevent breaking changes by analyzing changes in OpenAPI specifications, SQL migrations, package dependencies, Terraform/CloudFormation templates, and configuration files, providing detailed feedback on potential risks before merging.

## ✨ Features

- 🔍 **API Drift Detection**: Analyzes OpenAPI specification changes for breaking API modifications using @useoptic/openapi-utilities
- 📊 **Database Schema Analysis**: Detects risky SQL operations in migration files with AST-based parsing via node-sql-parser
- 📦 **Dependency Drift Detection**: Monitors package.json and package-lock.json for version changes, security vulnerabilities, and license modifications
- 🏗️ **Infrastructure as Code Analysis**: Analyzes Terraform plans and CloudFormation templates for infrastructure drift
- ⚙️ **Configuration Drift Detection**: Monitors YAML/TOML configuration files, Docker Compose, and feature flags for changes
- 🎯 **Smart Risk Scoring**: Categorizes changes by severity (Low, Medium, High) with transparent reasoning
- 💬 **Intelligent PR Comments**: Provides detailed analysis with collapsible sections and fix suggestions
- 🤖 **Optional LLM Integration**: Enhanced plain English explanations with OpenAI or Anthropic APIs
- 🔗 **Cross-Layer Correlation**: Automatically detects relationships between different types of drift using multiple correlation strategies
- 🔍 **Code Analysis Correlation**: Analyzes JavaScript/TypeScript code to find API-to-database relationships using AST parsing
- 🚢 **Kubernetes Manifest Analysis**: Analyzes Kubernetes deployments for security risks and configuration drift
- ⚙️ **Configurable Policies**: Customize blocking behavior based on risk levels
- 🔄 **Rename Detection**: Handles file renames intelligently for OpenAPI specs and database tables
- 🛡️ **Override Support**: Emergency bypass with audit trail
- 🔐 **Security-First**: Key-only analysis for configuration files, redacts sensitive values

## 🚀 Quick Start

### Basic Usage

Add this workflow to your repository at `.github/workflows/driftcontrol.yml`:

```yaml
name: DriftControl Analysis
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  drift-analysis:
    runs-on: ubuntu-latest
    name: Analyze API and Database Drift
    steps:
      - name: DriftControl
        uses: raulgsh/driftcontrol-action-public@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          openapi_path: 'openapi.yaml'
          sql_glob: 'migrations/**/*.sql'
```

### Advanced Configuration

```yaml
- name: DriftControl with Custom Settings
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    openapi_path: 'api/openapi.yml'
    sql_glob: 'database/migrations/**/*.sql'
    terraform_plan_path: 'terraform/plan.json'
    cloudformation_glob: 'cloudformation/**/*.yml'
    config_yaml_glob: 'config/**/*.yml'
    feature_flags_path: 'config/features.json'
    cost_threshold: '100'
    fail_on_medium: 'true'
    override: 'false'
    llm_provider: 'openai'
    llm_api_key: ${{ secrets.OPENAI_API_KEY }}
    llm_model: 'gpt-4'
    correlation_config_path: '.github/driftcontrol.yml'
```

## ⚙️ Configuration

### Input Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `token` | GitHub token for API access | No | `${{ github.token }}` |
| `openapi_path` | Path to the OpenAPI specification file | No | `openapi.yaml` |
| `sql_glob` | Glob pattern for SQL migration files | No | `migrations/**/*.sql` |
| `terraform_plan_path` | Path to Terraform plan JSON file | No | - |
| `cloudformation_glob` | Glob pattern for CloudFormation templates | No | - |
| `config_yaml_glob` | Glob pattern for configuration YAML files | No | - |
| `feature_flags_path` | Path to feature flags file | No | - |
| `cost_threshold` | Cost threshold for infrastructure changes | No | `1000` |
| `llm_provider` | LLM provider (openai or anthropic) | No | - |
| `llm_api_key` | API key for LLM provider (use secrets) | No | - |
| `llm_model` | Model name (gpt-4, claude-3-opus, etc) | No | - |
| `llm_max_tokens` | Max tokens for LLM response | No | `150` |
| `correlation_config_path` | Path to correlation configuration file | No | `.github/driftcontrol.yml` |
| `fail_on_medium` | Block merges on medium-severity drift | No | `false` |
| `override` | Bypass merge blocks (with audit trail) | No | `false` |
| `vulnerability_provider` | Vulnerability detection provider (osv, github, static) | No | `static` |
| `kubernetes_glob` | Glob pattern for Kubernetes manifest files | No | `**/k8s/**/*.{yaml,yml}` |
| `env_files` | Analyze .env files for secret changes | No | `true` |

### Risk Levels

#### High Severity (❌ Blocks merge by default)
- **API**: Endpoint removal, breaking parameter changes, response schema removal
- **Database**: `DROP TABLE`, `DROP COLUMN`, table/column deletions
- **Dependencies**: Major version bumps, security vulnerabilities (CVE), integrity mismatches
- **Infrastructure**: Security group deletions, resource deletions, critical resource changes
- **Configuration**: Secret key removal/addition, critical configuration changes

#### Medium Severity (⚠️ Configurable blocking)
- **API**: Required field additions, parameter type changes
- **Database**: `NOT NULL` constraints, column type narrowing, constraint additions
- **Dependencies**: Minor version bumps, license changes, transitive dependency changes
- **Infrastructure**: Cost increases above threshold, security group changes, resource policy changes
- **Configuration**: Feature flag changes, container service modifications, dependency removals

#### Low Severity (✅ Informational only)
- **API**: New endpoints, optional parameter additions
- **Database**: New tables, new optional columns, index additions
- **Dependencies**: Patch version updates, new dependency additions
- **Infrastructure**: Tag changes, metadata updates, non-critical resource changes
- **Configuration**: New configuration keys, optional setting changes

## 📋 Examples

### Example 1: API Breaking Change Detection

**OpenAPI Change:**
```yaml
# Before
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          required: true
          
# After  
paths:
  /users/{userId}:  # Parameter renamed - breaking change!
    get:
      parameters:
        - name: userId
          required: true
```

**DriftControl Response:**
```
❌ HIGH SEVERITY: Breaking API changes detected
- BREAKING_CHANGE: Parameter 'id' removed from /users/{id}
- New endpoint added: /users/{userId}

💡 Suggestion: Use API versioning to maintain backward compatibility
```

### Example 2: Database Schema Analysis

**SQL Migration:**
```sql
-- High-risk operation detected
ALTER TABLE users DROP COLUMN email;

-- Medium-risk operation detected  
ALTER TABLE profiles ADD CONSTRAINT profiles_user_id_unique UNIQUE(user_id);
```

**DriftControl Response:**
```
❌ HIGH SEVERITY: Destructive database changes detected
- DROP COLUMN: email (data loss risk)

⚠️ MEDIUM SEVERITY: Schema constraint changes
- UNIQUE constraint added: profiles_user_id_unique

🛡️ Recommendation: Consider data migration scripts before applying
```

### Example 3: Dependency Drift Detection

**package.json Change:**
```json
// Before
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.10"
  }
}

// After
{
  "dependencies": {
    "express": "^5.0.0",  // Major version bump!
    "lodash": "^4.17.10",
    "event-stream": "^3.3.4"  // Known vulnerable package!
  }
}
```

**DriftControl Response:**
```
❌ HIGH SEVERITY: Critical dependency issues detected
- MAJOR_VERSION_BUMP: express (4.x → 5.x) - breaking changes expected
- SECURITY_VULNERABILITY: event-stream - known malicious package

⚠️ MEDIUM SEVERITY: License compliance check needed
- New dependency added: event-stream

🔒 Security Alert: Remove event-stream immediately and audit dependencies
```

### Example 4: Kubernetes Security Analysis

**Kubernetes Deployment:**
```yaml
# Deployment with security risks
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true  # Security risk detected
      containers:
      - name: app
        securityContext:
          privileged: true  # Security risk detected
        # Missing resource limits - risk detected
```

**DriftControl Response:**
```
❌ HIGH SEVERITY: Kubernetes security risks detected
- K8S_HOST_NETWORK_ENABLED: Host network access enabled
- K8S_PRIVILEGED_CONTAINER: Privileged container detected  
- K8S_NO_RESOURCE_LIMITS: Missing resource limits

🛡️ Security Alert: Review container security policies before deployment
```

### Example 5: Infrastructure Drift Detection

**Terraform Plan Changes:**
```json
{
  "resource_changes": [{
    "type": "aws_security_group_rule",
    "change": {
      "actions": ["delete"],
      "before": { "cidr_blocks": ["10.0.0.0/8"] }
    }
  }]
}
```

**DriftControl Response:**
```
❌ HIGH SEVERITY: Security configuration changes
- SECURITY_GROUP_DELETION: Removing access rule for 10.0.0.0/8

⚠️ Impact Analysis:
- Potential connectivity issues for internal services
- Review dependent resources before applying

💡 Suggestion: Document security group changes in runbook
```

### Example 6: Environment Configuration Analysis

**.env File Changes:**
```bash
# Before
DATABASE_URL=postgres://localhost/app
API_KEY=secret123

# After  
DATABASE_URL=postgres://prod-server/app  # Configuration change detected
NEW_SECRET_TOKEN=xyz789                  # New secret key detected
# API_KEY removed                        # Secret removal detected
```

**DriftControl Response:**
```
⚠️ MEDIUM SEVERITY: Configuration drift detected
- SECRET_REMOVED: API_KEY (potential service disruption)
- SECRET_ADDED: NEW_SECRET_TOKEN (review access requirements)
- CONFIG_CHANGED: DATABASE_URL (environment target change)

🔐 Security Note: Key values redacted in analysis for security
```

## 🔗 Configuration-Driven Correlation

DriftControl automatically detects relationships between different components using multiple correlation strategies (Entity, Operation, Infrastructure, Dependency, Temporal, and Code Analysis). You can enhance this with explicit correlation rules.

### Setting Up Correlation Rules

Create a file at `.github/driftcontrol.yml` in your repository:

```yaml
# .github/driftcontrol.yml
correlation_rules:
  # Map API endpoints to database tables
  - type: api_to_db
    source: /v1/users/{userId}
    target: application_users
    description: "Maps the public user API to the internal user table"
  
  # Map Infrastructure resources to configuration files
  - type: iac_to_config
    source: aws_lambda_function.user_processor
    target: config/user-service.yml
    description: "Lambda function configuration"
  
  # Ignore known irrelevant correlations to reduce noise
  - type: ignore
    source: package-lock.json
    target: openapi.yml
    reason: "Dependency updates rarely affect API spec"
```

### Benefits of Configuration-Driven Correlation

1. **Maximum Confidence**: User-defined rules have confidence 1.0, overriding heuristic correlations
2. **Reduce False Positives**: Explicitly ignore unrelated components that happen to change together
3. **Cross-Team Knowledge**: Capture architectural decisions and relationships in code
4. **Severity Escalation**: Correlated changes automatically increase severity levels
5. **Root Cause Analysis**: Better identify which changes trigger cascading effects

### Correlation Strategies

DriftControl uses multiple correlation strategies:

- **Entity Correlation**: Matches table names, API endpoints, and resource names using fuzzy matching
- **Operation Correlation**: Correlates CRUD operations across API endpoints and database operations
- **Infrastructure Correlation**: Links infrastructure resources to configuration and application components
- **Dependency Correlation**: Tracks how dependency changes affect APIs and databases
- **Temporal Correlation**: Identifies changes that happen together in time
- **Code Analysis Correlation**: Analyzes JavaScript/TypeScript code using AST parsing to trace function calls and identify database operations, linking API endpoints to database usage patterns through call graph analysis

### Example Impact

When DriftControl detects changes in both `/v1/users/{userId}` API endpoint and the `application_users` table, it will:
- Recognize these are correlated based on your configuration
- Upgrade severity (e.g., from Low → Medium or Medium → High)
- Provide context about the cross-layer impact
- Help reviewers understand the full scope of changes

## 📊 Performance Benchmarks

DriftControl is optimized for speed and efficiency with parallel analyzer execution:

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| **Total PR Scan Time (P50)** | 30s | ~2s | ✅ Exceeds target |
| **Total PR Scan Time (P95)** | 60s | ~3s | ✅ Exceeds target |
| **API Diff Processing** | 5s max | <1s | ✅ Exceeds target |
| **SQL Migration Parse** | 8s max | <1s | ✅ Exceeds target |
| **Test Coverage** | >70% | 92.51% | ✅ Exceeds target |

The action runs entirely within GitHub Action runners with no external dependencies, ensuring consistent performance across all environments.

## 🔧 Development & Testing

### Prerequisites

- Node.js >= 20.0.0
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/raulgsh/driftcontrol-action-public.git
cd driftcontrol-action

# Install dependencies
npm install
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run linting
npm run lint
```

### Local Development

```bash
# Run the action locally
npm start
```

### Project Structure

```
driftcontrol-action/
├── src/
│   ├── index.js              # Main entry point
│   ├── analyzers/            # Analysis modules
│   │   ├── openapi/          # OpenAPI drift analysis
│   │   ├── sql/              # SQL migration analysis
│   │   ├── config/           # Configuration and dependency analysis
│   │   └── iac/              # Infrastructure as Code analysis
│   ├── scoring/              # Risk assessment logic
│   ├── commenting/           # PR comment generation
│   ├── correlation/          # Cross-layer correlation analysis
│   ├── risk-scorer.js        # Risk assessment entry point
│   ├── comment-generator.js  # Comment generation entry point
│   └── github-api.js         # GitHub API interactions
├── __tests__/                # Test files
├── action.yml               # GitHub Action metadata
├── package.json            # Node.js configuration
└── README.md              # This file
```

## 🛡️ Security

### Safe Operations

DriftControl focuses on **defensive security analysis** and will:
- ✅ Analyze code for potential security risks
- ✅ Detect breaking changes that could impact security
- ✅ Provide security-focused recommendations
- ✅ Generate detection rules for security monitoring

### Limitations

DriftControl will **NOT**:
- ❌ Create, modify, or improve potentially malicious code
- ❌ Generate offensive security tools
- ❌ Bypass security controls or authentication

## 📈 Advanced Features

### Dependency Security Scanning

DriftControl now provides **comprehensive security vulnerability detection** through multiple integrated databases:

#### Vulnerability Detection Providers

**🔐 OSV Database (Recommended)**
- ✅ **Comprehensive**: Full Open Source Vulnerability database coverage
- ✅ **Up-to-date**: Real-time vulnerability feeds from multiple sources
- ✅ **Accurate**: Precise version range matching using semantic versioning
- ✅ **Performance**: Batch API queries for efficiency
- ✅ **Coverage**: Thousands of vulnerabilities across all npm packages

```yaml
- name: DriftControl with OSV Database
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    vulnerability_provider: 'osv'  # Comprehensive OSV database scanning
```

**🐙 GitHub Advisory Database**
- ✅ **Native Integration**: Uses GitHub's Dependency Review API
- ✅ **Repository Context**: Analyzes PR-specific dependency changes
- ✅ **Severity Mapping**: High/Medium/Low severity classification
- ✅ **No Rate Limits**: Integrated with GitHub ecosystem

```yaml
- name: DriftControl with GitHub Advisory
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    vulnerability_provider: 'github'  # GitHub's dependency review API
```

**📋 Static List (Fallback)**
- ⚠️ **Limited**: Only 5 known malicious packages for demonstration
- ✅ **No Dependencies**: Works without external API calls
- ⚠️ **Not Recommended**: Use only for testing or offline environments

```yaml
- name: DriftControl with Static List
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    vulnerability_provider: 'static'  # Basic hardcoded list (default)
```

#### Enhanced Security Features

**What DriftControl now provides**:
- ✅ **Full vulnerability database coverage** (OSV/GitHub providers)
- ✅ **Real-time vulnerability detection** with semantic version matching
- ✅ **CVSS severity scoring** (Critical/High/Medium/Low)
- ✅ **Transitive dependency vulnerability detection**
- ✅ **Batch processing** for performance optimization
- ✅ **Graceful fallbacks** when APIs are unavailable

**Migration Path**:
- **Current users**: Default remains `static` for backward compatibility
- **New deployments**: Recommended to use `osv` for comprehensive scanning
- **GitHub Enterprise**: Use `github` provider for native integration

DriftControl now provides production-ready security scanning alongside drift detection, reducing the need for additional security tools in your CI/CD pipeline.

### Infrastructure Cost Analysis

When using with Terraform or CloudFormation:

```yaml
- name: DriftControl with Cost Limits
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    terraform_plan_path: 'terraform/plan.json'
    cost_threshold: '100'  # Block if monthly cost increase > $100
```

### Override Policy

For emergency deployments, use the override feature:

```yaml
- name: Emergency Override
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    override: 'true'  # Bypass blocking with audit trail
```

This creates a permanent audit record while allowing the merge to proceed.

### Custom Risk Policies

Configure different risk tolerances per environment:

```yaml
# Production - Strict
- name: Production DriftControl
  if: github.base_ref == 'main'
  with:
    fail_on_medium: 'true'
    
# Staging - Relaxed  
- name: Staging DriftControl
  if: github.base_ref == 'staging'
  with:
    fail_on_medium: 'false'
```

### Configuration Security

DriftControl provides security-first configuration analysis:

- **Redacted Sensitive Keys**: Automatically redacts passwords, tokens, API keys
- **Key-Only Analysis**: Never exposes configuration values, only structure
- **Feature Flag Tracking**: Monitors feature toggles for unexpected changes
- **.env and .properties Support**: Analyzes environment and properties files with key-only security approach
- **Kubernetes Security Analysis**: Detects privileged containers, host network access, missing resource limits

### Cross-Layer Correlation Analysis

DriftControl automatically detects relationships between different types of drift:

**Features:**
- **API to Database Linking**: Identifies when API endpoint changes relate to database schema modifications
- **Infrastructure to Application**: Connects IaC changes to application configuration needs
- **Dependency Impact Mapping**: Shows how dependency changes affect APIs and databases
- **Root Cause Identification**: Automatically identifies the source of cascading changes
- **Visual Drift Graph**: Displays relationships as an ASCII graph in PR comments

**Example Output:**
```
🔗 Cross-Layer Correlations Detected:

[api] openapi.yaml
  └─affects(85%)→ [database] migrations/v2.sql
[database] migrations/v2.sql
  └─requires(90%)→ [configuration] config/app.yml

🎯 Identified Root Causes:
- ⚡ API: openapi.yaml (90% confidence)
```

### Enhanced Explanations with LLM

Enable plain English explanations for better understanding:

```yaml
- name: DriftControl with AI Explanations
  uses: raulgsh/driftcontrol-action-public@v1
  with:
    llm_provider: 'openai'  # or 'anthropic'
    llm_api_key: ${{ secrets.OPENAI_API_KEY }}
    llm_model: 'gpt-4'  # or 'gpt-3.5-turbo', 'claude-3-opus', etc.
    llm_max_tokens: '200'  # Keep explanations concise
```

Features:
- **Automatic Fallback**: Uses rule-based explanations if LLM fails
- **Context-Aware**: Analyzes drift type and severity for relevant explanations
- **Impact Summaries**: Generates business-focused impact analysis
- **Security**: API keys only via GitHub secrets, no sensitive data sent to LLMs

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/raulgsh/driftcontrol-action-public/issues) with:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or screenshots

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`npm test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📚 Documentation

- [Technical Specification](SPEC.md)
- [Architecture Guide](ARCHITECTURE.md)
- [Configuration Template](CC_TEMPLATE.md)

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

- 📖 [Documentation](https://github.com/raulgsh/driftcontrol-action-public/wiki)
- 🐛 [Bug Reports](https://github.com/raulgsh/driftcontrol-action-public/issues)
- 💬 [Discussions](https://github.com/raulgsh/driftcontrol-action-public/discussions)
- 📧 Email: support@driftcontrol.dev

## 🏆 Acknowledgments

- [@useoptic/openapi-utilities](https://www.npmjs.com/package/@useoptic/openapi-utilities) for OpenAPI diff analysis
- [@apidevtools/swagger-parser](https://www.npmjs.com/package/@apidevtools/swagger-parser) for OpenAPI validation
- [node-sql-parser](https://www.npmjs.com/package/node-sql-parser) for SQL AST parsing
- [dbgate-query-splitter](https://www.npmjs.com/package/dbgate-query-splitter) for SQL statement splitting
- [@actions/github](https://www.npmjs.com/package/@actions/github) for GitHub API integration

---

**Built with ❤️ for safer deployments**