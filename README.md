# SIL Infosec Analyst Assessment Lab

A hands-on security lab developed for the **SIL Information Security Analyst Assessment**. The lab demonstrates API security, WAF protection, authentication and authorization, rate limiting, AI/LLM security guardrails, SIEM monitoring, secure CI/CD, SAST, SCA, DAST, secret scanning, and detection engineering.

The objective was not only to document recommended controls, but to **build, test, investigate, improve, and re-test security controls using a reproducible local environment**.

## Assessment Coverage

### Section 1A — API Gateway & AI Security

The lab demonstrates:

- API Gateway architecture using Kong
- OWASP CRS / ModSecurity WAF protection
- API authentication and authorization
- JWT and API-key authentication
- Access control and ACL enforcement
- Rate limiting
- Request size and schema validation
- Secure handling of synthetic PHI
- Outbound AI/LLM security controls
- Prompt-injection protection
- PHI and sensitive-data egress prevention
- PII redaction from AI responses
- Security logging and audit trails
- Cloudflare edge protection and tunnel-based access
- Defence-in-depth between Cloudflare and the local WAF

### Section 1B — Security Operations & Secure Development

The lab also demonstrates:

- Wazuh SIEM deployment
- Security log ingestion and parsing
- Custom SIEM detection rules
- Ransomware detection
- Shadow AI detection
- New log-source onboarding
- Field-mapping troubleshooting
- Bulk-PHI detection
- GitHub Actions security pipeline
- Gitleaks secret scanning
- Semgrep SAST
- Software Composition Analysis (SCA)
- Detection of hallucinated/non-existent packages
- OWASP ZAP DAST
- AI-generated code security testing
- Custom security rules for AI-style coding flaws
- Branch protection / security gate configuration

---

## Architecture

The lab uses a layered architecture consisting of:

```text
                         Internet / Client
                                |
                                v
                    +----------------------+
                    | Cloudflare Edge      |
                    | Tunnel / WAF Rules   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | OWASP CRS /          |
                    | ModSecurity WAF      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Kong API Gateway      |
                    | Auth / ACL / Rate     |
                    | Limits / Validation   |
                    +----+-------------+----+
                         |             |
              +----------+             +----------+
              v                                   v
      +---------------+                    +---------------+
      | Patients API  |                    | Appointments  |
      | JWT + ACL     |                    | API Key       |
      +---------------+                    +---------------+
              |
              |
              v
      +----------------------+
      | AI Security Proxy    |
      | Input Guardrails     |
      | Output Redaction     |
      | Egress Controls      |
      +----------------------+
```

The environment is separated into internal, edge, and egress network segments.

---

## Technology Stack

| Component | Technology |
|---|---|
| API Gateway | Kong 3.8 |
| WAF | OWASP ModSecurity CRS |
| Web Server | nginx |
| APIs | Python / FastAPI |
| Authentication | JWT / API Key |
| Identity & Access | ACL / Authorization policies |
| AI Security Proxy | Python / FastAPI |
| SIEM | Wazuh |
| SAST | Semgrep |
| Secret Scanning | Gitleaks |
| SCA | Dependency/security scanning |
| DAST | OWASP ZAP |
| Edge Security | Cloudflare |
| CI/CD | GitHub Actions |
| Containerization | Docker Compose |
| Testing | pytest |

All patient and security-event data used in the lab is **synthetic**.

---

## Repository Layout

```text
docker-compose.yml        All local services
gateway/kong.yml          Kong gateway policies
apis/patients/            Sample API using JWT + ACL
apis/appointments/        Sample API using API key
ai-proxy/                 AI/LLM security proxy and guardrail tests
scripts/make_jwt.py       Lab JWT generator

ARCHITECTURE.md           Architecture and design rationale
DEMO.md                   API, WAF and AI-security demonstrations
PIPELINE.md               CI/CD security pipeline documentation

.github/workflows/        GitHub Actions security workflow
.pre-commit-config.yaml  Pre-commit security hooks
.gitleaks.toml            Gitleaks configuration
.semgrep/                 Custom Semgrep rules
zap/rules.tsv             ZAP rules used by the pipeline

pipeline-demo/            Deliberately vulnerable AI-generated-code demo
```

---

# Demonstrated Security Controls

## API Authentication

The lab demonstrates multiple authentication mechanisms.

### Appointments API

Requests without the required API key are rejected:

```text
HTTP 401
```

Requests with the valid lab API key are accepted:

```text
HTTP 200
```

### Patients API

The Patients API requires a valid JWT.

The lab demonstrates:

- Missing JWT → `401`
- Valid JWT → `200`
- Tampered JWT → `401`
- Unauthorized access → rejected

---

## WAF Protection

The ModSecurity WAF uses the OWASP Core Rule Set to detect and block malicious requests.

The lab tests include:

- SQL injection
- Cross-site scripting (XSS)
- Path traversal
- Scanner/sqlmap activity

Malicious requests are blocked with:

```text
HTTP 403
```

The security logs identify the triggered ModSecurity rules and attack categories.

---

## Rate Limiting

The Kong API Gateway applies request-rate controls to protect backend services from excessive traffic.

A controlled test produced:

```text
120 requests → HTTP 200
10 requests   → HTTP 429
```

This demonstrates enforcement of the configured request threshold and provides protection against excessive automated requests.

---

## Request Validation

The APIs enforce request validation using defined schemas.

Invalid appointment data is rejected before reaching the application logic:

```text
HTTP 422
```

This provides an additional layer of protection against malformed or unexpected input.

---

# AI / LLM Security Guardrails

The AI security proxy provides an additional control layer before requests reach an external AI service.

The lab currently uses a **mock model response** rather than a live external LLM integration.

The proxy demonstrates controls for:

- Prompt injection
- Synthetic PHI
- Database connection strings
- Sensitive credentials
- PII in model output
- Security audit logging

### Example outcomes

```text
Clean request              → HTTP 200
Prompt injection           → HTTP 400
Synthetic PHI              → HTTP 400
Database connection string → HTTP 400
Sensitive output           → Redacted
```

The guardrail test suite contains:

```text
19/19 tests passing
```

The audit logging records the security decision and finding type without storing the full user prompt.

---

# Cloudflare Edge Protection

The lab also includes Cloudflare protection through a tunnel-based deployment.

Testing demonstrated defence in depth:

```text
Client
  |
  v
Cloudflare Edge
  |
  v
ModSecurity / OWASP CRS
  |
  v
Kong
  |
  v
Application
```

Observed behaviour included:

- Unauthorized requests rejected at the edge
- sqlmap activity blocked by Cloudflare
- SQL injection reaching the origin WAF and being blocked by ModSecurity
- XSS reaching the origin WAF and being blocked
- Path traversal reaching the origin WAF and being blocked

The Cloudflare rate-limit rule did not trigger during the test scenario and this result is documented rather than presented as a successful control.

---

# SIEM & Detection Engineering

Wazuh was deployed as a single-node SIEM for the lab environment.

Security telemetry was used to demonstrate:

- Log ingestion
- Log parsing
- Field mapping
- Custom detection rules
- Ransomware detection
- Shadow AI detection
- Bulk-PHI detection

Example custom detections include:

```text
100200  Shadow AI / public AI service DNS activity
100301  Ransomware-related activity
100406  Bulk-PHI activity
```

The log-source onboarding exercise also demonstrated troubleshooting of a field-mapping issue where the user field was initially blank. After correcting the mapping, the expected correlation rule generated a Level-12 alert.

---

# Secure CI/CD Pipeline

The GitHub Actions pipeline combines multiple security controls:

```text
Pre-commit
    |
    v
Gitleaks
    |
    v
SCA / Dependency Checks
    |
    v
Semgrep SAST
    |
    v
AI Abuse-Case Tests
    |
    v
OWASP ZAP DAST
    |
    v
Security Gate
```

The pipeline demonstrates:

- Secret detection
- Dependency/SCA checks
- SAST
- DAST
- AI-generated-code testing
- Guardrail regression tests
- Security gates

The assessment also includes a deliberately vulnerable demonstration PR showing how AI-style coding flaws can be identified before merging.

---

# AI-Generated Code Security

A deliberately vulnerable demo was used to test whether conventional security controls could identify weaknesses introduced through AI-assisted development.

The pipeline identified:

- Custom AI-generated-code security findings
- Guardrail bypass behaviour
- Dependency/package risks
- Security issues requiring manual review

The SAST demonstration produced:

```text
7 findings
5 custom AI-code rules
```

The pipeline also rejected a hallucinated dependency:

```text
fastapi-guardrails-pro
```

because the package does not exist on PyPI.

After fixes were applied, the clean-path PR passed all configured security checks.

---

# Evidence

The repository assessment evidence is organized using the following naming convention:

```text
1A-c-Lab-Demonstration/
1A-e-AI-Guardrails/
1B-Q1-SIEM/
1B-Q2-CICD/
1B-Q3-SIEM-Detections/
1B-Q6-AI-Logic-Flaws/
```

Evidence filenames correspond to the assessment questions and are intended to make individual claims independently verifiable.

The evidence follows the progression:

```text
Build
  ↓
Test
  ↓
Observe
  ↓
Investigate
  ↓
Fix
  ↓
Re-test
```

Where a control did not behave as expected, the result is documented rather than omitted.

---

# Important Lab Notes

This repository is an assessment/laboratory environment and is **not intended to be deployed directly to production**.

Before using any component outside the lab:

1. Replace all `CHANGE_ME` secrets.
2. Never commit `.env` files or credentials.
3. Rotate any credentials that may have been exposed during testing.
4. Replace regex-based AI guardrails with production-grade controls.
5. Implement proper secrets management.
6. Use production identity and key-management solutions.
7. Review logging for privacy and data-retention requirements.
8. Harden network segmentation and egress controls.
9. Perform a formal security review before production deployment.

The AI guardrail detector used in this lab is intentionally lightweight and regex-based. A production implementation should consider stronger controls such as **Microsoft Presidio, dedicated prompt-injection detection, structured data-loss prevention, or Cloudflare security controls for AI traffic**.

---

## Reproducibility

The primary local environment can be started with:

```bash
docker compose up -d
```

To stop the lab:

```bash
docker compose down
```

For the Wazuh environment, the Docker application stack should be stopped first on systems with limited memory.

### 8 GB RAM

Do not run the entire Docker application stack and Wazuh simultaneously on an 8 GB machine.

Stop the application stack before starting Wazuh:

```bash
docker compose down
```

---

## Disclaimer

All patient information, credentials, API keys, tokens, and other sensitive-looking values used in the demonstrations are **synthetic lab data**.

This project was created for security assessment, testing, learning, and demonstration purposes.
