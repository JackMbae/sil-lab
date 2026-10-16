# Section 1B Q2 + Q6 — CI/CD Security Pipeline

This document describes the security controls I implemented in the SIL assessment lab's CI/CD pipeline and the findings generated during testing.

The pipeline was designed to demonstrate that security checks should not simply produce a green or red build. Each finding was investigated, its limitations were considered, and the pipeline was improved where the initial implementation was insufficient.

The final pipeline covers:

- Secret scanning
- Hallucinated-package detection
- Software Composition Analysis (SCA)
- Static Application Security Testing (SAST)
- AI abuse-case testing
- Dynamic Application Security Testing (DAST)
- AI-generated-code security testing
- Security gates for pull requests

---

# 1. Pipeline Architecture

The security pipeline combines controls at different stages of the software development lifecycle.

| Gate | Where | Tool | What it detects | Build behaviour |
|---|---|---|---|---|
| Secrets | Pre-commit + CI | Gitleaks 8.21.2 + `.gitleaks.toml` | API keys, tokens, Kong JWT secrets | Blocks on findings |
| Hallucinated packages | Pre-commit + CI | `scripts/check_deps_exist.py` | Non-existent packages, unpublished versions, very new packages | Blocks on errors |
| SCA | CI | pip-audit | Known vulnerabilities, including transitive dependencies | Blocks on vulnerabilities |
| SAST | CI | Semgrep | Injection, JWT validation issues, TLS disabled, unsafe LLM output, PHI logging, fail-open guardrails, IDOR | Blocks on ERROR findings |
| Abuse tests | CI | pytest | AI guardrail and application logic bypasses | Blocks on failures |
| DAST | CI | OWASP ZAP API scan | Runtime vulnerabilities, headers, caching, CORS and API behaviour | Blocks according to `zap/rules.tsv` |

The controls are deliberately complementary. No single scanner is treated as sufficient to establish that the application is secure.



---

# 2. Security Pipeline Flow

The resulting workflow is:

```text
Developer Change
      |
      v
+--------------------+
| Pre-commit Checks  |
|                    |
| Gitleaks           |
| Dependency Check   |
+---------+----------+
          |
          v
+--------------------+
| GitHub Actions     |
|                    |
| SCA                |
| Semgrep SAST       |
| Abuse Tests        |
+---------+----------+
          |
          v
+--------------------+
| DAST               |
|                    |
| OWASP ZAP API Scan |
| Authenticated      |
| WAF On / Off       |
+---------+----------+
          |
          v
+--------------------+
| Security Gate      |
+---------+----------+
          |
          v
       Merge
```

The pipeline was designed so that vulnerabilities identified at an earlier and cheaper stage are caught before progressing to later stages.

---

# 3. Initial Pipeline Run

I intentionally ran the initial pipeline before making the identified fixes.

The first run was expected to fail, and this provided useful evidence for the assessment rather than being treated as a problem with the exercise.

The initial results included:

- Five AI guardrail abuse-test failures
- A vulnerable transitive `starlette` dependency identified by SCA
- A SAST warning for potential IDOR on `/patients/{patient_id}`
- Successful secret scanning
- DAST execution after the prerequisite security checks passed

The initial pipeline therefore provided a baseline against which the subsequent fixes could be measured.

---

# 4. Secret Scanning

I implemented Gitleaks both as a local pre-commit control and as part of CI.

The configuration includes custom detection for secrets that are specific to this lab, including the Kong JWT secret format.

The pipeline is designed to identify:

- API keys
- Tokens
- Application secrets
- Kong JWT secrets
- Other credential-like values

The custom rule was necessary because the default Gitleaks rules did not identify the Kong JWT secret stored in the lab's YAML configuration.

This demonstrated an important limitation of generic security tooling: a scanner may only detect a secret when its format is already known to the scanner.

I also tested the pre-commit control by generating a random fake secret-like value and attempting to commit it.

The secret was detected before it could be committed.

When a real secret is detected, the correct response is to **rotate the credential first**, then remove it from the repository. Simply deleting the value from the latest commit does not invalidate a secret that has already been exposed.

---

# 5. Hallucinated Package Detection

AI-assisted development can introduce dependencies that appear plausible but do not actually exist.

I therefore implemented a custom dependency check:

```text
scripts/check_deps_exist.py
```

The check identifies:

- Packages that do not exist on PyPI
- Versions that have never been published
- Packages that are too recently published to meet the lab's configured trust threshold

This check runs both locally and in CI.

During the Q6 demonstration, the pipeline detected the deliberately introduced package:

```text
fastapi-guardrails-pro==1.0.0
```

The package does not exist on PyPI, so the security pipeline blocked the change.

This demonstrated that dependency validation can provide a security control specifically against AI-generated or hallucinated dependencies.

---

# 6. Software Composition Analysis

I used `pip-audit` to identify known vulnerabilities in Python dependencies.

The SCA stage initially identified a vulnerable transitive dependency:

```text
starlette 0.45.3
```

The important finding was that the vulnerable dependency was not necessarily obvious from the application's direct dependency list.

The pipeline therefore demonstrated why dependency scanning should resolve the complete dependency tree rather than checking only the packages explicitly listed by the developer.

I fixed the issue by upgrading the parent dependency to a release that brought in a patched version of Starlette, followed by rebuilding and re-running the pipeline.

The preferred remediation was therefore to upgrade the parent dependency rather than manually pinning the transitive dependency.

---

# 7. Semgrep SAST

The pipeline uses Semgrep with:

```text
p/python
p/owasp-top-ten
.semgrep/ai-code-rules.yml
```

The custom rules were written specifically around security mistakes that could occur in this application.

The rules cover issues including:

- Injection
- Unverified JWTs
- TLS being disabled
- Unsafe execution of LLM output
- PHI being logged
- Fail-open AI guardrails
- IDOR

The pipeline blocks on ERROR-level findings.

Warnings are retained for manual security review.

One important finding was:

```text
/patients/{patient_id}
```

The gateway successfully established **who** the user was, but the application did not independently establish whether that user was authorized to access the **specific patient record**.

This was identified by a custom Semgrep rule as a potential IDOR issue.

The finding demonstrates the difference between authentication and object-level authorization.

---

# 8. AI Guardrail Abuse Testing

I implemented dedicated abuse-case tests for the AI security proxy:

```text
ai-proxy/test_abuse_cases.py
```

The tests were designed from a threat perspective rather than simply testing the expected application flow.

The question was:

> How could an attacker get sensitive information past the guardrail?

The initial abuse tests identified several logic flaws that were not detected by conventional scanners.

### Content-list bypass

A request containing:

```text
content: [{"type":"text", ...}]
```

could bypass the guardrail because the implementation assumed that message content would always be a simple string.

The application therefore accepted content that the guardrail had not actually inspected.

### Split-message bypass

Sensitive content split across multiple messages could also bypass the original regular-expression check.

### Malformed input

Malformed messages could cause a `500` response because the proxy did not initially enforce an adequate input schema.

These findings demonstrated that valid application syntax does not necessarily mean that the security logic is correct.

---

# 9. Fixing the AI Guardrail Logic

I corrected the identified guardrail weaknesses by:

- Extracting text from list-form message content
- Rejecting content types that the guardrail cannot inspect
- Scanning individual messages
- Scanning the joined message content
- Returning `400` for malformed messages
- Ensuring the guardrail fails closed rather than silently allowing uninspected content

The abuse-case tests were then re-run.

The final guardrail test suite passed:

```text
19/19 tests passing
```

This created a permanent regression test for the security logic rather than relying on a one-time manual verification.

---

# 10. Deliberately Vulnerable AI-Generated-Code PR

For the Q6 assessment, I created a demonstration PR containing deliberately vulnerable code representative of security issues that can occur in AI-assisted development.

The demonstration included:

- AI-style security flaws
- A hallucinated dependency
- Code requiring additional security review

The security pipeline detected the issues before the PR could be merged.

The SAST stage identified:

```text
7 findings
5 custom AI-code rules
```

The hallucinated dependency check also rejected:

```text
fastapi-guardrails-pro==1.0.0
```

The PR was closed without merging.

This demonstrated that AI-generated code should be subjected to the same, and in some cases stronger, security controls as manually written code.

---

# 11. Branch Protection

I configured the `main` branch so that the security checks are required before changes can be merged.

The intended workflow is:

```text
Pull Request
     |
     v
Security Pipeline
     |
     +---- Fail ----> Fix
     |
     +---- Pass ----> Review
                       |
                       v
                     Merge
```

This prevents security controls from becoming merely advisory checks that developers can ignore.

The branch ruleset evidence is included in the assessment evidence.

---

# 12. Initial DAST Approach — What Did Not Work

One of the most important lessons from the assessment came from the first DAST implementation.

The initial approach used an OWASP ZAP full scan with a traditional spider.

The resulting report was green, but the result was misleading.

The report showed:

- Approximately 93–96% of responses were `4xx`
- Only approximately 3–6% were `2xx`
- Only five endpoints were discovered
- The discovered endpoints were primarily GET requests
- The Patients API was not properly exercised
- POST requests and meaningful API parameters were not covered
- WAF-On and DetectionOnly reports were effectively identical
- No High findings were reported

The clean report therefore did **not** demonstrate that the APIs were secure.

The problem was test coverage, not necessarily application security.

---

# 13. DAST Redesign

I replaced the initial spider-based approach with an authenticated OWASP ZAP **API scan** driven by the OpenAPI specifications for the two APIs.

The revised approach:

1. Loads the OpenAPI specification.
2. Discovers the actual API endpoints.
3. Exercises the supported HTTP methods.
4. Supplies the required API authentication.
5. Tests the APIs with the WAF enabled.
6. Repeats testing with the WAF in DetectionOnly mode.
7. Checks how many requests actually reached the API.
8. Applies the configured rules in `zap/rules.tsv`.

The coverage check was an important addition.

I did not treat a clean DAST report as successful unless I could demonstrate that ZAP had actually exercised the application.

The final principle was:

> **Never accept a clean DAST report without checking its coverage.**

---

# 14. Why WAF-On and DetectionOnly Testing Matters

I used two WAF modes to distinguish between attacks blocked at the perimeter and vulnerabilities that remained in the application.

### WAF On

This represents the protection an attacker would encounter in the deployed environment.

Attack payloads intercepted by the WAF are rejected before reaching the application.

### DetectionOnly

This allows the request to reach the application while the WAF records what it would have detected.

This is useful for identifying application weaknesses that are currently being hidden by the WAF.

If an attack succeeds in DetectionOnly mode but is blocked when the WAF is enabled, the application should still be reviewed.

The WAF should be treated as a defence-in-depth control, not as a replacement for secure application code.

---

# 15. DAST Findings & Remediation

The meaningful DAST run identified several findings that were triaged individually.

| Finding | Risk | Decision |
|---|---|---|
| Storable/cacheable content on `/v1/appointments` | Informational | Fix for PHI APIs |
| `X-Content-Type-Options` missing | Low | Fix |
| CSP / Permissions-Policy missing | Medium / Low | Accept for JSON-only APIs; required for web front ends |
| User Agent Fuzzer | Informational | No action |

For the appointment API, I treated cacheability as important because the application represents patient-related data.

The planned remediation was to add:

```text
Cache-Control: no-store
```

through Kong so that proxies and browsers do not cache sensitive API responses.

I also added the `nosniff` response header through the gateway.

CSP and Permissions-Policy were treated differently because the lab APIs return JSON and do not render an HTML user interface.

---

# 16. What the Pipeline Demonstrated

The completed pipeline demonstrated that different security tools identify different classes of problems.

| Security Problem | Primary Detection |
|---|---|
| Exposed secrets | Gitleaks |
| Kong-specific secret | Custom Gitleaks rule |
| Vulnerable transitive dependency | pip-audit |
| Known source-code weaknesses | Semgrep |
| AI guardrail logic bypass | Abuse tests |
| Hallucinated dependency | Custom dependency check |
| Runtime/API weaknesses | OWASP ZAP |
| Object-level authorization concern | Custom Semgrep rule |
| WAF-hidden application weaknesses | ZAP + DetectionOnly |
| AI-generated-code flaws | Custom Semgrep + abuse tests |

The key lesson was that **no individual scanner was sufficient**.

In particular, every conventional scanner initially missed the content-list guardrail bypass. The issue was a logic flaw based on an assumption about the structure of user input rather than a known vulnerable code pattern.

The threat model identified the weakness, the abuse test reproduced it, and the resulting test was then added permanently to CI.

---

# 17. Security Testing Philosophy

The pipeline follows a layered approach:

```text
              Human Threat Model
                       |
                       v
              Abuse-Case Tests
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
     SAST            SCA         Secret Scan
        |              |              |
        +--------------+--------------+
                       |
                       v
                     DAST
                       |
                       v
                 Runtime Evidence
                       |
                       v
                Security Review
```

For AI-assisted development, I treat generated code as code written by a new junior developer: it must be reviewed for intent, assumptions, authorization boundaries, data handling, and failure behaviour rather than being trusted because it passes conventional static analysis.

---

# 18. Final Pipeline Result

The final implementation provided a security pipeline covering the major stages of the software lifecycle:

```text
Developer
   |
   v
Pre-commit
   |
   +--> Secret scanning
   +--> Dependency validation
   |
   v
Pull Request
   |
   +--> SCA
   +--> SAST
   +--> AI abuse tests
   |
   v
Authenticated DAST
   |
   +--> WAF On
   +--> WAF DetectionOnly
   +--> Coverage verification
   |
   v
Security Review
   |
   v
Merge
```

The most important outcome was not simply achieving a green pipeline. The process demonstrated the ability to:

**build → test → identify weaknesses → investigate → remediate → re-test → enforce the control in CI.**

This approach ensures that security findings discovered during the assessment become repeatable controls rather than one-time manual observations.
