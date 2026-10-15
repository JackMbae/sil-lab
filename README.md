# SIL Infosec Analyst Assessment: lab

## Two-week plan
| Days | Section | Deliverable | Status |
|---|---|---|---|
| 1–3 | 1A (a–c) | Run this lab; redraw the architecture diagram; screenshots of every DEMO.md test | Lab ready |
| 4 | 1A (d–f) | Written answers: rate limiting, auth, data handling, AI guardrails, risks | |
| 5–7 | 1B (1, 3, 4) | Wazuh SIEM (single-node, 4 GB): onboard Kong/WAF/ai-proxy logs, ransomware + Shadow AI rules | |
| 8–9 | 1B (2, 6) | GitHub Actions pipeline: gitleaks pre-commit, Semgrep SAST, SCA + hallucinated-package check, abuse tests, ZAP DAST (see PIPELINE.md) | Pipeline ready |
| 10 | 1B (4, 5) | Incomplete logs + multi-cloud compliance answers | |
| 11–12 | Section 2 | Soft-skills answers in YOUR voice + one-page incident report | |
| 13 | All | Assemble the final document, check every claim against a screenshot | |
| 14 | | Buffer, then submit early | |

**8 GB RAM tip:** don't run everything at once. Stop this stack (`docker compose down`) before starting Wazuh.

## Layout
```
docker-compose.yml        all services (WAF, Kong, 2 APIs, AI proxy, optional Cloudflare tunnel)
gateway/kong.yml          gateway policy: auth, ACL, rate limits, size limits, logging
apis/patients/            sample API 1 (synthetic PHI, JWT + ACL)
apis/appointments/        sample API 2 (API key)
ai-proxy/                 outbound LLM guardrail proxy + 10 unit tests
scripts/make_jwt.py       lab JWT generator
ARCHITECTURE.md           draft diagram + design rationale
DEMO.md                   every test to run and screenshot
PIPELINE.md               CI/CD security pipeline: run steps, findings, report interpretation
.github/workflows/        security.yml (all CI gates)
.pre-commit-config.yaml   gitleaks + hallucinated-package hooks
.gitleaks.toml            secret rules + narrow allowlist
.semgrep/                 custom rules for AI-generated code flaws
zap/rules.tsv             which ZAP alerts fail the build
pipeline-demo/            flawed 'AI-generated' file for the demo PR (never merge)
```

## Before using beyond your laptop
Replace every `CHANGE_ME` secret, and never commit a `.env` file. The guardrail detector is regex-based for the lab; say so in your write-up and name the production upgrade (Presidio, a prompt-injection classifier, or Cloudflare Firewall for AI).
