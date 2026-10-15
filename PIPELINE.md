# Section 1B Q2 + Q6: CI/CD security pipeline

## What runs where
| Gate | Where | Tool | Catches | Blocks on |
|---|---|---|---|---|
| Secrets | pre-commit + CI (full history) | gitleaks 8.21.2 + `.gitleaks.toml` | API keys, tokens, Kong JWT secret (custom rule) | any finding |
| Hallucinated packages | pre-commit + CI | `scripts/check_deps_exist.py` | package not on PyPI, version never published, package < 90 days old | any error |
| SCA | CI | pip-audit (OSV + PyPI advisories) | known CVEs **including transitive deps** | any vuln |
| SAST | CI | Semgrep: `p/python`, `p/owasp-top-ten`, `.semgrep/ai-code-rules.yml` | injection, unverified JWT, TLS off, LLM output executed, PHI logged, fail-open guardrail, IDOR | ERROR only |
| Abuse tests | CI | pytest `ai-proxy/test_abuse_cases.py` | guardrail logic bypasses | any failure |
| DAST | CI, after secrets + SAST | OWASP ZAP full scan, twice: WAF On / DetectionOnly | runtime vulns, headers, CORS | FAIL rules in `zap/rules.tsv` |

## Run it (step by step, screenshot each)
1. Create a **private** GitHub repo `sil-lab`, then from the lab folder:
   ```
   git init && git add . && git commit -m "SIL lab" && git branch -M main
   git remote add origin https://github.com/<you>/sil-lab.git && git push -u origin main
   ```
2. **Actions** tab → `security` run. **Expected first run: red.** That is the point:
   - `abuse-tests`: 5 failures (the guardrail bypasses below)
   - `sca`: starlette 0.45.3 advisories (pulled in by fastapi 0.115.9)
   - `sast`: passes the gate, but the report has a **WARNING** for IDOR on `/patients/{patient_id}`
   - `secrets`: green
   - `dast`: runs because secrets + SAST passed; download the `zap-report-*` artifacts
3. Pre-commit locally: `pip install pre-commit && pre-commit install`, then generate a random fake key and try to commit it (PowerShell): `"LLM_API_KEY = '$(-join (1..32 | % { '0123456789abcdef'[(Get-Random 16)] }))'" | Out-File -Encoding ascii fake_secret.py; git add fake_secret.py; git commit -m test`. Screenshot the block, then delete `fake_secret.py`.
4. **Fix and go green** (your own work, this is the story for the write-up):
   - SCA: bump fastapi to a release that allows a patched starlette, rebuild, re-run tests.
   - Abuse tests: make `main.py` extract text from list-form content, reject content types it can't inspect (fail closed), scan the messages joined with no separator as well as each one, and return 400 for malformed messages.
5. **Demo PR** (Q6 evidence): new branch, copy `pipeline-demo/ai_generated_helper.py` into `ai-proxy/helper.py`, add `fastapi-guardrails-pro==1.0.0` to `ai-proxy/requirements.txt`, open a PR. Screenshot the 5 Semgrep ERRORs + the hallucinated-package error blocking the merge. Close the PR without merging.
6. Settings → Branches → protect `main`: require the `security` checks to pass. Screenshot.

## What the lab already found (verified, use as evidence)
| Finding | Found by | Missed by | Why |
|---|---|---|---|
| PHI sent as `content: [{"type":"text",...}]` skips the guardrail → 200 | abuse test | unit tests, Semgrep, ZAP | Code is valid; the flaw is an assumption (content is always a string) |
| PHI split across two messages slips past the regex | abuse test | all scanners | Joined with `\n`, the phone number no longer matches |
| Malformed message → 500 crash | abuse test | | No input schema on the proxy |
| starlette 0.45.3 vulnerable (transitive) | pip-audit | OSV-Scanner on `requirements.txt` | OSV only reads the 3 listed packages; pip-audit resolves the tree |
| Kong JWT secret in `kong.yml` | custom gitleaks rule | gitleaks defaults | Default rules don't know Kong's YAML format |
| `/patients/{id}`: any clinician can read any patient | custom Semgrep rule (WARNING) | ZAP, stock rules | Gateway proves *who*, nobody checks *whether this patient is theirs* |

## Reading the reports (Q2: interpretation)
- **gitleaks:** for each hit decide real vs fake. A real hit = **rotate first**, then remove; deleting the commit doesn't un-leak a key that was pushed. Allowlist only the exact fake value, never a whole file (see `.gitleaks.toml`).
- **Semgrep:** triage each as true positive, false positive (add `# nosemgrep: <rule-id>` with a reason, reviewed in the PR), or accepted risk (ticket). Track the false-positive rate per rule; a noisy rule gets ignored by developers.
- **SCA:** check (1) is the vulnerable function reachable in our code, (2) is a fixed version available, (3) is it direct or transitive. Fix by upgrading the parent, not pinning the child by hand.
- **ZAP:** risk + confidence. High risk / medium+ confidence = fix. Compare the two runs:
  - **On** shows what an attacker sees in prod; most attack payloads get 403.
  - **DetectionOnly** shows what the WAF is hiding. Anything that only appears here is a real app bug **protected by one control**; fix it in code, don't rely on the WAF.
  - Headers (X-Content-Type-Options, Server leak, wildcard CORS) are WARN: real, low severity, matches the 1A findings.

## Catching AI logic flaws (Q6), the strategy in one table
| Layer | Control |
|---|---|
| Before commit | Pre-commit hooks for secrets + invented packages; AI tool configured with a security system prompt; no secrets/PHI in prompts |
| PR | Custom Semgrep rules for the mistakes AI makes in *this* codebase; `CODEOWNERS` forces a security reviewer on `gateway/`, `ai-proxy/`, auth code; PR template asks "AI-assisted? which parts?" |
| Tests | Abuse-case tests written from a threat model (STRIDE / OWASP LLM Top 10), not from the code. Ask "how do I get PHI past this?", not "does it work?" |
| Runtime | DAST with and without the WAF; guardrail audit logs to the SIEM; alert on unusual allow/block ratios |
| People | Reviewers check *intent* vs *implementation*; AI code reviewed as if from a new junior developer |

Key point for the write-up: every scanner here missed the content-list bypass. Scanners find known patterns; **logic flaws need a human threat model turned into tests**, and that test then runs forever in CI.
