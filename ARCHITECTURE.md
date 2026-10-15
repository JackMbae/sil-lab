# Section 1A(a): architecture (draft, redraw it in your own diagram tool)

```mermaid
flowchart LR
  subgraph Internet
    U[Clients / partner apps]
    ATK[Attackers / bots]
  end

  subgraph CF[Cloudflare edge]
    CFW[WAF managed rules + OWASP]
    CFR[Rate limiting + Bot management + DDoS]
    CFA[Access / mTLS for partners]
  end

  subgraph DMZ[Edge network]
    T[cloudflared tunnel - no inbound ports]
    MS[ModSecurity + OWASP CRS - 2nd WAF layer]
  end

  subgraph INT[Internal network - no internet]
    K[Kong API Gateway: JWT / API keys, ACLs, rate limits, size limits, correlation IDs]
    P[Patients API - PHI]
    A[Appointments API]
    DB[(PostgreSQL - encrypted, private subnet)]
  end

  subgraph ID[Identity]
    IDP[IdP - Keycloak / Entra ID: OAuth2 + OIDC, MFA]
    V[Secrets vault - HashiCorp Vault / cloud KMS]
  end

  subgraph AI[Outbound AI egress]
    G[AI Guardrail Proxy: injection detection, PHI block, PII redaction, audit]
    LLM[Enterprise LLM - Azure OpenAI / Bedrock, zero data retention]
  end

  SIEM[(SIEM - Wazuh)]

  U & ATK --> CFW --> CFR --> CFA --> T --> MS --> K
  K --> P & A --> DB
  K -. validate tokens .-> IDP
  P & A -. fetch creds .-> V
  P & A --> G --> LLM
  CFW & MS & K & P & A & G -. JSON logs .-> SIEM
```

## Why each layer exists (be ready to defend these)
| Layer | Purpose | Key decision |
|---|---|---|
| Cloudflare edge | Absorbs DDoS, blocks known attacks and bots before they reach us | Origin only reachable through the tunnel, so the WAF can't be bypassed by hitting the server IP directly |
| ModSecurity + CRS | Second, self-hosted WAF close to the APIs | Defence in depth; full audit logs we control; works if the edge is misconfigured |
| Kong gateway | Single enforcement point for auth, rate limits, request size, routing | Admin API bound to localhost only; DB-less config kept in Git (reviewed and versioned) |
| APIs | Business logic | Strict schema validation, non-root containers, generic error messages |
| Database | Storage | Private network only, encryption at rest, least-privilege DB users per API |
| IdP | Who the caller is | OAuth2 client-credentials for services, OIDC + MFA for users; short-lived tokens |
| AI guardrail proxy | The only path to the LLM | Holds the LLM key (devs never see it); egress firewall blocks direct LLM access (stops Shadow AI) |
| SIEM | Detection and investigation | Every layer logs JSON with a shared `X-Request-ID` to trace one request end to end |

## Cloud mapping (if asked for a cloud preference)
| Component | AWS | Azure | Lab |
|---|---|---|---|
| Edge WAF | AWS WAF / Cloudflare | Front Door WAF / Cloudflare | Cloudflare |
| Gateway | API Gateway / Kong on EKS | API Management | Kong |
| Identity | Cognito / Entra ID | Entra ID | JWT (Keycloak optional) |
| Secrets | Secrets Manager + KMS | Key Vault | env vars (lab only) |
| LLM | Bedrock | Azure OpenAI | mock / any OpenAI-compatible |
| SIEM | Security Lake / Wazuh | Sentinel / Wazuh | Wazuh |
