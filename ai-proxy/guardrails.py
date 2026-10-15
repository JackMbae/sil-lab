"""
Input/output guardrails for outbound Enterprise LLM traffic.

Lab version uses regex + heuristics so it runs in ~50 MB of RAM.
Production: swap detect_* for Microsoft Presidio (PII/PHI NER), a prompt-injection
classifier (e.g. Llama Prompt Guard / ProtectAI deberta model), or a managed service
such as Cloudflare Firewall for AI / Azure AI Content Safety.
"""
import re
from dataclasses import dataclass, field

# --- PHI / PII patterns (Kenya-focused + generic) ---
PATTERNS = {
    "KE_NATIONAL_ID": re.compile(r"\b\d{7,8}\b(?=.{0,40}\b(id|national|kitambulisho)\b)|\b(id|national id)[\s:#no.]*\d{7,8}\b", re.I),
    "KE_PHONE": re.compile(r"(?<!\d)(?:\+?254|0)(?:7|1)\d{8}(?!\d)"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "MRN": re.compile(r"\b(?:MRN|medical record(?: number)?)[\s:#-]*[A-Z0-9-]{4,}\b", re.I),
    "SHA_NHIF": re.compile(r"\b(?:SHA|NHIF)[\s:#-]*(?:no\.?|number)?[\s:#-]*\d{6,12}\b", re.I),
    "DOB": re.compile(r"\b(?:dob|date of birth)[\s:]*\d{4}-\d{2}-\d{2}\b", re.I),
    "CARD_NUMBER": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}
# Diagnosis words only count as PHI when they appear together with an identifier
CLINICAL_TERMS = re.compile(r"\b(diagnos\w*|hiv|tb|tuberculosis|diabetes|hypertension|pregnan\w*|cancer|prescri\w*)\b", re.I)

# --- Secrets that must never reach a public/enterprise LLM ---
SECRETS = {
    "DB_CONNECTION_STRING": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|redis)://[^\s:@]+:[^\s@]+@[^\s]+", re.I),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GENERIC_API_KEY": re.compile(r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}", re.I),
}

# --- Prompt-injection heuristics ---
INJECTION = [
    re.compile(p, re.I) for p in [
        r"ignore (all |any )?(previous|prior|above) (instructions|rules|prompts?)",
        r"disregard (the |your )?(system|previous) (prompt|instructions)",
        r"you are now (in )?(dan|developer mode|jailbreak)",
        r"(reveal|print|show|repeat) (your |the )?(system prompt|hidden instructions)",
        r"act as .{0,30}(without|no) (restrictions|filters|rules)",
        r"</?(system|assistant)>",
    ]
]


@dataclass
class Verdict:
    action: str = "allow"                     # allow | redact | block
    findings: list = field(default_factory=list)
    text: str = ""


def scan_input(text: str) -> Verdict:
    """Prompt leaving the network: block secrets and injections, block PHI (identifier + clinical)."""
    findings = [f"SECRET:{k}" for k, rx in SECRETS.items() if rx.search(text)]
    findings += ["PROMPT_INJECTION" for rx in INJECTION if rx.search(text)][:1]
    ids = [k for k, rx in PATTERNS.items() if rx.search(text)]
    if ids and CLINICAL_TERMS.search(text):
        findings.append("PHI:" + "+".join(ids))   # identifier + health info = PHI
    if findings:
        return Verdict("block", findings, "")
    if ids:                                        # PII without clinical context: redact, don't block
        return Verdict("redact", [f"PII:{k}" for k in ids], redact(text))
    return Verdict("allow", [], text)


def scan_output(text: str) -> Verdict:
    """LLM response coming back: strip any PII/secrets before the user or app sees it."""
    ids = [k for k, rx in PATTERNS.items() if rx.search(text)]
    secrets = [k for k, rx in SECRETS.items() if rx.search(text)]
    if ids or secrets:
        return Verdict("redact", [f"PII:{k}" for k in ids] + [f"SECRET:{k}" for k in secrets], redact(text))
    return Verdict("allow", [], text)


def redact(text: str) -> str:
    for name, rx in {**SECRETS, **PATTERNS}.items():
        text = rx.sub(f"[REDACTED_{name}]", text)
    return text
