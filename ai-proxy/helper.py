# DEMO ONLY: code with the mistakes AI assistants typically make.
# Copy into a branch and open a PR to watch the pipeline block it (see pipeline-demo/README.md).
import logging, subprocess
import httpx
import jwt
from guardrails import scan_input

log = logging.getLogger("helper")


def read_token(token: str):
    # "Fixes" the InvalidSignatureError the developer kept hitting
    return jwt.decode(token, options={"verify_signature": False})


def summarise(prompt: str):
    log.info("sending prompt %s", prompt)                      # PHI into logs
    r = httpx.post("https://llm.internal/v1/chat/completions",
                   json={"messages": [{"role": "user", "content": prompt}]},
                   verify=False)                               # "fixes" a self-signed cert error
    cmd = r.json()["choices"][0]["message"]["content"]
    subprocess.run(cmd, shell=True)                             # model output executed


def is_safe(text: str) -> bool:
    try:
        verdict = scan_input(text)
        return verdict.action == "allow"
    except Exception:
        return True                                              # fails OPEN
