"""
Outbound AI gateway: an OpenAI-compatible endpoint internal tools call instead of the LLM directly.
Egress firewall/DNS rules allow ONLY this proxy to reach the LLM provider (blocks Shadow AI).

UPSTREAM_URL empty -> mock mode (no API key needed for the demo).
"""
import json, logging, os, sys, time, uuid
import httpx
from fastapi import FastAPI, HTTPException, Request
from guardrails import scan_input, scan_output

UPSTREAM_URL = os.getenv("UPSTREAM_URL", "")        # e.g. https://api.openai.com/v1/chat/completions
UPSTREAM_KEY = os.getenv("UPSTREAM_API_KEY", "")    # held ONLY by the proxy, never by apps/devs
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "8000"))

app = FastAPI(title="AI Guardrail Proxy")
log = logging.getLogger("ai-proxy")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


def audit(event: str, **kw):
    # Log the decision and finding TYPES, never the prompt content itself (it may hold PHI)
    log.info(json.dumps({"service": "ai-proxy", "event": event, "ts": time.time(), **kw}))


@app.get("/health")
def health():
    return {"status": "ok", "mode": "upstream" if UPSTREAM_URL else "mock"}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    rid = request.headers.get("x-request-id", str(uuid.uuid4()))
    user = request.headers.get("x-consumer-username", "unknown")
    body = await request.json()
    messages = body.get("messages", [])
    prompt = "\n".join(m.get("content", "") for m in messages if isinstance(m.get("content"), str))

    if len(prompt) > MAX_PROMPT_CHARS:
        audit("blocked", reason="PROMPT_TOO_LONG", user=user, request_id=rid)
        raise HTTPException(413, "Prompt too long")

    v = scan_input(prompt)
    if v.action == "block":
        audit("blocked", findings=v.findings, user=user, request_id=rid)
        raise HTTPException(400, {"error": "Request blocked by AI usage policy", "findings": v.findings, "request_id": rid})
    if v.action == "redact":
        audit("input_redacted", findings=v.findings, user=user, request_id=rid)
        for m in messages:
            if isinstance(m.get("content"), str):
                m["content"] = scan_input(m["content"]).text or m["content"]

    if UPSTREAM_URL:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(UPSTREAM_URL, json={**body, "messages": messages},
                             headers={"Authorization": f"Bearer {UPSTREAM_KEY}"})
        data = r.json()
    else:  # mock LLM that (deliberately) echoes a phone number, to demo output scrubbing
        data = {"choices": [{"message": {"role": "assistant",
                "content": f"Mock answer. Contact the clinic on 0712345678. You asked: {messages[-1]['content'][:200]}"}}]}

    for ch in data.get("choices", []):
        out = scan_output(ch["message"]["content"])
        if out.action == "redact":
            audit("output_redacted", findings=out.findings, user=user, request_id=rid)
            ch["message"]["content"] = out.text

    audit("allowed", user=user, request_id=rid, input_action=v.action)
    return data
