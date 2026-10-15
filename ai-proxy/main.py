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


class Uninspectable(ValueError):
    """Content the guardrail cannot read. Policy: if we can't inspect it, it doesn't leave."""


def extract_texts(messages) -> list[str]:
    """Every piece of text in the request, in any format the API accepts. Fails CLOSED."""
    if not isinstance(messages, list) or not messages:
        raise Uninspectable("messages must be a non-empty list")
    texts = []
    for m in messages:
        if not isinstance(m, dict):
            raise Uninspectable("each message must be an object")
        content = m.get("content")
        if content is None:
            continue
        if isinstance(content, str):                       # "content": "hello"
            texts.append(content)
        elif isinstance(content, list):                    # "content": [{"type":"text","text":"hello"}]
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    texts.append(part["text"])
                else:                                      # images, audio, files, unknown types
                    kind = part.get("type") if isinstance(part, dict) else type(part).__name__
                    raise Uninspectable(f"content type '{kind}' cannot be inspected")
        else:
            raise Uninspectable(f"content of type {type(content).__name__} cannot be inspected")
    return texts


def redact_messages(messages):
    """Redact PHI in place, in both string and list-of-parts content."""
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            m["content"] = scan_input(c).text or c
        elif isinstance(c, list):
            for part in c:
                part["text"] = scan_input(part["text"]).text or part["text"]


@app.post("/v1/chat/completions")
async def chat(request: Request):
    rid = request.headers.get("x-request-id", str(uuid.uuid4()))
    user = request.headers.get("x-consumer-username", "unknown")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object")
    messages = body.get("messages")

    try:
        texts = extract_texts(messages)
    except Uninspectable as e:
        audit("blocked", reason="UNINSPECTABLE_CONTENT", detail=str(e), user=user, request_id=rid)
        raise HTTPException(422, {"error": "Request blocked: content cannot be inspected", "request_id": rid})

    prompt = "\n".join(texts)
    if len(prompt) > MAX_PROMPT_CHARS:
        audit("blocked", reason="PROMPT_TOO_LONG", user=user, request_id=rid)
        raise HTTPException(413, "Prompt too long")

    # Scan the messages as separate lines AND glued together, so PHI split across
    # messages ("0712" + "345678") is still caught. Strictest verdict wins.
    v = scan_input(prompt)
    if v.action != "block":
        glued = scan_input("".join(texts))
        if glued.action == "block":
            v = glued
    if v.action == "block":
        audit("blocked", findings=v.findings, user=user, request_id=rid)
        raise HTTPException(400, {"error": "Request blocked by AI usage policy", "findings": v.findings, "request_id": rid})
    if v.action == "redact":
        audit("input_redacted", findings=v.findings, user=user, request_id=rid)
        redact_messages(messages)

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