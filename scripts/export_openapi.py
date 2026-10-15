"""
Export each API's OpenAPI spec, rewritten to the gateway URL, so ZAP can scan every
endpoint, method and parameter (a spider finds almost nothing on a JSON API).

Kong maps  /v1/appointments/...  ->  appointments-api  /appointments/...
so the spec paths stay the same and only the server URL becomes http://localhost:8080/v1.

Usage: python scripts/export_openapi.py   (needs fastapi installed; writes zap/*-openapi.json)
"""
import importlib.util, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATEWAY = "http://localhost:8080/v1"
APIS = {"appointments": ROOT / "apis/appointments/main.py", "patients": ROOT / "apis/patients/main.py"}

for name, path in APIS.items():
    spec = importlib.util.spec_from_file_location(f"{name}_main", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    doc = mod.app.openapi()
    doc["servers"] = [{"url": GATEWAY}]
    # /health is not routed through the gateway, so leave it out of the scan
    doc["paths"] = {p: v for p, v in doc["paths"].items() if p.startswith(f"/{name}")}
    # Give path IDs a real example: without one ZAP sends the literal "patient_id",
    # every GET returns 404 and the record lookup is never attacked (found in run #7).
    for ops in doc["paths"].values():
        for op in ops.values():
            for prm in op.get("parameters", []):
                if prm["name"] == "patient_id" and prm["in"] == "path":
                    prm["example"] = "P001"
                    prm.setdefault("schema", {})["example"] = "P001"
    out = ROOT / "zap" / f"{name}-openapi.json"
    out.write_text(json.dumps(doc, indent=2))
    print(f"{out.relative_to(ROOT)}: {len(doc['paths'])} paths, "
          f"{sum(len(v) for v in doc['paths'].values())} operations")
sys.exit(0)