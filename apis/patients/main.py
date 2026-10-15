"""Sample API 1: Patients (handles synthetic PHI, so it needs the strictest controls)."""
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
import json, logging, sys, time

app = FastAPI(title="Patients API", version="1.0")
log = logging.getLogger("patients")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

# Synthetic data only: never use real patient records in a lab
PATIENTS = {
    "P001": {"id": "P001", "name": "Test Patient One", "dob": "1990-01-01", "condition": "Hypertension"},
    "P002": {"id": "P002", "name": "Test Patient Two", "dob": "1985-06-15", "condition": "Type 2 Diabetes"},
}


class PatientIn(BaseModel):
    id: str = Field(pattern=r"^P\d{3}$")          # strict input validation
    name: str = Field(min_length=2, max_length=80)
    dob: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    condition: str = Field(max_length=120)


@app.middleware("http")
async def audit_log(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    # Structured JSON audit log for the SIEM. Logs WHO accessed WHAT, never the PHI itself.
    log.info(json.dumps({
        "service": "patients-api", "method": request.method, "path": request.url.path,
        "status": response.status_code, "consumer": request.headers.get("x-consumer-username", "unknown"),
        "request_id": request.headers.get("x-request-id"), "ms": round((time.time() - start) * 1000),
    }))
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/patients/{patient_id}")
def get_patient(patient_id: str):
    p = PATIENTS.get(patient_id)
    if not p:
        raise HTTPException(404, "Not found")   # generic error, no internal details
    return p


@app.post("/patients", status_code=201)
def create_patient(p: PatientIn):
    PATIENTS[p.id] = p.model_dump()
    return {"created": p.id}
