"""Sample API 2: Appointments (lower sensitivity, higher traffic)."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Appointments API", version="1.0")

APPOINTMENTS = [
    {"id": 1, "patient_id": "P001", "date": "2026-11-02", "clinic": "Outpatient"},
    {"id": 2, "patient_id": "P002", "date": "2026-11-05", "clinic": "Diabetes Clinic"},
]


class AppointmentIn(BaseModel):
    patient_id: str = Field(pattern=r"^P\d{3}$")
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    clinic: str = Field(max_length=60)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/appointments")
def list_appointments(patient_id: str | None = None):
    if patient_id:
        return [a for a in APPOINTMENTS if a["patient_id"] == patient_id]
    return APPOINTMENTS


@app.post("/appointments", status_code=201)
def book(a: AppointmentIn):
    new = {"id": len(APPOINTMENTS) + 1, **a.model_dump()}
    APPOINTMENTS.append(new)
    return new
