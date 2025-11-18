from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import hmac
import hashlib


app = FastAPI(
    title="Attendance API",
    description="Secure IoT Attendance System",
    version="1.0.0"
)


# === Device Registry ===
DEVICES = {
    "Rabby_pukpuk": "khulja sim sim"
}


# === Pydantic Schema ===
class AttendanceRequest(BaseModel):
    device_id: str
    message: str  # card_id
    signature: str


# === HMAC Verification Logic ===
def verify_signature(device_id: str, message: str, signature: str) -> bool:
    secret = DEVICES.get(device_id)
    if not secret:
        return False

    msg = f"{device_id}{message}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# === API Route ===
@app.post("/attendance")
async def receive_data(payload: AttendanceRequest):

    print("\n--- [SERVER] Received Data ---")
    print(payload.dict())

    # Verify HMAC
    if not verify_signature(payload.device_id, payload.message, payload.signature):
        print(f"❌ Invalid signature from {payload.device_id}")
        raise HTTPException(
            status_code=403,
            detail={"status": "failed", "message": "Verification failed"}
        )

    print(f"✅ Verified from {payload.device_id}: {payload.message}")

    # TODO: Save attendance record to database here

    return {
        "status": "success",
        "message": "Valid signature",
        "device_id": payload.device_id
    }


# Run: uvicorn main:app --host 192.168.1.3 --port 1013 --reload
