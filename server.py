"""
TRUST — Terminal Risk & Unseen Signal Tracker
FastAPI Web Server & Static File Host with Optional Anonymized Telemetry.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="TRUST - Terminal Risk & Unseen Signal Tracker",
    description="Browser-Observable Pre-Banking Terminal Safety Check",
    version="1.0.0"
)

# Enable CORS for local testing without unsafe credential wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# In-memory store for anonymized fleet metrics (no PII)
telemetry_logs: List[Dict[str, Any]] = []

class TelemetryPayload(BaseModel):
    trustScore: int
    riskLevel: str
    confidence: str
    terminalFingerprint: str
    criticalFailures: int
    highWarnings: int
    timestamp: Optional[str] = None


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "TRUST Security Server",
        "version": "1.0.0",
        "timestamp": time.time()
    }


@app.post("/api/telemetry/log")
async def log_telemetry(payload: TelemetryPayload):
    """
    Optional anonymized telemetry logging endpoint for kiosk fleet operators.
    Local analysis runs 100% in-browser; this logs aggregate statistics only.
    """
    entry = payload.dict()
    entry["server_received_at"] = time.time()
    telemetry_logs.append(entry)
    
    # Cap in-memory history to last 500 records
    if len(telemetry_logs) > 500:
        telemetry_logs.pop(0)

    return {"status": "recorded", "count": len(telemetry_logs)}


@app.get("/api/telemetry/stats")
async def get_telemetry_stats():
    """
    Get aggregate risk trends across terminals
    """
    if not telemetry_logs:
        return {
            "totalScans": 0,
            "averageTrustScore": 100,
            "riskBreakdown": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        }

    total = len(telemetry_logs)
    avg_score = sum(log["trustScore"] for log in telemetry_logs) / total
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for log in telemetry_logs:
        rl = log.get("riskLevel", "LOW")
        if rl in risk_counts:
            risk_counts[rl] += 1

    return {
        "totalScans": total,
        "averageTrustScore": round(avg_score, 1),
        "riskBreakdown": risk_counts
    }


@app.get("/download/trust-security-suite.zip")
async def download_zip():
    """
    Serve the pre-packaged ZIP bundle of the complete TRUST repository
    """
    zip_path = os.path.join(os.path.dirname(__file__), "trust-security-suite.zip")
    if not os.path.exists(zip_path):
        raise HTTPException(status_code=404, detail="ZIP bundle not found. Run generate_zip.py first.")
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename="trust-security-suite.zip"
    )


@app.get("/standalone", response_class=HTMLResponse)
async def serve_standalone():
    standalone_path = os.path.join(os.path.dirname(__file__), "trust-standalone.html")
    if os.path.exists(standalone_path):
        with open(standalone_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Standalone file missing</h1>", status_code=404)


# Mount static assets
if os.path.exists(os.path.join(os.path.dirname(__file__), "static")):
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        content = f.read()
    # Add Content Security Policy header for inline scripts (required for app functionality)
    return HTMLResponse(
        content=content,
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
