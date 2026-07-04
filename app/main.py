import os
import re
import sys
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.agents.run_config import RunConfig
from google.genai import types

# Add parent directory to path to allow importing app module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.agent import app as adk_app

app = FastAPI(title="PhishShield AI Dashboard")

# Initialize ADK session service
session_service = InMemorySessionService()
runner = Runner(
    app=adk_app,
    session_service=session_service,
)

class AnalyzeRequest(BaseModel):
    email_content: str

@app.post("/api/analyze")
async def analyze_email(req: AnalyzeRequest):
    if not req.email_content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty")

    user_id = "ui-user"
    # Generate unique session ID for each run
    import uuid
    session_id = f"session-{uuid.uuid4()}"

    # Create the session
    try:
        await session_service.create_session(
            app_name="app",
            user_id=user_id,
            session_id=session_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initialize session: {str(e)}")

    new_message = types.Content(
        role="user",
        parts=[types.Part.from_text(text=req.email_content)]
    )

    final_text = ""
    tool_calls = []
    tool_responses = []

    try:
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=new_message,
            run_config=RunConfig()
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        final_text += part.text
            
            for fc in event.get_function_calls():
                tool_calls.append({
                    "name": fc.name,
                    "args": fc.args
                })
                
            for fr in event.get_function_responses():
                # Serialize response to avoid json issues
                response_str = ""
                if fr.response:
                    if isinstance(fr.response, dict):
                        response_str = fr.response.get("result", str(fr.response))
                    else:
                        response_str = str(fr.response)
                tool_responses.append({
                    "name": fr.name,
                    "response": response_str
                })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent runtime error: {str(e)}")

    # Parsed results dictionary
    results = {
        "email_content": req.email_content,
        "redacted_content": req.email_content,
        "pii_count": 0,
        "injection_detected": False,
        "threat_score": 1,
        "decision": "SAFE_TO_ARCHIVE",
        "tone_indicators": [],
        "domain_reputation": [],
        "final_text": final_text
    }

    # 1. Parse security checkpoint response
    checkpoint_response = ""
    for resp in tool_responses:
        if resp["name"] == "security_checkpoint":
            checkpoint_response = resp["response"]
            break
            
    if checkpoint_response:
        # Check for BLOCK_INJECTION
        if "BLOCK_INJECTION" in checkpoint_response:
            results["injection_detected"] = True
            results["decision"] = "BLOCK_INJECTION"
            results["threat_score"] = 10
        
        # Check for redacted count
        pii_match = re.search(r"PII redacted:\s*(\d+)", checkpoint_response)
        if pii_match:
            results["pii_count"] = int(pii_match.group(1))
            
        # Try to find the redacted content in the response string
        # Format: Content: ...
        content_match = re.search(r"Content:\s*(.*)", checkpoint_response)
        if content_match:
            results["redacted_content"] = content_match.group(1)

    # 2. Parse Tone indicators
    for resp in tool_responses:
        if resp["name"] == "detect_tone_indicators":
            tone_resp = resp["response"]
            if "DETECTED" in tone_resp:
                # E.g. "⚠️ DETECTED: urgency: immediately, threat: legal action"
                results["tone_indicators"].append(tone_resp)

    # 3. Parse Domain reputation
    for resp in tool_responses:
        if resp["name"] == "check_domain_reputation":
            results["domain_reputation"].append(resp["response"])

    # 4. Extract threat score & final decision from the LLM text
    if results["injection_detected"]:
        results["decision"] = "BLOCK_INJECTION"
        results["threat_score"] = 10
    else:
        # Search for SAFE_TO_ARCHIVE / CRITICAL_HALT
        if "CRITICAL_HALT" in final_text:
            results["decision"] = "CRITICAL_HALT"
        elif "SAFE_TO_ARCHIVE" in final_text:
            results["decision"] = "SAFE_TO_ARCHIVE"
        else:
            # Fallback based on score
            results["decision"] = "SAFE_TO_ARCHIVE"

        # Search for threat score
        score_match = re.search(r"(?:threat\s+)?score:?\s*(\d+)", final_text, re.IGNORECASE)
        if score_match:
            results["threat_score"] = int(score_match.group(1))
        elif results["decision"] == "CRITICAL_HALT":
            results["threat_score"] = 8  # fallback high score
        else:
            # If tone or domain reputation flags issues, bump score slightly
            if results["tone_indicators"] or results["domain_reputation"]:
                results["threat_score"] = 5
            else:
                results["threat_score"] = 1

    return JSONResponse(content=results)

# Mount static files folder
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def read_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>PhishShield AI Dashboard</h1><p>Static frontend not found yet.</p>")
