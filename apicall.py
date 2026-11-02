from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from typing import Optional

import os
from dotenv import load_dotenv

from colibri import systemone, colibri_text
from log import get_alert_cortex, get_alert_s1

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="LLM API")

# Configure CORS middleware to allow cross-origin requests from the React/Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Default Vite dev server port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Input data schemas
class AlertRequest(BaseModel):
    console: str
    client: Optional[str] = None
    alert_id: str

class ChatRequest(BaseModel):
    alert_id: str
    message: str


@app.get("/api/clients")
async def get_clients():
    """Retrieve the list of allowed clients from environment configuration."""
    raw_clients = os.getenv("CLIENT_LIST", "")
    clients_list = [c.strip() for c in raw_clients.split(",") if c.strip()]
    return {
        "clients": clients_list
    }

@app.post("/api/analyze")
async def analyze_alert(request: AlertRequest):
    """Analyze a security alert using log contextualization and LLM classification models."""
    alert_id = request.alert_id
    console = request.console
    client = request.client

    print(alert_id, console, client)

    # Fetch alert log data depending on the selected EDR/XDR console
    if console == "Cortex XDR":
        context = get_alert_cortex(alert_id, client)
    else:
        context = get_alert_s1(alert_id)

    # Calculate classification entropy and category
    entropy, classification = systemone(context)

    # Generate reasoning if prediction confidence meets threshold
    if entropy < 0.5:
        motivation = colibri_text(context, classification)
    else:
        motivation = "FURTHER LOG COLLECTION REQUIRED"
    
    return {
        "status": "success",
        "entropy": f"{entropy:.2f}", 
        "classification": classification,
        "reasoning": f"Analysis for alert {request.alert_id}:\n {motivation}"
    }

@app.post("/api/chat")
async def chat_with_context(request: ChatRequest):
    """Handle follow-up questions from the analyst within the alert context."""
    # MOCK RESPONSE
    return {
        "reply": f"Fetched additional details for alert {request.alert_id} regarding query: '{request.message}'. No further anomalies detected."
    }

if __name__ == "__main__":
    # Launch the FastAPI application server
    uvicorn.run(app, host="0.0.0.0", port=8001)