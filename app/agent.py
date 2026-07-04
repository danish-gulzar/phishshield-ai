# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from datetime import datetime

from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.genai import types

from .config import config


# ============================================================================
# SECURITY CHECKPOINT FUNCTION
# ============================================================================

def security_checkpoint(email_content: str) -> str:
    """Security checkpoint for PII redaction and injection detection."""
    
    # PII Redaction patterns
    pii_patterns = {
        "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        "ssn": r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        "api_key": r'\b(sk-[a-zA-Z0-9]{32}|api_key_[a-zA-Z0-9]{32})\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    }
    
    redacted_content = email_content
    pii_count = 0
    
    for pii_type, pattern in pii_patterns.items():
        matches = re.findall(pattern, email_content, re.IGNORECASE)
        if matches:
            pii_count += len(matches)
            redacted_content = re.sub(pattern, '[REDACTED]', redacted_content, flags=re.IGNORECASE)
    
    # Prompt injection detection
    injection_keywords = [
        "ignore previous instructions",
        "system override",
        "you are now a",
        "forget everything",
    ]
    
    injection_detected = any(keyword.lower() in email_content.lower() for keyword in injection_keywords)
    
    if injection_detected:
        return f"⚠️ BLOCK_INJECTION: Prompt injection detected. PII redacted: {pii_count} items."
    
    return f"✅ SAFE_TO_ANALYZE: PII redacted: {pii_count} items. Content: {redacted_content[:200]}..."


# ============================================================================
# PHISHING ANALYSIS TOOLS
# ============================================================================

def check_domain_reputation(domain: str) -> str:
    """Check if a domain has known phishing reputation."""
    suspicious_domains = ["phishing-site.com", "fake-bank.net", "scam-alert.org", "verify-account-secure-login.com"]
    if any(sus in domain.lower() for sus in suspicious_domains):
        return f"⚠️ SUSPICIOUS: {domain} matches known phishing patterns"
    return f"✅ SAFE: {domain} has no known issues"


def detect_tone_indicators(text: str) -> str:
    """Detect emotional manipulation indicators in text."""
    urgency_keywords = ["immediately", "urgent", "asap", "right now", "within 24 hours"]
    threat_keywords = ["account will be closed", "legal action", "suspended", "terminated"]
    
    detected = []
    for keyword in urgency_keywords:
        if keyword in text.lower():
            detected.append(f"urgency: {keyword}")
    for keyword in threat_keywords:
        if keyword in text.lower():
            detected.append(f"threat: {keyword}")
    
    if detected:
        return f"⚠️ DETECTED: {', '.join(detected)}"
    return "✅ SAFE: No manipulation indicators detected"


# ============================================================================
# ROOT AGENT
# ============================================================================

root_agent = Agent(
    name="phishshield_ai",
    model=Gemini(
        model=config.model,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction="""You are PhishShield AI, an automated phishing detection system.

When a user provides email content:
1. First, use the security_checkpoint function to redact PII and check for injection
2. If safe, analyze the content for phishing indicators:
   - Check for urgency/threat language using detect_tone_indicators
   - Check domain reputation if URLs are present using check_domain_reputation
3. Assign a threat score (1-10) based on detected indicators
4. Provide a clear decision: SAFE_TO_ARCHIVE (score ≤ 7) or CRITICAL_HALT (score > 7)

Be thorough in your analysis and explain your reasoning.""",
    tools=[security_checkpoint, check_domain_reputation, detect_tone_indicators],
)


# ============================================================================
# APP DEFINITION
# ============================================================================

app = App(
    root_agent=root_agent,
    name="app",
)
