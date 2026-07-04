#!/usr/bin/env python3
"""
PhishShield AI MCP Server
Provides tools for phishing detection and security analysis.
"""

import asyncio
import json
import re
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from datetime import datetime


# Initialize MCP Server
mcp_server = Server("phishshield-mcp-server")


# ============================================================================
# MCP TOOLS
# ============================================================================

@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="check_domain_reputation",
            description="Check if a domain has known phishing or malicious reputation",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to check (e.g., example.com)"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="analyze_url_safety",
            description="Analyze URL for obfuscation patterns and suspicious characteristics",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL to analyze"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="check_email_sender_reputation",
            description="Check email sender reputation and common spoofing patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "email_address": {
                        "type": "string",
                        "description": "Email address to check"
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain from email headers"
                    }
                },
                "required": ["email_address"]
            }
        ),
        Tool(
            name="detect_tone_indicators",
            description="Detect emotional manipulation indicators in text (urgency, threat, pressure)",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text content to analyze for tone indicators"
                    }
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="extract_links",
            description="Extract all URLs from email content for analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Email content to extract links from"
                    }
                },
                "required": ["content"]
            }
        ),
    ]


@mcp_server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "check_domain_reputation":
        domain = arguments.get("domain", "")
        result = _check_domain_reputation(domain)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "analyze_url_safety":
        url = arguments.get("url", "")
        result = _analyze_url_safety(url)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "check_email_sender_reputation":
        email_address = arguments.get("email_address", "")
        domain = arguments.get("domain", "")
        result = _check_email_sender_reputation(email_address, domain)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "detect_tone_indicators":
        text = arguments.get("text", "")
        result = _detect_tone_indicators(text)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    elif name == "extract_links":
        content = arguments.get("content", "")
        result = _extract_links(content)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ============================================================================
# TOOL IMPLEMENTATIONS
# ============================================================================

def _check_domain_reputation(domain: str) -> dict:
    """Check domain reputation against known phishing patterns."""
    domain = domain.lower()
    
    # Known suspicious patterns
    suspicious_tlds = [".xyz", ".top", ".zip", ".mov", ".tk", ".ml", ".ga"]
    suspicious_keywords = ["login", "secure", "account", "verify", "update", "bank", "paypal"]
    
    risk_score = 0
    indicators = []
    
    # Check TLD
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        risk_score += 3
        indicators.append(f"Suspicious TLD: {domain.split('.')[-1]}")
    
    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in domain:
            risk_score += 2
            indicators.append(f"Contains suspicious keyword: {keyword}")
    
    # Check for character substitution (typosquatting)
    common_brands = ["google", "microsoft", "apple", "amazon", "facebook", "paypal"]
    for brand in common_brands:
        if brand in domain and domain != f"{brand}.com":
            risk_score += 4
            indicators.append(f"Potential typosquatting for {brand}")
    
    # Check for excessive subdomains
    if domain.count(".") > 3:
        risk_score += 2
        indicators.append("Excessive subdomains")
    
    # Determine risk level
    if risk_score >= 7:
        risk_level = "CRITICAL"
    elif risk_score >= 4:
        risk_level = "HIGH"
    elif risk_score >= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "timestamp": datetime.utcnow().isoformat()
    }


def _analyze_url_safety(url: str) -> dict:
    """Analyze URL for obfuscation and suspicious patterns."""
    url_lower = url.lower()
    
    risk_score = 0
    indicators = []
    
    # Check for obfuscation
    if "hxxp://" in url_lower or "hxxps://" in url_lower:
        risk_score += 5
        indicators.append("URL obfuscation detected (hxxp)")
    
    # Check for IP address instead of domain
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    if re.search(ip_pattern, url):
        risk_score += 4
        indicators.append("IP address used instead of domain")
    
    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
    if any(shortener in url_lower for shortener in shorteners):
        risk_score += 2
        indicators.append("URL shortener detected")
    
    # Check for excessive length
    if len(url) > 200:
        risk_score += 2
        indicators.append("Unusually long URL")
    
    # Check for suspicious parameters
    suspicious_params = ["password", "token", "session", "auth", "login", "verify"]
    for param in suspicious_params:
        if f"{param}=" in url_lower:
            risk_score += 1
            indicators.append(f"Contains sensitive parameter: {param}")
    
    # Check for mixed HTTP/HTTPS
    if "http://" in url_lower and "https://" in url_lower:
        risk_score += 3
        indicators.append("Mixed HTTP/HTTPS protocol")
    
    # Determine risk level
    if risk_score >= 8:
        risk_level = "CRITICAL"
    elif risk_score >= 5:
        risk_level = "HIGH"
    elif risk_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "timestamp": datetime.utcnow().isoformat()
    }


def _check_email_sender_reputation(email_address: str, domain: str = "") -> dict:
    """Check email sender reputation and spoofing patterns."""
    email_lower = email_address.lower()
    domain_lower = domain.lower() if domain else ""
    
    risk_score = 0
    indicators = []
    
    # Extract domain from email
    email_domain = email_address.split("@")[-1] if "@" in email_address else ""
    
    # Check for free email providers (often used in phishing)
    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    if email_domain in free_providers:
        risk_score += 1
        indicators.append("Free email provider used")
    
    # Check for display name mismatches
    if domain and email_domain != domain_lower:
        risk_score += 4
        indicators.append(f"Domain mismatch: email domain ({email_domain}) != header domain ({domain})")
    
    # Check for suspicious patterns in local part
    local_part = email_address.split("@")[0] if "@" in email_address else ""
    if re.match(r'.*\d{4,}.*', local_part):
        risk_score += 2
        indicators.append("Local part contains multiple digits (potential random generation)")
    
    # Check for common spoofing patterns
    if "noreply" in local_part.lower() or "no-reply" in local_part.lower():
        risk_score += 1
        indicators.append("No-reply address (common in legitimate but also phishing)")
    
    # Check for role-based addresses
    role_accounts = ["admin@", "support@", "security@", "billing@", "info@"]
    if any(local_part.lower().startswith(role[:-1]) for role in role_accounts):
        risk_score += 2
        indicators.append("Role-based account address")
    
    # Determine risk level
    if risk_score >= 6:
        risk_level = "HIGH"
    elif risk_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "email_address": email_address,
        "email_domain": email_domain,
        "header_domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "timestamp": datetime.utcnow().isoformat()
    }


def _detect_tone_indicators(text: str) -> dict:
    """Detect emotional manipulation indicators in text."""
    text_lower = text.lower()
    
    urgency_keywords = ["immediately", "urgent", "asap", "right now", "within 24 hours", 
                       "act now", "don't delay", "time sensitive", "expires soon"]
    threat_keywords = ["account will be closed", "legal action", "suspended", "terminated",
                      "lose access", "consequences", "serious", "final notice"]
    pressure_keywords = ["verify", "confirm", "update", "click here", "immediate action",
                        "required", "mandatory", "must", "failure to"]
    
    detected = {
        "urgency": [],
        "threat": [],
        "pressure": []
    }
    
    for keyword in urgency_keywords:
        if keyword in text_lower:
            detected["urgency"].append(keyword)
    
    for keyword in threat_keywords:
        if keyword in text_lower:
            detected["threat"].append(keyword)
    
    for keyword in pressure_keywords:
        if keyword in text_lower:
            detected["pressure"].append(keyword)
    
    total_indicators = len(detected["urgency"]) + len(detected["threat"]) + len(detected["pressure"])
    
    if total_indicators >= 5:
        risk_level = "CRITICAL"
    elif total_indicators >= 3:
        risk_level = "HIGH"
    elif total_indicators >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "text_length": len(text),
        "detected_indicators": detected,
        "total_indicators": total_indicators,
        "risk_level": risk_level,
        "timestamp": datetime.utcnow().isoformat()
    }


def _extract_links(content: str) -> dict:
    """Extract all URLs from content."""
    # URL regex pattern
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-?=&%]*'
    urls = re.findall(url_pattern, content)
    
    # Remove duplicates while preserving order
    unique_urls = list(dict.fromkeys(urls))
    
    return {
        "total_links": len(urls),
        "unique_links": len(unique_urls),
        "links": unique_urls,
        "timestamp": datetime.utcnow().isoformat()
    }


# ============================================================================
# SERVER ENTRY POINT
# ============================================================================

async def main():
    """Run the MCP server with stdio transport."""
    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
