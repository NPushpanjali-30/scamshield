"""Optional MCP server exposing ScamShield tools to compatible AI assistants.

Run:  pip install mcp  &&  python mcp_server.py   (stdio transport)
Reuses the existing analysis functions in main.py; no new scoring logic.
"""
from mcp.server.fastmcp import FastMCP

import main

mcp = FastMCP("scamshield-verify")

GUIDANCE = {
    "otp": "Call your bank to block cards/UPI, change passwords, report on 1930 or cybercrime.gov.in. Never share OTPs.",
    "payment": "Call 1930 immediately, inform your bank with the transaction ID, keep screenshots, file at cybercrime.gov.in.",
    "link": "Do not enter details, change passwords, scan the device, report if money was lost.",
}


@mcp.tool()
def analyze_message(text: str) -> dict:
    """Analyze a message for scam risk (rule-based, no LLM)."""
    return main.full_analysis(main.clean_text(text), use_llm=False)


@mcp.tool()
def check_url(url: str) -> dict:
    """Check a URL for suspicious patterns and explain the indicators."""
    return main.analyze_url(url)


@mcp.tool()
def safety_guidance(situation: str) -> str:
    """Safety steps for 'otp', 'payment' or 'link' situations."""
    return GUIDANCE.get(situation.lower(), "Call 1930 (cyber-fraud helpline) or 112 for emergencies; report at cybercrime.gov.in.")


if __name__ == "__main__":
    mcp.run()
