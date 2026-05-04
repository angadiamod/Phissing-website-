"""Visual cloning detection using Gemini 3 Flash vision on a website screenshot."""
from __future__ import annotations

import base64
import json
import os
import re
import asyncio
from urllib.parse import quote

import httpx


SCREENSHOT_ENDPOINT = "https://s.wordpress.com/mshots/v1/{url}?w=1024&h=640"


async def fetch_screenshot(url: str, timeout: float = 20.0) -> bytes | None:
    """Use the public WordPress mshots service to get a PNG screenshot.
    Returns None if we can't get a real image within the timeout."""
    shot_url = SCREENSHOT_ENDPOINT.format(url=quote(url, safe=""))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for _ in range(4):
            try:
                resp = await client.get(shot_url)
            except Exception:
                await asyncio.sleep(2)
                continue
            # mshots returns a tiny placeholder (< 10KB) until the shot is ready
            if resp.status_code == 200 and len(resp.content) > 15000 and resp.content[:4] in (b"\x89PNG", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1"):
                return resp.content
            await asyncio.sleep(2)
    return None


async def analyze_visual(url: str) -> dict:
    """Return {cnn_score, cloned_brand, similarity, suspicious_elements, screenshot_b64}."""
    from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent

    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    screenshot = await fetch_screenshot(url)

    if not screenshot or not api_key:
        # Fallback: no screenshot available → neutral score
        return {
            "cnn_score": 0.0,
            "cloned_brand": None,
            "similarity": 0,
            "suspicious_elements": [],
            "screenshot_b64": None,
            "note": "Screenshot unavailable — visual analysis skipped",
        }

    b64 = base64.b64encode(screenshot).decode()

    chat = LlmChat(
        api_key=api_key,
        session_id=f"phish-visual-{abs(hash(url))}",
        system_message=(
            "You are a phishing visual-clone analyst. Look at a website screenshot and "
            "decide if it visually impersonates a well-known brand login/banking page "
            "(e.g. PayPal, Amazon, Google, Microsoft, Apple, SBI, HDFC, ICICI, Facebook, "
            "Instagram, Netflix). Respond ONLY with a compact JSON object."
        ),
    ).with_model("gemini", "gemini-3-flash-preview")

    prompt = (
        "Analyse this screenshot. Return ONLY JSON with this exact schema:\n"
        "{\"cloned_brand\": string|null, \"similarity\": integer 0-100, "
        "\"suspicious_elements\": string[], \"reasoning\": string}\n"
        "Rules: If it clearly looks like an ORIGINAL legitimate page (e.g. the real PayPal), "
        "set cloned_brand to null and similarity below 20. If it mimics a brand but is on a "
        "suspicious domain, return that brand and similarity 60-100. Keep reasoning to 1 sentence."
    )

    try:
        response = await chat.send_message(UserMessage(
            text=prompt,
            file_contents=[ImageContent(image_base64=b64)],
        ))
    except Exception as e:
        return {
            "cnn_score": 0.0, "cloned_brand": None, "similarity": 0,
            "suspicious_elements": [], "screenshot_b64": b64,
            "note": f"Vision model error: {type(e).__name__}",
        }

    # Extract JSON from the response text
    text = response if isinstance(response, str) else str(response)
    match = re.search(r"\{[\s\S]*\}", text)
    parsed: dict = {}
    if match:
        try:
            parsed = json.loads(match.group(0))
        except Exception:
            parsed = {}

    similarity = int(parsed.get("similarity") or 0)
    cloned_brand = parsed.get("cloned_brand")
    elements = parsed.get("suspicious_elements") or []
    reasoning = parsed.get("reasoning", "")

    return {
        "cnn_score": float(similarity),
        "cloned_brand": cloned_brand,
        "similarity": similarity,
        "suspicious_elements": elements if isinstance(elements, list) else [str(elements)],
        "reasoning": reasoning,
        "screenshot_b64": b64,
    }
