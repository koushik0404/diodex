"""Optional local LLM explanation layer for DIODEx."""

from __future__ import annotations

import json
from typing import Any

import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3.5:4b"


def build_prompt(
    detection: dict[str, Any],
    evidence: dict[str, Any],
) -> str:
    """Build a constrained prompt from already-derived security facts."""
    payload = {
        "threat_name": detection.get("threat_name"),
        "confidence": detection.get("confidence"),
        "anomaly_score": detection.get("anomaly_score"),
        "evidence": evidence.get("signals", []),
        "metrics": evidence.get("metrics", {}),
    }

    return f"""
You are a cybersecurity explanation assistant.

The security detector has ALREADY made the decision.
Do NOT change, question, or invent the security verdict.

Explain ONLY the supplied evidence.

Return ONLY valid JSON in this exact shape:
{{"explanation":"one concise analyst-friendly explanation"}}

Security data:
{json.dumps(payload, ensure_ascii=True)}
""".strip()


def _extract_explanation(data: dict[str, Any]) -> str | None:
    """Extract explanation from Ollama response or thinking output."""
    raw = data.get("response")

    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            explanation = parsed.get("explanation")
            if isinstance(explanation, str) and explanation.strip():
                return explanation.strip()
        except json.JSONDecodeError:
            return raw.strip()

    # Qwen may place structured output in the thinking field.
    thinking = data.get("thinking")

    if isinstance(thinking, str) and thinking.strip():
        try:
            parsed = json.loads(thinking)
            explanation = parsed.get("explanation")
            if isinstance(explanation, str) and explanation.strip():
                return explanation.strip()
        except json.JSONDecodeError:
            return None

    return None


def generate_explanation(
    detection: dict[str, Any],
    evidence: dict[str, Any],
    timeout: int = 60,
) -> str | None:
    """Generate a local explanation with Ollama.

    Returns None when Ollama is unavailable or no usable explanation exists.
    """
    prompt = build_prompt(detection, evidence)

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "format": "json",
            },
            timeout=timeout,
        )
        response.raise_for_status()

        data = response.json()
        return _extract_explanation(data)

    except (requests.RequestException, ValueError, TypeError):
        return None