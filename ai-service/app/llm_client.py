import json
import logging
import os
import re

from openai import AsyncOpenAI

logger = logging.getLogger("ai-service.llm")

_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
_GROQ_KEY = os.getenv("GROQ_API_KEY", "")
_OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")

_PROVIDER_CONFIG = {
    "groq": {
        "api_key": _GROQ_KEY,
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "max_tokens": 2048,
    },
    "openai": {
        "api_key": _OPENAI_KEY,
        "base_url": None,
        "model": "gpt-4o",
        "max_tokens": 2048,
    },
}


def _get_client() -> tuple[AsyncOpenAI, str, int]:
    cfg = _PROVIDER_CONFIG.get(_PROVIDER, _PROVIDER_CONFIG["groq"])
    client = AsyncOpenAI(
        api_key=cfg["api_key"] or "placeholder",
        base_url=cfg["base_url"],
    )
    return client, cfg["model"], cfg["max_tokens"]


def _extract_json(text: str) -> dict:
    """Extrai JSON da resposta do LLM, tolerando markdown code blocks."""
    # Remove markdown code fences se presentes
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    text = text.rstrip("`").strip()

    # Tenta parse direto
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Tenta encontrar o primeiro objeto JSON
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return {"erro": "Resposta não parseável", "raw": text[:500]}


async def call_llm(system_prompt: str, user_prompt: str) -> dict:
    client, model, max_tokens = _get_client()

    if not (_GROQ_KEY if _PROVIDER == "groq" else _OPENAI_KEY):
        logger.warning("API key não configurada para provider '%s'", _PROVIDER)
        return {
            "erro": f"API key do provider '{_PROVIDER}' não configurada",
            "configurar": f"Defina {'GROQ_API_KEY' if _PROVIDER == 'groq' else 'OPENAI_API_KEY'} no .env",
        }

    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.1,  # baixa temperatura para respostas consistentes
        )
        raw_text = response.choices[0].message.content or ""
        logger.info(
            "LLM response: provider=%s tokens_used=%s",
            _PROVIDER,
            response.usage.total_tokens if response.usage else "?",
        )
        return _extract_json(raw_text)

    except Exception as e:
        logger.error("LLM call failed: %s — %s", type(e).__name__, str(e)[:200])
        return {"erro": f"Falha na chamada ao LLM: {type(e).__name__}"}
