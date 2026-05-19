import json
import logging
import os
import re

from openai import AsyncOpenAI

logger = logging.getLogger("ai-service.llm")

_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
_GROQ_KEY = os.getenv("GROQ_API_KEY", "")
_OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

_PROVIDER_CONFIG = {
    "groq": {
        "api_key": _GROQ_KEY,
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "max_tokens": 2048,
        "needs_key": True,
        "key_env": "GROQ_API_KEY",
    },
    "openai": {
        "api_key": _OPENAI_KEY,
        "base_url": None,
        "model": "gpt-4o",
        "max_tokens": 2048,
        "needs_key": True,
        "key_env": "OPENAI_API_KEY",
    },
    "ollama": {
        "api_key": "ollama",
        "base_url": f"{_OLLAMA_HOST}/v1",
        "model": _OLLAMA_MODEL,
        "max_tokens": 2048,
        "needs_key": False,
        "key_env": None,
    },
}


def _get_client() -> tuple[AsyncOpenAI, str, int, dict]:
    cfg = _PROVIDER_CONFIG.get(_PROVIDER, _PROVIDER_CONFIG["groq"])
    client = AsyncOpenAI(
        api_key=cfg["api_key"] or "placeholder",
        base_url=cfg["base_url"],
    )
    return client, cfg["model"], cfg["max_tokens"], cfg


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
    client, model, max_tokens, cfg = _get_client()

    if cfg["needs_key"] and not cfg["api_key"]:
        logger.warning("API key não configurada para provider '%s'", _PROVIDER)
        return {
            "erro": f"API key do provider '{_PROVIDER}' não configurada",
            "configurar": f"Defina {cfg['key_env']} no .env",
        }

    logger.info("Calling LLM: provider=%s model=%s", _PROVIDER, model)

    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.1,
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
        if _PROVIDER == "ollama" and "connection" in str(e).lower():
            return {
                "erro": "Ollama não está acessível",
                "detalhe": f"Verifique se o serviço Ollama está rodando em {_OLLAMA_HOST}",
                "dica": "Execute: docker-compose --profile ollama up",
            }
        return {"erro": f"Falha na chamada ao LLM: {type(e).__name__}"}
