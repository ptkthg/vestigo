import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator, Literal

import httpx
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .database import (
    init_db, close_db, save_analysis, save_diagnosis,
    get_similar_analyses, search_history, get_history, get_stats,
    get_org_config, save_org_config,
)
from .webhook import fire_webhook

logger = logging.getLogger("gateway")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

PARSER_URL = os.getenv("PARSER_URL", "http://parser-service:8001")
ENRICHER_URL = os.getenv("ENRICHER_URL", "http://enricher-service:8002")
AI_URL = os.getenv("AI_URL", "http://ai-service:8003")
INTERNAL_SECRET = os.getenv("INTERNAL_API_SECRET", "")
RATE_LIMIT = os.getenv("RATE_LIMIT_PER_MINUTE", "10")

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(title="Vestigo Gateway", version="1.0.0", docs_url=None, redoc_url=None, lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class AnalyzeRequest(BaseModel):
    log_raw: str = Field(..., min_length=1, max_length=100_000)
    perfil: Literal["n1", "n2n3"] = "n1"

    @field_validator("log_raw")
    @classmethod
    def sanitize_log(cls, v: str) -> str:
        # Remove null bytes e caracteres de controle problemáticos
        v = v.replace("\x00", "").replace("\r\n", "\n")
        # Proibe tentativas de command injection via log
        if re.search(r"[`$][\({]", v):
            raise ValueError("Conteúdo inválido detectado")
        return v


def _internal_headers() -> dict:
    return {"X-Internal-Secret": INTERNAL_SECRET, "Content-Type": "application/json"}


async def _call_service(client: httpx.AsyncClient, url: str, payload: dict, timeout: float = 30.0) -> dict:
    try:
        resp = await client.post(url, json=payload, headers=_internal_headers(), timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        logger.error("Service %s returned %s", url, e.response.status_code)
        raise HTTPException(status_code=502, detail=f"Serviço interno retornou erro {e.response.status_code}")
    except httpx.TimeoutException:
        logger.error("Service %s timed out", url)
        raise HTTPException(status_code=504, detail="Timeout ao chamar serviço interno")
    except httpx.ConnectError:
        logger.error("Cannot connect to %s", url)
        raise HTTPException(status_code=503, detail="Serviço interno indisponível")


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway"}


@app.post("/api/analyze")
@limiter.limit(f"{RATE_LIMIT}/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    # Não loga o conteúdo do log, apenas metadados
    logger.info(
        "Analyze request: perfil=%s log_size=%d ip=%s",
        body.perfil,
        len(body.log_raw),
        get_remote_address(request),
    )

    async with httpx.AsyncClient() as client:
        # Módulo 1: Parser
        parsed = await _call_service(
            client,
            f"{PARSER_URL}/parse",
            {"log_raw": body.log_raw},
        )

        # Módulo 2: Enricher
        enriched = await _call_service(
            client,
            f"{ENRICHER_URL}/enrich",
            parsed,
            timeout=45.0,
        )

        # Módulo 3: AI
        analysis = await _call_service(
            client,
            f"{AI_URL}/analyze",
            {"contexto": enriched, "perfil": body.perfil},
            timeout=60.0,
        )

    severidade = analysis.get("severidade")
    mitre_id = analysis.get("mitre_id")
    mitre_tecnica = analysis.get("mitre_tecnica")
    iocs = analysis.get("iocs", {})
    iocs_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
    evento = enriched.get("evento", "")[:200]

    await save_analysis(
        perfil=body.perfil,
        severidade=severidade,
        mitre_id=mitre_id,
        mitre_tecnica=mitre_tecnica,
        evento=evento,
        log_size=len(body.log_raw),
        iocs_count=iocs_count,
        result=analysis,
    )

    logger.info(
        "Analysis complete: perfil=%s severity=%s",
        body.perfil,
        analysis.get("severidade", "?"),
    )
    return analysis


def _sse(event: str, data: dict) -> str:
    return f"data: {json.dumps({'event': event, **data})}\n\n"


async def _stream_analysis(body: "AnalyzeRequest") -> AsyncIterator[str]:
    async with httpx.AsyncClient() as client:
        try:
            yield _sse("progress", {"stage": "parser"})
            parsed = await _call_service(client, f"{PARSER_URL}/parse", {"log_raw": body.log_raw})

            yield _sse("progress", {"stage": "enricher"})
            enriched = await _call_service(client, f"{ENRICHER_URL}/enrich", parsed, timeout=45.0)

            # Envia contexto histórico antes da IA responder
            enr = enriched.get("enriquecimento", {})
            mitre_id_pre = enr.get("mitre_id")
            similar = await get_similar_analyses(mitre_id_pre, enriched.get("evento"))
            if similar:
                yield _sse("context", {"similar": similar})

            yield _sse("progress", {"stage": "ai"})
            org_context = await get_org_config()
            analysis = await _call_service(
                client, f"{AI_URL}/analyze",
                {"contexto": enriched, "perfil": body.perfil, "org_context": org_context},
                timeout=60.0,
            )
        except HTTPException as e:
            yield _sse("error", {"detail": e.detail})
            return

    severidade = analysis.get("severidade")
    mitre_id = analysis.get("mitre_id")
    mitre_tecnica = analysis.get("mitre_tecnica")
    iocs = analysis.get("iocs", {})
    iocs_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
    evento = enriched.get("evento", "")[:200]

    analysis_id = await save_analysis(
        perfil=body.perfil,
        severidade=severidade,
        mitre_id=mitre_id,
        mitre_tecnica=mitre_tecnica,
        evento=evento,
        log_size=len(body.log_raw),
        iocs_count=iocs_count,
        result=analysis,
    )

    await fire_webhook(analysis, analysis_id)
    yield _sse("result", {"data": analysis, "analysis_id": analysis_id})
    yield "data: [DONE]\n\n"


@app.post("/api/analyze/stream")
@limiter.limit(f"{RATE_LIMIT}/minute")
async def analyze_stream(request: Request, body: AnalyzeRequest):
    logger.info(
        "Stream analyze: perfil=%s log_size=%d ip=%s",
        body.perfil, len(body.log_raw), get_remote_address(request),
    )
    return StreamingResponse(
        _stream_analysis(body),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/history")
async def history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str = Query(""),
    severity: str = Query(""),
    mitre: str = Query(""),
    diagnosis: str = Query(""),
):
    items, total = await search_history(
        q=q, severity=severity, mitre=mitre, diagnosis=diagnosis,
        limit=limit, offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


class BatchRequest(BaseModel):
    logs: list[str] = Field(..., min_length=1, max_length=20)
    perfil: Literal["n1", "n2n3"] = "n1"


@app.post("/api/analyze/batch")
@limiter.limit(f"{RATE_LIMIT}/minute")
async def analyze_batch(request: Request, body: BatchRequest):
    import asyncio

    async def _analyze_one(log_raw: str) -> dict:
        try:
            async with httpx.AsyncClient() as client:
                parsed = await _call_service(client, f"{PARSER_URL}/parse", {"log_raw": log_raw})
                enriched = await _call_service(client, f"{ENRICHER_URL}/enrich", parsed, timeout=45.0)
                analysis = await _call_service(
                    client, f"{AI_URL}/analyze",
                    {"contexto": enriched, "perfil": body.perfil}, timeout=60.0,
                )
            iocs = analysis.get("iocs", {})
            iocs_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
            await save_analysis(
                perfil=body.perfil,
                severidade=analysis.get("severidade"),
                mitre_id=analysis.get("mitre_id"),
                mitre_tecnica=analysis.get("mitre_tecnica"),
                evento=enriched.get("evento", "")[:200],
                log_size=len(log_raw),
                iocs_count=iocs_count,
                result=analysis,
            )
            return {"ok": True, "result": analysis}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    results = await asyncio.gather(*[_analyze_one(log) for log in body.logs])
    return {"total": len(results), "results": results}


class DiagnosisRequest(BaseModel):
    verdict: Literal["falso_positivo", "verdadeiro_positivo", "inconclusivo"]
    note: str = Field("", max_length=2000)


@app.patch("/api/analyses/{analysis_id}/diagnosis")
async def set_diagnosis(analysis_id: int, body: DiagnosisRequest):
    ok = await save_diagnosis(analysis_id, body.verdict, body.note)
    if not ok:
        raise HTTPException(status_code=404, detail="Análise não encontrada ou banco indisponível")
    return {"ok": True, "analysis_id": analysis_id, "verdict": body.verdict}


class CorrelateRequest(BaseModel):
    logs: list[str] = Field(..., min_length=2, max_length=10)
    perfil: Literal["n1", "n2n3"] = "n2n3"


@app.post("/api/analyze/correlate")
@limiter.limit(f"{RATE_LIMIT}/minute")
async def analyze_correlate(request: Request, body: CorrelateRequest):
    import asyncio

    logger.info("Correlate request: %d logs ip=%s", len(body.logs), get_remote_address(request))

    async def _parse_enrich(log_raw: str) -> dict:
        async with httpx.AsyncClient() as client:
            parsed = await _call_service(client, f"{PARSER_URL}/parse", {"log_raw": log_raw})
            enriched = await _call_service(client, f"{ENRICHER_URL}/enrich", parsed, timeout=45.0)
        return enriched

    enriched_events = await asyncio.gather(*[_parse_enrich(log) for log in body.logs])

    org_context = await get_org_config()

    async with httpx.AsyncClient() as client:
        correlation = await _call_service(
            client,
            f"{AI_URL}/correlate",
            {"eventos": list(enriched_events), "org_context": org_context},
            timeout=90.0,
        )

    return correlation


@app.get("/api/org-config")
async def get_config():
    return await get_org_config()


@app.put("/api/org-config")
async def update_config(config: dict):
    ok = await save_org_config(config)
    if not ok:
        raise HTTPException(status_code=503, detail="Banco indisponível")
    return {"ok": True}


@app.get("/api/stats")
async def stats():
    return await get_stats()


# Serve o frontend estático
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_path):
    app.mount("/", StaticFiles(directory=static_path, html=True), name="static")
