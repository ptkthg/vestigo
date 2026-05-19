import logging
import os

from fastapi import FastAPI, HTTPException, Header, Depends

from .schemas import AnalyzeRequest, AnalysisResponse, CorrelateRequest, CorrelateResponse
from .llm_client import call_llm
from .prompts import (
    SYSTEM_N1, build_prompt_n1,
    SYSTEM_N2N3, build_prompt_n2n3,
    SYSTEM_CORRELATE, build_prompt_correlate,
)

logger = logging.getLogger("ai-service")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Vestigo AI Service", version="1.0.0", docs_url=None, redoc_url=None)

INTERNAL_SECRET = os.getenv("INTERNAL_API_SECRET", "")


def _verify_internal(x_internal_secret: str = Header(default="")):
    if INTERNAL_SECRET and x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-service"}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(
    body: AnalyzeRequest,
    _: None = Depends(_verify_internal),
):
    ctx = body.contexto
    perfil = body.perfil

    org = body.org_context or {}
    if perfil == "n1":
        system = SYSTEM_N1
        user = build_prompt_n1(ctx, org)
    else:
        system = SYSTEM_N2N3
        user = build_prompt_n2n3(ctx, org)

    logger.info("Calling LLM for perfil=%s event=%s", perfil, ctx.get("evento", "?")[:50])

    resultado = await call_llm(system, user)

    enr = ctx.get("enriquecimento", {})
    return AnalysisResponse(
        perfil=perfil,
        severidade=resultado.get("severidade_confirmada") or enr.get("severidade", "medium"),
        resultado=resultado,
        mitre_id=enr.get("mitre_id"),
        mitre_tecnica=enr.get("mitre_tecnica"),
        iocs=ctx.get("iocs", {}),
    )


@app.post("/correlate", response_model=CorrelateResponse)
async def correlate(
    body: CorrelateRequest,
    _: None = Depends(_verify_internal),
):
    org = body.org_context or {}
    user = build_prompt_correlate(body.eventos, org)

    logger.info("Correlating %d events", len(body.eventos))

    resultado = await call_llm(SYSTEM_CORRELATE, user)

    return CorrelateResponse(
        total_eventos=len(body.eventos),
        resultado=resultado,
        severidade_geral=resultado.get("severidade_geral", "medium"),
        e_ataque_coordenado=bool(resultado.get("e_ataque_coordenado", False)),
    )
