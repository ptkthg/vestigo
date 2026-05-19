from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    contexto: dict[str, Any]
    perfil: Literal["n1", "n2n3"] = "n1"
    org_context: dict[str, Any] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    perfil: str
    severidade: str
    resultado: dict[str, Any]
    mitre_id: Optional[str] = None
    mitre_tecnica: Optional[str] = None
    iocs: dict[str, list] = Field(default_factory=dict)


class CorrelateRequest(BaseModel):
    eventos: list[dict[str, Any]] = Field(..., min_length=2, max_length=10)
    org_context: dict[str, Any] = Field(default_factory=dict)


class CorrelateResponse(BaseModel):
    total_eventos: int
    resultado: dict[str, Any]
    severidade_geral: str
    e_ataque_coordenado: bool
