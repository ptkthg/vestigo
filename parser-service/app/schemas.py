from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


class ParseRequest(BaseModel):
    log_raw: str = Field(..., min_length=1, max_length=100_000)


class OrigemContext(BaseModel):
    tipo: str = "desconhecido"  # ip_interno | ip_externo | desconhecido
    reputacao: str = "desconhecida"  # limpa | suspeita | maliciosa | desconhecida
    pais: Optional[str] = None
    asn: Optional[str] = None


class DestinoContext(BaseModel):
    tipo: str = "desconhecido"
    servico: Optional[str] = None
    porta: Optional[int] = None


class UsuarioContext(BaseModel):
    tipo: str = "desconhecido"  # humano | conta_servico | sistema | desconhecido
    privilegio: str = "desconhecido"  # admin | usuario | anonimo | desconhecido


class IOCs(BaseModel):
    ips: list[str] = Field(default_factory=list)
    dominios: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


class Enriquecimento(BaseModel):
    mitre_tecnica: Optional[str] = None
    mitre_id: Optional[str] = None
    cve: Optional[str] = None
    severidade: str = "medium"  # low | medium | high | critical
    score_confianca: str = "low"  # high | medium | low
    justificativa_confianca: str = ""


class EventoContext(BaseModel):
    evento: str = ""
    fonte: str = ""
    formato: str = ""
    timestamp: str = ""
    quantidade_eventos: int = 1
    janela_tempo_segundos: Optional[int] = None
    origem: OrigemContext = Field(default_factory=OrigemContext)
    destino: DestinoContext = Field(default_factory=DestinoContext)
    usuario: UsuarioContext = Field(default_factory=UsuarioContext)
    acao: str = ""
    status: str = "desconhecido"  # sucesso | falha | bloqueado | desconhecido
    iocs: IOCs = Field(default_factory=IOCs)
    enriquecimento: Enriquecimento = Field(default_factory=Enriquecimento)
    contexto_externo: dict[str, Any] = Field(default_factory=dict)
