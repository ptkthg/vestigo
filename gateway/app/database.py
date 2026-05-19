import json
import logging
import os

import asyncpg

logger = logging.getLogger("gateway.db")

_pool: asyncpg.Pool | None = None

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vestigo:vestigo@postgres:5432/vestigo",
)

_CREATE_ORG_CONFIG = """
CREATE TABLE IF NOT EXISTS org_config (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    config     JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT single_row CHECK (id = 1)
);
INSERT INTO org_config (id, config) VALUES (1, '{}') ON CONFLICT DO NOTHING;
"""

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS analyses (
    id              SERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    perfil          VARCHAR(10) NOT NULL,
    severidade      VARCHAR(20),
    mitre_id        VARCHAR(30),
    mitre_tecnica   TEXT,
    evento          TEXT,
    log_size        INTEGER,
    iocs_count      INTEGER DEFAULT 0,
    result_json     JSONB NOT NULL,
    diagnosis       VARCHAR(30),
    diagnosis_note  TEXT,
    diagnosed_at    TIMESTAMPTZ
);
"""

_MIGRATE = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='analyses' AND column_name='diagnosis') THEN
        ALTER TABLE analyses
            ADD COLUMN diagnosis      VARCHAR(30),
            ADD COLUMN diagnosis_note TEXT,
            ADD COLUMN diagnosed_at   TIMESTAMPTZ;
    END IF;
END$$;
"""


async def init_db() -> None:
    global _pool
    try:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
        async with _pool.acquire() as conn:
            await conn.execute(_CREATE_ORG_CONFIG)
            await conn.execute(_CREATE_TABLE)
            await conn.execute(_MIGRATE)
        logger.info("Database connected and schema ready")
    except Exception as e:
        logger.warning("Database unavailable, history disabled: %s", e)
        _pool = None


async def close_db() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def save_analysis(
    perfil: str,
    severidade: str | None,
    mitre_id: str | None,
    mitre_tecnica: str | None,
    evento: str | None,
    log_size: int,
    iocs_count: int,
    result: dict,
) -> int | None:
    if _pool is None:
        return None
    try:
        async with _pool.acquire() as conn:
            row_id = await conn.fetchval(
                """
                INSERT INTO analyses
                    (perfil, severidade, mitre_id, mitre_tecnica, evento, log_size, iocs_count, result_json)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
                """,
                perfil,
                severidade,
                mitre_id,
                mitre_tecnica,
                evento,
                log_size,
                iocs_count,
                json.dumps(result),
            )
            return row_id
    except Exception as e:
        logger.warning("Failed to save analysis: %s", e)
        return None


async def save_diagnosis(analysis_id: int, verdict: str, note: str) -> bool:
    if _pool is None:
        return False
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE analyses
                SET diagnosis = $1, diagnosis_note = $2, diagnosed_at = NOW()
                WHERE id = $3
                """,
                verdict,
                note or None,
                analysis_id,
            )
        return True
    except Exception as e:
        logger.warning("Failed to save diagnosis: %s", e)
        return False


async def get_similar_analyses(mitre_id: str | None, evento: str | None, limit: int = 5) -> list[dict]:
    """Busca análises anteriores similares com diagnóstico do analista."""
    if _pool is None:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = []

            # Prioridade 1: mesmo MITRE ID com diagnóstico
            if mitre_id:
                rows = await conn.fetch(
                    """
                    SELECT id, created_at, severidade, mitre_id, mitre_tecnica,
                           evento, diagnosis, diagnosis_note, diagnosed_at, perfil
                    FROM analyses
                    WHERE mitre_id = $1 AND diagnosis IS NOT NULL
                    ORDER BY created_at DESC
                    LIMIT $2
                    """,
                    mitre_id,
                    limit,
                )

            # Prioridade 2: mesmo MITRE sem diagnóstico (contexto de frequência)
            if mitre_id and len(rows) < limit:
                extra = await conn.fetch(
                    """
                    SELECT id, created_at, severidade, mitre_id, mitre_tecnica,
                           evento, diagnosis, diagnosis_note, diagnosed_at, perfil
                    FROM analyses
                    WHERE mitre_id = $1 AND diagnosis IS NULL
                    ORDER BY created_at DESC
                    LIMIT $2
                    """,
                    mitre_id,
                    limit - len(rows),
                )
                rows = list(rows) + list(extra)

            result = []
            for r in rows:
                d = dict(r)
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                if d.get("diagnosed_at"):
                    d["diagnosed_at"] = d["diagnosed_at"].isoformat()
                result.append(d)
            return result
    except Exception as e:
        logger.warning("Failed to fetch similar analyses: %s", e)
        return []


async def get_diagnosis_summary(mitre_id: str | None) -> dict:
    """Retorna contagem de diagnósticos para um MITRE ID."""
    if _pool is None or not mitre_id:
        return {}
    try:
        async with _pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM analyses WHERE mitre_id = $1", mitre_id
            )
            rows = await conn.fetch(
                """
                SELECT diagnosis, COUNT(*) as count
                FROM analyses
                WHERE mitre_id = $1 AND diagnosis IS NOT NULL
                GROUP BY diagnosis
                """,
                mitre_id,
            )
            return {
                "total_ocorrencias": total,
                "diagnosticos": {r["diagnosis"]: r["count"] for r in rows},
            }
    except Exception as e:
        logger.warning("Failed to fetch diagnosis summary: %s", e)
        return {}


async def search_history(
    q: str = "",
    severity: str = "",
    mitre: str = "",
    diagnosis: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    if _pool is None:
        return []
    try:
        conditions = []
        params: list = []
        i = 1

        if q:
            conditions.append(
                f"""(
                    mitre_id ILIKE ${i} OR evento ILIKE ${i}
                    OR result_json::text ILIKE ${i}
                )"""
            )
            params.append(f"%{q}%")
            i += 1
        if severity:
            conditions.append(f"severidade = ${i}")
            params.append(severity)
            i += 1
        if mitre:
            conditions.append(f"mitre_id ILIKE ${i}")
            params.append(f"%{mitre}%")
            i += 1
        if diagnosis == "none":
            conditions.append("diagnosis IS NULL")
        elif diagnosis:
            conditions.append(f"diagnosis = ${i}")
            params.append(diagnosis)
            i += 1

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params += [limit, offset]

        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT id, created_at, perfil, severidade, mitre_id, mitre_tecnica,
                       evento, log_size, iocs_count, diagnosis, diagnosis_note, diagnosed_at
                FROM analyses
                {where}
                ORDER BY created_at DESC
                LIMIT ${i} OFFSET ${i+1}
                """,
                *params,
            )
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM analyses {where}",
                *params[:-2],
            )
            result = []
            for r in rows:
                d = dict(r)
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                if d.get("diagnosed_at"):
                    d["diagnosed_at"] = d["diagnosed_at"].isoformat()
                result.append(d)
            return result, total
    except Exception as e:
        logger.warning("Failed to search history: %s", e)
        return [], 0


async def get_history(limit: int = 50, offset: int = 0) -> list[dict]:
    if _pool is None:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, created_at, perfil, severidade, mitre_id, mitre_tecnica,
                       evento, log_size, iocs_count, diagnosis, diagnosis_note, diagnosed_at
                FROM analyses
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                """,
                limit,
                offset,
            )
            result = []
            for r in rows:
                d = dict(r)
                if d.get("created_at"):
                    d["created_at"] = d["created_at"].isoformat()
                if d.get("diagnosed_at"):
                    d["diagnosed_at"] = d["diagnosed_at"].isoformat()
                result.append(d)
            return result
    except Exception as e:
        logger.warning("Failed to fetch history: %s", e)
        return []


async def get_org_config() -> dict:
    if _pool is None:
        return {}
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow("SELECT config FROM org_config WHERE id = 1")
            return dict(row["config"]) if row else {}
    except Exception as e:
        logger.warning("Failed to get org config: %s", e)
        return {}


async def save_org_config(config: dict) -> bool:
    if _pool is None:
        return False
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO org_config (id, config, updated_at)
                VALUES (1, $1, NOW())
                ON CONFLICT (id) DO UPDATE SET config = $1, updated_at = NOW()
                """,
                json.dumps(config),
            )
        return True
    except Exception as e:
        logger.warning("Failed to save org config: %s", e)
        return False


async def get_stats() -> dict:
    if _pool is None:
        return {}
    try:
        async with _pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM analyses")
            by_severity = await conn.fetch(
                "SELECT severidade, COUNT(*) as count FROM analyses GROUP BY severidade ORDER BY count DESC"
            )
            by_perfil = await conn.fetch(
                "SELECT perfil, COUNT(*) as count FROM analyses GROUP BY perfil"
            )
            by_day = await conn.fetch(
                """
                SELECT DATE(created_at) as day, COUNT(*) as count
                FROM analyses
                WHERE created_at >= NOW() - INTERVAL '30 days'
                GROUP BY day ORDER BY day
                """
            )
            top_mitre = await conn.fetch(
                """
                SELECT mitre_id, mitre_tecnica, COUNT(*) as count
                FROM analyses
                WHERE mitre_id IS NOT NULL
                GROUP BY mitre_id, mitre_tecnica
                ORDER BY count DESC
                LIMIT 5
                """
            )
            diagnosis_counts = await conn.fetch(
                """
                SELECT diagnosis, COUNT(*) as count
                FROM analyses
                WHERE diagnosis IS NOT NULL
                GROUP BY diagnosis
                """
            )
        return {
            "total": total,
            "by_severity": [dict(r) for r in by_severity],
            "by_perfil": [dict(r) for r in by_perfil],
            "by_day": [{"day": str(r["day"]), "count": r["count"]} for r in by_day],
            "top_mitre": [dict(r) for r in top_mitre],
            "diagnosis_counts": {r["diagnosis"]: r["count"] for r in diagnosis_counts},
        }
    except Exception as e:
        logger.warning("Failed to fetch stats: %s", e)
        return {}
