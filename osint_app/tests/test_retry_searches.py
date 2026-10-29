"""Botón "Reintentar búsquedas fallidas": se repiten SOLO las consultas que los buscadores bloquearon.

Sin red: los buscadores se ponen "en pausa" con el mismo mecanismo que usa la aplicación tras un bloqueo real, así
ninguna consulta sale del equipo. La prueba con búsquedas reales (Glenda Morejón: 0 → 41 resultados en 20 s) está
en el registro del 2026-10-29.
"""
import time

import pytest

from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult
from osint_app.core.models import SearchResult
from osint_app.utils import search_engine as se

SEED = SeedData(name="Glenda Morejón", context="atleta marcha", country="Ecuador")


@pytest.fixture
def buscadores_en_pausa():
    saved = dict(se._cooldown_until)
    for name, _ in se._engines():
        se._cooldown_until[name] = time.time() + 300
    yield
    se._cooldown_until.clear()
    se._cooldown_until.update(saved)


def test_la_busqueda_bloqueada_apunta_sus_consultas(buscadores_en_pausa):
    engine = ProfilerEngine()
    engine.run_parallel(SEED, only_tools=["WebSearch", "Google Dorks"])
    pending = {name: queries for name, _, queries in engine.pending_retries()}
    assert set(pending) == {"WebSearch", "Google Dorks"} and set(engine.warnings) == set(pending)
    assert '"Glenda Morejón"' in pending["WebSearch"] and len(pending["WebSearch"]) == 5
    assert se.retry_wait_seconds() > 0          # el botón dice cuánto falta en vez de reintentar en vano


def test_reintentar_aun_bloqueado_lo_deja_pendiente(buscadores_en_pausa):
    engine = ProfilerEngine()
    engine.run_parallel(SEED, only_tools=["WebSearch"])
    before = engine.pending_retries()[0][2]
    new = engine.retry_failed_searches()
    assert [r.tool_name for r in new] == ["WebSearch:reintento"]
    assert engine.pending_retries()[0][2] == before          # mismas consultas, sin duplicar ni perderlas
    assert "WebSearch" in engine.warnings                     # el aviso de la ficha se mantiene
    assert engine.tools["WebSearch"].only_queries is None     # la herramienta vuelve a buscar todo la próxima vez


def test_solo_se_repiten_las_que_fallaron(buscadores_en_pausa):
    tool = ProfilerEngine().tools["WebSearch"]
    tool.only_queries = {'"Glenda Morejón" site:github.com'}
    tool.execute(SEED.to_query_params())
    assert tool.incomplete_runs[-1][1] == ['"Glenda Morejón" site:github.com']


def test_el_reintento_no_duplica_los_informes_del_caso(temp_db):
    engine = ProfilerEngine()
    hit = SearchResult(title="Glenda Morejón", url="https://es.wikipedia.org/wiki/Glenda_Morej%C3%B3n",
                       snippet="Atleta ecuatoriana", source_tool="WebSearch")
    engine.results = [ToolResult(tool_name="WebSearch", status="ok", results=[hit])]
    case_id = engine.save_to_case(SEED)
    retry = ToolResult(tool_name="WebSearch:reintento", status="ok", results=[hit])
    engine.results.append(retry)
    engine.save_to_case(SEED, case_id=case_id, results=[retry])
    assert [r.tool_name for r in temp_db.get_reports(case_id)] in (["WebSearch", "WebSearch:reintento"],
                                                                   ["WebSearch:reintento", "WebSearch"])
