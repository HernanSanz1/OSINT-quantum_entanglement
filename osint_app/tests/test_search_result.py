"""SearchResult: los datos estructurados (raw_data) deben sobrevivir al guardado en reportes."""
import json
from datetime import datetime

from osint_app.core.models import SearchResult


def _sr(**kw):
    return SearchResult(title="t", url="u", snippet="s", source_tool="x", **kw)


def test_to_dict_keeps_raw_data():
    d = _sr(raw_data={"gps": {"lat": 1.5, "lon": -2.5}, "level": "alto"}).to_dict()
    assert d["raw_data"] == {"gps": {"lat": 1.5, "lon": -2.5}, "level": "alto"}


def test_to_dict_is_json_safe_for_odd_values():
    d = _sr(raw_data={"when": datetime(2024, 1, 2, 3, 4, 5), "tags": {"a"}, "n": 3}).to_dict()
    json.dumps(d)                                   # no debe fallar
    assert d["raw_data"]["when"] == "2024-01-02 03:04:05" and d["raw_data"]["n"] == 3


def test_to_dict_unserializable_becomes_empty():
    loop = {}
    loop["self"] = loop                             # referencia circular: json no puede
    assert _sr(raw_data=loop).to_dict()["raw_data"] == {}


def test_raw_data_survives_profiler_save_and_cti_reads_it(temp_db):
    from osint_app.cti_link import collect_tech_terms_from_reports
    from osint_app.profiler_engine import ProfilerEngine, SeedData, ToolResult

    eng = ProfilerEngine()
    eng.results = [ToolResult(tool_name="Tech Detect", status="ok", results=[
        SearchResult(title="Servidor web", url="", snippet="", source_tool="Tech Detect", category="Technology",
                  raw_data={"technology": "nginx", "domain": "empresa.com"}),
        SearchResult(title="Metadatos: foto.jpg", url="", snippet="Imagen", source_tool="File Metadata",
                     raw_data={"gps": {"lat": 39.1, "lon": -79.4}}),
    ])]
    case_id = eng.save_to_case(SeedData(name="Prueba", domain="empresa.com"))
    reports = temp_db.get_reports(case_id)
    items = json.loads(reports[0].raw_json)
    assert items[0]["raw_data"]["technology"] == "nginx"
    assert items[1]["raw_data"]["gps"] == {"lat": 39.1, "lon": -79.4}
    assert "nginx" in collect_tech_terms_from_reports(reports)
