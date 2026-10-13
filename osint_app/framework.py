"""
OSINT Framework v2 — Orchestrator with DataCompatibilityEngine.
Runs one tool at a time, extracts entities from results, and saves reports.
"""
import json, time, logging
from typing import Dict, List

from .core.models import SearchResult, TargetData, ToolReport
from .tools import build_tool_registry
from .db.feedback_db import db
from .utils.compatibility import DataCompatibilityEngine
from .utils.data_paths import data_dir
from .utils.entity_extractor import EntityExtractor
from .utils.resource_monitor import ResourceMonitor
from .utils.secret_vault import vault

logger = logging.getLogger(__name__)
CONFIG_PATH = data_dir() / "osint_config.json"


class OSINTFramework:
    """v2 orchestrator: one tool at a time with DataCompatibilityEngine."""

    def __init__(self):
        self.tools: Dict = build_tool_registry()
        self.compat = DataCompatibilityEngine()
        self.extractor = EntityExtractor()
        self.resource = ResourceMonitor()
        self._load_config()

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self):
        # 1. API Keys via unified vault
        for name, tool in self.tools.items():
            if tool.requires_api_key:
                val = vault.get(name)
                if val:
                    tool.api_key = val
                    
        # 2. Server URLs via local config (Not secrets)
        if CONFIG_PATH.exists():
            try:
                cfg = json.loads(CONFIG_PATH.read_text())
                for name, url in cfg.get("server_urls", {}).items():
                    if name in self.tools:
                        self.tools[name].BASE_URL = url
            except Exception as e:
                logger.error(f"Config load: {e}")

    def save_config(self, server_urls: Dict[str, str] = None):
        """Save non-secret application configuration."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        cfg = json.loads(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}

        if server_urls:
            cfg.setdefault("server_urls", {}).update(server_urls)
            for n, u in server_urls.items():
                if n in self.tools:
                    self.tools[n].BASE_URL = u
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

    # ── Compatibility check ───────────────────────────────────────────────────

    def check_tool(self, tool_name: str, case_id: int):
        """Return CompatibilityResult for a tool given the current case data."""
        tool = self.tools.get(tool_name)
        if not tool:
            raise ValueError(f"Tool '{tool_name}' not found")
        case_data = db.get_target_data(case_id)
        return self.compat.check_tool(tool, case_data)

    def check_all_tools(self, case_id: int) -> Dict:
        """Return CompatibilityResult for every tool."""
        case_data = db.get_target_data(case_id)
        return {
            name: self.compat.check_tool(tool, case_data)
            for name, tool in self.tools.items()
        }

    # ── Execution ─────────────────────────────────────────────────────────────

    MAX_TARGETS_PER_RUN = 25
    _PARAM_TO_FIELD = {"target_name": "name", "role": "note", "hash_value": "hash"}

    def _split_by_main_field(self, tool, case_data: List[TargetData]):
        """Una tanda por cada valor marcado del dato principal de la herramienta, con el resto de datos igual.

        Las herramientas reciben un solo valor por tipo (QueryParameters). Antes, con 3 IP marcadas, IP Reputation
        analizaba solo una e ignoraba el resto sin avisar (prueba real 2026-10-13: la IP de salida de Tor, marcada
        junto a 8.8.8.8, no se analizó). Devuelve ([(etiqueta, datos)], nº de valores); una sola tanda si no hay varios.
        """
        reqs = getattr(tool, "requirements", None)
        for param in (reqs.mandatory if reqs else []):
            field = self._PARAM_TO_FIELD.get(param, param)
            main = [d for d in case_data if d.field_type.lower() == field]
            if len(main) > 1:
                rest = [d for d in case_data if d.field_type.lower() != field]
                return [(d.value, rest + [d]) for d in main[:self.MAX_TARGETS_PER_RUN]], len(main)
        return [("", case_data)], 1

    def run_tool(
        self,
        tool_name: str,
        case_id: int,
        progress_cb=None,      # progress_cb(msg: str)
        target_data_ids: List[int] = None,
        extra_args: str = "",
    ) -> ToolReport:
        """
        Execute one tool for a case.
        Validates compatibility, runs, saves report, extracts entities.
        """
        tool = self.tools.get(tool_name)
        if not tool:
            raise ValueError(f"Tool '{tool_name}' not registered")

        case_data = db.get_target_data(case_id)
        if target_data_ids is not None:
            case_data = [d for d in case_data if d.id in target_data_ids]

        batches, total_targets = self._split_by_main_field(tool, case_data)
        checks = [(label, self.compat.check_tool(tool, data, extra_args=extra_args)) for label, data in batches]
        if not checks[0][1].can_run:
            raise RuntimeError(checks[0][1].user_message())

        if progress_cb:
            progress_cb(f"Iniciando {tool_name}…")
            if len(checks) > 1:
                progress_cb(f"🎯 {len(checks)} objetivos marcados: se analizan uno por uno.")
            if total_targets > len(batches):
                progress_cb(f"⚠️ Solo se analizan los primeros {self.MAX_TARGETS_PER_RUN} objetivos marcados.")

        if tool.is_heavy and self.resource.is_overloaded():
            if progress_cb:
                progress_cb("⚠️  Sistema bajo carga. Continuando de todos modos…")

        start = time.time()
        results: List[SearchResult] = []
        errors: List[str] = []
        try:
            tool._progress_cb = progress_cb   # ← allows tool to emit progress
            for i, (label, compat) in enumerate(checks, 1):
                if getattr(tool, "_is_cancelled", False):
                    break
                if len(checks) > 1 and progress_cb:
                    progress_cb(f"▶ Objetivo {i}/{len(checks)}: {label}")
                try:
                    results.extend(tool.execute(compat.auto_params))
                except Exception as e:
                    logger.error(f"Tool error [{tool_name}] {label}: {e}")
                    errors.append(f"{label + ': ' if label else ''}{type(e).__name__}: {e}"[:200])
                    if progress_cb and len(checks) > 1:
                        progress_cb(f"❌ {label}: {type(e).__name__}: {e}"[:200])
        finally:
            tool._progress_cb = None           # ← always clean up
        # Solo es "error" si no salió nada; un objetivo fallido entre varios queda anotado en el resumen
        status = "error" if errors and not results else "ok"
        error_text = "; ".join(errors)[:200]

        elapsed = time.time() - start

        # Build summary (si falló, el motivo queda en el reporte en vez de un "0 resultados" mudo)
        cats = {}
        for r in results:
            cats[r.category] = cats.get(r.category, 0) + 1
        if status == "error":
            summary = f"Error: {error_text}"
        else:
            summary = f"{len(results)} resultados. "
            if len(checks) > 1:
                summary = f"{len(checks)} objetivos · " + summary
            summary += "  ".join(f"{k}: {v}" for k, v in cats.items())
            if errors:
                summary += f"  · Fallaron {len(errors)}: {error_text}"

        # Persist report
        report = ToolReport(
            case_id=case_id, tool_name=tool_name,
            raw_json=json.dumps([r.to_dict() for r in results]),
            summary=summary, status=status,
            execution_time=round(elapsed, 2),
            results_count=len(results),
        )
        report.id = db.save_report(report)

        # Extract and persist entities
        if results:
            entities = self.extractor.extract_from_results(results)
            db.save_extracts(report.id, case_id, entities)  # type: ignore

        if progress_cb:
            if status == "error":
                progress_cb(f"❌ {tool_name} falló tras {elapsed:.1f}s — {error_text}")
            else:
                progress_cb(f"✅ {tool_name} finalizado — {len(results)} resultados en {elapsed:.1f}s")

        return report

    # ── Entity relay ──────────────────────────────────────────────────────────

    def get_extracted_entities(self, report_id: int) -> Dict:
        """Return entities extracted from a specific report."""
        return db.get_extracts(report_id)

    def add_entities_to_case(self, case_id: int, entities: Dict,
                              source: str, selected: List[str] = None):
        """Add extracted entities as TargetData to the case (sin repetir lo que el caso ya tiene)."""
        existing = {(d.field_type.lower(), d.value.strip().lower()) for d in db.get_target_data(case_id)}
        for field_type, values in entities.items():
            for val in values:
                if selected is not None and val not in selected:
                    continue
                key = (field_type.lower(), val.strip().lower())
                if key in existing:
                    continue
                existing.add(key)
                td = TargetData(
                    case_id=case_id, field_type=field_type,
                    value=val, source=source, confidence=70,
                )
                db.add_target_data(td)
