"""
Multi-LLM AI Engine — orchestrates 3 brains for OSINT correlation.

Brains:
  1. OllamaBrain  — local, private, offline (llama3.2 ~2GB RAM)
  2. VeniceBrain (1)  — Venice model A
  3. VeniceBrain (2)  — Venice model B

All brains receive the same OSINT context and return independent analyses.
Responses are merged into a consensus + tool suggestions.
"""
import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .core.models import AICorrelation, ToolReport
from .db.feedback_db import db
from .llm_brains import LLMBrain, OllamaBrain, OpenAIBrain, VeniceBrain

logger = logging.getLogger(__name__)


@dataclass
class MultiLLMResult:
    """Result from a triple-brain analysis pass."""
    responses: Dict[str, str] = field(default_factory=dict)     # brain_name → raw text
    consensus: str = ""                                          # merged final answer
    suggestions: List[str] = field(default_factory=list)        # next tools to run
    new_entities: Dict[str, List[str]] = field(default_factory=dict)  # AI-discovered entities
    errors: Dict[str, str] = field(default_factory=dict)        # brain_name → error msg
    prompt: str = ""


class MultiLLMEngine:
    """
    Triple-brain OSINT analysis engine.
    Runs brains in parallel threads, then merges with consensus.
    """

    def __init__(
        self,
        openai_key: str = "",
        venice_key: str = "",
        ollama_model: str = "llama3.2",
        venice_model_1: str = "gpt-5.2",
        venice_model_2: str = "claude-opus",
    ):
        v_key = venice_key or openai_key
        self.brains: Dict[str, LLMBrain] = {
            "Ollama":   OllamaBrain(model=ollama_model),
            "Venice 1": VeniceBrain(api_key=v_key, model=venice_model_1, name="Venice (Modelo A)"),
            "Venice 2": VeniceBrain(api_key=v_key, model=venice_model_2, name="Venice (Modelo B)"),
        }

    # ── Config ────────────────────────────────────────────────────────────────

    def _update_keys(self, venice_key: str = ""):
        if venice_key:
            self.brains["Venice 1"].api_key = venice_key
            self.brains["Venice 2"].api_key = venice_key

    def set_key(self, brain_name: str, key: str):
        if brain_name in self.brains:
            self.brains[brain_name].api_key = key

    def set_model(self, brain_name: str, model: str):
        if brain_name in self.brains:
            self.brains[brain_name].model = model

    def brain_status(self) -> Dict[str, str]:
        """Return status line for each brain."""
        return {name: brain.status_line() for name, brain in self.brains.items()}

    def enabled_brains(self) -> List[str]:
        return [name for name, b in self.brains.items() if b.enabled and b.is_available()]

    # ── Core analysis ─────────────────────────────────────────────────────────

    def analyze(
        self,
        case_id: int,
        report_ids: List[int],
        extra_question: str = "",
        progress_cb=None,          # progress_cb(brain_name, status)
    ) -> Tuple[MultiLLMResult, AICorrelation]:
        """
        Run triple-brain analysis on selected reports.
        Returns (MultiLLMResult, AICorrelation stored in DB).
        """
        reports = [r for r in db.get_reports(case_id) if r.id in report_ids]

        # Build entity corpus from existing extracts
        entity_corpus = self._collect_entities(case_id, report_ids)

        # Build prompt
        prompt = self._build_prompt(reports, entity_corpus, extra_question)

        result = self._query_all_brains(prompt, progress_cb)
        result.prompt = prompt

        # Merge responses into consensus
        active = {n: r for n, r in result.responses.items() if r}
        if active:
            result.consensus = self._merge_responses(active, entity_corpus)
            result.suggestions = self._extract_suggestions(active)
        else:
            result.consensus = (
                "⬜ Ningún cerebro disponible.\n"
                "• Para análisis local: ejecuta `ollama pull llama3.2`\n"
                "• Para ChatGPT/Venice: configura las API keys en Ajustes"
            )

        # Persist as AICorrelation
        corr_data = {
            "responses": result.responses,
            "consensus": result.consensus,
        }
        corr = AICorrelation(
            case_id=case_id,
            report_ids=report_ids,
            prompt=prompt,
            response=json.dumps(corr_data, ensure_ascii=False),
        )
        corr.id = db.save_correlation(corr)

        return result, corr

    def query_manually(self, question: str, case_id: int, report_ids: List[int],
                        progress_cb=None) -> MultiLLMResult:
        """Answer a free-form user question with context from the case."""
        reports = [r for r in db.get_reports(case_id) if r.id in report_ids]
        entity_corpus = self._collect_entities(case_id, report_ids)
        targets = db.get_target_data(case_id)
        context = self._build_context_summary(reports, entity_corpus, targets)
        prompt = (
            f"Contexto del caso OSINT:\n{context}\n\n"
            f"Pregunta del analista: {question}"
        )
        result = self._query_all_brains(prompt, progress_cb)
        result.prompt = prompt
        active = {n: r for n, r in result.responses.items() if r}
        result.consensus = self._merge_responses(active, entity_corpus) if active else "Sin respuesta."
        return result

    def run_debate(
        self,
        case_id: int,
        report_ids: List[int],
        progress_cb=None,
    ) -> Tuple[MultiLLMResult, AICorrelation]:
        """
        Two-phase OSINT Correlational Debate.
        Phase 1: Independent analysis by each brain.
        Phase 2: Brains critique each other's findings to build the ultimate prompt/recommendation.
        """
        reports = [r for r in db.get_reports(case_id) if r.id in report_ids]
        entity_corpus = self._collect_entities(case_id, report_ids)

        # FASE 1: Análisis Independiente (Contexto Crudo)
        base_prompt = self._build_prompt(reports, entity_corpus, extra_q="Analiza estos datos de forma exhaustiva para preparar un debate con otros agentes.")
        phase1_result = self._query_all_brains(base_prompt, lambda n, s: progress_cb(n, f"(F1) {s}") if progress_cb else None)

        valid_responses = {n: r for n, r in phase1_result.responses.items() if r}
        if len(valid_responses) < 2:
            # Fallback if only 1 (or 0) brains answer; we can't truly debate.
            phase1_result.consensus = (
                "⚠️ Debate cancelado: Se requieren al menos 2 cerebros activos para debatir.\n"
                f"Obtuvimos {len(valid_responses)} respuestas útiles en la Ronda 1.\n"
                "Usa el Análisis Normal en su lugar."
            )
            return phase1_result, None

        # FASE 2: El Gran Debate (Síntesis y Crítica Cruzada)
        debate_context = "--- RESULTADOS DE LA RONDA 1 ---\n"
        for bname, resp in valid_responses.items():
            debate_context += f"\n>> OPINIÓN DE {bname.upper()} <<\n{resp}\n{'-'*30}\n"

        debate_prompt = (
            f"Estás en un DEBATE CORRELACIONAL de OSINT con otras inteligencias artificiales.\n\n"
            f"{debate_context}\n"
            "INSTRUCCIÓN PARA RONDA 2:\n"
            "1. Analiza y critica constructivamente las respuestas de tus colegas.\n"
            "2. Combina los hallazgos para extraer la verdad más precisa.\n"
            "3. Concluye formulando de 1 a 3 PROMPTS EXACTOS (o cadenas de dorks) que el humano "
            "debería ejecutar inmediatamente para avanzar en la investigación con el menor ruido posible."
        )

        phase2_result = self._query_all_brains(debate_prompt, lambda n, s: progress_cb(n, f"(F2) {s}") if progress_cb else None)
        phase2_result.prompt = "DEBATE MULTI-IA"
        
        active_p2 = {n: r for n, r in phase2_result.responses.items() if r}
        
        # Merge Final Veredict
        parts = [
            "🔴 🟢 🔵 DEBATE CIBERNÉTICO COMPLETADO",
            "═════════════════════════════════════════",
            "  SÍNTESIS FINAL POST-CRÍTICA CRUZADA",
            "═════════════════════════════════════════",
        ]
        for brain_name, resp in active_p2.items():
            icon = {"Ollama": "🦙", "ChatGPT": "🧠", "Venice": "🔓"}.get(brain_name, "🤖")
            parts += [f"\n{icon} VEREDICTO DE {brain_name.upper()}", "─" * 40, resp.strip()]
            
        phase2_result.consensus = "\n".join(parts)
        
        # Persist as AICorrelation
        corr_data = {
            "responses": active_p2,
            "consensus": phase2_result.consensus,
            "debate_phase_1": valid_responses
        }
        corr = AICorrelation(
            case_id=case_id,
            report_ids=report_ids,
            prompt="--- MODO DEBATE ---",
            response=json.dumps(corr_data, ensure_ascii=False),
        )
        corr.id = db.save_correlation(corr)

        return phase2_result, corr

    # ── Brain parallel query ──────────────────────────────────────────────────

    def _query_all_brains(self, prompt: str, progress_cb=None) -> MultiLLMResult:
        result = MultiLLMResult()
        threads = []
        lock = threading.Lock()

        def _run_brain(name: str, brain: LLMBrain):
            if not brain.enabled or not brain.is_available():
                with lock:
                    result.errors[name] = brain.last_error
                return
            if progress_cb:
                progress_cb(name, "consultando…")
            resp = brain.query(prompt)
            with lock:
                if resp:
                    result.responses[name] = resp
                else:
                    result.errors[name] = brain.last_error
            if progress_cb:
                progress_cb(name, "✅ listo" if resp else f"⬜ {brain.last_error[:40]}")

        for name, brain in self.brains.items():
            t = threading.Thread(target=_run_brain, args=(name, brain), daemon=True)
            threads.append(t)
            t.start()
            import time
            time.sleep(2.0)  # Stagger connections to bypass burst rate limits
            
        for t in threads:
            t.join(timeout=130)

        return result

    # ── Prompt building ───────────────────────────────────────────────────────

    def _build_prompt(self, reports: List[ToolReport],
                       entity_corpus: Dict, extra_q: str = "") -> str:
        if reports:
            case_id = reports[0].case_id
            targets = db.get_target_data(case_id)
        else:
            targets = []
            
        ctx = self._build_context_summary(reports, entity_corpus, targets)
        q = (f"\nPregunta adicional del analista: {extra_q}" if extra_q else "")
        
        # Inject available tools so the AI knows what Sentinel can do
        from osint_app.tools import build_tool_registry
        reg = build_tool_registry()
        tool_list = ", ".join(f"'{name}'" for name in reg.keys())
        
        return (
            f"Datos del caso OSINT:\n{ctx}"
            f"\n\n--- HERRAMIENTAS DISPONIBLES EN EL FRAMEWORK ---\n"
            f"Tienes a tu disposición las siguientes herramientas instaladas:\n{tool_list}\n"
            "--------------------------------------------------\n"
            f"\nInstrucción CRÍTICA DE ALTA PRIORIDAD:\n"
            "Eres un motor analítico estricto. Tu tarea es correlacionar los reportes EXCLUSIVAMENTE con los 'Datos Objetivo Base' proporcionados arriba.\n"
            "REGLA DE ORO: Ignora y descarta CUALQUIER información, perfil o mención en los reportes que pertenezca a homónimos o personas/entidades que no coincidan de forma comprobable con los datos base.\n"
            "Si un dato es un falso positivo, explícalo brevemente y descártalo.\n"
            "Haz siempre referencia a los 'Report IDs' de las herramientas de los que extraes información válida.\n"
            "Basado en tus hallazgos lógicos, TERMINA TU ANÁLISIS RECOMENDANDO EXACTAMENTE QUÉ HERRAMIENTA DISPONIBLE SE DEBE EJECUTAR A CONTINUACIÓN. Menciona la herramienta por su nombre exacto y qué dato se le debe alimentar para seguir la huella."
            f"{q}"
        )

    def _build_context_summary(self, reports: List[ToolReport], corpus: Dict, targets: List = None) -> str:
        lines = []
        if reports:
            lines.append(f"ID de Caso: #{reports[0].case_id}")
            
        if targets:
            lines.append("\n=== DATOS OBJETIVO BASE (Verdad Absoluta) ===")
            for t in targets:
                lines.append(f"• {t.field_type}: {t.value}")
            lines.append("=============================================\n")
            
        for r in reports[:12]:  # limit context size
            lines.append(f"• [Report ID: #{r.id}] Herramienta: {r.tool_name} → {r.results_count} resultados ({r.status})")
            try:
                data = json.loads(r.raw_json)
                for item in data[:3]:   # first 3 results for context
                    lines.append(f"  - {item.get('title','?')} [{item.get('category','?')}]")
            except Exception:
                pass
        if corpus:
            lines.append("\nEntidades secundarias detectadas:")
            for ft, counter in list(corpus.items())[:8]:
                top = counter.most_common(4)
                lines.append(f"  [{ft}] " + "  •  ".join(f"{v}(×{c})" for v, c in top))
        return "\n".join(lines)

    def _collect_entities(self, case_id: int, report_ids: List[int]) -> Dict:
        from collections import Counter
        corpus: Dict[str, Counter] = {}
        for rid in report_ids:
            extracts = db.get_extracts(rid)
            for ft, vals in extracts.items():
                corpus.setdefault(ft, Counter()).update(vals)
        return corpus

    # ── Consensus merge ───────────────────────────────────────────────────────

    def _merge_responses(self, responses: Dict[str, str], corpus: Dict) -> str:
        parts = [
            "═════════════════════════════════════════",
            f"  ANÁLISIS TRIPLE-BRAIN  ({len(responses)} de 3 activos)",
            "═════════════════════════════════════════",
        ]
        for brain_name, resp in responses.items():
            icon = {"Ollama": "🦙", "ChatGPT": "🧠", "Venice": "🔓"}.get(brain_name, "🤖")
            parts += [f"\n{icon} {brain_name.upper()}", "─" * 40, resp.strip()]

        if len(responses) > 1:
            parts += [
                "\n═════════════════════════════════════════",
                "  PUNTOS EN COMÚN (consenso)",
                "═════════════════════════════════════════",
            ]
            # Find common keywords across all responses
            words_per_brain = [
                set(r.lower().split()) for r in responses.values()
            ]
            common = words_per_brain[0]
            for ws in words_per_brain[1:]:
                common &= ws
            meaningful = [
                w for w in common
                if len(w) > 5 and w not in {
                    "sobre", "desde", "tiene", "puede", "todos",
                    "datos", "herramienta", "análisis", "resultado",
                }
            ]
            if meaningful:
                parts.append("  Términos coincidentes: " + ", ".join(meaningful[:12]))
            else:
                parts.append("  Analiza cada respuesta por separado para comparar perspectivas.")

        return "\n".join(parts)

    def _extract_suggestions(self, responses: Dict[str, str]) -> List[str]:
        """Pull tool names mentioned by the brains as next steps."""
        known_tools = [
            "Sherlock", "Holehe", "TheHarvester", "Hunter", "GHunt",
            "Subfinder", "AMASS", "CENSYS", "dnspython", "Maigret",
            "Wayback", "snscrape", "SpiderFoot", "Recon-ng", "sn0int",
            "IntelOwl", "MISP", "ipwhois", "phonenumbers",
        ]
        mentioned: Counter = Counter()
        all_text = " ".join(responses.values()).lower()
        for tool in known_tools:
            if tool.lower() in all_text:
                mentioned[tool] += all_text.count(tool.lower())
        suggestions = []
        for tool, _ in mentioned.most_common(5):
            suggestions.append(f"💡 Mencionado por los cerebros: {tool}")
        return suggestions
