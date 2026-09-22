"""
OSINT Profiler - Motor de perfilamiento automático de personas
Ejecuta todas las herramientas disponibles, correlaciona y guarda en el caso.
"""
import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .case_manager import CaseManager
from .db.feedback_db import db
from .core.models import Case, TargetData, ToolReport, QueryParameters, SearchResult
from .correlation_engine import CorrelationEngine
from .tools import build_tool_registry
from .tools.web_search import WebSearchTool, GitHubOSINTTool, UsernameVariantsTool

logger = logging.getLogger(__name__)


@dataclass
class ProfileSeed:
    """Datos semilla para iniciar el perfilamiento."""
    name: str
    context: str = ""  # Universidad, empresa, ciudad, etc.
    email: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    phone: Optional[str] = None


@dataclass
class ProfileResult:
    """Resultado consolidado del perfilamiento."""
    case_id: int
    name: str
    confirmed_data: Dict[str, List[str]] = field(default_factory=dict)
    possible_profiles: List[Dict[str, Any]] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    tools_executed: List[str] = field(default_factory=list)
    total_findings: int = 0


class OSINTProfiler:
    """Motor de perfilamiento automático."""

    def __init__(self):
        self.case_manager = CaseManager()
        self.tool_registry = build_tool_registry()

        # Add web tools
        self.web_search = WebSearchTool()
        self.github_osint = GitHubOSINTTool()
        self.username_variants = UsernameVariantsTool()

    def profile_person(self, seed: ProfileSeed) -> ProfileResult:
        """
        Ejecuta perfilamiento completo de una persona.

        1. Crea caso
        2. Agrega datos semilla
        3. Ejecuta herramientas de búsqueda web
        4. Genera variantes de username
        5. Busca en GitHub
        6. Ejecuta herramientas disponibles (Sherlock, Holehe, etc.)
        7. Correlaciona datos
        8. Guarda todo en el caso
        """
        # 1. Crear caso
        case = self.case_manager.create(
            f"Perfil: {seed.name}",
            f"Perfilamiento automático. Contexto: {seed.context}"
        )
        logger.info(f"Caso creado: ID {case.id}")

        result = ProfileResult(
            case_id=case.id,
            name=seed.name
        )

        # 2. Agregar datos semilla
        self._add_seed_data(case.id, seed)

        # 3. Búsqueda web general
        self._run_web_search(case.id, seed, result)

        # 4. Generar variantes de username
        self._run_username_variants(case.id, seed, result)

        # 5. Buscar en GitHub (si hay username)
        usernames = self._get_discovered_usernames(case.id)
        for username in usernames:
            self._run_github_osint(case.id, username, result)

        # 6. Ejecutar herramientas disponibles
        self._run_available_tools(case.id, seed, usernames, result)

        # 7. Correlacionar
        self._correlate_findings(case.id, result)

        # 8. Extraer imágenes de avatares
        self._extract_images(case.id, result)

        result.total_findings = self._count_findings(case.id)

        logger.info(f"Perfilamiento completado: {result.total_findings} hallazgos")
        return result

    def _add_seed_data(self, case_id: int, seed: ProfileSeed):
        """Agrega los datos semilla al caso."""
        if seed.name:
            db.add_target_data(TargetData(
                case_id=case_id,
                field_type="name",
                value=seed.name,
                source="manual",
                confidence=100
            ))
        if seed.context:
            db.add_target_data(TargetData(
                case_id=case_id,
                field_type="context",
                value=seed.context,
                source="manual",
                confidence=100
            ))
        if seed.email:
            db.add_target_data(TargetData(
                case_id=case_id,
                field_type="email",
                value=seed.email,
                source="manual",
                confidence=100
            ))
        if seed.username:
            db.add_target_data(TargetData(
                case_id=case_id,
                field_type="username",
                value=seed.username,
                source="manual",
                confidence=100
            ))
        if seed.domain:
            db.add_target_data(TargetData(
                case_id=case_id,
                field_type="domain",
                value=seed.domain,
                source="manual",
                confidence=100
            ))

    def _run_web_search(self, case_id: int, seed: ProfileSeed, result: ProfileResult):
        """Ejecuta búsqueda web y guarda resultados."""
        try:
            params = QueryParameters(
                target_name=seed.name,
                domain=seed.domain,
                observable=seed.context
            )

            start = time.time()
            search_results = self.web_search.execute(params)
            elapsed = time.time() - start

            # Guardar reporte
            report = ToolReport(
                case_id=case_id,
                tool_name="WebSearch",
                raw_json=json.dumps([r.__dict__ for r in search_results]),
                summary=f"Búsqueda web: {len(search_results)} resultados",
                status="ok",
                execution_time=elapsed,
                results_count=len(search_results)
            )
            report_id = db.save_report(report)

            # Extraer entidades
            entities = self._extract_entities_from_results(search_results)
            db.save_extracts(report_id, case_id, entities)

            # Agregar URLs como posibles perfiles
            for r in search_results:
                if r.category in ["LinkedIn", "GitHub", "Twitter/X", "Facebook", "Instagram"]:
                    result.possible_profiles.append({
                        'platform': r.category,
                        'url': r.url,
                        'title': r.title,
                        'confidence': r.relevance_score
                    })

            result.tools_executed.append("WebSearch")
            logger.info(f"WebSearch: {len(search_results)} resultados")

        except Exception as e:
            logger.error(f"WebSearch error: {e}")

    def _run_username_variants(self, case_id: int, seed: ProfileSeed, result: ProfileResult):
        """Genera variantes de username y busca."""
        try:
            params = QueryParameters(
                target_name=seed.name,
                observable=seed.context
            )

            start = time.time()
            variant_results = self.username_variants.execute(params)
            elapsed = time.time() - start

            # Guardar reporte
            report = ToolReport(
                case_id=case_id,
                tool_name="UsernameVariants",
                raw_json=json.dumps([r.__dict__ for r in variant_results]),
                summary=f"Variantes de username: {len(variant_results)} resultados",
                status="ok",
                execution_time=elapsed,
                results_count=len(variant_results)
            )
            report_id = db.save_report(report)

            # Extraer usernames encontrados
            for r in variant_results:
                if r.category == "GitHub Match":
                    # Agregar username confirmado
                    db.add_target_data(TargetData(
                        case_id=case_id,
                        field_type="username",
                        value=r.url.split('/')[-1],
                        source="UsernameVariants",
                        confidence=85
                    ))
                    result.possible_profiles.append({
                        'platform': 'GitHub',
                        'url': r.url,
                        'title': r.title,
                        'confidence': 85
                    })

                    # Extraer avatar si existe
                    if r.extra_data and r.extra_data.get('avatar_url'):
                        result.images.append(r.extra_data['avatar_url'])

            result.tools_executed.append("UsernameVariants")
            logger.info(f"UsernameVariants: {len(variant_results)} resultados")

        except Exception as e:
            logger.error(f"UsernameVariants error: {e}")

    def _run_github_osint(self, case_id: int, username: str, result: ProfileResult):
        """Ejecuta OSINT de GitHub para un username."""
        try:
            params = QueryParameters(username=username)

            start = time.time()
            github_results = self.github_osint.execute(params)
            elapsed = time.time() - start

            # Guardar reporte
            report = ToolReport(
                case_id=case_id,
                tool_name="GitHubOSINT",
                raw_json=json.dumps([r.__dict__ for r in github_results]),
                summary=f"GitHub OSINT @{username}: {len(github_results)} resultados",
                status="ok",
                execution_time=elapsed,
                results_count=len(github_results)
            )
            report_id = db.save_report(report)

            # Extraer datos del perfil
            for r in github_results:
                if r.category == "GitHub Profile" and r.extra_data:
                    extra = r.extra_data

                    # Guardar datos confirmados
                    if extra.get('name'):
                        db.add_target_data(TargetData(
                            case_id=case_id,
                            field_type="name",
                            value=extra['name'],
                            source="GitHub",
                            confidence=90
                        ))
                        result.confirmed_data.setdefault('name', []).append(extra['name'])

                    if extra.get('email'):
                        db.add_target_data(TargetData(
                            case_id=case_id,
                            field_type="email",
                            value=extra['email'],
                            source="GitHub",
                            confidence=95
                        ))
                        result.confirmed_data.setdefault('email', []).append(extra['email'])

                    if extra.get('company'):
                        db.add_target_data(TargetData(
                            case_id=case_id,
                            field_type="company",
                            value=extra['company'],
                            source="GitHub",
                            confidence=85
                        ))
                        result.confirmed_data.setdefault('company', []).append(extra['company'])

                    if extra.get('location'):
                        db.add_target_data(TargetData(
                            case_id=case_id,
                            field_type="location",
                            value=extra['location'],
                            source="GitHub",
                            confidence=80
                        ))
                        result.confirmed_data.setdefault('location', []).append(extra['location'])

                    if extra.get('twitter'):
                        db.add_target_data(TargetData(
                            case_id=case_id,
                            field_type="twitter",
                            value=f"@{extra['twitter']}",
                            source="GitHub",
                            confidence=90
                        ))
                        result.confirmed_data.setdefault('twitter', []).append(f"@{extra['twitter']}")

                    if extra.get('avatar_url'):
                        result.images.append(extra['avatar_url'])

            result.tools_executed.append(f"GitHubOSINT:{username}")
            logger.info(f"GitHubOSINT @{username}: {len(github_results)} resultados")

        except Exception as e:
            logger.error(f"GitHubOSINT error: {e}")

    def _run_available_tools(self, case_id: int, seed: ProfileSeed,
                             usernames: List[str], result: ProfileResult):
        """Ejecuta las herramientas OSINT que estén disponibles."""

        # Sherlock - para cada username
        if 'Sherlock' in self.tool_registry:
            sherlock = self.tool_registry['Sherlock']
            if sherlock.is_available:
                for username in usernames[:3]:  # Limitar
                    try:
                        params = QueryParameters(username=username)
                        start = time.time()
                        results = sherlock.execute(params)
                        elapsed = time.time() - start

                        report = ToolReport(
                            case_id=case_id,
                            tool_name=f"Sherlock:{username}",
                            raw_json=json.dumps([r.__dict__ for r in results]),
                            summary=f"Sherlock @{username}: {len(results)} perfiles",
                            status="ok",
                            execution_time=elapsed,
                            results_count=len(results)
                        )
                        db.save_report(report)

                        for r in results:
                            result.possible_profiles.append({
                                'platform': r.category,
                                'url': r.url,
                                'title': r.title,
                                'confidence': r.relevance_score
                            })

                        result.tools_executed.append(f"Sherlock:{username}")
                    except Exception as e:
                        logger.error(f"Sherlock error: {e}")

        # Holehe - si hay email
        if 'Holehe' in self.tool_registry and seed.email:
            holehe = self.tool_registry['Holehe']
            if holehe.is_available:
                try:
                    params = QueryParameters(email=seed.email)
                    start = time.time()
                    results = holehe.execute(params)
                    elapsed = time.time() - start

                    report = ToolReport(
                        case_id=case_id,
                        tool_name="Holehe",
                        raw_json=json.dumps([r.__dict__ for r in results]),
                        summary=f"Holehe: {len(results)} servicios",
                        status="ok",
                        execution_time=elapsed,
                        results_count=len(results)
                    )
                    db.save_report(report)
                    result.tools_executed.append("Holehe")
                except Exception as e:
                    logger.error(f"Holehe error: {e}")

        # Maigret - búsqueda profunda de username
        if 'Maigret' in self.tool_registry:
            maigret = self.tool_registry['Maigret']
            if maigret.is_available:
                for username in usernames[:2]:
                    try:
                        params = QueryParameters(username=username)
                        start = time.time()
                        results = maigret.execute(params)
                        elapsed = time.time() - start

                        report = ToolReport(
                            case_id=case_id,
                            tool_name=f"Maigret:{username}",
                            raw_json=json.dumps([r.__dict__ for r in results]),
                            summary=f"Maigret @{username}: {len(results)} perfiles",
                            status="ok",
                            execution_time=elapsed,
                            results_count=len(results)
                        )
                        db.save_report(report)

                        for r in results:
                            result.possible_profiles.append({
                                'platform': r.category,
                                'url': r.url,
                                'title': r.title,
                                'confidence': r.relevance_score
                            })

                        result.tools_executed.append(f"Maigret:{username}")
                    except Exception as e:
                        logger.error(f"Maigret error: {e}")

    def _get_discovered_usernames(self, case_id: int) -> List[str]:
        """Obtiene usernames descubiertos hasta ahora."""
        target_data = db.get_target_data(case_id)
        usernames = [td.value for td in target_data if td.field_type == "username"]
        return list(set(usernames))

    def _extract_entities_from_results(self, results: List[SearchResult]) -> Dict[str, List[str]]:
        """Extrae entidades de los resultados de búsqueda."""
        entities = {
            'url': [],
            'username': [],
            'domain': []
        }

        import re
        for r in results:
            if r.url:
                entities['url'].append(r.url)

                # Extraer username de URLs de redes sociales
                url_lower = r.url.lower()
                if 'github.com/' in url_lower:
                    parts = r.url.split('github.com/')
                    if len(parts) > 1:
                        username = parts[1].split('/')[0].split('?')[0]
                        if username and username not in ['search', 'explore', 'topics']:
                            entities['username'].append(username)

                elif 'linkedin.com/in/' in url_lower:
                    parts = r.url.split('/in/')
                    if len(parts) > 1:
                        username = parts[1].split('/')[0].split('?')[0]
                        if username:
                            entities['username'].append(username)

                elif 'twitter.com/' in url_lower or 'x.com/' in url_lower:
                    for pattern in ['twitter.com/', 'x.com/']:
                        if pattern in url_lower:
                            parts = r.url.split(pattern)
                            if len(parts) > 1:
                                username = parts[1].split('/')[0].split('?')[0]
                                if username and username not in ['search', 'explore', 'i']:
                                    entities['username'].append(username)

        # Deduplicate
        for key in entities:
            entities[key] = list(set(entities[key]))

        return entities

    def _correlate_findings(self, case_id: int, result: ProfileResult):
        """Ejecuta correlación de hallazgos."""
        try:
            engine = CorrelationEngine(case_id)
            summary = engine.get_profile_summary()

            result.correlations = summary.get('top_correlations', [])

            # Sugerir herramientas adicionales
            suggestions = engine.suggest_tools()
            if suggestions:
                logger.info(f"Herramientas sugeridas: {suggestions}")

        except Exception as e:
            logger.error(f"Correlation error: {e}")

    def _extract_images(self, case_id: int, result: ProfileResult):
        """Extrae URLs de imágenes de avatares de los reportes."""
        reports = db.get_reports(case_id)

        for report in reports:
            try:
                data = json.loads(report.raw_json)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            extra = item.get('extra_data', {})
                            if isinstance(extra, dict) and extra.get('avatar_url'):
                                if extra['avatar_url'] not in result.images:
                                    result.images.append(extra['avatar_url'])
            except:
                pass

    def _count_findings(self, case_id: int) -> int:
        """Cuenta el total de hallazgos."""
        reports = db.get_reports(case_id)
        return sum(r.results_count for r in reports)


def profile_person_cli(name: str, context: str = "", email: str = None,
                       username: str = None) -> ProfileResult:
    """
    Función de conveniencia para perfilamiento desde CLI.

    Ejemplo:
        from osint_app.profiler import profile_person_cli
        result = profile_person_cli("Juan Riofrio", "UDLA Ecuador")
        print(f"Caso ID: {result.case_id}")
        print(f"Hallazgos: {result.total_findings}")
        print(f"Perfiles posibles: {result.possible_profiles}")
    """
    profiler = OSINTProfiler()
    seed = ProfileSeed(
        name=name,
        context=context,
        email=email,
        username=username
    )
    return profiler.profile_person(seed)
