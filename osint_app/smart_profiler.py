"""
Smart OSINT Profiler - Motor de perfilamiento con correlación inteligente.
NO guarda datos sin verificar que coincidan con el objetivo.
"""
import json
import time
import re
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from .case_manager import CaseManager
from .db.feedback_db import db
from .core.models import Case, TargetData, ToolReport, QueryParameters, SearchResult

logger = logging.getLogger(__name__)


@dataclass
class ProfileSeed:
    """Datos semilla - lo que SABEMOS del objetivo."""
    name: str
    context: str = ""  # Universidad, empresa, ciudad
    country: str = ""  # País
    email: Optional[str] = None
    username: Optional[str] = None
    year_hint: Optional[str] = None  # Año de nacimiento o graduación


@dataclass
class CandidateProfile:
    """Un perfil candidato encontrado."""
    platform: str
    url: str
    username: str
    display_name: str = ""
    bio: str = ""
    location: str = ""
    company: str = ""
    avatar_url: str = ""
    extra_data: Dict[str, Any] = field(default_factory=dict)

    # Scores de correlación
    name_match_score: float = 0.0
    context_match_score: float = 0.0
    total_score: float = 0.0
    rejection_reason: str = ""


class SmartProfiler:
    """
    Profiler inteligente que:
    1. Busca candidatos en múltiples fuentes
    2. Evalúa cada candidato contra los datos semilla
    3. Solo guarda los que pasan el umbral de correlación
    4. Descarta automáticamente los que claramente no coinciden
    """

    CORRELATION_THRESHOLD = 0.5  # Mínimo para considerar un candidato

    def __init__(self):
        self.case_manager = CaseManager()
        self.candidates: List[CandidateProfile] = []
        self.rejected: List[CandidateProfile] = []

    def profile(self, seed: ProfileSeed) -> Dict[str, Any]:
        """
        Ejecuta perfilamiento completo con correlación inteligente.
        """
        # Crear caso
        case = self.case_manager.create(
            f"Perfil: {seed.name}",
            f"Contexto: {seed.context} | País: {seed.country}"
        )

        # Agregar datos semilla
        self._add_seed(case.id, seed)

        # Extraer hints del contexto
        seed = self._enrich_seed(seed)

        # Generar variantes de username inteligentes
        username_variants = self._generate_smart_variants(seed)

        # Buscar en GitHub
        for variant in username_variants:
            candidate = self._check_github(variant)
            if candidate:
                self._evaluate_candidate(candidate, seed)

        # Buscar en web (LinkedIn, etc.)
        web_candidates = self._search_web(seed)
        for candidate in web_candidates:
            self._evaluate_candidate(candidate, seed)

        # Filtrar y guardar solo los buenos
        accepted = [c for c in self.candidates if c.total_score >= self.CORRELATION_THRESHOLD]

        # Guardar resultados
        self._save_results(case.id, seed, accepted)

        return {
            'case_id': case.id,
            'seed': seed,
            'accepted_candidates': len(accepted),
            'rejected_candidates': len(self.rejected),
            'candidates': [self._candidate_to_dict(c) for c in accepted],
            'rejected': [self._candidate_to_dict(c) for c in self.rejected[:5]],  # Top 5 rechazados
        }

    def _enrich_seed(self, seed: ProfileSeed) -> ProfileSeed:
        """Extrae información adicional del contexto."""
        context_lower = seed.context.lower()

        # Detectar país
        if not seed.country:
            if 'ecuador' in context_lower:
                seed.country = 'Ecuador'
            elif 'colombia' in context_lower:
                seed.country = 'Colombia'
            elif 'perú' in context_lower or 'peru' in context_lower:
                seed.country = 'Perú'

        # Detectar año
        if not seed.year_hint:
            year_match = re.search(r'(19|20)\d{2}', seed.context + seed.name)
            if year_match:
                seed.year_hint = year_match.group()

        return seed

    def _generate_smart_variants(self, seed: ProfileSeed) -> List[str]:
        """
        Genera variantes de username ESPECÍFICAS basadas en el contexto.
        """
        variants = []
        name = seed.name.lower().strip()
        parts = re.split(r'[\s\-_]+', name)

        if len(parts) < 2:
            return [name]

        first = parts[0]
        last = parts[-1]

        # Variantes básicas
        base_variants = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}{first}",
            f"{first[0]}.{last}",
            f"{first[0]}_{last}",
            f"{first[0]}d{last}",   # Patrón común: jdriofrio (inicial + d + apellido)
            f"{first[0]}_{last}",
            f"{last}{first[0]}",
            f"{last}_{first[0]}",
        ]

        # Variantes con letras intermedias comunes (segundo nombre)
        for middle in ['d', 'a', 'j', 'm', 'c', 'l', 'e', 's']:
            base_variants.append(f"{first[0]}{middle}{last}")

        # Si hay año, agregar variantes con año (PRIORITARIAS)
        if seed.year_hint:
            year = seed.year_hint
            year_short = year[-2:]
            for v in base_variants:
                variants.append(f"{v}{year}")      # juanriofrio2006
                variants.append(f"{v}{year_short}")  # juanriofrio06
            # El año al inicio también
            variants.append(f"{year}{first}{last}")

        # Agregar las básicas después
        variants.extend(base_variants)

        # Si hay username conocido, ponerlo primero
        if seed.username:
            if seed.username in variants:
                variants.remove(seed.username)
            variants.insert(0, seed.username)

        return list(dict.fromkeys(variants))[:20]  # Dedup, max 20

    def _check_github(self, username: str) -> Optional[CandidateProfile]:
        """Verifica si existe un usuario en GitHub y extrae datos."""
        import urllib.request
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            url = f"https://api.github.com/users/{username}"
            req = urllib.request.Request(url, headers={
                'User-Agent': 'SENTINEL-OSINT/1.0',
                'Accept': 'application/vnd.github.v3+json'
            })
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))

                return CandidateProfile(
                    platform='GitHub',
                    url=data.get('html_url', ''),
                    username=data.get('login', ''),
                    display_name=data.get('name', ''),
                    bio=data.get('bio', '') or '',
                    location=data.get('location', '') or '',
                    company=data.get('company', '') or '',
                    avatar_url=data.get('avatar_url', ''),
                    extra_data={
                        'repos': data.get('public_repos', 0),
                        'followers': data.get('followers', 0),
                        'created_at': data.get('created_at', ''),
                        'twitter': data.get('twitter_username', ''),
                    }
                )
        except Exception:
            return None

    def _search_web(self, seed: ProfileSeed) -> List[CandidateProfile]:
        """Busca en la web y extrae candidatos."""
        # Por ahora retorna vacío - implementar con búsqueda real
        return []

    def _evaluate_candidate(self, candidate: CandidateProfile, seed: ProfileSeed):
        """
        Evalúa un candidato contra los datos semilla.
        Calcula scores de correlación y decide si aceptar o rechazar.
        """
        # Score de nombre
        name_score = self._calculate_name_score(candidate, seed)
        candidate.name_match_score = name_score

        # Score de contexto (ubicación, universidad, etc.)
        context_score = self._calculate_context_score(candidate, seed)
        candidate.context_match_score = context_score

        # Score total ponderado
        # Nombre es más importante que contexto
        candidate.total_score = (name_score * 0.6) + (context_score * 0.4)

        # Reglas de rechazo automático
        rejection = self._check_rejection_rules(candidate, seed)
        if rejection:
            candidate.rejection_reason = rejection
            candidate.total_score = 0
            self.rejected.append(candidate)
        else:
            self.candidates.append(candidate)

    def _calculate_name_score(self, candidate: CandidateProfile, seed: ProfileSeed) -> float:
        """Calcula qué tan bien coincide el nombre."""
        if not candidate.display_name:
            # Si no hay nombre, verificar si el username coincide con el patrón
            return self._username_to_name_score(candidate.username, seed.name)

        seed_name = seed.name.lower().strip()
        cand_name = candidate.display_name.lower().strip()

        # Match exacto
        if seed_name == cand_name:
            return 1.0

        # Tokenizar
        seed_parts = set(re.split(r'[\s\-_]+', seed_name))
        cand_parts = set(re.split(r'[\s\-_]+', cand_name))

        # Intersección
        common = seed_parts & cand_parts
        if not common:
            return 0.0

        # Score basado en cuántas partes coinciden
        score = len(common) / max(len(seed_parts), len(cand_parts))

        # Bonus si el apellido coincide (más importante)
        seed_last = list(seed_parts)[-1] if seed_parts else ""
        if seed_last in cand_parts:
            score += 0.2

        return min(score, 1.0)

    def _username_to_name_score(self, username: str, name: str) -> float:
        """Evalúa si un username podría corresponder a un nombre."""
        username = username.lower()
        name_parts = re.split(r'[\s\-_]+', name.lower())

        if len(name_parts) < 2:
            return 0.3 if name_parts[0] in username else 0.0

        first = name_parts[0]
        last = name_parts[-1]

        # Patrones comunes
        patterns = [
            f"{first}{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}{first}",
            f"{first[0]}d{last}",  # jdriofrio
        ]

        for pattern in patterns:
            if pattern in username:
                return 0.7

        # Al menos el apellido está
        if last in username:
            return 0.5

        # Al menos el nombre está
        if first in username:
            return 0.3

        return 0.0

    def _calculate_context_score(self, candidate: CandidateProfile, seed: ProfileSeed) -> float:
        """Calcula qué tan bien coincide el contexto."""
        score = 0.0

        # Ubicación
        if candidate.location and seed.country:
            loc_lower = candidate.location.lower()
            country_lower = seed.country.lower()

            if country_lower in loc_lower:
                score += 0.5
            elif self._is_same_region(loc_lower, country_lower):
                score += 0.3
            # Penalizar si claramente es otro país
            elif self._is_different_country(loc_lower, country_lower):
                score -= 0.5

        # Contexto en bio
        if candidate.bio and seed.context:
            context_lower = seed.context.lower()
            bio_lower = candidate.bio.lower()

            # Buscar keywords del contexto en la bio
            context_words = re.findall(r'\w+', context_lower)
            matches = sum(1 for w in context_words if len(w) > 3 and w in bio_lower)
            if matches:
                score += min(0.3 * matches, 0.5)

        return max(min(score, 1.0), 0.0)

    def _is_same_region(self, location: str, country: str) -> bool:
        """Verifica si están en la misma región."""
        latam = ['ecuador', 'colombia', 'perú', 'peru', 'chile', 'argentina',
                 'mexico', 'méxico', 'latam', 'latinoamerica', 'south america']

        loc_is_latam = any(c in location for c in latam)
        country_is_latam = any(c in country for c in latam)

        return loc_is_latam and country_is_latam

    def _is_different_country(self, location: str, expected_country: str) -> bool:
        """Verifica si claramente es un país diferente."""
        other_countries = ['spain', 'españa', 'usa', 'united states', 'germany',
                          'alemania', 'france', 'francia', 'uk', 'england',
                          'china', 'japan', 'india', 'canada', 'australia']

        # Si la ubicación menciona explícitamente otro país
        for other in other_countries:
            if other in location and other not in expected_country:
                return True

        return False

    def _check_rejection_rules(self, candidate: CandidateProfile, seed: ProfileSeed) -> Optional[str]:
        """
        Reglas de rechazo automático.
        Retorna razón de rechazo o None si es aceptable.
        """
        # Regla 1: Nombre completamente diferente
        if candidate.display_name:
            seed_parts = set(re.split(r'[\s\-_]+', seed.name.lower()))
            cand_parts = set(re.split(r'[\s\-_]+', candidate.display_name.lower()))

            # Si no comparten NINGUNA parte del nombre, rechazar
            if not (seed_parts & cand_parts):
                # Verificar si al menos el apellido está en el username
                seed_last = list(seed_parts)[-1] if seed_parts else ""
                if seed_last not in candidate.username.lower():
                    return f"Nombre no coincide: '{candidate.display_name}' vs '{seed.name}'"

        # Regla 2: País claramente diferente
        if candidate.location and seed.country:
            if self._is_different_country(candidate.location.lower(), seed.country.lower()):
                return f"Ubicación no coincide: '{candidate.location}' vs '{seed.country}'"

        # Regla 3: Empresa muy específica que no coincide con contexto de estudiante
        if candidate.company and seed.context:
            if 'universidad' in seed.context.lower() or 'udla' in seed.context.lower():
                # Si es estudiante pero el perfil tiene empresa tech grande, probablemente no es
                big_companies = ['google', 'microsoft', 'amazon', 'meta', 'apple', 'flowable']
                company_lower = candidate.company.lower()
                if any(c in company_lower for c in big_companies):
                    return f"Perfil profesional vs estudiante: empresa '{candidate.company}'"

        return None

    def _add_seed(self, case_id: int, seed: ProfileSeed):
        """Agrega datos semilla al caso."""
        db.add_target_data(TargetData(
            case_id=case_id, field_type="name", value=seed.name,
            source="seed", confidence=100
        ))
        if seed.context:
            db.add_target_data(TargetData(
                case_id=case_id, field_type="context", value=seed.context,
                source="seed", confidence=100
            ))
        if seed.country:
            db.add_target_data(TargetData(
                case_id=case_id, field_type="country", value=seed.country,
                source="seed", confidence=100
            ))
        if seed.username:
            db.add_target_data(TargetData(
                case_id=case_id, field_type="username", value=seed.username,
                source="seed", confidence=100
            ))

    def _save_results(self, case_id: int, seed: ProfileSeed,
                      accepted: List[CandidateProfile]):
        """Guarda resultados verificados en el caso."""

        # Guardar reporte de candidatos aceptados
        report = ToolReport(
            case_id=case_id,
            tool_name="SmartProfiler",
            raw_json=json.dumps([self._candidate_to_dict(c) for c in accepted]),
            summary=f"Perfilamiento: {len(accepted)} candidatos verificados, {len(self.rejected)} rechazados",
            status="ok",
            results_count=len(accepted)
        )
        report_id = db.save_report(report)

        # Agregar datos de candidatos aceptados al target_data
        for candidate in accepted:
            if candidate.total_score >= 0.5:  # Umbral de aceptación
                conf = int(candidate.total_score * 100)

                db.add_target_data(TargetData(
                    case_id=case_id, field_type="username", value=candidate.username,
                    source=f"SmartProfiler:{candidate.platform}", confidence=conf
                ))

                if candidate.display_name:
                    db.add_target_data(TargetData(
                        case_id=case_id, field_type="verified_name", value=candidate.display_name,
                        source=f"SmartProfiler:{candidate.platform}", confidence=conf
                    ))

                if candidate.avatar_url:
                    db.add_target_data(TargetData(
                        case_id=case_id, field_type="avatar", value=candidate.avatar_url,
                        source=f"SmartProfiler:{candidate.platform}", confidence=conf
                    ))

        # Guardar reporte de rechazados
        if self.rejected:
            reject_report = ToolReport(
                case_id=case_id,
                tool_name="SmartProfiler:Rejected",
                raw_json=json.dumps([self._candidate_to_dict(c) for c in self.rejected]),
                summary=f"Candidatos rechazados: {len(self.rejected)}",
                status="ok",
                results_count=len(self.rejected)
            )
            db.save_report(reject_report)

    def _candidate_to_dict(self, c: CandidateProfile) -> Dict[str, Any]:
        return {
            'platform': c.platform,
            'url': c.url,
            'username': c.username,
            'display_name': c.display_name,
            'location': c.location,
            'company': c.company,
            'bio': c.bio,
            'avatar_url': c.avatar_url,
            'scores': {
                'name': round(c.name_match_score, 2),
                'context': round(c.context_match_score, 2),
                'total': round(c.total_score, 2),
            },
            'rejection_reason': c.rejection_reason,
            'extra': c.extra_data,
        }


def smart_profile(name: str, context: str = "", country: str = "",
                  username: str = None) -> Dict[str, Any]:
    """
    Función CLI para perfilamiento inteligente.

    Ejemplo:
        from osint_app.smart_profiler import smart_profile
        result = smart_profile("Juan Riofrio", "UDLA Ecuador", "Ecuador")
    """
    profiler = SmartProfiler()
    seed = ProfileSeed(
        name=name,
        context=context,
        country=country,
        username=username
    )
    return profiler.profile(seed)
