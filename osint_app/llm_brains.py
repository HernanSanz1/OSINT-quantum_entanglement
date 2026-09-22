"""
Triple-Brain LLM wrappers for OSINT App v2.
Each brain is OpenAI-API compatible; Venice and Ollama just use different base_urls.
"""
import json
import logging
import requests
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── System prompt shared by all brains ────────────────────────────────────────
OSINT_SYSTEM = (
    "Eres un analista OSINT experto y estricto. Recibirás tu objetivo primario y datos de herramientas.\n"
    "Instrucciones CRÍTICAS E INQUEBRANTABLES:\n"
    "1. VERIFICACIÓN DE HOMÓNIMOS: Cruza CADA DATO encontrado con los 'Datos Objetivo Base'. "
    "Mucha gente se llama igual. Si un reporte menciona a un 'Juan Pérez' que es ingeniero, pero tus datos base "
    "dicen que tu objetivo es carpintero, DESCARTA AUTOMÁTICAMENTE ese reporte. No alucines ni asumas.\n"
    "2. Identifica la información más útil solo si está matemáticamente o contextualmente comprobada con el objetivo.\n"
    "3. Ofrece SIEMPRE de 2 a 3 recomendaciones prácticas de herramientas OSINT con parámetros exactos para profundizar "
    "solo en los vectores que resultaron ser 100% positivos.\n"
    "Responde siempre en español. Sé concreto, técnico, suspicaz (duda de los datos) y orientado a la acción."
)


# ── Abstract base ─────────────────────────────────────────────────────────────

class LLMBrain(ABC):
    """Abstract brain — one per LLM provider."""

    def __init__(self, name: str, model: str):
        self.name = name
        self.model = model
        self.enabled = True
        self._last_error: str = ""

    @abstractmethod
    def query(self, prompt: str, system: str = OSINT_SYSTEM) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @property
    def last_error(self) -> str:
        return self._last_error

    def status_line(self) -> str:
        ok = self.is_available()
        icon = "✅" if ok else "⬜"
        note = "" if ok else f" — {self._last_error[:60]}"
        return f"{icon} {self.name} [{self.model}]{note}"


# ── Ollama (local) ────────────────────────────────────────────────────────────

class OllamaBrain(LLMBrain):
    """
    Local Ollama brain — data never leaves the machine.
    Connects to http://localhost:11434.
    Recommended model for ≤3 GB RAM: llama3.2
    """
    BASE = "http://localhost:11434"

    def __init__(self, model: str = "llama3.2"):
        super().__init__("Ollama (local)", model)

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.BASE}/api/tags", timeout=3)
            if not r.ok:
                self._last_error = f"HTTP {r.status_code}"
                return False
            models = [m["name"] for m in r.json().get("models", [])]
            if not models:
                self._last_error = "Sin modelos — ejecuta: ollama pull llama3.2"
                return False
            if self.model not in models:
                # Try to find a partial match
                match = next((m for m in models if self.model.split(":")[0] in m), None)
                if match:
                    self.model = match
                else:
                    self.model = models[0]  # use first available
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.BASE}/api/tags", timeout=3)
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

    def query(self, prompt: str, system: str = OSINT_SYSTEM) -> str:
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                "stream": False,
                "options": {"num_ctx": 4096},   # keeps RAM usage low
            }
            r = requests.post(f"{self.BASE}/api/chat", json=payload, timeout=120)
            if not r.ok:
                self._last_error = f"HTTP {r.status_code}"
                return ""
            return r.json().get("message", {}).get("content", "")
        except Exception as e:
            self._last_error = str(e)
            logger.error(f"Ollama query error: {e}")
            return ""

    def pull_model(self, model: str = "llama3.2") -> bool:
        """Trigger a model pull (blocking). Returns True on success."""
        try:
            r = requests.post(
                f"{self.BASE}/api/pull",
                json={"name": model},
                timeout=1800,  # pulling can take a while
                stream=True,
            )
            # Drain the streaming response
            for line in r.iter_lines():
                pass
            self.model = model
            return True
        except Exception as e:
            self._last_error = str(e)
            return False


# ── OpenAI / ChatGPT ──────────────────────────────────────────────────────────

class OpenAIBrain(LLMBrain):
    """ChatGPT via official OpenAI API."""

    def __init__(self, api_key: str = "", model: str = "gpt-4o-mini"):
        super().__init__("ChatGPT (OpenAI)", model)
        self.api_key = api_key

    def is_available(self) -> bool:
        if not self.api_key:
            self._last_error = "Sin API key — configura en Ajustes"
            return False
        return True

    def query(self, prompt: str, system: str = OSINT_SYSTEM) -> str:
        if not self.api_key:
            return ""
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=1200,
                temperature=0.3,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            self._last_error = str(e)
            logger.error(f"OpenAI error: {e}")
            return ""


# ── Venice AI (uncensored) ─────────────────────────────────────────────────────

class VeniceBrain(LLMBrain):
    """
    Venice AI — OpenAI-compatible API with uncensored models.
    Base URL: https://api.venice.ai/api/v1
    Get key at: https://venice.ai/settings/api
    """
    BASE_URL = "https://api.venice.ai/api/v1"

    def __init__(self, api_key: str = "", model: str = "llama-3.3-70b", name: str = "Venice (sin censura)"):
        super().__init__(name, model)
        self.api_key = api_key

    def is_available(self) -> bool:
        if not self.api_key:
            self._last_error = "Sin API key — obtén una en venice.ai/settings/api"
            return False
        return True

    def query(self, prompt: str, system: str = OSINT_SYSTEM) -> str:
        if not self.api_key:
            return ""
        
        import requests, time, random
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Jitter on secondary attempts to prevent concurrent rate limit collision
                if attempt > 0:
                    time.sleep(random.uniform(1.0, 3.0))
                    
                resp = requests.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                # Check for rate-limiting or explicit HTTP errors
                if resp.status_code == 429:
                    self._last_error = "Rate limit (HTTP 429) alcanzado."
                    continue
                elif resp.status_code != 200:
                    self._last_error = f"HTTP Error {resp.status_code}: {resp.text}"
                    continue
                
                data = resp.json()
                if "choices" in data and len(data["choices"]) > 0:
                    content = data["choices"][0].get("message", {}).get("content", "")
                    if content:
                        return content
                
            except Exception as e:
                self._last_error = str(e)
                logger.error(f"Venice error (attempt {attempt+1}/{max_retries}): {e}")
                
        self._last_error = "API Error: No response after retries. Proxy proxy might be rate-limiting o denegando modelo."
        return ""

    def list_models(self) -> List[str]:
        """Return available Venice models."""
        try:
            r = requests.get(
                f"{self.BASE_URL}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10,
            )
            data = r.json()
            return [m["id"] for m in data.get("data", [])]
        except Exception:
            return ["llama-3.3-70b", "venice-uncensored", "dolphin-mistral-24b"]
