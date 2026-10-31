"""--setup: lista de pasos de la instalación con su estado y qué hacer; no cambia nada."""
from types import SimpleNamespace

from osint_app.utils import setup_check
from osint_app.utils.setup_check import Step


class FakeVault:
    def __init__(self, **keys):
        self.keys = keys

    def get(self, name):
        return self.keys.get(name, "")


def test_render_says_what_to_do_and_where_to_start():
    text = setup_check.render([Step("Python 3.12", True, "3.12.10"),
                               Step("Dependencias", False, "faltan: ddgs", "pip install -r requirements.txt"),
                               Step("Clave de Hunter.io", None, "sin configurar", "Opcional: --set-key Hunter.io")])
    assert "✅ Python 3.12" in text and "❌ Dependencias: faltan: ddgs" in text and "⬜ Clave de Hunter.io" in text
    assert "→ pip install -r requirements.txt" in text and "Empieza por: Dependencias" in text


def test_everything_needed_ready():
    assert "Todo lo necesario está listo" in setup_check.render([Step("a", True), Step("b", None, "", "opcional")])


def test_keys_are_reported_without_their_value(monkeypatch):
    import osint_app.utils.secret_vault as sv
    monkeypatch.setattr(sv, "vault", FakeVault(GitHub="ghp_secreto"))
    ok = setup_check.check_key("GitHub", "límite", "crea un token", required=True)
    assert ok.ok is True and "ghp_secreto" not in f"{ok.detail}{ok.action}"
    missing = setup_check.check_key("Hunter.io", "correos", "--set-key Hunter.io")
    assert missing.ok is None and "--set-key Hunter.io" in missing.action


def test_docker_off_or_on(monkeypatch):
    monkeypatch.setattr(setup_check, "_docker", lambda: "docker.exe")
    off = setup_check.check_docker(run=lambda *a, **k: SimpleNamespace(returncode=1, stdout=""))
    assert off.ok is None and "Engine running" in off.action
    on = setup_check.check_docker(run=lambda *a, **k: SimpleNamespace(returncode=0, stdout="29.8.1\n"))
    assert on.ok is True and on.detail == "funcionando"
    monkeypatch.setattr(setup_check, "_docker", lambda: "")
    assert "Docker Desktop" in setup_check.check_docker().action


def test_searxng_answers_or_not(monkeypatch):
    import osint_app.utils.secret_vault as sv
    monkeypatch.setattr(sv, "vault", FakeVault(SearXNG="http://127.0.0.1:8888"))
    assert setup_check.check_searxng(get=lambda *a, **k: SimpleNamespace(status_code=200)).ok is True

    def down(*a, **k):
        raise OSError("sin conexión")
    step = setup_check.check_searxng(get=down)
    assert step.ok is None and "searxng_local.py start" in step.action
    monkeypatch.setattr(sv, "vault", FakeVault())
    assert setup_check.check_searxng().detail == "no configurado"


def test_requirements_are_read_from_the_project():
    names = setup_check._required_packages()
    assert "requests" in names and "PySide6" in names and "tzdata" in names
    assert not any(n.startswith(("#", "subfinder", "censys")) for n in names)
