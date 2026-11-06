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


# ── Asistente que arregla (05-11-2026): pregunta antes de cada paso ──────────────────────────────────────────

def _fake_check(states, title, fix_result="hecho"):
    """Comprobación que devuelve el siguiente estado de la lista cada vez que se llama."""
    calls = []

    def fix():
        calls.append(title)
        return fix_result

    def check():
        ok = states.pop(0) if len(states) > 1 else states[0]
        return Step(title, ok, "listo" if ok else "falta", fix=None if ok else fix, fix_label=f"arreglar {title}")
    return check, calls


def test_interactive_asks_before_each_step_and_rechecks():
    deps, deps_calls = _fake_check([False, False, True], "Dependencias")
    key, key_calls = _fake_check([None, None, None], "Clave de Hunter.io")
    answers = iter(["s", "s", "n"])            # empezar · arreglar dependencias · NO a la clave
    said = []
    steps = [deps(), key()]
    result = setup_check.run_interactive(steps, ask=lambda q: next(answers), say=said.append, check_list=[deps, key])
    assert deps_calls == ["Dependencias"] and key_calls == []
    assert result == {"arreglados": 1, "saltados": 1, "fallidos": 0}
    assert any("✅ Dependencias: listo (hecho)" in s for s in said)


def test_interactive_changes_nothing_if_not_accepted():
    deps, calls = _fake_check([False], "Dependencias")
    said = []
    result = setup_check.run_interactive([deps()], ask=lambda q: "", say=said.append, check_list=[deps])
    assert calls == [] and result["arreglados"] == 0 and said == ["No he cambiado nada."]


def test_interactive_reports_a_failed_fix_and_goes_on():
    def broken():
        raise RuntimeError("pip no pudo descargar")
    first = lambda: Step("Dependencias", False, "falta", fix=broken, fix_label="instalar")   # noqa: E731
    second, calls = _fake_check([None, None, True], "Copia de seguridad")
    said = []
    result = setup_check.run_interactive([first(), second()], ask=lambda q: "s", say=said.append,
                                         check_list=[first, second])
    assert any("❌ No se pudo: pip no pudo descargar" in s for s in said)
    assert calls == ["Copia de seguridad"] and result == {"arreglados": 1, "saltados": 0, "fallidos": 1}


def test_nothing_to_fix_asks_nothing():
    asked = []
    setup_check.run_interactive([Step("Python", True)], ask=asked.append, say=lambda s: None, check_list=[])
    assert asked == []


def test_which_steps_offer_a_fix(monkeypatch):
    import osint_app.utils.secret_vault as sv
    monkeypatch.setattr(sv, "vault", FakeVault())
    assert setup_check.check_key("Hunter.io", "x", "y").fix is not None         # sin clave: la pide
    monkeypatch.setattr(sv, "vault", FakeVault(**{"Hunter.io": "k"}))
    assert setup_check.check_key("Hunter.io", "x", "y").fix is None             # guardada: nada que hacer
    monkeypatch.setattr(setup_check, "_docker_running", lambda *a, **k: False)
    assert setup_check._searxng_fix() is None                                    # sin Docker no se crea SearXNG
    monkeypatch.setattr(setup_check, "_docker_running", lambda *a, **k: True)
    assert setup_check._searxng_fix() is not None
    assert setup_check.check_python().fix is None                                # esto solo se explica


def test_pip_fix_uses_this_python_and_fails_loudly():
    ran = []
    ok = lambda cmd, cwd=None: (ran.append(cmd), SimpleNamespace(returncode=0))[1]           # noqa: E731
    assert setup_check._pip_install(["maigret"], run=ok) == "instalado"
    import sys
    import pytest
    # El Python que ejecuta SENTINEL (el del entorno env), no otro que haya en el equipo
    assert ran[0] == [sys.executable, "-m", "pip", "install", "maigret"]
    with pytest.raises(RuntimeError):
        setup_check._pip_install(["x"], run=lambda cmd, cwd=None: SimpleNamespace(returncode=1))
