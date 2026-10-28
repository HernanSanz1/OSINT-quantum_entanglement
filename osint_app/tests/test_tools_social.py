"""Sherlock, Holehe, GHunt, Instaloader y snscrape: sin binarios ni red (el subproceso se simula)."""
import subprocess

import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import social_tools
from osint_app.tools.social_tools import (
    GHuntTool, HoleheTool, SherlockTool, SnscrapeYoutubeTool, _clean_email, _clean_username, _run,
)


def progress_of(tool):
    seen = []
    tool._progress_cb = seen.append
    return seen


@pytest.fixture
def program(monkeypatch):
    """Simula que los programas están instalados y registra con qué argumentos se lanzan."""
    state = {"calls": []}

    def install(output="", code=0, installed=("sherlock", "holehe", "ghunt", "instaloader", "snscrape")):
        state["calls"].clear()                                    # cada instalación empieza con el registro vacío
        monkeypatch.setattr(social_tools.shutil, "which", lambda name: f"/bin/{name}" if name in installed else None)
        monkeypatch.setattr(social_tools, "pip_tool_command",
                            lambda name: [f"/bin/{name}"] if name in installed else [])

        def fake_run(cmd, timeout=300, label=""):
            state["calls"].append((cmd, timeout))
            return output, code
        monkeypatch.setattr(social_tools, "_run", fake_run)
        return state
    return install


# ── validación de lo que llega a un programa externo ─────────────────────────

@pytest.mark.parametrize("value,clean", [
    ("jperez", "jperez"), ("@jperez", "jperez"), ("  j.perez-99 ", "j.perez-99"), ("José_Muñoz", "José_Muñoz"), ("a", "a"),
    ("-evil", ""), ("--folderoutput", ""), ("@-x", ""), ("a b", ""), ("x;rm", ""), ("", ""), (None, ""), ("x" * 65, ""),
])
def test_clean_username(value, clean):
    assert _clean_username(value) == clean


@pytest.mark.parametrize("value,clean", [
    ("a@x.com", "a@x.com"), (" a.b+c@mail.empresa.com ", "a.b+c@mail.empresa.com"),
    ("-x@y.com", ""), ("a b@x.com", ""), ("sin-arroba", ""), ("a@x", ""), ("", ""), (None, ""),
])
def test_clean_email(value, clean):
    assert _clean_email(value) == clean


def test_run_reports_timeout_and_missing_program_with_code_minus_one(monkeypatch):
    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(social_tools.subprocess, "run", timeout)
    assert _run(["x"]) == ("", -1)
    monkeypatch.setattr(social_tools.subprocess, "run", lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError()))
    assert _run(["x"]) == ("", -1)
    monkeypatch.setattr(social_tools.subprocess, "run", lambda cmd, **kw: type("P", (), {"stdout": "salida", "returncode": 3})())
    assert _run(["x"]) == ("salida", 3)


# ── Sherlock ─────────────────────────────────────────────────────────────────

SHERLOCK_OUTPUT = """\
[*] Checking username jperez on:
[+] GitHub: https://github.com/jperez
[+] Reddit: https://www.reddit.com/user/jperez
[-] Twitter: Not Found!
[+] SinUrl
[*] Search completed with 2 results
"""


def test_sherlock_parses_found_profiles(program):
    state = program(SHERLOCK_OUTPUT)
    results = SherlockTool().execute(QueryParameters(username="@jperez"))
    assert [(r.title, r.url) for r in results] == [("Perfil en GitHub: jperez", "https://github.com/jperez"),
                                                   ("Perfil en Reddit: jperez", "https://www.reddit.com/user/jperez")]
    assert all(r.category == "Social Media" and r.relevance_score == 80 for r in results)
    cmd, timeout = state["calls"][0]
    assert cmd == ["/bin/sherlock", "jperez", "--print-found", "--timeout", "10"] and timeout == 300


def test_sherlock_extra_args_replace_the_defaults(program):
    state = program("")
    SherlockTool().execute(QueryParameters(username="jperez", extra_args="--site GitHub --timeout 5"))
    assert state["calls"][0][0] == ["/bin/sherlock", "jperez", "--site", "GitHub", "--timeout", "5"]


@pytest.mark.parametrize("hostile", ["-evil", "--folderoutput", "-o", "", "a b"])
def test_sherlock_never_passes_an_option_disguised_as_a_username(program, hostile):
    state = program(SHERLOCK_OUTPUT)
    tool = SherlockTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(username=hostile)) == [] and state["calls"] == []                    # antes: el usuario se pasaba tal cual
    assert any("no es válido" in m for m in seen)


def test_sherlock_timeout_is_reported_and_missing_program_is_silent(program):
    program("", code=-1)
    tool = SherlockTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(username="jperez")) == [] and any("se agotó el tiempo" in m for m in seen)   # antes: nada
    program("", installed=())
    assert SherlockTool().execute(QueryParameters(username="jperez")) == []
    assert SherlockTool().check_available() is False


# ── Holehe ───────────────────────────────────────────────────────────────────

HOLEHE_OUTPUT = """\
*********************
   usuario@mail.com
*********************
[+] twitter.com
[+] gravatar.com
[-] spotify.com
[x] Rate limit snapchat.com

121 websites checked in 4.20 seconds
"""


def test_holehe_lists_only_the_plus_lines(program):
    state = program(HOLEHE_OUTPUT)
    results = HoleheTool().execute(QueryParameters(email="usuario@mail.com"))
    assert [r.title for r in results] == ["Email registrado en: twitter.com", "Email registrado en: gravatar.com"]
    assert results[0].snippet == "usuario@mail.com tiene cuenta en twitter.com" and results[0].category == "Email Social"
    assert state["calls"][0][0] == ["/bin/holehe", "usuario@mail.com", "--only-used"]


def test_holehe_help_text_is_not_a_registered_service(program):
    # con un correo inválido Holehe imprime su ayuda, que menciona "--only-used": antes se daba como un servicio
    program("usage: holehe [-h] [--only-used] email\nholehe: error: the following arguments are required: email")
    assert HoleheTool().execute(QueryParameters(email="usuario@mail.com")) == []
    program("[+]\n[+]   \n")
    assert HoleheTool().execute(QueryParameters(email="usuario@mail.com")) == []                             # un [+] vacío tampoco


@pytest.mark.parametrize("hostile", ["-x@y.com", "a b@x.com", "no-es-correo", ""])
def test_holehe_validates_the_email(program, hostile):
    state = program(HOLEHE_OUTPUT)
    tool = HoleheTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(email=hostile)) == [] and state["calls"] == [] and any("no es válido" in m for m in seen)


def test_holehe_timeout_is_reported(program):
    program("", code=-1)
    tool = HoleheTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(email="usuario@mail.com")) == [] and any("se agotó el tiempo" in m for m in seen)


# ── GHunt ────────────────────────────────────────────────────────────────────

def test_ghunt_normal_output_mentioning_auth_is_a_real_result(program):
    # antes bastaba con que la salida contuviera "auth" para darla por "bloqueada"
    state = program("Name: Juan Pérez\nGoogle Authenticator: enabled\nAuthor of 3 maps\n")
    (result,) = GHuntTool().execute(QueryParameters(email="juan@gmail.com"))
    assert result.category == "Google Account" and result.relevance_score == 90 and "Juan Pérez" in result.snippet
    assert result.title == "GHunt — análisis de juan@gmail.com"
    assert state["calls"][0] == (["/bin/ghunt", "email", "juan@gmail.com"], 120)


@pytest.mark.parametrize("output", ["Error in load_and_auth: no credentials", "Please run: ghunt login first"])
def test_ghunt_missing_session_is_detected_by_its_own_markers(program, output):
    program(output)
    (result,) = GHuntTool().execute(QueryParameters(email="juan@gmail.com"))
    assert result.category == "Error" and "Falta Autenticación" in result.title and result.relevance_score == 100


def test_ghunt_edge_cases(program):
    program("")
    assert GHuntTool().execute(QueryParameters(email="juan@gmail.com")) == []                               # sin salida: nada
    state = program("algo")
    assert GHuntTool().execute(QueryParameters(email="-x@y.com")) == [] and state["calls"] == []
    state = program("Name: X")
    GHuntTool().execute(QueryParameters(email="juan@gmail.com", extra_args="--json out.json"))
    assert state["calls"][0][0][-2:] == ["--json", "out.json"]
    program("", code=-1)
    tool = GHuntTool()
    seen = progress_of(tool)
    tool.execute(QueryParameters(email="juan@gmail.com"))
    assert any("se agotó el tiempo" in m for m in seen)


# ── Instaloader: verificado en real (Instagram exige sesión: HTTP 429 a consultas anónimas) ──


# ── snscrape (obsoleta) ──────────────────────────────────────────────────────

def test_snscrape_is_reported_as_deprecated():
    (result,) = SnscrapeYoutubeTool().execute(QueryParameters(username="x"))
    assert result.category == "Error / Deprecado" and "Obsoleta" in result.title and result.relevance_score == 100


def test_sherlock_skips_search_pages(program):
    # Real (Luisito Comunica): op.gg devolvía su página de búsqueda, y acababa en "otra persona" por "Japón"
    program(SHERLOCK_OUTPUT + "[+] op.gg [LeagueOfLegends] Japan: https://op.gg/lol/summoners/search?q=jperez&region=jp\n")
    urls = [r.url for r in SherlockTool().execute(QueryParameters(username="jperez"))]
    assert urls == ["https://github.com/jperez", "https://www.reddit.com/user/jperez"]
