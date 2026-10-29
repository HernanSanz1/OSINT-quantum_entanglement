"""Subfinder, Amass, SpiderFoot, Recon-ng y Maigret: el lanzador `_run` con subprocesos REALES; las herramientas con `_run` simulado."""
import sys
import time

import pytest

from osint_app.core.models import QueryParameters
from osint_app.tools import heavy_tools
from osint_app.tools.heavy_tools import (
    AmassTool, MaigretTool, ReconNgTool, SpiderFootTool, SubfinderTool, _hostnames, _run, _safe_domain, _safe_username, _tool_failed,
)


class Dummy:
    _is_cancelled = False


def progress_of(tool):
    seen = []
    tool._progress_cb = seen.append
    return seen


def py(code):
    return [sys.executable, "-c", code]


# ── _run con procesos de verdad ──────────────────────────────────────────────

@pytest.mark.parametrize("size", [500, 4_200, 200_000])
def test_run_does_not_lose_output_bigger_than_the_pipe_buffer(size):
    # antes: el programa se bloqueaba al llenar la tubería (~4 KB en Windows), se agotaba el tiempo y se perdía TODO
    out, code = _run(Dummy(), py(f"print('x'*{size})"), timeout=20)
    assert code == 0 and len(out.strip()) == size


def test_run_truncates_huge_output_without_blocking(monkeypatch):
    monkeypatch.setattr(heavy_tools, "MAX_OUTPUT_BYTES", 10_000)
    out, code = _run(Dummy(), py("print('x'*500000)"), timeout=20)
    assert code == 0 and len(out) == 10_000


def test_run_merges_stderr_and_keeps_accents():
    out, code = _run(Dummy(), py("import sys; print('año ñandú ✓'); print('aviso', file=sys.stderr)"), timeout=20)
    assert code == 0 and "año ñandú ✓" in out and "aviso" in out


def test_run_returns_the_exit_code_of_the_program():
    assert _run(Dummy(), py("import sys; print('x'); sys.exit(3)"), timeout=20)[1] == 3


def test_run_timeout_kills_the_program_and_says_so():
    start = time.time()
    out, code = _run(Dummy(), py("import time; time.sleep(60)"), timeout=1)
    assert (out, code) == ("⚠️ Timeout", -1) and time.time() - start < 10


def test_run_cancel_stops_the_program_quickly():
    tool = Dummy()
    tool._is_cancelled = True
    start = time.time()
    out, code = _run(tool, py("import time; time.sleep(60)"), timeout=60)
    assert out.startswith("🛑") and code == -1 and time.time() - start < 10


def test_run_missing_binary_is_reported():
    out, code = _run(Dummy(), ["programa-que-no-existe-xyz"], timeout=5)
    assert code == -1 and "no alojado" in out


def test_run_can_feed_a_script_through_stdin():
    out, code = _run(Dummy(), py("import sys; print(sys.stdin.read().upper())"), timeout=20, stdin_text="uno\ndos\n")
    assert code == 0 and "UNO" in out and "DOS" in out


# ── validación ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [("empresa.com", "empresa.com"), ("a b.com", ""), ("-evil", ""), ("sin-punto", ""), ("", ""),
                                            ("empresa.com\nshell id", "")])
def test_safe_domain(value, expected):
    assert _safe_domain(QueryParameters(domain=value)) == expected


@pytest.mark.parametrize("value,expected", [("jperez", "jperez"), ("@jperez", "jperez"), ("-evil", ""), ("--help", ""), ("a b", ""), ("", "")])
def test_safe_username(value, expected):
    assert _safe_username(QueryParameters(username=value)) == expected


def test_hostnames_keeps_only_valid_unique_hosts():
    out = "WWW.empresa.com\n[INF] Current version: 2.6\napi.empresa.com\nwww.empresa.com\n\n⚠️ Timeout\nno es host\n"
    assert _hostnames(out, "empresa.com") == ["www.empresa.com", "api.empresa.com"]
    assert len(_hostnames("\n".join(f"h{i}.empresa.com" for i in range(500)), "empresa.com")) == heavy_tools.MAX_RESULTS


def test_tool_failed_distinguishes_cancel_timeout_and_missing_program():
    tool = SubfinderTool()
    seen = progress_of(tool)
    assert _tool_failed(tool, "X", "salida", 0) is False and seen == []
    assert _tool_failed(tool, "X", "algo", 2) is False                                              # un código de error normal no es un aviso de _run
    assert _tool_failed(tool, "X", "🛑 Cancelado por el usuario", -1) and "cancelado" in seen[-1]
    assert _tool_failed(tool, "X", "⚠️ Timeout", -1) and "se agotó el tiempo" in seen[-1]
    assert _tool_failed(tool, "X", "❌ Error: Binario 'x' no alojado", -1) and "no alojado" in seen[-1]


# ── herramientas con `_run` simulado ─────────────────────────────────────────

@pytest.fixture
def fake_run(monkeypatch, tmp_path):
    state = {"calls": []}
    sf = tmp_path / "spiderfoot" / "sf.py"                  # SpiderFoot "clonado" (sin entorno propio)
    sf.parent.mkdir()
    sf.write_text("")
    monkeypatch.setattr(heavy_tools, "SPIDERFOOT_PATH", sf)
    monkeypatch.setattr(heavy_tools, "cloned_tool", lambda folder, script: None)

    def install(out="", rc=0):
        state["calls"].clear()

        def run(tool, cmd, timeout=300, stdin_text=""):
            state["calls"].append({"cmd": cmd, "timeout": timeout, "stdin": stdin_text})
            return out, rc
        monkeypatch.setattr(heavy_tools, "_run", run)
        monkeypatch.setattr(heavy_tools, "_find_go_binary", lambda name: f"/go/bin/{name}")
        monkeypatch.setattr(heavy_tools.shutil, "which", lambda name: f"/bin/{name}")
        return state
    return install


@pytest.mark.parametrize("tool_class,prefix,score", [(SubfinderTool, "Subdominio: ", 70), (AmassTool, "AMASS: ", 72)])
def test_subdomain_tools_list_only_real_hostnames(fake_run, tool_class, prefix, score):
    state = fake_run("www.empresa.com\napi.empresa.com\n[INF] Enumerating\nwww.empresa.com\n")
    results = tool_class().execute(QueryParameters(domain="empresa.com"))
    assert [r.title for r in results] == [prefix + "www.empresa.com", prefix + "api.empresa.com"]
    assert results[0].url == "https://www.empresa.com" and results[0].category == "Subdomain" and results[0].relevance_score == score
    assert "empresa.com" in state["calls"][0]["cmd"]


@pytest.mark.parametrize("tool_class", [SubfinderTool, AmassTool])
@pytest.mark.parametrize("out", ["⚠️ Timeout", "🛑 Cancelado por el usuario", "❌ Error: Binario 'x' no alojado localmente"])
def test_subdomain_tools_never_turn_a_warning_into_a_result(fake_run, tool_class, out):
    fake_run(out, rc=-1)                                                                            # antes: "Subdominio: ⚠️ Timeout" con url https://⚠️ Timeout
    tool = tool_class()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and seen


@pytest.mark.parametrize("tool_class", [SubfinderTool, AmassTool, ReconNgTool])
@pytest.mark.parametrize("domain", ["", "a b.com", "-evil", "sin-punto"])
def test_domain_tools_ignore_invalid_domains(fake_run, tool_class, domain):
    state = fake_run("www.empresa.com")
    assert tool_class().execute(QueryParameters(domain=domain)) == [] and state["calls"] == []


def test_subfinder_extra_args_are_appended(fake_run):
    state = fake_run("")
    SubfinderTool().execute(QueryParameters(domain="empresa.com", extra_args="-all -rl 10"))
    assert state["calls"][0]["cmd"][-3:] == ["-all", "-rl", "10"]


def test_spiderfoot_picks_a_real_observable_never_the_free_text_context(fake_run):
    state = fake_run("sfp_emails juan@empresa.com\n")
    SpiderFootTool().execute(QueryParameters(observable="ingeniero UDLA Ecuador", domain="empresa.com"))
    cmd = state["calls"][0]["cmd"]
    assert cmd[0] == sys.executable and cmd[2:4] == ["-s", "empresa.com"] and "ingeniero" not in " ".join(cmd)
    assert SpiderFootTool._pick_target(QueryParameters(observable="1.2.3.4", domain="x.com")) == "1.2.3.4"
    assert SpiderFootTool._pick_target(QueryParameters(observable="juan@empresa.com")) == "juan@empresa.com"
    assert SpiderFootTool._pick_target(QueryParameters(observable="solo texto libre")) == ""


def test_spiderfoot_results_errors_and_failures(fake_run):
    fake_run("dns A 1.2.3.4\n\nwhois registrante X\n")
    results = SpiderFootTool().execute(QueryParameters(domain="empresa.com"))
    assert [r.title for r in results] == ["SpiderFoot: dns A 1.2.3.4", "SpiderFoot: whois registrante X"]
    fake_run("Traceback (most recent call last):\nValueError: x")
    (crash,) = SpiderFootTool().execute(QueryParameters(domain="empresa.com"))
    assert crash.category == "Error" and "Error Crítico" in crash.title
    fake_run("⚠️ Timeout", rc=-1)
    assert SpiderFootTool().execute(QueryParameters(domain="empresa.com")) == []                    # antes: "SpiderFoot: ⚠️ Timeout" como hallazgo
    assert SpiderFootTool().execute(QueryParameters()) == []


def test_reconng_script_uses_the_domain_and_lists_matching_lines(fake_run):
    state = fake_run("| www.empresa.com | 1.2.3.4 |\n[*] 1 hosts\nnada.otro.org\nmail.empresa.com\n")
    results = ReconNgTool().execute(QueryParameters(domain="empresa.com"))
    assert [r.category for r in results] == ["Subdomain"] * 2 and "www.empresa.com" in results[0].title
    stdin = state["calls"][0]["stdin"]
    assert "db insert domains empresa.com\n" in stdin and stdin.rstrip().endswith("exit") and state["calls"][0]["cmd"] == ["/bin/recon-ng"]


@pytest.mark.parametrize("out,message", [("⚠️ Timeout", "se agotó el tiempo"), ("🛑 Cancelado por el usuario", "cancelado"),
                                         ("❌ Error: Binario no alojado", "no alojado")])
def test_reconng_reports_why_it_gave_nothing(fake_run, out, message):
    fake_run(out, rc=-1)
    tool = ReconNgTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(domain="empresa.com")) == [] and any(message in m for m in seen)


def test_maigret_never_gets_an_option_as_username_and_reports_timeouts(fake_run):
    state = fake_run("{}")
    for hostile in ("-evil", "--help", "a b", ""):
        assert MaigretTool().execute(QueryParameters(username=hostile)) == []
    assert state["calls"] == []
    fake_run("⚠️ Timeout", rc=-1)
    tool = MaigretTool()
    seen = progress_of(tool)
    assert tool.execute(QueryParameters(username="jperez")) == [] and any("se agotó el tiempo" in m for m in seen)   # antes: "Maigret no devolvió un JSON válido"


# ── Maigret: sitios que no pudo comprobar ────────────────────────────────────

MAIGRET_SUMMARY = (  # salida real (midudev, 2026-10-28)
    '[!] Too many errors of type "Bot protection" (9.97%). Try to switch to another ip address\n'
    '[!] Too many errors of type "Access denied" (3.22%). It\'s recommended to use --cloudflare-bypass\n'
    '[!] Too many errors of type "Unsupported username format" (12.86%)\n'
    '[!] Too many errors of type "Bot protection" (8.36%). Try to switch to another ip address\n')


def test_maigret_usual_bot_protection_is_information_not_a_network_warning():
    from osint_app.tools.heavy_tools import maigret_unchecked_sites
    msg = maigret_unchecked_sites(MAIGRET_SUMMARY)
    assert msg.startswith("ℹ️") and "protección anti-bots 10 %" in msg and "DNS" not in msg
    assert "formato" not in msg                     # "Unsupported username format" no es un fallo


def test_maigret_many_unchecked_sites_is_a_warning():
    from osint_app.tools.heavy_tools import maigret_unchecked_sites
    msg = maigret_unchecked_sites(MAIGRET_SUMMARY + '[!] Too many errors of type "Connecting failure" (22.1%)\n')
    assert msg.startswith("⚠️") and "conexión 22 %" in msg
    assert maigret_unchecked_sites("") == ""
