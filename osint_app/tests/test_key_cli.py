"""Guardar claves de API por consola: oculta, sin mostrarla y sin tocar el baúl real en los tests."""
import sys

import pytest

from osint_app import main as main_module
from osint_app.utils import key_cli, secret_vault
from osint_app.utils.secret_vault import SecretVault

SECRET = "ghp_CLAVE_SECRETA_DE_PRUEBA_123"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    for var in ("GITHUB_TOKEN", "OSINT_HUNTER_KEY", "OSINT_CENSYS_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(secret_vault, "dpapi", type("NoDpapi", (), {"AVAILABLE": False}))     # texto plano: se puede inspeccionar
    v = SecretVault(tmp_path / "keys")
    monkeypatch.setattr(key_cli, "default_vault", v)
    return v


def run(name, answer, v, capsys):
    out = []
    code = key_cli.set_key_interactive(name, ask=lambda prompt: answer, say=out.append, v=v)
    return code, "\n".join(out)


@pytest.mark.parametrize("typed", ["GitHub", "github", " GITHUB ", "gitHub"])
def test_set_key_is_case_insensitive_and_saves(vault, capsys, typed):
    code, out = run(typed, SECRET, vault, capsys)
    assert code == 0 and vault.get("GitHub") == SECRET
    assert SECRET not in out and "Clave de GitHub guardada" in out                        # nunca se repite en pantalla


def test_empty_or_blank_answer_saves_nothing(vault, capsys):
    for answer in ("", "   ", None):
        code, out = run("GitHub", answer, vault, capsys)
        assert code == 1 and "no se guardó nada" in out
    assert vault.get("GitHub") == "" and vault.all_names() == []


def test_unknown_name_lists_the_valid_ones_and_asks_nothing(vault):
    out = []

    def never(prompt):
        raise AssertionError("no debe pedir nada")
    assert key_cli.set_key_interactive("Inventada", ask=never, say=out.append, v=vault) == 2
    text = "\n".join(out)
    assert "Inventada" in text and "GitHub" in text and "Hunter.io" in text


def test_prompt_never_contains_a_value_and_trims_whitespace(vault):
    asked = []
    key_cli.set_key_interactive("Hunter.io", ask=lambda p: (asked.append(p) or f"  {SECRET}\n"), say=lambda m: None, v=vault)
    assert asked and SECRET not in asked[0] and vault.get("Hunter.io") == SECRET


def test_warns_when_an_environment_variable_overrides(vault, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "del-entorno")
    out = []
    key_cli.set_key_interactive("GitHub", ask=lambda p: SECRET, say=out.append, v=vault)
    assert any("GITHUB_TOKEN" in line and "prioridad" in line for line in out)


def test_show_keys_never_prints_values(vault):
    vault.set("GitHub", SECRET)
    out = []
    key_cli.show_keys(say=out.append, v=vault)
    text = "\n".join(out)
    assert SECRET not in text and "GitHub" in text and "Hunter.io" in text and "set via vault" in text and "not configured" in text


# ── conexión con el programa principal ───────────────────────────────────────

def test_main_keys_option(vault, monkeypatch, capsys):
    vault.set("Hunter.io", SECRET)
    monkeypatch.setattr(sys, "argv", ["main", "--keys"])
    with pytest.raises(SystemExit) as exit_info:
        main_module.main()
    assert exit_info.value.code == 0
    printed = capsys.readouterr().out
    assert "Hunter.io" in printed and SECRET not in printed


def test_main_set_key_option_asks_hidden_and_saves(vault, monkeypatch, capsys):
    asked = []
    monkeypatch.setattr(key_cli.getpass, "getpass", lambda prompt: (asked.append(prompt) or SECRET))
    monkeypatch.setattr(sys, "argv", ["main", "--set-key", "github"])
    with pytest.raises(SystemExit) as exit_info:
        main_module.main()
    assert exit_info.value.code == 0 and vault.get("GitHub") == SECRET
    assert asked and SECRET not in capsys.readouterr().out


def test_the_key_is_not_accepted_as_a_command_argument(monkeypatch):
    # "--set-key GitHub ghp_xxx" dejaría la clave en el historial de la consola: debe rechazarse
    monkeypatch.setattr(sys, "argv", ["main", "--set-key", "GitHub", SECRET])
    with pytest.raises(SystemExit) as exit_info:
        main_module.main()
    assert exit_info.value.code == 2                                  # error de uso de argparse, no se guarda nada
