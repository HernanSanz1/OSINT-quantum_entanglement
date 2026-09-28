"""Soporte opcional de token de GitHub (sube el límite de 60 a 5.000/hora)."""
from osint_app.tools.web_search import github_headers


def test_no_token_no_authorization(monkeypatch):
    from osint_app.utils import secret_vault
    monkeypatch.setattr(secret_vault.vault, "get", lambda name: "")
    h = github_headers()
    assert "Authorization" not in h
    assert h["User-Agent"] and h["Accept"]


def test_token_from_vault_adds_bearer(monkeypatch):
    from osint_app.utils import secret_vault
    monkeypatch.setattr(secret_vault.vault, "get",
                        lambda name: "ghp_test123" if name == "GitHub" else "")
    h = github_headers()
    assert h["Authorization"] == "Bearer ghp_test123"


def test_explicit_token_overrides_vault():
    assert github_headers("abc")["Authorization"] == "Bearer abc"


def test_vault_maps_github_to_env(monkeypatch):
    # La clave "GitHub" toma la variable de entorno estándar GITHUB_TOKEN.
    from osint_app.utils.secret_vault import SecretVault
    monkeypatch.setenv("GITHUB_TOKEN", "env_tok")
    assert SecretVault().get("GitHub") == "env_tok"
