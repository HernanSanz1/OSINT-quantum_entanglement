"""Ficha de persona: qué cuentas son suyas, cuáles de otra persona y cuáles solo hablan de ella.

Los casos salen de perfiles reales de figuras públicas (Jefferson Pérez, Andersson Boscán, Luisito Comunica;
2026-10-21). Enfoque A: nada se borra, se separa con su motivo.
"""
from osint_app.reports.person_report import build_person_report, render_person_html


def cand(url, score, source="WebSearch", **extra):
    return {"source": source, "url": url, "title": url, "snippet": "", "confidence": score,
            "category": "Social Media", "warning": "", "extra": extra}


def official(url, platform):
    return cand(url, 85, "Wikidata", platform=platform, official=True, name="Persona")


def report(seed, cands):
    r = build_person_report(seed, cands)
    return r, {a["url"]: a for a in r["accounts"]}, {h["url"]: h["warning"] for h in r["homonyms"]}


LUISITO = {"name": "Luis Arturo Villar Sudek", "aliases": ["Luisito Comunica"], "country": "México"}


def test_official_youtube_channel_is_his_even_without_his_name_in_the_url():
    # Antes: canal oficial de Wikidata (UCLCCMz3…) con 50 puntos → "otra persona" frente a @anderssonboscan
    _, accounts, homonyms = report({"name": "Andersson Boscán"}, [
        official("https://www.youtube.com/channel/UCLCCMz3exOqYc59IN0VOLlA", "YouTube"),
        cand("https://www.youtube.com/@anderssonboscan", 70),
    ])
    assert "https://www.youtube.com/channel/UCLCCMz3exOqYc59IN0VOLlA" in accounts and not homonyms
    assert accounts["https://www.youtube.com/channel/UCLCCMz3exOqYc59IN0VOLlA"]["official"]


def test_same_username_as_a_verified_account_is_kept_with_a_note():
    # reypalomo_ es un alias oficial de Luisito (Instagram en Wikidata); su TikTok no es "otra persona"
    _, accounts, homonyms = report(LUISITO, [
        official("https://www.instagram.com/reypalomo_", "Instagram"),
        official("https://www.tiktok.com/@LuisitoComunica", "TikTok"),
        cand("https://www.tiktok.com/@reypalomo_", 30, "Maigret"),
    ])
    tiktok = accounts["https://www.tiktok.com/@reypalomo_"]
    assert "Mismo usuario" in tiktok["note"] and not homonyms


def test_profile_without_anything_of_the_name_is_a_mention_not_an_account():
    r, accounts, homonyms = report(LUISITO, [
        official("https://x.com/LuisitoComunica", "X/Twitter"),
        cand("https://in.linkedin.com/in/net-worth-fever", 50),
        cand("https://ar.linkedin.com/in/agust%C3%ADn-dom%C3%ADnguez-prieto-368639314", 40),
        cand("https://www.linkedin.com/in/luis-arturo-villar-sudek-5761942", 40),
    ])
    mentions = [m["url"] for m in r["mentions"]]
    assert "https://in.linkedin.com/in/net-worth-fever" in mentions
    assert "https://ar.linkedin.com/in/agust%C3%ADn-dom%C3%ADnguez-prieto-368639314" in mentions
    assert "https://www.linkedin.com/in/luis-arturo-villar-sudek-5761942" in accounts      # lleva su nombre
    assert not homonyms


def test_low_confidence_name_only_match_is_another_person():
    # GitHub de un desarrollador llamado igual, sacado de una variante del nombre
    _, accounts, homonyms = report({"name": "Jefferson Pérez Quezada"}, [
        official("https://x.com/jeffersonperezq", "X/Twitter"),
        cand("https://github.com/jefferson-quezada", 25, "UsernameVariants"),
    ])
    assert "https://github.com/jefferson-quezada" not in accounts
    assert "solo coincide el nombre" in homonyms["https://github.com/jefferson-quezada"]


def test_other_account_on_a_platform_with_a_clear_one_is_another_person():
    _, accounts, homonyms = report(LUISITO, [
        official("https://x.com/LuisitoComunica", "X/Twitter"),
        cand("https://x.com/LuisiComunica", 50),
    ])
    assert "más probable es @luisitocomunica" in homonyms["https://x.com/LuisiComunica"]


def test_confirmed_by_the_analyst_always_stays():
    r = build_person_report({"name": "Jefferson Pérez Quezada"},
                            [cand("https://github.com/jefferson-quezada", 25)],
                            confirmed_urls=["https://github.com/jefferson-quezada"])
    assert [a["url"] for a in r["accounts"]] == ["https://github.com/jefferson-quezada"]


def test_youtube_subpage_is_grouped_with_the_channel_and_named_from_the_path():
    # Antes salía como cuenta aparte "canal channels?app=desktop&shelf_id=2"
    r, accounts, _ = report({"name": "Andersson Boscán"}, [
        cand("https://www.youtube.com/@anderssonboscan", 70),
        cand("https://www.youtube.com/c/AnderssonBoscan/channels?app=desktop&shelf_id=2", 70),
    ])
    assert len(r["accounts"]) == 1 and "channels?" not in r["accounts"][0]["handle"]


def test_html_shows_official_and_the_note():
    r = build_person_report(LUISITO, [official("https://www.instagram.com/reypalomo_", "Instagram"),
                                      cand("https://t.me/reypalomo_", 30, "Maigret")])
    page = render_person_html(r)
    assert "Oficial (Wikidata)" in page and "Mismo usuario que una de sus cuentas verificadas" in page
