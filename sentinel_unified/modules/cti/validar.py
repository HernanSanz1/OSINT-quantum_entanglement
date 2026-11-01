#!/usr/bin/env python3
"""Revisión del boletín antes de enviarlo a un cliente: lo que la evaluación 4 tuvo que encontrar a mano.

Uso: python validar.py RUTA_DEL_BOLETIN.html   → imprime un JSON con el número de noticias y la lista de problemas.

Comprueba en cada noticia: frase cortada (el texto acaba sin punto justo antes de «Leer más»), párrafo en inglés,
enlace a la fuente, producto dudoso en «Afecta a …» y títulos repetidos; y en el boletín, secciones vacías y que
el de un cliente lo diga. No cambia el boletín: solo informa.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

from render import is_english

_ITEM = re.compile(r"<(li|p)\b[^>]*>(.*?)</\1>", re.S | re.I)
_SECTION = re.compile(r"<h2[^>]*>(.*?)</h2>(.*?)(?=<h2|</body>|$)", re.S | re.I)
_BUTTON = re.compile(r"<a\b[^>]*class=\"info-button\"[^>]*>.*?</a>", re.S | re.I)
_ORIGINAL_TITLE = re.compile(r"Titular original \(en inglés\):\s*«[^»]*»\.?", re.I)
_AFFECTS = re.compile(r"Afecta a ([^.]+?)\.(?:\s|$)")
# Un producto no lleva preposiciones inglesas ni nombres de tipos de fallo: "Microsoft Integer Overflow or Wraparound
# in GitLab" (evaluación 4) es la descripción del fallo, no el producto
_BAD_PRODUCT = re.compile(r"producto afectado no especificado|^[a-z0-9_/.-]+:|\b(?:in|or|of|via|the)\b|overflow|"
                          r"wraparound|injection|traversal|deserialization|use.after.free", re.I)
# Texto de la fuente cortado: "…incluido en Leer más ...", "[...]"
_TRUNCATED = re.compile(r"Leer m[aá]s\s*(?:\.\.\.|…)|\[\s*(?:\.\.\.|…)\s*\]|(?:\.\.\.|…)\s*Fuente principal", re.I)
REPEATED_PRODUCT = 3
_END_OK = re.compile(r"[.!?»)\"”]\s*$")
_NO_ITEMS_OK = {"referencias"}            # la lista de enlaces del final


def _text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def _client(path: Path) -> str:
    # AltelThreatIntell_2026W44_XTRIM.html o AltelThreatIntell_20261029_XTRIM.html
    match = re.search(r"_(?:\d{8}|\d{4}W\d{2})_([A-Z][A-Z0-9]+)\.html$", path.name)
    return match.group(1) if match and match.group(1) != "GLOBAL" else ""


def validate(page: str, client: str = "") -> dict:
    """{"noticias": n, "problemas": [{"tipo", "seccion", "titulo", "detalle"}]} del HTML de un boletín."""
    body = re.sub(r"<(style|script)\b.*?</\1>", "", page, flags=re.S | re.I)
    problems, seen, total, products = [], {}, 0, {}

    def add(kind, section, title, detail):
        problems.append({"tipo": kind, "seccion": section, "titulo": title[:90], "detalle": detail})

    for raw_heading, content in _SECTION.findall(body):
        section = _text(raw_heading)
        key = re.sub(r"[^a-záéíóúñ ]", "", section.lower()).strip()
        # Un <p> sin título en negrita ni enlace es un texto de la sección (introducción, nota), no una noticia
        items = [m.group(2) for m in _ITEM.finditer(content) if _text(m.group(2))
                 and (m.group(1).lower() == "li" or re.search(r"<(?:strong|a)\b", m.group(2), re.I))]
        # Que nada nombre las tecnologías del cliente es una buena noticia, no un fallo del boletín
        if not items and key not in _NO_ITEMS_OK and not key.startswith("lo que afecta"):
            add("sección vacía", section, "", "La sección no tiene ninguna noticia.")
        if key in _NO_ITEMS_OK:
            continue
        for item in items:
            total += 1
            # Título: en negrita en las noticias; en los CVE es el propio enlace ("CVE-2026-… CVSS 10.0 CRÍTICA")
            title_match = (re.search(r"<strong>(.*?)</strong>", item, re.S)
                           or re.match(r"\s*<a\b(?![^>]*info-button)[^>]*>(.*?)</a>", item, re.S))
            title = _text(title_match.group(1)).rstrip(":") if title_match else ""
            text = _text(_BUTTON.sub("", item))
            body_text = text[len(_text(title_match.group(1))):].lstrip(": ").strip() if title_match else text
            if not re.search(r"href=\"https?://", item):
                add("sin enlace", section, title, "La noticia no enlaza a su fuente.")
            cut = _TRUNCATED.search(body_text)
            if cut:
                start = max(0, cut.start() - 50)
                add("frase cortada", section, title, f"El texto de la fuente está cortado: «…{body_text[start:cut.end()]}»")
            elif body_text and not _END_OK.search(body_text):
                add("frase cortada", section, title, f"Termina así: «…{body_text[-60:]}»")
            if is_english(_ORIGINAL_TITLE.sub("", body_text)):
                add("en inglés", section, title, f"Empieza así: «{body_text[:80]}…»")
            affects = _AFFECTS.search(text)
            if affects:
                product = affects.group(1).strip()
                products.setdefault(product, []).append(section)
                if _BAD_PRODUCT.search(product):
                    add("producto dudoso", section, title, f"Dice «Afecta a {product}»: eso no parece un producto.")
            norm = re.sub(r"\W+", " ", title.lower()).strip()
            if norm and norm in seen:
                add("título repetido", section, title, f"Ya aparece en «{seen[norm]}».")
            elif norm:
                seen[norm] = section
    for product, sections in products.items():
        if len(sections) >= REPEATED_PRODUCT:
            add("producto repetido", sections[0], "", f"«{product}» aparece {len(sections)} veces: conviene agruparlas "
                                                      f"en una sola entrada para dejar sitio a otras amenazas.")
    if client and f"preparado para {client}".lower() not in _text(body).lower():
        add("cliente", "", "", f"Es el boletín de {client} pero no lo dice («Boletín preparado para {client}»).")
    return {"noticias": total, "problemas": problems}


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python validar.py BOLETIN.html", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    result = validate(path.read_text(encoding="utf-8"), _client(path))
    print(json.dumps({"archivo": str(path), **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
