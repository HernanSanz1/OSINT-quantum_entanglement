"""Métrica real de la detección de homónimos (por señal de país).

Conjunto etiquetado que mide precisión/recall/exactitud del detector actual
(enfoque A: aviso por país claramente distinto) y sirve de regresión. Ejecuta
con `-s` para ver el reporte de números.
"""
from osint_app.utils.homonyms import homonym_warning


# (texto del candidato, país objetivo, debería_marcarse)
# Homónimos con señal de país ajeno → SÍ deben marcarse.
SIGNAL_HOMONYMS = [
    ("Juan Perez - Madrid, Spain", "Ecuador", True),
    ("John Smith, based in USA", "Ecuador", True),
    ("Perfil de Berlín, Germany", "Colombia", True),
    ("Software engineer in England", "Ecuador", True),
    ("Vive en France desde 2010", "Perú", True),
    ("Profile located in China", "Ecuador", True),
    ("Trabaja en Toronto, Canada", "Ecuador", True),
    ("Based in Sydney, Australia", "Colombia", True),
    ("Desde España, Madrid", "Ecuador", True),
    ("Developer from India (Bangalore)", "Ecuador", True),
]

# Buenos candidatos (mismo país/región o sin señal) → NO deben marcarse.
# Incluye trampas: 'usa' (verbo), 'Indiana', 'causa', etc.
GOOD_CANDIDATES = [
    ("Juan Perez - Quito, Ecuador", "Ecuador", False),
    ("Ingeniero de software, sin ubicación", "Ecuador", False),
    ("El objetivo usa varias herramientas de red", "Ecuador", False),   # 'usa' verbo
    ("Con una causa legal pendiente en Guayaquil", "Ecuador", False),   # 'causa'
    ("Vive en Indiana... digo, en Quito", "Ecuador", False),            # 'Indiana' ≠ India
    ("Perfil en Bogotá, Colombia", "Ecuador", False),                   # LATAM, no ajeno
    ("Radica en Lima, Perú", "Ecuador", False),                         # LATAM
    ("Estudiante en la UDLA, Ecuador", "Ecuador", False),
    ("Usuario activo en foros", "Ecuador", False),                      # 'Usuario' ≠ USA
    ("Trabaja en la industria del calzado", "Ecuador", False),          # 'industria' no dispara
]

# Homónimos SIN señal de país: el detector NO puede detectarlos (limitación
# conocida del enfoque A). Se documenta como recall fuera de alcance.
NO_SIGNAL_HOMONYMS = [
    ("Pedro Gomez, contador jubilado", "Ecuador"),
    ("Otra persona con el mismo nombre", "Ecuador"),
    ("Perfil profesional en LinkedIn", "Ecuador"),
]


def _flagged(text, country):
    return homonym_warning(text, country) is not None


def _confusion(cases):
    tp = fp = tn = fn = 0
    for text, country, should in cases:
        got = _flagged(text, country)
        if should and got:
            tp += 1
        elif should and not got:
            fn += 1
        elif not should and got:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def test_homonym_detection_metrics(capsys):
    cases = SIGNAL_HOMONYMS + GOOD_CANDIDATES
    tp, fp, tn, fn = _confusion(cases)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    accuracy = (tp + tn) / len(cases)

    # Limitación: homónimos sin señal de país (fuera de alcance)
    missed = sum(1 for text, country in NO_SIGNAL_HOMONYMS if not _flagged(text, country))

    with capsys.disabled():
        print("\n=== MÉTRICA HOMÓNIMOS (detección por señal de país) ===")
        print(f"Casos evaluados: {len(cases)} (homónimos con señal: {len(SIGNAL_HOMONYMS)}, "
              f"buenos: {len(GOOD_CANDIDATES)})")
        print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
        print(f"Precisión: {precision:.0%}  |  Recall: {recall:.0%}  |  Exactitud: {accuracy:.0%}")
        print(f"Limitación conocida (homónimos SIN señal de país): "
              f"{missed}/{len(NO_SIGNAL_HOMONYMS)} no detectados (esperado).")

    # Garantías (regresión):
    assert fp == 0, "No debe marcar buenos candidatos como homónimos (precisión 100%)"
    assert recall == 1.0, "Debe detectar todos los homónimos con señal de país"
    assert missed == len(NO_SIGNAL_HOMONYMS), "Los sin-señal quedan fuera de alcance (esperado)"
