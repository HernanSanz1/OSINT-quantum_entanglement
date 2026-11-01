"""Decisiones del 31-10-2026: botón «Enviar» del boletín como borrador de correo, y aviso al guardar informes."""
import email
from email import policy

import pytest

from osint_app.utils import mail_draft

PAGE = """<!DOCTYPE html><html><head><title>Altel</title><style>
body { font-family: Arial, sans-serif; color: #333; }
h2 { color: #0074a6; font-size: 20px; }
.info-button { color: #ffffff; background-color: #0097db; }
.info-button:hover { background-color: #0056b3; }
header::before { content: ""; }
header img { max-width: 230px; }
</style></head><body><header><img src="https://x/logo.png"><h1>Boletín</h1></header>
<p>Boletín preparado para <strong>XTRIM</strong>. Se priorizan sus tecnologías.</p>
<h2 style="color: red">Amenaza</h2>
<ul><li><strong>Fallo en FortiGate:</strong> Hay que actualizar.<a class="info-button" href="https://ejemplo.ec/a">Leer Más</a></li></ul>
</body></html>"""


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    return tmp_path


def test_client_and_subject_from_file_name():
    assert mail_draft.bulletin_client("AltelThreatIntell_2026W44_XTRIM.html") == "XTRIM"
    assert mail_draft.bulletin_client("AltelThreatIntell_2026W44.html") == "GLOBAL"
    assert mail_draft.bulletin_client("otro.html") == "GLOBAL"
    assert mail_draft.bulletin_subject("AltelThreatIntell_2026W44_XTRIM.html") == \
        "Boletín de ciberamenazas: semana 44 de 2026 (XTRIM)"
    assert mail_draft.bulletin_subject("AltelThreatIntell_20261029.html") == "Boletín de ciberamenazas del 29-10-2026"


def test_parse_addresses_separates_invalid_and_repeated():
    valid, invalid = mail_draft.parse_addresses("soc@xtrim.com.ec; <ana@x.ec>, malo@ ,SOC@xtrim.com.ec\nb@c.io")
    assert valid == ["soc@xtrim.com.ec", "ana@x.ec", "b@c.io"]
    assert invalid == ["malo@"]


def test_recipients_are_remembered_per_client_and_cross_client_detected(data):
    assert mail_draft.load_recipients() == {}
    mail_draft.save_recipients("CER", ["soc@cer.ec"])
    mail_draft.save_recipients("XTRIM", ["soc@xtrim.ec"])
    assert mail_draft.load_recipients() == {"CER": ["soc@cer.ec"], "XTRIM": ["soc@xtrim.ec"]}
    # El boletín de XTRIM a una dirección guardada para CER: hay que avisar
    assert mail_draft.other_client_addresses("XTRIM", ["SOC@cer.ec", "nuevo@x.ec", "soc@xtrim.ec"]) == {"SOC@cer.ec": "CER"}
    assert (data / "cti" / "destinatarios.json").exists()


def test_broken_recipients_file_is_ignored(data):
    (data / "cti").mkdir()
    (data / "cti" / "destinatarios.json").write_text("{roto", encoding="utf-8")
    assert mail_draft.load_recipients() == {}


def test_email_html_inlines_styles_without_overriding_own_ones():
    out = mail_draft.email_html(PAGE)
    assert "<style" not in out
    assert out.startswith('<div style="font-family: Arial, sans-serif; color: #333;')
    # La regla de h2 va primero y el style propio al final (manda el propio, como en el navegador)
    assert 'style="color: #0074a6; font-size: 20px; color: red"' in out
    assert "background-color: #0097db" in out and "#0056b3" not in out      # sin :hover
    assert 'max-width: 230px' in out                                         # «header img»
    assert 'content: ""' not in out                                          # sin ::before


def test_plain_text_keeps_sentences_whole_and_links():
    text = mail_draft.plain_text(PAGE)
    assert "Boletín preparado para XTRIM. Se priorizan sus tecnologías." in text
    assert "Hay que actualizar. Leer Más (https://ejemplo.ec/a)" in text
    assert "Altel" not in text                                               # el <title> no es del cuerpo


def test_draft_is_an_unsent_email_with_both_versions(data):
    bulletin = data / "AltelThreatIntell_2026W44_XTRIM.html"
    bulletin.write_text(PAGE, encoding="utf-8")
    draft = mail_draft.write_draft(bulletin, ["soc@xtrim.ec", "ana@x.ec"])
    assert draft == data / "cti" / "boletines" / "borradores" / "AltelThreatIntell_2026W44_XTRIM.eml"
    msg = email.message_from_bytes(draft.read_bytes(), policy=policy.default)
    assert msg["X-Unsent"] == "1"                 # Outlook lo abre como correo nuevo, editable
    assert msg["Subject"] == "Boletín de ciberamenazas: semana 44 de 2026 (XTRIM)"
    assert msg["To"] == "soc@xtrim.ec, ana@x.ec"
    assert "From" not in msg                      # sale de la cuenta de quien lo envía
    assert "Fallo en FortiGate" in msg.get_body(("html",)).get_content()
    assert "Fallo en FortiGate" in msg.get_body(("plain",)).get_content()


def test_draft_without_recipients_has_no_to(data):
    bulletin = data / "AltelThreatIntell_2026W44.html"
    bulletin.write_text(PAGE, encoding="utf-8")
    msg = email.message_from_bytes(mail_draft.write_draft(bulletin, []).read_bytes(), policy=policy.default)
    assert "To" not in msg and msg["Subject"] == "Boletín de ciberamenazas: semana 44 de 2026"


def test_saved_message_says_where_and_warns_for_cloud(data, monkeypatch):
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from osint_app.gui import reports_folder
    from osint_app.utils.data_paths import private_reports_dir
    text, kind = reports_folder.saved_message(private_reports_dir() / "Ficha_x.html", "Ficha")
    assert (text, kind) == ("Ficha guardada en tu carpeta privada de informes", "success")
    other = data / "otra"
    text, kind = reports_folder.saved_message(other / "f.pdf", "Ficha en PDF")
    assert kind == "success" and str(other) in text
    monkeypatch.setattr(reports_folder, "synced_warning", lambda folder: "nube")
    text, kind = reports_folder.saved_message(other / "f.pdf", "Ficha en PDF")
    assert kind == "warning" and "se sube a la nube" in text


def test_announce_saved_adds_open_folder_button(data, monkeypatch):
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from osint_app.gui import reports_folder
    calls, opened = [], []

    class Toast:
        def show(self, text, kind="info", action=None):
            calls.append((text, kind, action))

    app = type("App", (), {"toast": Toast()})()
    monkeypatch.setattr(reports_folder, "show_in_folder", opened.append)
    reports_folder.announce_saved(app, data / "f.json", "Exportación del perfil")
    text, kind, (label, callback) = calls[0]
    assert label == "📂 Abrir carpeta"
    callback()
    assert opened == [data / "f.json"]


def test_toast_action_button_runs_callback_and_lasts_longer():
    QtWidgets = pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    from osint_app.gui.components import Toast
    parent = QtWidgets.QWidget()
    clicked = []
    toast = Toast(parent, "Ficha guardada", "success", action=("📂 Abrir carpeta", lambda: clicked.append(1)))
    assert toast.timer.interval() == 10000
    toast.action_button.click()
    assert clicked == [1]
    assert Toast(parent, "hola", "info").timer.interval() == 3000
    del app


def test_mailto_and_webmail_links_carry_recipients_and_subject():
    subject = "Boletín de ciberamenazas: semana 44 de 2026 (XTRIM)"
    assert mail_draft.mailto_url(["soc@x.ec", "ana+cti@y.ec"], subject) == (
        "mailto:soc@x.ec,ana%2Bcti@y.ec?subject=Bolet%C3%ADn%20de%20ciberamenazas%3A%20semana%2044%20de%202026"
        "%20%28XTRIM%29")
    gmail = mail_draft.webmail_url("gmail", ["soc@x.ec", "b@y.ec"], subject)
    assert gmail.startswith("https://mail.google.com/mail/?view=cm&fs=1&to=soc@x.ec,b@y.ec&su=Bolet%C3%ADn")
    outlook = mail_draft.webmail_url("outlook", [], subject)
    assert outlook.startswith("https://outlook.office.com/mail/deeplink/compose?to=&subject=Bolet%C3%ADn")


def test_eml_handler_ignores_the_choose_an_app_dialog(monkeypatch):
    # Fuera de Windows no hay asociaciones que consultar; en Windows, «Elegir una aplicación» no cuenta como programa
    monkeypatch.setattr(mail_draft.sys, "platform", "linux")
    assert mail_draft.eml_handler() == ""
