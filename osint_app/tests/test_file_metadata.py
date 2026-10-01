"""File Metadata: EXIF, PDF y Office con archivos sintéticos de metadatos conocidos (sin red)."""
import io
import zipfile

import pytest
from PIL import Image

from osint_app.core.models import QueryParameters
from osint_app.tools import file_metadata as fm
from osint_app.tools.file_metadata import (
    FileMetadataTool, build_findings, detect_kind, exif_date, gps_to_decimal, has_metadata,
    inspect_bytes, parse_office_xml, pdf_date,
)


# ── archivos de prueba ───────────────────────────────────────────────────────

def make_jpeg(with_exif=True) -> bytes:
    ex = Image.Exif()
    if with_exif:
        ex[0x010F], ex[0x0110] = "Canon", "EOS 80D"
        ex[0x0131], ex[0x013B], ex[0x0132] = "Adobe Photoshop 25.0", "Juan Perez", "2024:03:05 14:07:09"
        ex[0x8769] = {0x9003: "2024:03:05 14:07:09", 0xA431: "123456789", 0xA434: "EF 50mm"}
        ex[0x8825] = {1: "S", 2: (2.0, 12.0, 30.0), 3: "W", 4: (78.0, 30.0, 0.0)}
    buf = io.BytesIO()
    Image.new("RGB", (8, 6), "red").save(buf, "JPEG", exif=ex)      # Exif vacío = sin etiquetas
    return buf.getvalue()


def make_pdf(meta=None) -> bytes:
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(100, 100)
    if meta:
        w.add_metadata(meta)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


CORE = (b'<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        b'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        b'<dc:creator>Maria Lopez</dc:creator><cp:lastModifiedBy>Carlos Ruiz</cp:lastModifiedBy>'
        b'<dcterms:created>2023-05-10T08:00:00Z</dcterms:created><dc:title>Informe</dc:title></cp:coreProperties>')
APP = (b'<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
       b'<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion><Company>Empresa SA</Company></Properties>')


def make_office(core=CORE, app=APP) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<x/>")
        if core is not None:
            zf.writestr("docProps/core.xml", core)
        if app is not None:
            zf.writestr("docProps/app.xml", app)
    return buf.getvalue()


# ── utilidades ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("head,kind", [
    (b"\xff\xd8\xff\xe0", "image"), (b"\x89PNG\r\n\x1a\n", "image"), (b"RIFF\x00\x00\x00\x00WEBP", "image"),
    (b"II*\x00", "image"), (b"%PDF-1.7", "pdf"), (b"PK\x03\x04", "zip"), (b"<html>", ""), (b"", ""),
])
def test_detect_kind(head, kind):
    assert detect_kind(head) == kind


@pytest.mark.parametrize("dms,ref,expected", [
    ((2.0, 12.0, 30.0), "S", -2.208333), ((78.0, 30.0, 0.0), "W", -78.5),
    ((40.0, 26.0, 46.0), "N", 40.446111), ((10.0, 0.0, 0.0), "E", 10.0),
    ((95.0, 0.0, 0.0), "N", None),          # latitud fuera de rango
    ((190.0, 0.0, 0.0), "E", None),         # longitud fuera de rango
    ((1.0, 2.0, 3.0), "X", None), (None, "N", None), ((1.0, 2.0), "N", None), (("a", 1, 2), "N", None),
    ((float("nan"), 0.0, 0.0), "N", None),
])
def test_gps_to_decimal(dms, ref, expected):
    assert gps_to_decimal(dms, ref) == expected


def test_dates():
    assert exif_date("2024:03:05 14:07:09") == "2024-03-05 14:07:09"
    assert exif_date(b"2024:03:05 14:07:09\x00") == "2024-03-05 14:07:09"
    assert pdf_date("D:20240115103000+01'00'") == "2024-01-15 10:30:00 UTC+01:00"
    assert pdf_date("D:20220606111519-07'00'") == "2022-06-06 11:15:19 UTC-07:00"
    assert pdf_date("D:20240115103000Z") == "2024-01-15 10:30:00 UTC"
    assert pdf_date("D:20240115103000") == "2024-01-15 10:30:00"
    assert pdf_date("D:2020") == "2020-01-01 00:00:00"


# ── imágenes ─────────────────────────────────────────────────────────────────

def test_image_with_full_exif():
    info = inspect_bytes(make_jpeg())
    assert (info["camera_make"], info["camera_model"]) == ("Canon", "EOS 80D")
    assert info["software"] == "Adobe Photoshop 25.0" and info["artist"] == "Juan Perez"
    assert info["camera_serial"] == "123456789" and info["lens"] == "EF 50mm"
    assert info["taken"] == "2024-03-05 14:07:09"
    assert info["gps"]["lat"] == -2.208333 and info["gps"]["lon"] == -78.5
    assert "openstreetmap.org" in info["gps"]["maps"]
    assert info["format"] == "JPEG" and info["size"] == "8x6"
    sev = {s for s, _ in build_findings(info)}
    assert sev == {"alta", "media"}


def test_image_without_exif_has_no_metadata():
    info = inspect_bytes(make_jpeg(with_exif=False))
    assert info["kind"] == "imagen" and not has_metadata(info) and build_findings(info) == []


def test_exif_timezone_offset():
    ex = Image.Exif()
    ex[0x8769] = {0x9003: "2024:03:05 14:07:09", 0x9011: "-05:00"}
    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, "JPEG", exif=ex)
    assert inspect_bytes(buf.getvalue())["taken"] == "2024-03-05 14:07:09 UTC-05:00"


def test_png_text_chunks():
    from PIL.PngImagePlugin import PngInfo
    meta = PngInfo()
    meta.add_text("Author", "Ana Mora")
    meta.add_text("Software", "GIMP 2.10")
    buf = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf, "PNG", pnginfo=meta)
    info = inspect_bytes(buf.getvalue())
    assert info["author"] == "Ana Mora" and info["software"] == "GIMP 2.10"


def test_corrupt_or_foreign_files_return_none():
    inspect_bytes(make_jpeg()[:60])          # truncado: no debe lanzar excepción
    assert inspect_bytes(b"<html><body>hola</body></html>") is None
    assert inspect_bytes(b"%PDF-1.4 basura") is None
    assert inspect_bytes(b"") is None


# ── PDF ──────────────────────────────────────────────────────────────────────

def test_pdf_metadata():
    info = inspect_bytes(make_pdf({"/Author": "Maria Lopez", "/Creator": "Word",
                                   "/Producer": "Microsoft Word 2016", "/CreationDate": "D:20240115103000+01'00'"}))
    assert info["kind"] == "PDF" and info["pages"] == 1
    assert info["author"] == "Maria Lopez" and info["producer"] == "Microsoft Word 2016"
    assert info["created"] == "2024-01-15 10:30:00 UTC+01:00"
    assert ("media", "Autor registrado: Maria Lopez. Puede ser un nombre real o el usuario del equipo") in build_findings(info)


def make_bare_pdf() -> bytes:
    from pypdf import PdfWriter
    w = PdfWriter()
    w.add_blank_page(10, 10)
    w._info = None                      # sin diccionario de información (ni siquiera "Producer")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_execute_keeps_pdf_and_office_names_in_snippet(tool, tmp_path):
    (tmp_path / "a.pdf").write_bytes(make_pdf({"/Author": "Ana"}))
    (tmp_path / "b.docx").write_bytes(make_office())
    assert tool.execute(QueryParameters(url=str(tmp_path / "a.pdf")))[0].snippet.startswith("PDF · ")
    assert tool.execute(QueryParameters(url=str(tmp_path / "b.docx")))[0].snippet.startswith("Documento Office · ")


def test_pdf_without_metadata():
    info = inspect_bytes(make_bare_pdf())
    assert info["kind"] == "PDF" and info["pages"] == 1 and not has_metadata(info)


def test_pdf_producer_alone_counts_as_metadata():
    # pypdf escribe "Producer: pypdf" por defecto: es un metadato real
    assert inspect_bytes(make_pdf())["producer"] == "pypdf"


# ── Office ───────────────────────────────────────────────────────────────────

def test_office_metadata():
    info = inspect_bytes(make_office())
    assert info["kind"] == "documento Office"
    assert info["author"] == "Maria Lopez" and info["last_modified_by"] == "Carlos Ruiz"
    assert info["company"] == "Empresa SA" and info["application"] == "Microsoft Office Word"
    assert info["created"] == "2023-05-10 08:00:00" and info["title"] == "Informe"
    texts = " ".join(t for _, t in build_findings(info))
    assert "Carlos Ruiz" in texts and "Empresa SA" in texts


def test_office_xml_with_entities_is_ignored():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><cp:coreProperties xmlns:cp="u"><cp:lastModifiedBy>&a;</cp:lastModifiedBy></cp:coreProperties>'
    assert parse_office_xml(bomb, None) == {}
    assert parse_office_xml(b"<no es xml", None) == {}


def test_plain_zip_is_not_office():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hola")
    assert inspect_bytes(buf.getvalue()) is None


# ── descarga segura ──────────────────────────────────────────────────────────

def _addrinfo(*ips):
    return lambda host, port: [(2, 1, 6, "", (ip, 0)) for ip in ips]


@pytest.mark.parametrize("ips,public", [
    (["8.8.8.8"], True), (["127.0.0.1"], False), (["10.0.0.5"], False), (["169.254.169.254"], False),
    (["192.168.1.1"], False), (["8.8.8.8", "10.0.0.5"], False), (["::1"], False), ([], False),
])
def test_host_is_public(monkeypatch, ips, public):
    monkeypatch.setattr(fm.socket, "getaddrinfo", _addrinfo(*ips))
    assert fm.host_is_public("x.example.com") is public


def test_host_is_public_dns_failure(monkeypatch):
    def boom(*a):
        raise OSError("sin DNS")
    monkeypatch.setattr(fm.socket, "getaddrinfo", boom)
    assert fm.host_is_public("x.example.com") is False


class _Resp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.is_redirect = status in (301, 302, 303, 307, 308)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]


@pytest.fixture
def net(monkeypatch):
    """Descargas simuladas: hosts públicos salvo los que empiezan por 'interno'."""
    monkeypatch.setattr(fm, "host_is_public", lambda h: not h.startswith("interno"))
    calls = []

    def install(*responses):
        it = iter(responses)

        def fake_get(url, **kw):
            calls.append((url, kw.get("allow_redirects")))
            return next(it)
        monkeypatch.setattr(fm.requests, "get", fake_get)
        return calls
    return install


def test_download_ok_and_never_auto_follows_redirects(net):
    calls = net(_Resp(200, b"datos"))
    assert fm.download("https://ejemplo.com/a.jpg") == b"datos"
    assert calls == [("https://ejemplo.com/a.jpg", False)]


@pytest.mark.parametrize("url", ["http://interno.local/a.jpg", "ftp://ejemplo.com/a", "file:///etc/passwd", "http://127.0.0.1/a"])
def test_download_blocks_private_and_non_http(net, url):
    net(_Resp(200, b"x"))
    with pytest.raises(fm.DownloadError):
        fm.download(url)


def test_download_follows_public_redirect_but_blocks_private_one(net):
    net(_Resp(302, headers={"Location": "/otra.jpg"}), _Resp(200, b"ok"))
    assert fm.download("https://ejemplo.com/a.jpg") == b"ok"
    net(_Resp(302, headers={"Location": "http://interno.local/secreto"}), _Resp(200, b"NO"))
    with pytest.raises(fm.DownloadError):
        fm.download("https://ejemplo.com/a.jpg")


def test_download_retries_once_on_429_honoring_retry_after(net, monkeypatch):
    slept = []
    monkeypatch.setattr(fm.time, "sleep", slept.append)
    net(_Resp(429, headers={"Retry-After": "10"}), _Resp(200, b"ok"))
    assert fm.download("https://ejemplo.com/a") == b"ok" and slept == [10]
    net(_Resp(429, headers={"Retry-After": "9999"}), _Resp(200, b"ok"))      # se acota
    fm.download("https://ejemplo.com/a")
    assert slept[-1] == fm.MAX_WAIT
    net(_Resp(429), _Resp(429))                                                # solo un reintento
    with pytest.raises(fm.DownloadError, match="429"):
        fm.download("https://ejemplo.com/a")


def test_download_redirect_loop_and_errors(net):
    net(*[_Resp(302, headers={"Location": "https://ejemplo.com/b"})] * 6)
    with pytest.raises(fm.DownloadError, match="redirecciones"):
        fm.download("https://ejemplo.com/a")
    net(_Resp(404))
    with pytest.raises(fm.DownloadError, match="404"):
        fm.download("https://ejemplo.com/a")


def test_download_size_limits(net, monkeypatch):
    monkeypatch.setattr(fm, "MAX_BYTES", 100)
    net(_Resp(200, b"x" * 10, headers={"Content-Length": "5000"}))
    with pytest.raises(fm.DownloadError, match="grande"):
        fm.download("https://ejemplo.com/a")
    net(_Resp(200, b"x" * 500))          # sin Content-Length: se corta al leer
    with pytest.raises(fm.DownloadError, match="grande"):
        fm.download("https://ejemplo.com/a")


# ── herramienta ──────────────────────────────────────────────────────────────

@pytest.fixture
def tool(monkeypatch):
    t = FileMetadataTool()
    monkeypatch.setattr(t._rate, "wait_if_needed", lambda: None)
    return t


def test_execute_local_image(tool, tmp_path):
    f = tmp_path / "foto.jpg"
    f.write_bytes(make_jpeg())
    results = tool.execute(QueryParameters(url=str(f)))
    main, alerts = results[0], results[1:]
    assert main.category == "Metadatos" and main.source_tool == "File Metadata" and main.title == "Metadatos: foto.jpg"
    assert main.snippet.startswith("Imagen · ")
    for frag in ("Canon EOS 80D", "Juan Perez", "GPS: -2.208333, -78.5"):
        assert frag in main.snippet
    assert {a.relevance_score for a in alerts} == {88, 75} and all(a.category == "Alerta" for a in alerts)


def test_execute_without_metadata_says_so(tool, tmp_path):
    f = tmp_path / "limpia.jpg"
    f.write_bytes(make_jpeg(with_exif=False))
    results = tool.execute(QueryParameters(url=str(f)))
    assert len(results) == 1 and "sin metadatos" in results[0].snippet and results[0].relevance_score == 50


def test_execute_unsupported_or_missing_returns_nothing(tool, tmp_path):
    html = tmp_path / "pagina.html"
    html.write_bytes(b"<html>hola</html>")
    assert tool.execute(QueryParameters(url=str(html))) == []
    assert tool.execute(QueryParameters(url=str(tmp_path / "no_existe.jpg"))) == []
    assert tool.execute(QueryParameters(url=str(tmp_path))) == []         # un directorio no es archivo
    assert tool.execute(QueryParameters(url="")) == []


def test_execute_remote_and_cache(tool, monkeypatch):
    calls = {"n": 0}

    def fake_download(url):
        calls["n"] += 1
        return make_pdf({"/Author": "Maria Lopez"})
    monkeypatch.setattr(fm, "download", fake_download)
    first = tool.execute(QueryParameters(url="https://ejemplo.com/docs/Informe%20final.pdf"))
    assert first[0].title == "Metadatos: Informe final.pdf" and first[0].url.endswith("Informe%20final.pdf")
    assert tool.execute(QueryParameters(url="https://ejemplo.com/docs/Informe%20final.pdf")) == first
    assert calls["n"] == 1


def test_execute_download_error_returns_nothing(tool, monkeypatch):
    def boom(url):
        raise fm.DownloadError("HTTP 404")
    monkeypatch.setattr(fm, "download", boom)
    assert tool.execute(QueryParameters(url="https://ejemplo.com/a.jpg")) == []


def test_tool_registered_and_available():
    from osint_app.tools import build_tool_registry
    reg = build_tool_registry()
    assert "File Metadata" in reg and reg["File Metadata"].is_available
    assert reg["File Metadata"].requirements.mandatory == ["url"]
