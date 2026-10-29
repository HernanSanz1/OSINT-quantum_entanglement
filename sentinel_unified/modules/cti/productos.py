"""Producto afectado de una noticia o aviso CTI ("fabricante producto"), o "" si la fuente no lo dice claro.

Sin dependencias: lo usan el dossier (que se ejecuta como script) y la tabla de la pestaña CTI.

El aviso de Microsoft (MSRC) no trae el producto: en "product" va el título del fallo, y además Microsoft publica
fallos de terceros que afectan a sus productos (Azure Linux, Edge…). Antes se leía "Microsoft" + ese título y salían
productos falsos (evaluación 4): "Microsoft ipv4: free inet_opt…" para un fallo del kernel de Linux, "Microsoft
Integer Overflow or Wraparound in GitLab" para uno de GitLab o "Microsoft Chromium : Memory corruption".
"""
import re

# Productos de Microsoft por cómo empieza el título del aviso ("Windows ReFS Elevation of Privilege")
_MICROSOFT = re.compile(
    r"^(?:microsoft|windows|win32k|\.net|asp\.net|azure|office|outlook|excel|word|powerpoint|onenote|exchange|"
    r"sharepoint|teams|skype|visual studio|remote desktop|hyper-v|sql server|power ?bi|power automate|power apps|"
    r"dynamics|edge|internet explorer|mshtml|bing|onedrive|defender|intune|entra|copilot|bitlocker|"
    r"active directory|system center|xbox)\b", re.I)
# Lo que sigue al producto en el título: el tipo de fallo
_IMPACT = re.compile(r"\s*\b(?:remote code execution|elevation of privilege|information disclosure|denial of service|"
                     r"security feature bypass|spoofing|tampering|cross-site scripting|vulnerability)\b.*$", re.I)
# Commits del kernel de Linux: "ipv4: …", "net/sched: act_ct: …", "bpf, cgroup: …", "SUNRPC: …"
_LINUX = re.compile(r"^[a-z0-9_./-]+(?:,\s*[a-z0-9_./-]+)*:\s")
_KERNEL_SUBSYSTEMS = {"sunrpc", "nfsd", "nfs", "nfsv4", "nfsv4.1", "hid", "alsa", "asoc", "rdma", "kvm", "bluetooth",
                      "pci", "usb", "acpi", "smb", "cifs", "edac", "nfc", "iio", "drm", "ext4", "btrfs", "xfs", "f2fs",
                      "netfilter", "input", "keys", "drivers", "loongarch", "risc-v", "x86", "arm64", "powerpc", "s390"}
# Componente de Microsoft con el formato de sus avisos, "<componente> <tipo de fallo>": "Desktop Window Manager
# Elevation of Privilege", "DirectWrite Remote Code Execution". Los de terceros suelen describir el fallo con
# preposiciones ("Uncontrolled Resource Consumption in Elasticsearch Leading to Denial of Service").
_MICROSOFT_STYLE = re.compile(r"^((?:[A-Z0-9.(][\w.()+/-]*\s){0,5}[A-Z0-9.(][\w.()+/-]*)\s(?i:remote code execution|"
                              r"elevation of privilege|information disclosure|denial of service|security feature "
                              r"bypass|spoofing|tampering)(?i:\svulnerability)?$")
_FLAW_WORDS = re.compile(r"overflow|injection|traversal|corruption|leak|use[- ]after|out[- ]of[- ]bounds", re.I)
# Con el mismo formato, pero de otros: no llevan "Microsoft" delante
_THIRD_PARTY = {"bluez", "sqlite", "python", "messagepack-csharp", "openssl", "openssh", "curl", "git", "node.js",
                "apache", "nginx", "libxml2", "zlib", "perl", "golang", "go", "rust", "java", "oracle", "mysql",
                "postgresql", "redis", "kubernetes", "docker", "containerd", "grafana", "jenkins"}
# Tercero con su nombre delante: "Apache HTTP Server: mod_dav_fs…", "Chromium : Memory corruption"
_NAMED = re.compile(r"^([A-Z][\w.+-]*(?: [A-Z][\w.+-]*){0,3})\s*:\s")
_RENAMED = {"chromium": "Google Chromium"}
# Delante de los dos puntos, pero no es un producto ("Authorization: Negotiate sent to foreign origin")
_NOT_PRODUCTS = {"authorization", "google", "retrap", "role"}


def msrc_product(title: str) -> str:
    """Producto de un aviso de Microsoft a partir de su título; "" si no se puede saber."""
    text = re.sub(r"\s+", " ", re.sub(r"\bCVE-\d{4}-\d+\b", "", str(title or ""), flags=re.I)).strip()
    text = re.sub(r"^Role:\s*", "", text)               # "Role: Windows Fax Service Elevation of Privilege"
    if _MICROSOFT.match(text):
        name = _IMPACT.sub("", text).strip(" -:")
        return name if name.lower().startswith("microsoft") else f"Microsoft {name}"
    if _LINUX.match(text) or re.split(r"[:/]", text, 1)[0].strip().lower() in _KERNEL_SUBSYSTEMS:
        return "Linux kernel"
    named = _NAMED.match(text)
    if named:
        name = named.group(1)
        return "" if name.lower() in _NOT_PRODUCTS else _RENAMED.get(name.lower(), name)
    styled = _MICROSOFT_STYLE.match(text)
    if styled:
        name = styled.group(1)
        if name.lower().startswith("linux kernel"):
            return "Linux kernel"
        if _FLAW_WORDS.search(name):          # "BlueZ A2DP Stack-based Buffer Overflow": describe el fallo
            return ""
        return name if name.split()[0].lower() in _THIRD_PARTY else f"Microsoft {name}"
    return ""


def is_msrc(item: dict) -> bool:
    return item.get("fuente_id") == "microsoft_msrc" or "Microsoft Security Response" in str(item.get("fuente") or "")


def item_product(item: dict) -> str:
    """Producto que la propia noticia o aviso indica; "" si no lo dice o no está claro."""
    if is_msrc(item):
        return msrc_product(item.get("product") or item.get("titulo") or "")
    text = " ".join(str(item.get(k) or "").strip() for k in ("vendor", "product")).strip()
    return "" if len(text) > 60 or ":" in text else text


def catalog_products(items: list) -> dict:
    """CVE → producto, de los avisos que lo dicen. Primero el catálogo KEV de CISA, el más fiable."""
    out: dict = {}
    for item in sorted(items, key=lambda x: x.get("fuente_id") != "cisa_kev"):
        product = item_product(item)
        if not product:
            continue
        for cve in item.get("cves") or []:
            out.setdefault(str(cve).upper(), product)
    return out
