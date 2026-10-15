"""
PhishHunter Live - Catálogo de Firmas de Amenazas y Entidades Legítimas
=============================================================================
Alineado con:
- NIST SP 800-63B (Identificación de Typosquatting e Impersonación)
- MITRE ATT&CK T1583.001 (Acquire Infrastructure: Domains)
- MITRE ATT&CK T1566.002 (Phishing: Spearphishing Link / Quishing)
- CIS Controls v8 4.1 (Configuraciones Seguras y Control de TLDs de Riesgo)
- RFC 5890 (Internationalized Domain Names in Applications - IDNA)
"""

from typing import Dict, List, Set, Tuple
import unicodedata

# ---------------------------------------------------------------------------
# Catálogo de Entidades Legítimas Protegidas (Banca, FinTech, Big Tech, Envíos)
# Usadas como baseline contra ataques de Typosquatting y Suplantación de Marca
# ---------------------------------------------------------------------------
LEGITIMATE_TARGETS: Dict[str, List[str]] = {
    "Banca y Finanzas Global": [
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citi.com",
        "citibank.com",
        "bbva.com",
        "santander.com",
        "hsbc.com",
        "barclays.co.uk",
        "bancodechile.cl",
        "banorte.com",
        "itau.com.br",
        "capitalone.com",
        "usbank.com",
        "scotiabank.com",
        "pnc.com",
        "bancolombia.com",
    ],
    "Pasarelas de Pago y FinTech": [
        "paypal.com",
        "stripe.com",
        "square.com",
        "mercadopago.com",
        "mercadolibre.com",
        "venmo.com",
        "zellepay.com",
        "revolut.com",
        "wise.com",
        "payoneer.com",
    ],
    "Criptomonedas e Intercambios": [
        "binance.com",
        "coinbase.com",
        "metamask.io",
        "kraken.com",
        "crypto.com",
        "kucoin.com",
        "bybit.com",
        "ledger.com",
        "trezor.io",
    ],
    "Servicios Corporativos y Cloud": [
        "google.com",
        "accounts.google.com",
        "microsoft.com",
        "login.microsoftonline.com",
        "live.com",
        "office.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "aws.amazon.com",
        "meta.com",
        "facebook.com",
        "instagram.com",
        "whatsapp.com",
        "netflix.com",
        "linkedin.com",
        "github.com",
        "gitlab.com",
        "dropbox.com",
        "salesforce.com",
        "okta.com",
        "auth0.com",
        "zoom.us",
        "adobe.com",
    ],
    "Logística, Envíos y Telecomunicaciones": [
        "dhl.com",
        "fedex.com",
        "ups.com",
        "usps.com",
        "correos.es",
        "correos.cl",
        "estafeta.com",
        "verizon.com",
        "att.com",
        "t-mobile.com",
        "vodafone.com",
        "movistar.es",
        "claro.com",
    ],
}

# Lista aplanada de todos los dominios protegidos
ALL_PROTECTED_DOMAINS: List[str] = [
    domain for group in LEGITIMATE_TARGETS.values() for domain in group
]

# Nombres base limpios sin TLD (ej. "paypal", "google", "chase")
PROTECTED_BRAND_NAMES: Set[str] = {
    domain.split(".")[0] for domain in ALL_PROTECTED_DOMAINS
}

# ---------------------------------------------------------------------------
# TLDs de Alto Riesgo Estadístico (Abusados recurrentemente en campañas Quishing)
# Fuente: Spamhaus, SURBL, CIS Advisories
# ---------------------------------------------------------------------------
HIGH_RISK_TLDS: Set[str] = {
    "xyz", "top", "live", "buzz", "club", "work", "click", "gq", "cf",
    "tk", "ml", "ga", "rest", "cam", "fit", "icu", "monster", "sbs",
    "cfd", "vip", "space", "quest", "surf", "online", "site", "fun",
    "country", "stream", "bid", "loan", "men", "date", "racing", "win",
    "kim", "party", "review", "trade", "accountant", "faith", "cricket"
}

# ---------------------------------------------------------------------------
# Puertos Anómalos para Servicios Web Públicos (CIS Controls 4.1)
# Puertos no estándar que sugieren servidores de comando/control o túneles
# ---------------------------------------------------------------------------
ANOMALOUS_PORTS: Set[int] = {
    8080, 8443, 8000, 8888, 4444, 1337, 3000, 5000, 9000, 9999,
    21, 22, 23, 25, 445, 3389, 6667, 7001, 8081, 8088, 8085
}

# ---------------------------------------------------------------------------
# Palabras Clave Sospechosas en Rutas y Query Strings (Lures de Cosecha de Credenciales)
# ---------------------------------------------------------------------------
SUSPICIOUS_PATH_KEYWORDS: Set[str] = {
    "login", "signin", "log-in", "sign-in", "verify", "verification",
    "account-update", "banking", "secure-auth", "wallet", "2fa", "mfa",
    "billing", "confirm-identity", "passcode", "oauth", "token", "recover",
    "suspended", "unusual-activity", "security-alert", "reactivate",
    "passkey", "reset-password", "validation", "authenticate", "unlock-account",
    "claim-reward", "airdrop", "invoice-pdf", "doc-download"
}

# ---------------------------------------------------------------------------
# Mapeo de Caracteres Confusables (Homoglyphs - Cirílico, Griego vs Latín ASCII)
# RFC 5890 / MITRE ATT&CK T1566.002
# ---------------------------------------------------------------------------
CONFUSABLE_CHARACTERS: Dict[str, str] = {
    # Cirílico minúsculas
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0435": "e",  # Cyrillic small letter ie
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0443": "y",  # Cyrillic small letter u
    "\u0445": "x",  # Cyrillic small letter ha
    "\u045d": "i",  # Cyrillic small letter i with grave
    "\u04cf": "l",  # Cyrillic small letter palochka
    "\u0501": "d",  # Cyrillic small letter dze
    "\u051b": "q",  # Cyrillic small letter qa
    # Cirílico mayúsculas
    "\u0410": "A",
    "\u0412": "B",
    "\u0421": "C",
    "\u0415": "E",
    "\u041d": "H",
    "\u0406": "I",
    "\u0408": "J",
    "\u041a": "K",
    "\u041c": "M",
    "\u041e": "O",
    "\u0420": "P",
    "\u0422": "T",
    "\u0425": "X",
    "\u0423": "Y",
    # Griego minúsculas y mayúsculas
    "\u03bf": "o",  # Greek small letter omicron
    "\u03c1": "p",  # Greek small letter rho
    "\u03b1": "a",  # Greek small letter alpha
    "\u03bd": "v",  # Greek small letter nu
    "\u03c4": "t",  # Greek small letter tau
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a7": "X",
    "\u03a5": "Y",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calcula la distancia de edición de Levenshtein entre dos cadenas de caracteres.
    Implementación puramente algorítmica O(m*n) sin requerir compiladores externos.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_similarity_ratio(s1: str, s2: str) -> float:
    """
    Calcula el ratio de similitud normalizado entre 0.0 y 1.0.
    1.0 indica igualdad idéntica, valores cercanos a 1.0 indican alta probabilidad de Typosquatting.
    """
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


def extract_base_domain(hostname: str) -> str:
    """
    Extrae el dominio base (dominio.tld) omitiendo subdominios comunes (www, etc.).
    """
    parts = hostname.lower().strip().split(".")
    if len(parts) <= 2:
        return hostname.lower().strip()
    # Soporte para ccTLDs compuestos (ej: co.uk, com.br, com.mx)
    second_level_suffixes = {"co", "com", "org", "net", "edu", "gob", "gov"}
    if len(parts) >= 3 and parts[-2] in second_level_suffixes:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
