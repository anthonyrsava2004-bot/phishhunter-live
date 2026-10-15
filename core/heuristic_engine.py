"""
PhishHunter Live - Motor Heurístico de Inspección Defensiva y Ponderación de Riesgo
=============================================================================
Alineado con:
- ISO/IEC 27001:2022 (A.8.20 Aislamiento, A.8.24 Criptografía)
- OWASP ASVS v4.0 V5.1 (Manejo de Redirecciones / CWE-601)
- NIST SP 800-52 / 63B (Seguridad en Transporte y Mitigación de Typosquatting)
- CIS Controls v8 4.1 (Inspección Estructural y Control de Puertos)
- MITRE ATT&CK T1566.002 / T1583.001
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from utils.threat_signatures import (
    ALL_PROTECTED_DOMAINS,
    ANOMALOUS_PORTS,
    CONFUSABLE_CHARACTERS,
    HIGH_RISK_TLDS,
    PROTECTED_BRAND_NAMES,
    SUSPICIOUS_PATH_KEYWORDS,
    calculate_similarity_ratio,
    extract_base_domain,
    levenshtein_distance,
)


class HeuristicEngine:
    """
    Motor analítico multicapa para auditoría y evaluación cuantitativa de riesgo
    en amenazas de Quishing.
    """

    def __init__(self):
        # Mapeo rápido de caracteres confusables para detección homógrafa
        self.confusable_chars = CONFUSABLE_CHARACTERS

    def analyze(self, raw_data: str, trace_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Ejecuta la batería integral de controles heurísticos sobre la URL o dato crudo del QR.
        Retorna la matriz de hallazgos, desglose de penalizaciones y Risk Score final (0-100).
        """
        raw_text = raw_data.strip()
        flags: List[Dict[str, Any]] = []

        # Determinar si el contenido es una URL o texto arbitrario
        target_url = trace_result.get("final_url", raw_text) if trace_result else raw_text
        parsed_target = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        parsed_initial = urlparse(raw_text if "://" in raw_text else f"http://{raw_text}")

        target_hostname = parsed_target.hostname or ""
        initial_hostname = parsed_initial.hostname or ""

        # =========================================================================
        # 1. CONTROL: Detección de Ataques Homógrafos (RFC 5890 / MITRE T1566.002)
        # =========================================================================
        homograph_findings = self._detect_homograph_attack(raw_text, target_hostname)
        if homograph_findings:
            flags.append({
                "rule_id": "HOMOGRAPH-RFC5890",
                "name": "Ataque Homógrafo / Suplantación IDN Detectada",
                "severity": "CRÍTICA",
                "penalty": 45,
                "standard": "RFC 5890 / MITRE ATT&CK T1566.002",
                "description": homograph_findings["description"],
                "details": homograph_findings,
            })

        # =========================================================================
        # 2. CONTROL: Detección de Typosquatting (NIST SP 800-63B / MITRE T1583.001)
        # =========================================================================
        typo_findings = self._detect_typosquatting(target_hostname)
        if typo_findings:
            flags.append({
                "rule_id": "TYPOSQUAT-NIST800-63B",
                "name": "Impersonación de Marca / Typosquatting Confirmado",
                "severity": "CRÍTICA",
                "penalty": 40,
                "standard": "NIST SP 800-63B / MITRE ATT&CK T1583.001",
                "description": typo_findings["description"],
                "details": typo_findings,
            })

        # =========================================================================
        # 3. CONTROL: Auditoría Criptográfica y Transporte (ISO 27001 A.8.24 / NIST SP 800-52)
        # =========================================================================
        crypto_findings = self._audit_cryptography(parsed_target, trace_result)
        for item in crypto_findings:
            flags.append(item)

        # =========================================================================
        # 4. CONTROL: Inspección Estructural de URL (CIS Controls v8 4.1)
        # =========================================================================
        structural_findings = self._inspect_url_structure(parsed_target, target_url)
        for item in structural_findings:
            flags.append(item)

        # =========================================================================
        # 5. CONTROL: Trazabilidad de Redirecciones Seguras (OWASP ASVS V5.1 / CWE-601)
        # =========================================================================
        if trace_result:
            redirect_findings = self._inspect_redirect_hops(trace_result, initial_hostname, target_hostname)
            for item in redirect_findings:
                flags.append(item)

        # =========================================================================
        # Cálculo Ponderado de Risk Score (0 a 100)
        # =========================================================================
        total_penalty = sum(f["penalty"] for f in flags)
        risk_score = min(100, max(0, total_penalty))

        if risk_score >= 70:
            risk_level = "CRÍTICO / QUISHING"
            risk_badge = "🔴"
            action_recommended = "AISLAMIENTO PREVENTIVO TOTAL: Bloqueo incondicional de hipervínculo y contención en Sandbox."
        elif risk_score >= 30:
            risk_level = "SOSPECHOSO"
            risk_badge = "🟡"
            action_recommended = "PRECAUCIÓN / MONITOREO: Inspección pasiva obligatoria y verificación manual en Sandbox."
        else:
            risk_level = "SEGURO"
            risk_badge = "🟢"
            action_recommended = "CONFIABLE: No se observan firmas ni anomalías estructurales o criptográficas."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_badge": risk_badge,
            "action_recommended": action_recommended,
            "flags_detected": flags,
            "total_penalties": total_penalty,
            "target_url": target_url,
            "target_hostname": target_hostname,
        }

    def _detect_homograph_attack(self, raw_input: str, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Identifica caracteres confusables (cirílico, griego) y decodificación Punycode (xn--).
        """
        # Caso 1: Punycode explícito
        if "xn--" in hostname.lower():
            try:
                decoded_puny = hostname.encode("ascii").decode("idna")
                return {
                    "type": "punycode_idn",
                    "original": hostname,
                    "decoded": decoded_puny,
                    "description": (
                        f"El dominio utiliza codificación Punycode ({hostname}) que resuelve "
                        f"a '{decoded_puny}'. Esta técnica oculta caracteres visualmente idénticos "
                        f"para suplantar entidades legítimas (RFC 5890)."
                    ),
                }
            except Exception:
                return {
                    "type": "punycode_malformed",
                    "original": hostname,
                    "description": f"Dominio con prefijo IDN anómalo 'xn--' ({hostname}).",
                }

        # Caso 2: Caracteres no ASCII confusables mezclados en el texto crudo o hostname
        confusable_found = []
        normalized_str = ""
        for char in hostname:
            if char in self.confusable_chars:
                confusable_found.append({
                    "char": char,
                    "latin_equivalent": self.confusable_chars[char],
                    "unicode_code": f"U+{ord(char):04X}",
                })
                normalized_str += self.confusable_chars[char]
            else:
                normalized_str += char

        if confusable_found:
            return {
                "type": "mixed_script_homoglyph",
                "detected_characters": confusable_found,
                "spoofed_string": hostname,
                "apparent_target": normalized_str,
                "description": (
                    f"Se detectaron {len(confusable_found)} caracteres confusables no latinos "
                    f"en el nombre de host '{hostname}' simulando '{normalized_str}'. "
                    f"Patrón clásico de Quishing Homógrafo (MITRE ATT&CK T1566.002)."
                ),
            }

        return None

    def _detect_typosquatting(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Calcula la distancia de Levenshtein contra marcas y dominios oficiales protegidos.
        """
        if not hostname:
            return None

        clean_host = hostname.lower().strip()
        base_host = extract_base_domain(clean_host)
        host_stem = base_host.split(".")[0]

        # Si el dominio es exactamente uno de los legítimos, no es typosquatting
        if clean_host in ALL_PROTECTED_DOMAINS or base_host in ALL_PROTECTED_DOMAINS:
            return None

        # 1. Comparar contra dominios protegidos completos
        for legit_domain in ALL_PROTECTED_DOMAINS:
            dist = levenshtein_distance(base_host, legit_domain)
            ratio = calculate_similarity_ratio(base_host, legit_domain)

            # Si la distancia de edición es 1 o 2 sobre un dominio largo (ej: paypa1.com vs paypal.com)
            if dist in (1, 2) and ratio >= 0.78:
                return {
                    "matched_target": legit_domain,
                    "evaluated_domain": base_host,
                    "edit_distance": dist,
                    "similarity": round(ratio * 100, 1),
                    "description": (
                        f"El dominio '{base_host}' presenta una distancia de edición de {dist} "
                        f"(similitud {round(ratio * 100, 1)}%) respecto al dominio oficial '{legit_domain}'. "
                        f"Indicio certero de Typosquatting / Combosquatting (NIST SP 800-63B)."
                    ),
                }

        # 2. Detección de Brand Impersonation / Combosquatting (ej: paypal-security.com, login-apple.com)
        for brand in PROTECTED_BRAND_NAMES:
            if len(brand) >= 4 and brand in host_stem and host_stem != brand:
                return {
                    "matched_target": brand,
                    "evaluated_domain": base_host,
                    "description": (
                        f"El dominio contiene el nombre de marca protegida '{brand}' embebido en '{base_host}'. "
                        f"Patrón sospechoso de combosquatting utilizado para estafas de ingeniería social."
                    ),
                }

        return None

    def _audit_cryptography(
        self, parsed_url: Any, trace_result: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Audita cifrado en tránsito, certificados SSL/TLS y cabeceras HSTS (ISO 27001 A.8.24 / NIST SP 800-52).
        """
        findings = []

        # 1. Protocolo en texto claro (HTTP vs HTTPS)
        if parsed_url.scheme.lower() == "http":
            findings.append({
                "rule_id": "CRYPTO-CLEARTEXT-HTTP",
                "name": "Ausencia de Cifrado en Tránsito (HTTP Plano)",
                "severity": "ALTA",
                "penalty": 30,
                "standard": "ISO/IEC 27001:2022 Control A.8.24 / NIST SP 800-52",
                "description": (
                    "El enlace utiliza protocolo HTTP no cifrado, exponiendo las credenciales y datos "
                    "a interceptación 'Man-in-the-Middle' (MitM)."
                ),
            })

        # 2. Puertos anómalos
        port = parsed_url.port
        if port and port in ANOMALOUS_PORTS:
            findings.append({
                "rule_id": "NET-ANOMALOUS-PORT",
                "name": f"Puerto de Red Anómalo Detectado (:{port})",
                "severity": "ALTA",
                "penalty": 25,
                "standard": "CIS Controls v8 4.1 / NIST SP 800-52",
                "description": (
                    f"El enlace apunta al puerto no convencional :{port}. Los servicios bancarios "
                    f"y corporativos legítimos no emplean puertos no estándar para sus clientes."
                ),
            })

        # 3. Auditoría de certificado SSL si existe información de traza
        if trace_result:
            if not trace_result.get("ssl_valid", True):
                error_msg = trace_result.get("ssl_error_message", "Certificado inválido o revocado")
                findings.append({
                    "rule_id": "CRYPTO-INVALID-TLS",
                    "name": "Fallo Crítico de Validación de Certificado TLS",
                    "severity": "CRÍTICA",
                    "penalty": 40,
                    "standard": "ISO/IEC 27001:2022 Control A.8.24 / NIST SP 800-52",
                    "description": f"El servidor web presentó una infracción criptográfica: {error_msg}.",
                })

            if trace_result.get("has_tls_downgrade", False):
                findings.append({
                    "rule_id": "CRYPTO-TLS-DOWNGRADE",
                    "name": "Degradación Criptográfica de HTTPS a HTTP",
                    "severity": "CRÍTICA",
                    "penalty": 35,
                    "standard": "ISO/IEC 27001:2022 Control A.8.24",
                    "description": (
                        "La cadena de redirecciones degradó la conexión desde un origen HTTPS hacia un "
                        "destino HTTP sin cifrado (SSL Strip / Downgrade Attack)."
                    ),
                })

        return findings

    def _inspect_url_structure(self, parsed_url: Any, full_url: str) -> List[Dict[str, Any]]:
        """
        Inspección morfológica y estructural según CIS Controls v8 4.1.
        """
        findings = []
        hostname = (parsed_url.hostname or "").lower()

        # 1. Uso directo de dirección IP en lugar de FQDN
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            findings.append({
                "rule_id": "STRUCT-DIRECT-IP",
                "name": "Uso Directo de Dirección IP Numérica",
                "severity": "CRÍTICA",
                "penalty": 45,
                "standard": "CIS Controls v8 4.1",
                "description": (
                    f"La URL apunta directamente a la dirección IP '{hostname}' en lugar de un nombre "
                    f"de dominio calificado (FQDN). Técnica típica de campañas de malware y Quishing evasivo."
                ),
            })

        # 2. TLDs de alto riesgo
        parts = hostname.split(".")
        if len(parts) >= 2:
            tld = parts[-1].lower()
            if tld in HIGH_RISK_TLDS:
                findings.append({
                    "rule_id": "STRUCT-RISKY-TLD",
                    "name": f"Dominio de Nivel Superior de Alto Riesgo (.{tld})",
                    "severity": "MEDIA",
                    "penalty": 20,
                    "standard": "CIS Controls v8 4.1 / MITRE ATT&CK T1583.001",
                    "description": (
                        f"El TLD '.{tld}' está catalogado con alta tasa de abuso y fraude según "
                        f"inteligencia de amenazas globales por su bajo coste de registro."
                    ),
                })

        # 3. Profundidad excesiva de subdominios (ej. login.security.bank.client.evil.com)
        if len(parts) >= 4 and not is_ip:
            findings.append({
                "rule_id": "STRUCT-EXCESSIVE-SUBDOMAINS",
                "name": f"Profundidad Excesiva de Subdominios ({len(parts)} niveles)",
                "severity": "MEDIA",
                "penalty": 15,
                "standard": "CIS Controls v8 4.1",
                "description": (
                    "El nombre de host presenta una anidación anormal de subdominios, utilizada frecuentemente "
                    "para camuflar marcas en la barra de direcciones de dispositivos móviles."
                ),
            })

        # 4. Credenciales incrustadas en URL (user:pass@host)
        if parsed_url.username or parsed_url.password:
            findings.append({
                "rule_id": "STRUCT-EMBEDDED-CREDENTIALS",
                "name": "Credenciales o Caracteres '@' en Autoridad de URL",
                "severity": "CRÍTICA",
                "penalty": 35,
                "standard": "OWASP ASVS v4.0 V5.1",
                "description": (
                    "La URL incluye credenciales o el delimitador '@' en la autoridad de red, un truco "
                    "conocido para confundir a los usuarios sobre el host real de destino."
                ),
            })

        # 5. Palabras clave de señuelo (lures) en la ruta o query
        path_query = (parsed_url.path + "?" + parsed_url.query).lower()
        matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_query]
        if matched_keywords:
            findings.append({
                "rule_id": "STRUCT-LURE-KEYWORDS",
                "name": "Palabras Clave de Cosecha de Credenciales",
                "severity": "MEDIA",
                "penalty": 15,
                "standard": "MITRE ATT&CK T1566.002",
                "description": (
                    f"Se identificaron términos de ingeniería social asociados a robo de credenciales: "
                    f"{', '.join(matched_keywords[:4])}."
                ),
            })

        # 6. Ofuscación de caracteres hexadecimales excesivos
        hex_encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
        if hex_encoded_count >= 5:
            findings.append({
                "rule_id": "STRUCT-HEX-OBFUSCATION",
                "name": "Ofuscación URL Hexadecimal Anómala",
                "severity": "MEDIA",
                "penalty": 15,
                "standard": "OWASP ASVS v4.0 V5.1",
                "description": (
                    f"La URL contiene {hex_encoded_count} secuencias de escape percent-encoding, "
                    f"sugiriendo evasión deliberada de escáneres estáticos de seguridad."
                ),
            })

        return findings

    def _inspect_redirect_hops(
        self, trace_result: Dict[str, Any], initial_host: str, target_host: str
    ) -> List[Dict[str, Any]]:
        """
        Inspecciona saltos de redirección, acortadores y bucles (OWASP ASVS V5.1 / CWE-601).
        """
        findings = []
        redirect_count = trace_result.get("redirect_count", 0)

        # 1. Saltos múltiples excesivos (> 2 saltos)
        if redirect_count >= 2:
            findings.append({
                "rule_id": "REDIRECT-CHAIN-EXCESSIVE",
                "name": f"Cadena de Redirección Compleja ({redirect_count} saltos)",
                "severity": "ALTA",
                "penalty": 20,
                "standard": "OWASP ASVS v4.0 V5.1 / CWE-601",
                "description": (
                    f"La petición atravesó {redirect_count} saltos HTTP intermediarios. Los atacantes "
                    f"utilizan cadenas de saltos para evadir pasarelas de correo y filtros de red."
                ),
            })

        # 2. Salto entre dominios cruzados no relacionados (Cross-Domain Pivot)
        if initial_host and target_host and initial_host != target_host and redirect_count > 0:
            init_base = extract_base_domain(initial_host)
            target_base = extract_base_domain(target_host)
            if init_base != target_base:
                findings.append({
                    "rule_id": "REDIRECT-CROSS-DOMAIN-PIVOT",
                    "name": "Pivoteo Entre Dominios No Relacionados (Cross-Domain)",
                    "severity": "ALTA",
                    "penalty": 25,
                    "standard": "OWASP ASVS v4.0 V5.1 / CWE-601",
                    "description": (
                        f"El enlace inicial inició en '{init_base}' pero fue redirigido al dominio "
                        f"completamente diferente '{target_base}'. Patrón habitual de Open Redirects."
                    ),
                })

        # 3. Detección de bucle infinito de redirección
        if trace_result.get("loop_detected", False):
            findings.append({
                "rule_id": "REDIRECT-LOOP-DETECTED",
                "name": "Bucle Cíclico de Redirección Detectado",
                "severity": "MEDIA",
                "penalty": 15,
                "standard": "OWASP ASVS v4.0 V5.1",
                "description": "El servidor generó una redirección cíclica que vuelve sobre sí misma.",
            })

        return findings
