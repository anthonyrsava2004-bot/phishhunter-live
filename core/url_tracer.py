"""
PhishHunter Live - Trazabilidad Segura de Redirecciones y Auditoría TLS
=============================================================================
Alineado con:
- OWASP ASVS v4.0 V5.1 (Validación y Manejo Seguro de Redirecciones / CWE-601)
- ISO/IEC 27001:2022 Control A.8.24 (Uso de Criptografía / Seguridad en Tránsito)
- NIST SP 800-52 Rev. 2 (Guía para la Selección y Uso de TLS)
"""

import os
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class URLTracer:
    """
    Rastreador pasivo y seguro de cadenas de redirección HTTP con validación TLS.
    Ejecuta peticiones sin interpretar código ejecutable ni JavaScript del cliente.
    """

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 PhishHunterDefensiveCrawler/1.0"
    )

    def __init__(
        self,
        timeout: float = 4.0,
        max_hops: int = 7,
        user_agent: Optional[str] = None
    ):
        self.timeout = float(os.getenv("HTTP_TIMEOUT", str(timeout)))
        self.max_hops = int(os.getenv("MAX_REDIRECT_HOPS", str(max_hops)))
        self.user_agent = user_agent or os.getenv("USER_AGENT", self.DEFAULT_USER_AGENT)

    def _create_session(self) -> requests.Session:
        """
        Crea una sesión HTTP configurada con reintentos controlados y cabeceras neutrales.
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5,es;q=0.3",
            "DNT": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        })
        return session

    def trace(self, initial_url: str) -> Dict[str, Any]:
        """
        Rastrea paso a paso cada salto HTTP (301, 302, 307, 308) hasta alcanzar el destino final
        o el límite máximo de saltos.
        """
        # Normalizar esquema
        raw_url = initial_url.strip()
        if not re.match(r"^https?://", raw_url, re.IGNORECASE):
            # Si no especifica esquema, por defecto asumir https para evaluar si degrada a http
            current_url = "https://" + raw_url
        else:
            current_url = raw_url

        hops: List[Dict[str, Any]] = []
        visited_urls = set()
        final_url = current_url
        ssl_valid = True
        ssl_error_message: Optional[str] = None
        has_tls_downgrade = False
        loop_detected = False
        unreachable = False
        error_description: Optional[str] = None
        initial_parsed = urlparse(current_url)

        session = self._create_session()

        for hop_index in range(1, self.max_hops + 1):
            if current_url in visited_urls:
                loop_detected = True
                break
            visited_urls.add(current_url)

            parsed = urlparse(current_url)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # Resolución IP del host para trazabilidad forense
            resolved_ip = self._resolve_ip(hostname)

            start_time = time.time()
            try:
                # Realizar petición controlada sin seguir redirecciones automáticas
                response = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    verify=True,
                    stream=True,  # No descargar cuerpos de archivo pesados
                )
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                status_code = response.status_code

                # Cabeceras defensivas y de diagnóstico
                headers_snapshot = {
                    "server": response.headers.get("Server", "Oculto / No provisto"),
                    "location": response.headers.get("Location"),
                    "content_type": response.headers.get("Content-Type", ""),
                    "content_length": response.headers.get("Content-Length"),
                    "strict_transport_security": response.headers.get("Strict-Transport-Security"),
                    "x_frame_options": response.headers.get("X-Frame-Options"),
                    "content_security_policy": bool(response.headers.get("Content-Security-Policy")),
                }

                hop_record = {
                    "hop": hop_index,
                    "url": current_url,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "scheme": parsed.scheme,
                    "status_code": status_code,
                    "reason": response.reason,
                    "headers": headers_snapshot,
                    "elapsed_ms": elapsed_ms,
                }
                hops.append(hop_record)
                final_url = current_url

                # Verificar si es redirección HTTP estándar
                if status_code in (301, 302, 303, 307, 308):
                    next_loc = response.headers.get("Location")
                    if not next_loc:
                        break
                    # Resolver URLs relativas
                    next_url = urljoin(current_url, next_loc)

                    # Verificar si hubo degradación criptográfica de HTTPS a HTTP
                    if parsed.scheme == "https" and next_url.startswith("http://"):
                        has_tls_downgrade = True

                    current_url = next_url
                else:
                    # Se alcanzó el recurso final
                    break

            except requests.exceptions.SSLError as ssl_err:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                ssl_valid = False
                ssl_error_message = f"Fallo de Validación SSL/TLS: {str(ssl_err)}"
                hops.append({
                    "hop": hop_index,
                    "url": current_url,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "scheme": parsed.scheme,
                    "status_code": 0,
                    "reason": "SSL Certificate Error",
                    "headers": {},
                    "elapsed_ms": elapsed_ms,
                    "ssl_error": True
                })
                final_url = current_url
                break

            except requests.exceptions.Timeout:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                unreachable = True
                error_description = f"Timeout ({self.timeout}s) agotado al contactar {current_url}"
                hops.append({
                    "hop": hop_index,
                    "url": current_url,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "scheme": parsed.scheme,
                    "status_code": 408,
                    "reason": "Request Timeout",
                    "headers": {},
                    "elapsed_ms": elapsed_ms,
                })
                final_url = current_url
                break

            except requests.exceptions.ConnectionError as conn_err:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                unreachable = True
                error_description = f"Error de conexión: {str(conn_err)}"
                hops.append({
                    "hop": hop_index,
                    "url": current_url,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "scheme": parsed.scheme,
                    "status_code": 502,
                    "reason": "Connection Refused / Unreachable",
                    "headers": {},
                    "elapsed_ms": elapsed_ms,
                })
                final_url = current_url
                break

            except Exception as ex:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                unreachable = True
                error_description = f"Error inesperado de red: {str(ex)}"
                hops.append({
                    "hop": hop_index,
                    "url": current_url,
                    "hostname": hostname,
                    "resolved_ip": resolved_ip,
                    "port": port,
                    "scheme": parsed.scheme,
                    "status_code": 500,
                    "reason": "Network Failure",
                    "headers": {},
                    "elapsed_ms": elapsed_ms,
                })
                final_url = current_url
                break

        # Análisis adicional de auditoría de certificado en el host final
        tls_audit_info = self._audit_tls_certificate(final_url)
        if not tls_audit_info.get("valid", True):
            ssl_valid = False
            if not ssl_error_message:
                ssl_error_message = tls_audit_info.get("error")

        return {
            "initial_url": initial_url,
            "final_url": final_url,
            "redirect_count": max(0, len(hops) - 1),
            "hops": hops,
            "ssl_valid": ssl_valid,
            "ssl_error_message": ssl_error_message,
            "has_tls_downgrade": has_tls_downgrade,
            "loop_detected": loop_detected,
            "unreachable": unreachable,
            "error_description": error_description,
            "tls_audit": tls_audit_info,
        }

    def _resolve_ip(self, hostname: str) -> str:
        """
        Resuelve la dirección IP del nombre de host de forma segura.
        """
        if not hostname:
            return "N/A"
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return "No resuelto (DNS Failure)"

    def _audit_tls_certificate(self, url: str) -> Dict[str, Any]:
        """
        Inspecciona el certificado TLS del servidor remoto si utiliza HTTPS.
        Alineado con ISO 27001 A.8.24 y NIST SP 800-52.
        """
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return {
                "enforced": False,
                "valid": False,
                "reason": "La conexión utiliza protocolo HTTP en texto claro (sin cifrado).",
            }

        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return {"enforced": False, "valid": False, "reason": "Hostname inválido"}

        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Extraer emisor y sujeto
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))

                    return {
                        "enforced": True,
                        "valid": True,
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "Desconocido",
                        "issuer_cn": issuer.get("commonName", "Desconocido"),
                        "subject_cn": subject.get("commonName", "Desconocido"),
                        "expires": cert.get("notAfter", "Desconocido"),
                    }
        except ssl.SSLCertVerificationError as e:
            return {
                "enforced": True,
                "valid": False,
                "error": f"Fallo de verificación de certificado CA: {e.verify_message}",
            }
        except Exception as e:
            return {
                "enforced": True,
                "valid": False,
                "error": f"No se pudo completar handshake TLS: {str(e)}",
            }
