"""
PhishHunter Live - Sandbox Pasivo y Aislamiento Preventivo de Amenazas
=============================================================================
Alineado con:
- ISO/IEC 27001:2022 Control A.8.20 (Seguridad en Redes / Aislamiento Defensivo)
- OWASP Top 10 A03:2021 (Injection / CWE-79 Cross-Site Scripting)
- Mitigación de Descargas Drive-by y Ataques Zero-Day en Navegador
"""

import html
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment
import requests


class SandboxPreview:
    """
    Entorno pasivo de renderizado y extracción segura de metadatos OpenGraph.
    Desinfecta estrictamente cualquier elemento interactivo o script malicioso.
    """

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 PhishHunterDefensiveCrawler/1.0"
    )

    # Etiquetas HTML intrínsecamente peligrosas que se eliminan por completo
    DANGEROUS_TAGS = [
        "script", "noscript", "iframe", "frame", "frameset", "object",
        "embed", "applet", "base", "svg", "canvas", "audio",
        "video", "link", "meta"
    ]

    # Atributos de eventos de JavaScript que se purgan incondicionalmente
    DISALLOWED_ATTR_PREFIXES = ("on", "formaction")

    def __init__(self, timeout: float = 3.5, max_bytes: int = 512 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes  # Límite de 512 KB para evitar ataques de bomba de descompresión

    def fetch_and_isolate(self, target_url: str, is_dangerous: bool = True) -> Dict[str, Any]:
        """
        Descarga el recurso objetivo en modo pasivo y genera:
        1. Diccionario de metadatos OpenGraph / cabeceras de identidad de la página.
        2. Snapshot HTML sanitizado y neutralizado apto para renderizado en contenedor seguro.
        3. Resumen textual pasivo.
        """
        if not target_url or not re.match(r"^https?://", target_url, re.IGNORECASE):
            return self._empty_result(
                target_url,
                error="URL no válida para inspección en Sandbox pasivo."
            )

        headers = {
            "User-Agent": self.DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "DNT": "1",
        }

        try:
            # Petición pasiva limitada
            response = requests.get(
                target_url,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                verify=False,  # En sandbox forense analizamos incluso si el certificado es apócrifo
            )

            # Leer únicamente hasta el límite de bytes
            raw_content = b""
            for chunk in response.iter_content(chunk_size=8192):
                raw_content += chunk
                if len(raw_content) >= self.max_bytes:
                    break

            encoding = response.encoding or "utf-8"
            html_text = raw_content.decode(encoding, errors="replace")

            # Parsear con BeautifulSoup
            soup = BeautifulSoup(html_text, "html.parser")

            # Extraer metadatos OpenGraph y etiquetas de identidad
            metadata = self._extract_metadata(soup, target_url)

            # Sanitizar el DOM HTML para presentación segura
            sanitized_html = self._sanitize_html(soup)
            text_summary = self._extract_clean_text(soup)

            return {
                "success": True,
                "url": target_url,
                "status_code": response.status_code,
                "is_dangerous": is_dangerous,
                "isolated": is_dangerous,
                "metadata": metadata,
                "sanitized_html": sanitized_html,
                "text_summary": text_summary,
                "page_size_kb": round(len(raw_content) / 1024, 2),
                "error": None,
            }

        except requests.exceptions.Timeout:
            return self._empty_result(
                target_url,
                error=f"Timeout ({self.timeout}s): El servidor objetivo no respondió pasivamente."
            )
        except requests.exceptions.RequestException as e:
            return self._empty_result(
                target_url,
                error=f"Error de conexión en Sandbox pasivo: {str(e)}"
            )
        except Exception as e:
            return self._empty_result(
                target_url,
                error=f"Error inesperado de análisis: {str(e)}"
            )

    def _extract_metadata(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """
        Extrae OpenGraph (og:*), Twitter cards y etiquetas <title>/favicon.
        """
        meta_tags: Dict[str, str] = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property")
            content = tag.get("content")
            if name and content:
                meta_tags[name.lower().strip()] = content.strip()

        # Título
        title = (
            meta_tags.get("og:title")
            or meta_tags.get("twitter:title")
            or (soup.title.string.strip() if soup.title and soup.title.string else None)
            or "Sin título declarado"
        )

        # Descripción
        description = (
            meta_tags.get("og:description")
            or meta_tags.get("twitter:description")
            or meta_tags.get("description")
            or "Sin descripción OpenGraph provista"
        )

        # Nombre de sitio
        site_name = (
            meta_tags.get("og:site_name")
            or urlparse(base_url).hostname
            or "Desconocido"
        )

        # Imagen OpenGraph
        image_url = meta_tags.get("og:image") or meta_tags.get("twitter:image")
        if image_url:
            image_url = urljoin(base_url, image_url)

        # Favicon
        icon_url = None
        icon_tag = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon_tag and icon_tag.get("href"):
            icon_url = urljoin(base_url, icon_tag["href"])
        else:
            # Fallback convencional /favicon.ico
            parsed = urlparse(base_url)
            icon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        return {
            "title": html.escape(title[:180]),
            "description": html.escape(description[:300]),
            "site_name": html.escape(site_name),
            "image_url": image_url,
            "favicon_url": icon_url,
        }

    def _sanitize_html(self, soup: BeautifulSoup) -> str:
        """
        Desinfecta el árbol HTML eliminando scripts, estilos maliciosos y eventos (CWE-79).
        """
        # Crear copia independiente para sanitizar
        clean_soup = BeautifulSoup(str(soup), "html.parser")

        # 1. Eliminar comentarios HTML usando string= para evitar warnings
        for comment in clean_soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        # 2. Desmantelar todas las etiquetas peligrosas
        for tag_name in self.DANGEROUS_TAGS:
            for element in clean_soup.find_all(tag_name):
                element.decompose()

        # 3. Purgar atributos sospechosos y anular hipervínculos interactivos
        for tag in clean_soup.find_all(True):
            # Limpiar eventos Javascript (onclick, onload, etc.)
            attrs_to_remove = [
                attr for attr in tag.attrs
                if any(attr.lower().startswith(p) for p in self.DISALLOWED_ATTR_PREFIXES)
            ]
            for attr in attrs_to_remove:
                del tag[attr]

            # Neutralizar enlaces para evitar clics accidentales del analista
            if tag.name == "a":
                tag["href"] = "#"
                tag["onclick"] = "return false;"
                tag["title"] = "[ENLACE AISLADO POR PHISHHUNTER SANDBOX]"
                tag["style"] = "pointer-events: none; color: #888; text-decoration: line-through;"

            # Neutralizar formularios para impedir exfiltración de credenciales
            if tag.name == "form":
                tag["action"] = "#"
                tag["onsubmit"] = "return false;"
                tag["style"] = "background: rgba(255, 0, 0, 0.05); padding: 10px; border: 1px dashed #d9534f;"

            # Deshabilitar botones de envío y campos
            if tag.name in ("button", "input", "textarea", "select"):
                tag["disabled"] = "disabled"

        # Extraer únicamente el cuerpo (body) o el documento filtrado
        body = clean_soup.body or clean_soup
        return str(body)

    def _extract_clean_text(self, soup: BeautifulSoup) -> str:
        """
        Extrae el contenido textual legible despojado de etiquetas para inspección forense.
        """
        clean_soup = BeautifulSoup(str(soup), "html.parser")
        for tag_name in self.DANGEROUS_TAGS:
            for element in clean_soup.find_all(tag_name):
                element.decompose()

        text = clean_soup.get_text(separator=" ", strip=True)
        # Normalizar espacios
        cleaned = re.sub(r"\s+", " ", text)
        return cleaned[:800]

    def _empty_result(self, url: str, error: str) -> Dict[str, Any]:
        """
        Estructura por defecto cuando la extracción remota no es factible.
        """
        return {
            "success": False,
            "url": url,
            "status_code": 0,
            "is_dangerous": True,
            "isolated": True,
            "metadata": {
                "title": "Recurso Inaccesible o Bloqueado",
                "description": error,
                "site_name": urlparse(url).hostname or "Desconocido",
                "image_url": None,
                "favicon_url": None,
            },
            "sanitized_html": f"<div style='padding:20px; color:#d9534f;'><strong>Aislamiento Preventivo:</strong> {html.escape(error)}</div>",
            "text_summary": f"No se pudo extraer texto: {error}",
            "page_size_kb": 0.0,
            "error": error,
        }
