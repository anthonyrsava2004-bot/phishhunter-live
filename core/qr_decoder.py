"""
PhishHunter Live - Módulo de Decodificación y Visión Computacional QR
=============================================================================
Alineado con:
- ISO/IEC 18004 (Especificación de simbología de código QR)
- Entorno de ejecución Headless portable (sin requerir dependencias X11/GTK)
"""

from typing import Any, Dict, Optional, Tuple, Union
import cv2
import numpy as np
from PIL import Image
import io


class QRDecoder:
    """
    Decodificador robusto de códigos QR basado en OpenCV Headless con canalización
    de preprocesamiento morfológico multinivel para imágenes desafiantes o ruidosas.
    """

    def __init__(self):
        # Inicializar el detector QR estándar de OpenCV
        self.detector = cv2.QRCodeDetector()

    def decode_from_bytes(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Decodifica un código QR a partir de un flujo de bytes (subida de archivos o webcam).
        """
        try:
            # Convertir bytes a arreglo numpy
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is None:
                # Intentar cargar a través de PIL como alternativa de compatibilidad (WEBP, RGBA)
                pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
                img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

            return self.decode_from_cv2_image(img)
        except Exception as e:
            return {
                "success": False,
                "data": "",
                "points": None,
                "annotated_image": None,
                "method": "failed",
                "error": f"Error al procesar flujo de bytes de imagen: {str(e)}",
            }

    def decode_from_cv2_image(self, img: np.ndarray) -> Dict[str, Any]:
        """
        Aplica un pipeline de preprocesamiento adaptativo para decodificar el QR:
        1. Pase directo en BGR original.
        2. Escala de grises con ecualización de histograma (CLAHE).
        3. Umbralización adaptativa de Otsu.
        4. Redimensionamiento / Pirámide de escala para códigos de alta resolución.
        """
        if img is None or img.size == 0:
            return {
                "success": False,
                "data": "",
                "points": None,
                "annotated_image": None,
                "method": "empty",
                "error": "La imagen suministrada está vacía o corrupta.",
            }

        # Copia de trabajo para anotaciones
        annotated = img.copy()

        # 1. Intento Directo
        data, points, _ = self.detector.detectAndDecode(img)
        if data:
            annotated = self._draw_qr_quadrilateral(annotated, points)
            return {
                "success": True,
                "data": data.strip(),
                "points": points.tolist() if points is not None else None,
                "annotated_image": annotated,
                "method": "direct_pass",
                "error": None,
            }

        # 2. Pase con Escala de Grises y CLAHE (Contrast Limited Adaptive Histogram Equalization)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        data, points, _ = self.detector.detectAndDecode(enhanced)
        if data:
            annotated = self._draw_qr_quadrilateral(annotated, points)
            return {
                "success": True,
                "data": data.strip(),
                "points": points.tolist() if points is not None else None,
                "annotated_image": annotated,
                "method": "clahe_pass",
                "error": None,
            }

        # 3. Pase con Filtro Bilateral y Umbralización de Otsu
        blurred = cv2.bilateralFilter(gray, 9, 75, 75)
        _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        data, points, _ = self.detector.detectAndDecode(thresh)
        if data:
            annotated = self._draw_qr_quadrilateral(annotated, points)
            return {
                "success": True,
                "data": data.strip(),
                "points": points.tolist() if points is not None else None,
                "annotated_image": annotated,
                "method": "otsu_pass",
                "error": None,
            }

        # 4. Pase con Redimensionamiento si la imagen es excesivamente grande (> 1600px)
        h, w = img.shape[:2]
        if max(h, w) > 1200:
            scale = 1200.0 / max(h, w)
            resized = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
            data, points, _ = self.detector.detectAndDecode(resized)
            if data:
                # Reescalar los puntos a la dimensión original
                if points is not None:
                    points = points * (1.0 / scale)
                    annotated = self._draw_qr_quadrilateral(annotated, points)
                return {
                    "success": True,
                    "data": data.strip(),
                    "points": points.tolist() if points is not None else None,
                    "annotated_image": annotated,
                    "method": "scaled_pass",
                    "error": None,
                }

        return {
            "success": False,
            "data": "",
            "points": None,
            "annotated_image": annotated,
            "method": "exhausted",
            "error": "No se detectó ningún código QR válido tras aplicar los 4 filtros heurísticos de visión computacional.",
        }

    def _draw_qr_quadrilateral(self, img: np.ndarray, points: Optional[np.ndarray]) -> np.ndarray:
        """
        Dibuja un polígono verde de alta visibilidad delimitando el código QR detectado.
        """
        if points is None:
            return img

        try:
            pts = np.int32(points).reshape(-1, 2)
            # Dibujar polígono en verde neón defensivo (BGR: 0, 255, 0)
            cv2.polylines(img, [pts], isClosed=True, color=(0, 255, 0), thickness=4)
            # Dibujar esquinas reforzadas
            for point in pts:
                cv2.circle(img, (int(point[0]), int(point[1])), 6, (0, 165, 255), -1)
        except Exception:
            pass

        return img

    @staticmethod
    def generate_qr_image(data: str) -> np.ndarray:
        """
        Genera una imagen QR en memoria (formato BGR para OpenCV/Streamlit)
        útil para el laboratorio interactivo y pruebas.
        """
        import qrcode

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        return cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
