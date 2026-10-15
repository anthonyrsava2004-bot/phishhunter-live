"""
PhishHunter Live - Módulo de Decodificación y Visión Computacional QR
=============================================================================
Alineado con:
- ISO/IEC 18004 (Especificación de simbología de código QR)
- Entorno de ejecución Headless portable (sin requerir dependencias X11/GTK)
- Detección reforzada para cámaras móviles (Auto-orientación EXIF, ArUco y multi-escala)
"""

import io
from typing import Any, Dict, List, Optional, Tuple, Union
import cv2
import numpy as np
from PIL import Image, ImageOps


class QRDecoder:
    """
    Decodificador industrial de códigos QR basado en OpenCV Headless con soporte
    dual (ArUco + Detector Tradicional), normalización EXIF para smartphones y
    pipeline morfológico adaptativo multinivel.
    """

    def __init__(self):
        # 1. Detector ArUco avanzado (introducido en OpenCV moderno, superior contra ruido y ángulos)
        self.aruco_detector = None
        if hasattr(cv2, "QRCodeDetectorAruco"):
            try:
                self.aruco_detector = cv2.QRCodeDetectorAruco()
            except Exception:
                self.aruco_detector = None

        # 2. Detector tradicional de OpenCV
        self.legacy_detector = cv2.QRCodeDetector()

    def decode_from_bytes(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Decodifica un código QR a partir de un flujo de bytes con corrección EXIF
        automática para cámaras de teléfonos móviles.
        """
        try:
            # Cargar mediante PIL para normalizar orientación EXIF (imprescindible en iOS / Android)
            pil_img = Image.open(io.BytesIO(image_bytes))
            pil_img = ImageOps.exif_transpose(pil_img)
            pil_img = pil_img.convert("RGB")
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
        Ejecuta una canalización de búsqueda exhaustiva:
        1. Pases multi-escala (resolución nativa y downscales controlados a 1000px, 800px, 600px).
        2. Detectores combinados (ArUco primero, Legacy como respaldo).
        3. Filtros morfológicos: CLAHE, Enfoque (Unsharp Mask), Umbral Otsu, Umbral Adaptativo.
        4. Rotaciones angulares automáticas (0°, 90°, 180°, 270°).
        5. Inversión de polaridad (QRs claros sobre fondo oscuro).
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

        annotated = img.copy()
        orig_h, orig_w = img.shape[:2]

        # Lista de detectores ordenados por eficacia
        detectors = []
        if self.aruco_detector is not None:
            detectors.append(("aruco", self.aruco_detector))
        detectors.append(("legacy", self.legacy_detector))

        # Generar pirámide de escalas
        scale_variants = self._generate_scale_variants(img)

        # Matriz de intentos
        for scale_name, scaled_img, scale_factor in scale_variants:
            # 1. Pruebas directas en escalas
            for det_name, detector in detectors:
                data, points, _ = detector.detectAndDecode(scaled_img)
                if data and data.strip():
                    orig_points = self._rescale_points(points, scale_factor)
                    annotated = self._draw_qr_quadrilateral(annotated, orig_points)
                    return {
                        "success": True,
                        "data": data.strip(),
                        "points": orig_points.tolist() if orig_points is not None else None,
                        "annotated_image": annotated,
                        "method": f"{det_name}_{scale_name}_direct",
                        "error": None,
                    }

            # 2. Generar variantes de preprocesamiento para esta escala
            filter_variants = self._generate_filter_variants(scaled_img)
            for filter_name, filtered_img in filter_variants:
                for det_name, detector in detectors:
                    data, points, _ = detector.detectAndDecode(filtered_img)
                    if data and data.strip():
                        orig_points = self._rescale_points(points, scale_factor)
                        annotated = self._draw_qr_quadrilateral(annotated, orig_points)
                        return {
                            "success": True,
                            "data": data.strip(),
                            "points": orig_points.tolist() if orig_points is not None else None,
                            "annotated_image": annotated,
                            "method": f"{det_name}_{scale_name}_{filter_name}",
                            "error": None,
                        }

        # 3. Pase de rescate con rotaciones de 90° (por si el sensor no corrigió la orientación)
        rotations = [
            ("rot90", cv2.ROTATE_90_CLOCKWISE),
            ("rot180", cv2.ROTATE_180),
            ("rot270", cv2.ROTATE_90_COUNTERCLOCKWISE),
        ]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(gray)

        for rot_name, rot_code in rotations:
            rotated = cv2.rotate(clahe, rot_code)
            for det_name, detector in detectors:
                data, _, _ = detector.detectAndDecode(rotated)
                if data and data.strip():
                    return {
                        "success": True,
                        "data": data.strip(),
                        "points": None,
                        "annotated_image": annotated,
                        "method": f"{det_name}_{rot_name}_clahe",
                        "error": None,
                    }

        return {
            "success": False,
            "data": "",
            "points": None,
            "annotated_image": annotated,
            "method": "exhausted",
            "error": "No se detectó ningún código QR tras la inspección adaptativa multi-escala y morfológica.",
        }

    def _generate_scale_variants(self, img: np.ndarray) -> List[Tuple[str, np.ndarray, float]]:
        """
        Genera versiones reescaladas para optimizar la ventana de búsqueda de findPatterns.
        """
        h, w = img.shape[:2]
        max_dim = max(h, w)
        variants = [("orig", img, 1.0)]

        target_dims = [1000, 800, 600]
        for target in target_dims:
            if max_dim > target * 1.2:
                scale = target / float(max_dim)
                resized = cv2.resize(
                    img,
                    (int(w * scale), int(h * scale)),
                    interpolation=cv2.INTER_AREA
                )
                variants.append((f"scale_{target}", resized, scale))

        return variants

    def _generate_filter_variants(self, img: np.ndarray) -> List[Tuple[str, np.ndarray]]:
        """
        Genera variantes morfológicas y de realce de contraste de la imagen.
        """
        if len(img.shape) == 3:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        else:
            gray = img.copy()

        variants = []

        # 1. CLAHE Adaptativo moderado
        clahe_mod = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        variants.append(("clahe_mod", clahe_mod.apply(gray)))

        # 2. CLAHE Fuerte (para imágenes con sombras o iluminación irregular)
        clahe_strong = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(8, 8))
        enhanced_strong = clahe_strong.apply(gray)
        variants.append(("clahe_strong", enhanced_strong))

        # 3. Realce de Enfoque (Unsharp Masking) para cámaras borrosas
        gaussian = cv2.GaussianBlur(gray, (0, 0), 2.0)
        sharpened = cv2.addWeighted(gray, 1.6, gaussian, -0.6, 0)
        variants.append(("sharpened", sharpened))

        # 4. Umbralización Otsu con filtro bilateral
        blurred = cv2.bilateralFilter(gray, 7, 50, 50)
        _, thresh_otsu = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(("otsu", thresh_otsu))

        # 5. Umbralización Adaptativa Gaussiana
        adaptive_thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 21, 5
        )
        variants.append(("adaptive_gauss", adaptive_thresh))

        # 6. Inversión de polaridad (fondo oscuro, módulos claros)
        inverted = cv2.bitwise_not(gray)
        variants.append(("inverted", inverted))

        return variants

    def _rescale_points(self, points: Optional[np.ndarray], scale_factor: float) -> Optional[np.ndarray]:
        """
        Reasigna las coordenadas del polígono detectado a la escala original de la imagen.
        """
        if points is None:
            return None
        if scale_factor == 1.0 or scale_factor <= 0:
            return points
        return points * (1.0 / scale_factor)

    def _draw_qr_quadrilateral(self, img: np.ndarray, points: Optional[np.ndarray]) -> np.ndarray:
        """
        Dibuja un polígono verde de alta visibilidad delimitando el código QR detectado.
        """
        if points is None:
            return img

        try:
            pts = np.int32(points).reshape(-1, 2)
            cv2.polylines(img, [pts], isClosed=True, color=(0, 255, 0), thickness=4)
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
