"""
PhishHunter Live - Gestor de Persistencia y Bitácora Forense SQLite
=============================================================================
Alineado con:
- ISO/IEC 27001:2022 Control A.8.15 (Logging / Trazabilidad de Auditoría)
- OWASP ASVS v4.0 V8 (Requisitos de Registro de Auditoría y Verificación)
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class DatabaseManager:
    """
    Gestor de base de datos SQLite para registro forense inmutable de inspecciones
    y trazabilidad analítica de incidentes de Quishing.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inicializa la conexión y estructura de la base de datos.
        """
        if db_path is None:
            # Obtener desde variable de entorno o usar la ruta por defecto
            db_path = os.getenv("DATABASE_PATH", "database/phishhunter.db")

        self.db_path = Path(db_path)
        # Garantizar que el directorio padre exista
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def _get_connection(self):
        """
        Retorna una conexión SQLite contextual que garantiza su cierre inmediato al terminar el bloque.
        """
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=15.0,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """
        Crea la tabla audit_logs e índices necesarios si no existen.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    qr_raw_data TEXT NOT NULL,
                    final_url TEXT NOT NULL,
                    redirect_count INTEGER NOT NULL DEFAULT 0,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_level TEXT NOT NULL,
                    detected_flags TEXT NOT NULL,
                    client_ip TEXT NOT NULL
                )
            """)
            # Índices para optimizar consultas del SOC Dashboard
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_logs(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_risk_level 
                ON audit_logs(risk_level)
            """)
            conn.commit()

    def insert_audit_log(
        self,
        qr_raw_data: str,
        final_url: str,
        redirect_count: int,
        risk_score: int,
        risk_level: str,
        detected_flags: List[Dict[str, Any]],
        client_ip: str = "127.0.0.1"
    ) -> int:
        """
        Registra una inspección en la bitácora forense de auditoría.
        Retorna el ID del registro creado.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        flags_json = json.dumps(detected_flags, ensure_ascii=False)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (
                    timestamp, qr_raw_data, final_url, redirect_count,
                    risk_score, risk_level, detected_flags, client_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                qr_raw_data,
                final_url,
                redirect_count,
                risk_score,
                risk_level,
                flags_json,
                client_ip
            ))
            conn.commit()
            return cursor.lastrowid or 0

    def get_all_audit_logs(
        self,
        limit: int = 100,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Obtiene los registros de auditoría ordenados del más reciente al más antiguo.
        Permite filtrado opcional por texto en URL original o final.
        """
        query = """
            SELECT id, timestamp, qr_raw_data, final_url, redirect_count,
                   risk_score, risk_level, detected_flags, client_ip
            FROM audit_logs
        """
        params: List[Any] = []

        if search_query and search_query.strip():
            query += " WHERE qr_raw_data LIKE ? OR final_url LIKE ? OR risk_level LIKE ?"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            results: List[Dict[str, Any]] = []
            for row in rows:
                try:
                    flags = json.loads(row["detected_flags"])
                except Exception:
                    flags = []

                results.append({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "qr_raw_data": row["qr_raw_data"],
                    "final_url": row["final_url"],
                    "redirect_count": row["redirect_count"],
                    "risk_score": row["risk_score"],
                    "risk_level": row["risk_level"],
                    "detected_flags": flags,
                    "client_ip": row["client_ip"]
                })
            return results

    def get_audit_stats(self) -> Dict[str, Any]:
        """
        Calcula métricas agregadas para el SOC Dashboard.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Conteo total
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total_inspections = cursor.fetchone()[0]

            if total_inspections == 0:
                return {
                    "total_inspections": 0,
                    "critical_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "average_score": 0.0,
                    "redirects_total": 0,
                }

            # Conteos por nivel
            cursor.execute("""
                SELECT risk_level, COUNT(*) 
                FROM audit_logs 
                GROUP BY risk_level
            """)
            counts_by_level = {row[0]: row[1] for row in cursor.fetchall()}

            # Promedios y sumas
            cursor.execute("""
                SELECT AVG(risk_score), SUM(redirect_count) 
                FROM audit_logs
            """)
            avg_score, total_redirects = cursor.fetchone()

            return {
                "total_inspections": total_inspections,
                "critical_count": counts_by_level.get("CRÍTICO / QUISHING", 0),
                "suspicious_count": counts_by_level.get("SOSPECHOSO", 0),
                "safe_count": counts_by_level.get("SEGURO", 0),
                "average_score": round(float(avg_score or 0.0), 1),
                "redirects_total": int(total_redirects or 0),
            }

    def export_to_json(self) -> str:
        """
        Exporta todos los registros de la bitácora forense a formato JSON string.
        """
        logs = self.get_all_audit_logs(limit=10000)
        return json.dumps(logs, indent=2, ensure_ascii=False)

    def export_to_csv(self) -> str:
        """
        Exporta los registros en formato CSV delimitado por comas.
        """
        import csv
        import io

        logs = self.get_all_audit_logs(limit=10000)
        output = io.StringIO()
        fieldnames = [
            "id", "timestamp", "qr_raw_data", "final_url", "redirect_count",
            "risk_score", "risk_level", "detected_flags_count", "client_ip"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for log in logs:
            writer.writerow({
                "id": log["id"],
                "timestamp": log["timestamp"],
                "qr_raw_data": log["qr_raw_data"],
                "final_url": log["final_url"],
                "redirect_count": log["redirect_count"],
                "risk_score": log["risk_score"],
                "risk_level": log["risk_level"],
                "detected_flags_count": len(log["detected_flags"]),
                "client_ip": log["client_ip"],
            })

        return output.getvalue()

    def delete_log(self, log_id: int) -> bool:
        """
        Elimina un registro específico por su identificador primario.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
            conn.commit()
            return cursor.rowcount > 0

    def purge_all_logs(self) -> int:
        """
        Limpia toda la bitácora de auditoría (para entornos de pruebas / laboratorio).
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM audit_logs")
            conn.commit()
            return cursor.rowcount
