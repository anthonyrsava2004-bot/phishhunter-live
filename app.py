"""
PhishHunter Live: Sistema de Inspección Heurística y Aislamiento Preventivo contra Amenazas de Quishing mediante Visión Computacional
====================================================================================================================================
Cumplimiento normativo y controles de ciberseguridad:
- ISO/IEC 27001:2022 (A.8.15 Trazabilidad, A.8.20 Aislamiento Defensivo, A.8.24 Criptografía)
- OWASP ASVS v4.0 (V5.1 Validación de Redirecciones / CWE-601, CWE-79 Aislamiento XSS)
- NIST SP 800-52 Rev. 2 / NIST SP 800-63B (Transporte Seguro y Mitigación de Typosquatting)
- CIS Controls v8 (Control 4.1 Configuraciones Seguras y Control de Superficie de Ataque)
- MITRE ATT&CK (T1566.002 Phishing Link / Quishing, T1583.001 Dominios Comprometidos)
"""

import json
import os
import cv2
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from PIL import Image

from core.heuristic_engine import HeuristicEngine
from core.qr_decoder import QRDecoder
from core.sandbox_preview import SandboxPreview
from core.url_tracer import URLTracer
from database.db_manager import DatabaseManager
from utils.threat_signatures import ALL_PROTECTED_DOMAINS, HIGH_RISK_TLDS

# ==============================================================================
# Configuración de Streamlit y Estilos CSS SOC Defensivo
# ==============================================================================
st.set_page_config(
    page_title="PhishHunter Live | Anti-Quishing SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inyección de estilos CSS corporativos para entorno SOC de Ciberseguridad
st.markdown("""
<meta name="google" content="notranslate">
<style>
    /* Evitar que motores de traducción automática rompan el árbol DOM de React */
    body, div, p, span, h1, h2, h3, h4, h5, h6 {
        -webkit-font-smoothing: antialiased;
    }
    
    /* Tipografía y fondo principal */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0d131f 0%, #080c14 90%);
        color: #e2e8f0;
    }
    
    /* Contenedores y tarjetas Glassmorphism */
    .soc-card {
        background: rgba(22, 30, 46, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 18px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
    }
    
    .soc-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border-bottom: 2px solid #38bdf8;
        padding: 22px 28px;
        border-radius: 12px;
        margin-bottom: 25px;
    }
    
    /* Insignias de severidad */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    
    .badge-suspicious {
        background-color: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    
    .badge-safe {
        background-color: rgba(16, 185, 129, 0.2);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    
    .badge-control {
        background-color: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid #0284c7;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78rem;
        font-family: monospace;
    }
    
    /* Escudo de cuarentena para Sandbox */
    .quarantine-shield {
        background: rgba(239, 68, 68, 0.1);
        border: 2px dashed #ef4444;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        margin: 15px 0;
    }
    
    .safe-shield {
        background: rgba(16, 185, 129, 0.1);
        border: 2px solid #10b981;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        margin: 15px 0;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# Inicialización de Componentes y Estado de Sesión
# ==============================================================================
@st.cache_resource
def get_db_manager() -> DatabaseManager:
    return DatabaseManager()

@st.cache_resource
def get_qr_decoder() -> QRDecoder:
    return QRDecoder()

@st.cache_resource
def get_url_tracer() -> URLTracer:
    return URLTracer()

@st.cache_resource
def get_heuristic_engine() -> HeuristicEngine:
    return HeuristicEngine()

@st.cache_resource
def get_sandbox_preview() -> SandboxPreview:
    return SandboxPreview()

db = get_db_manager()
qr_decoder = get_qr_decoder()
url_tracer = get_url_tracer()
heuristic_engine = get_heuristic_engine()
sandbox_preview = get_sandbox_preview()

if "sample_url_to_analyze" not in st.session_state:
    st.session_state["sample_url_to_analyze"] = ""

# ==============================================================================
# Barra Lateral (Sidebar) - Estado del SOC y Configuración Defensiva
# ==============================================================================
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/security/white_48dp.png",
        width=50
    )
    st.title("PhishHunter SOC")
    st.markdown("**Sistema de Inspección Heurística de Quishing**")
    st.markdown("---")
    
    # Indicadores de Salud Operacional
    st.markdown("### 🟢 Telemetría del Sistema")
    st.markdown("- **Motor**: Heurístico Multicapa v2.4")
    st.markdown("- **Base Forense**: SQLite Local (`audit_logs`)")
    st.markdown(f"- **Timeout de Red**: `{os.getenv('HTTP_TIMEOUT', '4.0')}s`")
    st.markdown(f"- **Max Saltos**: `{os.getenv('MAX_REDIRECT_HOPS', '7')}`")
    st.markdown("- **Agente**: `PhishHunterDefensiveCrawler`")
    
    st.markdown("---")
    st.markdown("### 📜 Alineación Normativa")
    st.markdown("""
    - **ISO/IEC 27001:2022** (A.8.15, A.8.20, A.8.24)
    - **OWASP ASVS v4.0** (V5.1 / CWE-601 / CWE-79)
    - **NIST SP 800-52 / 63B**
    - **CIS Controls v8** (Control 4.1)
    - **MITRE ATT&CK** (T1566.002 / T1583.001)
    """)
    
    st.markdown("---")
    if st.button("🧹 Purgar Bitácora Forense (Lab)", use_container_width=True):
        count = db.purge_all_logs()
        st.success(f"Bitácora purgada ({count} registros eliminados).")
        st.rerun()

# ==============================================================================
# Encabezado Principal y Banner de Métricas Rápidas
# ==============================================================================
st.markdown("""
<div class="soc-header">
    <h1 style="color: #38bdf8; margin: 0; font-size: 2.1rem; display: flex; align-items: center; gap: 12px;">
        <span>🛡️</span> PhishHunter Live: Inspección Heurística y Aislamiento de Quishing
    </h1>
    <p style="color: #94a3b8; margin: 8px 0 0 0; font-size: 1.05rem;">
        Detección de Phishing mediante Códigos QR respaldada por Visión Computacional, Trazabilidad de Saltos HTTP, Auditoría Criptográfica TLS y Sandbox Pasivo.
    </p>
</div>
""", unsafe_allow_html=True)

# Obtener estadísticas agregadas de la base de datos local
stats = db.get_audit_stats()
col_stat1, col_stat2, col_stat3, col_stat4, col_stat5 = st.columns(5)

with col_stat1:
    st.metric("Total Inspecciones", stats["total_inspections"])
with col_stat2:
    st.metric("Amenazas Críticas", stats["critical_count"], delta_color="inverse")
with col_stat3:
    st.metric("Incidentes Sospechosos", stats["suspicious_count"])
with col_stat4:
    st.metric("Inspecciones Seguras", stats["safe_count"])
with col_stat5:
    st.metric("Risk Score Promedio", f"{stats['average_score']}/100")

st.markdown("---")

# ==============================================================================
# Pestañas Principales del Sistema
# ==============================================================================
tab_inspect, tab_dashboard, tab_compliance, tab_lab = st.tabs([
    "🔍 Inspección de Amenazas",
    "📊 SOC Forensic Dashboard & Trazabilidad",
    "🛡️ Catálogo de Controles y Marco Normativo",
    "🧪 Laboratorio de Muestras y Pruebas",
])


# ==============================================================================
# TAB 1: INSPECCIÓN DE AMENAZAS (LIVE SCAN / UPLOAD / MANUAL URL)
# ==============================================================================
with tab_inspect:
    st.markdown("### 📥 Entrada y Captura de Códigos QR")
    
    input_method = st.radio(
        "Seleccione el vector de entrada:",
        ["📁 Cargar Imagen QR (PNG, JPG, WEBP)", "📷 Escaneo en Vivo por Cámara Web", "⌨️ Entrada Manual de URL / Payload"],
        horizontal=True,
        key="input_vector_method"
    )
    
    decoded_qr_text: str = ""
    annotated_qr_image = None
    decoding_method = ""
    
    input_container = st.container()
    
    with input_container:
        if input_method == "📁 Cargar Imagen QR (PNG, JPG, WEBP)":
            uploaded_file = st.file_uploader(
                "Cargue un archivo de imagen que contenga un código QR:",
                type=["png", "jpg", "jpeg", "webp"],
                key="qr_file_uploader_widget",
                help="Soporta fotos móviles de alta resolución, imágenes con bajo contraste y formatos estándar."
            )
            if uploaded_file is not None:
                file_bytes = uploaded_file.read()
                decode_res = qr_decoder.decode_from_bytes(file_bytes)
                if decode_res["success"]:
                    decoded_qr_text = decode_res["data"]
                    annotated_qr_image = decode_res["annotated_image"]
                    decoding_method = decode_res["method"]
                    st.success(f"✅ Código QR detectado y decodificado exitosamente (Algoritmo: `{decoding_method}`).")
                else:
                    st.warning(f"⚠️ {decode_res['error']}")
                    st.image(file_bytes, caption="Imagen analizada sin QR detectable", width=300)

        elif input_method == "📷 Escaneo en Vivo por Cámara Web":
            st.info("Presente el código QR ante la cámara de su dispositivo y capture el fotograma:")
            camera_photo = st.camera_input("Capturar código QR en vivo", key="qr_camera_scanner_widget")
            if camera_photo is not None:
                photo_bytes = camera_photo.read()
                decode_res = qr_decoder.decode_from_bytes(photo_bytes)
                if decode_res["success"]:
                    decoded_qr_text = decode_res["data"]
                    annotated_qr_image = decode_res["annotated_image"]
                    decoding_method = decode_res["method"]
                    st.success(f"✅ Código QR extraído de la cámara (Algoritmo: `{decoding_method}`).")
                else:
                    st.warning(f"⚠️ {decode_res['error']}")
                    st.image(photo_bytes, caption="Captura de cámara procesada", width=320)

        else:  # Entrada Manual
            default_val = st.session_state.get("sample_url_to_analyze", "")
            decoded_qr_text = st.text_input(
                "Ingrese la URL o texto del señuelo para inspección heurística directa:",
                value=default_val,
                key="qr_manual_input_widget",
                placeholder="https://ejemplo-bancario-sospechoso.xyz/login"
            )

    # Si hay una imagen con anotación QR detectada, mostrarla
    if annotated_qr_image is not None:
        col_img1, col_img2 = st.columns([1, 2])
        with col_img1:
            rgb_annotated = cv2.cvtColor(annotated_qr_image, cv2.COLOR_BGR2RGB)
            st.image(rgb_annotated, caption="Delimitación de Simbología QR (OpenCV Bounding Polygon)", use_container_width=True)
        with col_img2:
            st.markdown("**Contenido Decodificado del Código QR:**")
            st.code(decoded_qr_text, language="text")

    # Botón para detonar el análisis integral de ciberseguridad
    if decoded_qr_text:
        st.markdown("---")
        btn_analyze = st.button("🚀 Ejecutar Inspección Defensiva Integral", type="primary", key="btn_trigger_inspection", use_container_width=True)

        if btn_analyze:
            with st.status("🔍 Ejecutando Cadena Defensiva de Inspección y Aislamiento...", expanded=True) as status:
                st.write("1️⃣ Rastreando saltos HTTP y validando TLS (OWASP ASVS V5.1 / ISO 27001 A.8.24)...")
                trace_result = url_tracer.trace(decoded_qr_text)
                
                st.write("2️⃣ Evaluando firmas homógrafas y decodificación Punycode (RFC 5890 / MITRE T1566.002)...")
                st.write("3️⃣ Calculando distancia de Levenshtein contra marcas oficiales (NIST SP 800-63B)...")
                st.write("4️⃣ Verificando IPs directas y TLDs de alto riesgo (CIS Controls v8 4.1)...")
                analysis = heuristic_engine.analyze(decoded_qr_text, trace_result)
                
                is_dangerous = analysis["risk_score"] >= 30
                st.write("5️⃣ Generando contenedor Sandbox pasivo con desinfección HTML (ISO 27001 A.8.20 / CWE-79)...")
                sandbox_res = sandbox_preview.fetch_and_isolate(
                    analysis["target_url"],
                    is_dangerous=is_dangerous
                )
                
                st.write("6️⃣ Registrando evidencia en la bitácora forense SQLite (ISO 27001 A.8.15)...")
                log_id = db.insert_audit_log(
                    qr_raw_data=decoded_qr_text,
                    final_url=analysis["target_url"],
                    redirect_count=trace_result["redirect_count"],
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    detected_flags=analysis["flags_detected"],
                    client_ip="127.0.0.1"
                )
                status.update(label="✅ Inspección Heurística Finalizada con Éxito", state="complete", expanded=False)

            # ------------------------------------------------------------------
            # Presentación de Resultados Forenses
            # ------------------------------------------------------------------
            score = analysis["risk_score"]
            level = analysis["risk_level"]
            
            # Encabezado del dictamen
            if score >= 70:
                badge_html = f'<span class="badge-critical">{analysis["risk_badge"]} {level} ({score}/100)</span>'
                alert_css = "quarantine-shield"
            elif score >= 30:
                badge_html = f'<span class="badge-suspicious">{analysis["risk_badge"]} {level} ({score}/100)</span>'
                alert_css = "soc-card"
            else:
                badge_html = f'<span class="badge-safe">{analysis["risk_badge"]} {level} ({score}/100)</span>'
                alert_css = "safe-shield"

            st.markdown(f"""
            <div class="{alert_css}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin: 0; color: #f8fafc;">Dictamen de Seguridad: {badge_html}</h3>
                    <span style="font-family: monospace; color: #94a3b8;">ID Auditoría: #{log_id}</span>
                </div>
                <p style="font-size: 1.05rem; margin: 5px 0;"><strong>Acción Defensiva Recomendada:</strong> {analysis["action_recommended"]}</p>
                <p style="font-size: 0.9rem; color: #94a3b8; margin: 0;">Destino final auditado: <code>{analysis["target_url"]}</code></p>
            </div>
            """, unsafe_allow_html=True)

            # Columnas de Métricas Técnicas
            col_res1, col_res2, col_res3, col_res4 = st.columns(4)
            with col_res1:
                st.metric("Risk Score", f"{score} / 100")
            with col_res2:
                st.metric("Saltos de Redirección", trace_result["redirect_count"])
            with col_res3:
                if not trace_result.get("is_web_url", True):
                    tls_status = "No Aplica (Carga P2P)"
                else:
                    tls_status = "Válido y Forzado" if trace_result["ssl_valid"] and not trace_result.get("has_tls_downgrade") else "Anómalo / Inválido"
                st.metric("Estado Criptográfico TLS", tls_status)
            with col_res4:
                st.metric("Reglas Infraccionadas", len(analysis["flags_detected"]))

            if analysis.get("payload_type") == "emvco_payment":
                emv = analysis.get("emvco_info", {})
                st.markdown(f"""
                <div class="soc-card" style="border-left: 4px solid #10b981; margin-top: 15px;">
                    <h4 style="color: #10b981; margin: 0 0 10px 0;">💳 Especificación de Pago Móvil EMVCo ({emv.get('network', 'P2P')})</h4>
                    <p style="margin: 4px 0;"><strong>Beneficiario / Comercio:</strong> {emv.get('merchant_name')}</p>
                    <p style="margin: 4px 0;"><strong>Ubicación:</strong> {emv.get('merchant_city')}, {emv.get('country_code')} (Perú)</p>
                    <p style="margin: 4px 0;"><strong>Moneda de Operación:</strong> {emv.get('currency')} | <strong>Categoría MCC:</strong> {emv.get('category_code')}</p>
                    <p style="margin: 4px 0; color: #94a3b8; font-size: 0.85rem;">Verificación de Integridad CRC16: <code>{emv.get('checksum')}</code></p>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")

            # ------------------------------------------------------------------
            # Matriz de Justificación Técnica y Mapeo de Controles
            # ------------------------------------------------------------------
            st.markdown("### 📋 Desglose Técnico de Hallazgos y Mapeo Normativo")
            
            if not analysis["flags_detected"]:
                st.success("✅ No se detectaron penalizaciones. La URL cumple con los estándares de transporte seguro (ISO 27001 A.8.24) y no muestra homógrafos ni suplantación de identidad.")
            else:
                for idx, flag in enumerate(analysis["flags_detected"], 1):
                    sev = flag["severity"]
                    sev_class = "badge-critical" if sev == "CRÍTICA" else ("badge-suspicious" if sev in ("ALTA", "MEDIA") else "badge-safe")
                    
                    st.markdown(f"""
                    <div class="soc-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h4 style="margin: 0; color: #38bdf8;">#{idx} {flag["name"]}</h4>
                            <div>
                                <span class="{sev_class}">{sev} (+{flag["penalty"]} pts)</span>
                                <span class="badge-control">{flag["standard"]}</span>
                            </div>
                        </div>
                        <p style="margin: 10px 0 0 0; color: #cbd5e1; font-size: 0.95rem;">{flag["description"]}</p>
                    </div>
                    """, unsafe_allow_html=True)

            # ------------------------------------------------------------------
            # Trazabilidad de Saltos de Redirección (OWASP ASVS V5.1 / CWE-601)
            # ------------------------------------------------------------------
            with st.expander("🌐 Cadena Forense de Redirecciones HTTP y Análisis de Cabeceras", expanded=True):
                if trace_result["hops"]:
                    hop_rows = []
                    for h in trace_result["hops"]:
                        hop_rows.append({
                            "Salto #": h["hop"],
                            "Código HTTP": f"{h['status_code']} {h.get('reason', '')}",
                            "Hostname": h["hostname"],
                            "IP Resuelta": h["resolved_ip"],
                            "Puerto": h["port"],
                            "Protocolo": h["scheme"].upper(),
                            "Latencia": f"{h['elapsed_ms']} ms",
                            "URL Objetivo": h["url"],
                        })
                    df_hops = pd.DataFrame(hop_rows)
                    st.dataframe(df_hops, use_container_width=True)
                    
                    # Detalles criptográficos TLS
                    tls_info = trace_result.get("tls_audit", {})
                    if tls_info.get("enforced"):
                        st.markdown(f"**Auditoría TLS Remota:** Versión: `{tls_info.get('tls_version')}` | Cifrado: `{tls_info.get('cipher')}` | Emisor CA: `{tls_info.get('issuer_cn')}` | Expira: `{tls_info.get('expires')}`")
                else:
                    st.info("No se generaron saltos de red o la URL no requirió redirección.")

            # ------------------------------------------------------------------
            # Sandbox Pasivo y Aislamiento Preventivo (ISO 27001 A.8.20 / CWE-79)
            # ------------------------------------------------------------------
            st.markdown("### 📦 Sandbox Pasivo y Aislamiento Preventivo")
            
            if is_dangerous:
                st.markdown("""
                <div class="quarantine-shield">
                    <h4 style="color: #ef4444; margin: 0;">🛡️ ESCUDO DE AISLAMIENTO ACTIVO (ISO/IEC 27001 Control A.8.20)</h4>
                    <p style="color: #cbd5e1; margin: 6px 0 0 0;">
                        Los enlaces directos están <strong>estrictamente bloqueados</strong> para evitar ataques 'Drive-by Download' o ejecución de exploits en el navegador del analista. A continuación se expone la réplica pasiva desinfectada.
                    </p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="safe-shield">
                    <h4 style="color: #10b981; margin: 0;">🟢 RECURSO VERIFICADO COMO SEGURO</h4>
                    <p style="color: #cbd5e1; margin: 6px 0 0 0;">
                        El recurso no presenta riesgo de quishing. Puede acceder de forma segura si lo requiere.
                    </p>
                </div>
                """, unsafe_allow_html=True)

            col_sand1, col_sand2 = st.columns([1, 1])
            with col_sand1:
                st.markdown("#### 🖼️ Metadatos OpenGraph Extraídos:")
                meta = sandbox_res["metadata"]
                st.markdown(f"**Título:** {meta['title']}")
                st.markdown(f"**Descripción:** {meta['description']}")
                st.markdown(f"**Sitio Web:** {meta['site_name']}")
                if meta.get("image_url"):
                    st.image(meta["image_url"], caption="Imagen OpenGraph del señuelo", width=260)
                if meta.get("favicon_url"):
                    st.markdown(f"**Favicon:** [Ver Icono]({meta['favicon_url']})")

            with col_sand2:
                st.markdown("#### 📄 Vista Sanitizada del DOM (Sin JavaScript):")
                st.markdown(f"*Tamaño de payload:* `{sandbox_res['page_size_kb']} KB`")
                st.text_area(
                    "Resumen de texto plano extraído pasivamente:",
                    sandbox_res["text_summary"],
                    height=180,
                    disabled=True
                )
                
                with st.expander("🔍 Inspeccionar Código HTML Sanitizado (CWE-79 Neutralizado)"):
                    st.code(sandbox_res["sanitized_html"], language="html")


# ==============================================================================
# TAB 2: SOC FORENSIC DASHBOARD & BITÁCORA DE AUDITORÍA
# ==============================================================================
with tab_dashboard:
    st.markdown("### 📊 Trazabilidad Forense e Incidentes Detectados (ISO/IEC 27001 A.8.15)")
    
    dash_stats = db.get_audit_stats()
    
    col_dash1, col_dash2 = st.columns([1, 1])
    with col_dash1:
        # Gráfico Donut de Severidad
        labels = ["CRÍTICO / QUISHING", "SOSPECHOSO", "SEGURO"]
        values = [dash_stats["critical_count"], dash_stats["suspicious_count"], dash_stats["safe_count"]]
        
        fig_donut = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.5,
            marker_colors=["#ef4444", "#f59e0b", "#10b981"]
        )])
        fig_donut.update_layout(
            title="Distribución de Incidentes por Nivel de Riesgo",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=40, b=20, l=20, r=20),
            height=300
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_dash2:
        # Gráfico de barras de firmas detectadas
        all_logs = db.get_all_audit_logs(limit=200)
        flag_frequencies = {}
        for l in all_logs:
            for f in l["detected_flags"]:
                r_name = f.get("name", "Desconocida")
                flag_frequencies[r_name] = flag_frequencies.get(r_name, 0) + 1
        
        if flag_frequencies:
            df_flags = pd.DataFrame(list(flag_frequencies.items()), columns=["Firma / Regla", "Frecuencia"])
            df_flags = df_flags.sort_values(by="Frecuencia", ascending=True).tail(8)
            fig_bar = px.bar(
                df_flags,
                x="Frecuencia",
                y="Firma / Regla",
                orientation="h",
                title="Firmas de Amenaza Más Frecuentes",
                color_discrete_sequence=["#38bdf8"]
            )
            fig_bar.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=40, b=20, l=20, r=20),
                height=300
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No hay suficientes incidentes registrados para generar gráficos de frecuencia.")

    st.markdown("---")
    st.markdown("### 🗃️ Registro Inmutable de Inspecciones (`audit_logs`)")
    
    # Barra de filtrado
    search_term = st.text_input("Filtrar bitácora por URL, dominio o nivel de severidad:", placeholder="Buscar...")
    logs_data = db.get_all_audit_logs(limit=150, search_query=search_term)
    
    if logs_data:
        # Formatear para tabla
        table_rows = []
        for row in logs_data:
            table_rows.append({
                "ID": row["id"],
                "Fecha / Hora (UTC)": row["timestamp"][:19].replace("T", " "),
                "Payload QR Original": row["qr_raw_data"],
                "URL Final": row["final_url"],
                "Saltos": row["redirect_count"],
                "Score": row["risk_score"],
                "Nivel": row["risk_level"],
                "Reglas": len(row["detected_flags"]),
                "IP Cliente": row["client_ip"],
            })
        df_table = pd.DataFrame(table_rows)
        st.dataframe(df_table, use_container_width=True, height=350)
    else:
        st.info("La bitácora de auditoría no contiene registros coincidentes con el filtro.")

    # Botones de exportación forense
    st.markdown("#### 📥 Exportar Bitácora Forense Oficial:")
    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        csv_data = db.export_to_csv()
        st.download_button(
            label="📄 Descargar Bitácora Forense en Formato CSV",
            data=csv_data,
            file_name="phishhunter_audit_logs.csv",
            mime="text/csv",
            use_container_width=True
        )
    with col_exp2:
        json_data = db.export_to_json()
        st.download_button(
            label="📦 Descargar Bitácora Forense en Formato JSON",
            data=json_data,
            file_name="phishhunter_audit_logs.json",
            mime="application/json",
            use_container_width=True
        )


# ==============================================================================
# TAB 3: CATÁLOGO DE CONTROLES Y MARCO NORMATIVO
# ==============================================================================
with tab_compliance:
    st.markdown("### 🛡️ Catálogo de Controles de Ciberseguridad Implementados")
    st.markdown("""
    PhishHunter Live articula una arquitectura de ciberdefensa alineada formalmente con los principales 
    estándares y marcos de la industria:
    """)
    
    col_c1, col_c2 = st.columns(2)
    
    with col_c1:
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #38bdf8; margin-top:0;">🔒 ISO/IEC 27001:2022</h4>
            <ul>
                <li><strong>Control A.8.15 (Logging):</strong> Registro sistemático inmutable en SQLite de cada inspección, trazando tiempo, IP, URL original, saltos y score.</li>
                <li><strong>Control A.8.20 (Seguridad en Redes / Aislamiento):</strong> Neutralización de enlaces y contención preventiva en Sandbox ante cualquier riesgo sospechoso o crítico.</li>
                <li><strong>Control A.8.24 (Uso de Criptografía):</strong> Inspección obligatoria de certificados SSL/TLS y penalización severa ante HTTP en texto claro o degradaciones criptográficas.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #38bdf8; margin-top:0;">🌐 OWASP ASVS v4.0 & Top 10</h4>
            <ul>
                <li><strong>Control V5.1 / CWE-601 (Open Redirects):</strong> Rastreo controlado salto por salto (301, 302, 307, 308) detectando bifurcaciones entre dominios no relacionados y bucles.</li>
                <li><strong>CWE-79 (Cross-Site Scripting):</strong> Sanitización estricta del DOM en Sandbox Pasivo, desarmando JavaScript y eventos onclick para evitar ataques 'Drive-by'.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col_c2:
        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #38bdf8; margin-top:0;">🏛️ NIST Special Publications</h4>
            <ul>
                <li><strong>NIST SP 800-52 Rev. 2:</strong> Verificación de suites criptográficas TLS, expiración de certificados y detección de puertos no convencionales.</li>
                <li><strong>NIST SP 800-63B / MITRE ATT&CK T1583.001:</strong> Detección de Typosquatting mediante cálculo de distancia de Levenshtein contra marcas y pasarelas oficiales.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="soc-card">
            <h4 style="color: #38bdf8; margin-top:0;">⚙️ CIS Controls v8 & RFC 5890</h4>
            <ul>
                <li><strong>CIS Controls v8 (4.1):</strong> Alerta por uso directo de direcciones IP públicas en lugar de FQDN y monitoreo de TLDs de alto riesgo (.xyz, .top, .live).</li>
                <li><strong>RFC 5890 / MITRE ATT&CK T1566.002:</strong> Detección de ataques homógrafos IDN por sustitución de caracteres cirílicos/griegos y prefijos Punycode (<code>xn--</code>).</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# TAB 4: LABORATORIO DE MUESTRAS Y PRUEBAS RÁPIDAS
# ==============================================================================
with tab_lab:
    st.markdown("### 🧪 Laboratorio Forense: Generador de Vectores de Quishing")
    st.markdown("""
    Seleccione un arquetipo de amenaza o vector legítimo para generar su respectivo código QR en memoria
    y transferirlo al motor de inspección defensiva:
    """)
    
    samples = {
        "🟢 Caso 1: Enlace Legítimo Seguro (Banca Oficial)": "https://www.chase.com",
        "🔴 Caso 2: Ataque Homógrafo Cirílico (MITRE T1566.002)": "https://\u0440aypal.com/verify-account",
        "🔴 Caso 3: Ataque Punycode IDN Oculto (RFC 5890)": "https://xn--pypal-4ve.com/security/login",
        "🔴 Caso 4: Typosquatting / Combosquatting (NIST SP 800-63B)": "https://paypa1.com/login",
        "🔴 Caso 5: IP Directa + Puerto Anómalo + HTTP (CIS Controls 4.1)": "http://198.51.100.23:8080/portal/auth",
        "🟡 Caso 6: TLD de Alto Riesgo + Lures de Credenciales": "https://soporte-bancario-urgente.xyz/update-banking-2fa",
    }
    
    selected_sample_title = st.selectbox("Seleccione un arquetipo de prueba:", list(samples.keys()))
    selected_payload = samples[selected_sample_title]
    
    col_lab1, col_lab2 = st.columns([1, 2])
    with col_lab1:
        # Generar código QR sintético
        qr_sample_img = QRDecoder.generate_qr_image(selected_payload)
        st.image(cv2.cvtColor(qr_sample_img, cv2.COLOR_BGR2RGB), caption="Código QR Generado para el Vector", width=220)

    with col_lab2:
        st.markdown(f"**Payload del Vector:**")
        st.code(selected_payload, language="text")
        
        if st.button("🚀 Cargar este Vector en la Pestaña de Inspección", type="primary"):
            st.session_state["sample_url_to_analyze"] = selected_payload
            st.success("Vector cargado en memoria de sesión. Diríjase a la pestaña '🔍 Inspección de Amenazas' para ejecutar la auditoría.")
