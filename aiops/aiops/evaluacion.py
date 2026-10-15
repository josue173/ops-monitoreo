"""Entrena el detector y mide su desempeño con datos etiquetados (requisito de la rúbrica)."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from .caracteristicas import NOMBRES, agrupar, matriz
from .filterlog import parsear_linea
from .modelo import Detector
from .simulador import TIPOS_ATAQUE, Generador


NOMBRE_ESPERADO = {
    "escaneo": "Escaneo de puertos",
    "escaneo_lento": "Escaneo de puertos",
    "barrido": "Barrido de red",
    "fuerza_bruta": "Fuerza bruta",
    "inundacion_udp": "Inundación UDP",
    "inundacion_syn": "Inundación SYN",
}


def ventanas(lineas_con_tiempo, ventana_s: int = 60):
    eventos = ((ts, e) for ts, linea in lineas_con_tiempo if (e := parsear_linea(linea)) is not None)
    return matriz(agrupar(eventos, ventana_s))


def entrenar_sintetico(minutos: int = 240, semilla: int = 1) -> Detector:
    """Entrena solo con tráfico normal: el modelo aprende qué es "lo habitual"."""
    lineas, _ = Generador(semilla).escenario(minutos, prob_ataque=0.0)
    x, _ = ventanas(lineas)
    return Detector.entrenar(x)


def evaluar(detector: Detector, minutos: int = 240, semillas=(2, 3, 4), prob_ataque: float = 0.25) -> dict:
    """Prueba con datos nuevos (semillas distintas a la del entrenamiento) que mezclan tráfico
    normal y ataques. Se combinan varios escenarios para que el resultado no dependa de uno solo."""
    ys, ps, vp, totales, bien_nombrados = [], [], Counter(), Counter(), Counter()
    for semilla in semillas:
        lineas, etiquetas = Generador(semilla).escenario(minutos, prob_ataque=prob_ataque)
        x, claves = ventanas(lineas)
        puntajes = detector.puntajes(x)
        tipos = detector.explicar(x)
        ys.append(np.array([1 if k in etiquetas else 0 for k in claves]))
        ps.append(puntajes)
        for k, s, t in zip(claves, puntajes, tipos):
            if s < 0 and k in etiquetas:
                vp[etiquetas[k]] += 1
                if t == NOMBRE_ESPERADO[etiquetas[k]]:
                    bien_nombrados[etiquetas[k]] += 1
        totales.update(etiquetas.values())
    y, puntajes = np.concatenate(ys), np.concatenate(ps)
    pred = (puntajes < 0).astype(int)
    recall_por_tipo = {t: round(vp[t] / totales[t], 3) for t in TIPOS_ATAQUE if totales[t]}

    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "escenarios": len(semillas),
        "minutos_por_escenario": minutos,
        "ventanas_evaluadas": int(len(y)),
        "ventanas_ataque": int(y.sum()),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 3),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 3),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 3),
        # el puntaje es "más bajo = más anómalo", por eso se invierte para el AUC
        "roc_auc": round(float(roc_auc_score(y, -puntajes)), 3) if 0 < y.sum() < len(y) else None,
        "tasa_falsos_positivos": round(float(fp / max(fp + tn, 1)), 4),
        "matriz_confusion": {"vn": int(tn), "fp": int(fp), "fn": int(fn), "vp": int(tp)},
        "recall_por_tipo": recall_por_tipo,
        "tipo_correcto": {t: round(bien_nombrados[t] / vp[t], 3) for t in recall_por_tipo if vp[t]},
        "ataques_por_tipo": dict(totales),
    }


def reporte_markdown(m: dict) -> str:
    mc = m["matriz_confusion"]
    filas_tipo = "\n".join(
        f"| {NOMBRE_ESPERADO[t]}{' (lento)' if t == 'escaneo_lento' else ''} | {m['ataques_por_tipo'][t]} "
        f"| {m['recall_por_tipo'][t]:.0%} | {m['tipo_correcto'].get(t, 0):.0%} |"
        for t in m["recall_por_tipo"]
    )
    return f"""# Evaluación del motor AIOps

Modelo: Isolation Forest (200 árboles) sobre {len(NOMBRES)} características por IP y ventana de 60 s,
con una envolvente de rango para valores más extremos que los vistos al entrenar.

Entrenamiento: solo tráfico normal. Prueba: {m['escenarios']} escenarios nuevos de {m['minutos_por_escenario']} minutos
con ataques mezclados (datos que el modelo nunca vio). Datos generados por el simulador; en la maqueta
se repite la evaluación con logs reales de pfSense.

| Métrica | Valor |
| --- | --- |
| Ventanas evaluadas | {m['ventanas_evaluadas']} ({m['ventanas_ataque']} con ataque) |
| Precisión | {m['precision']:.1%} |
| Recall (sensibilidad) | {m['recall']:.1%} |
| F1 | {m['f1']:.3f} |
| ROC AUC | {m['roc_auc']} |
| Tasa de falsos positivos | {m['tasa_falsos_positivos']:.2%} |

Matriz de confusión:

| | Predicho normal | Predicho anomalía |
| --- | --- | --- |
| Real normal | {mc['vn']} | {mc['fp']} |
| Real ataque | {mc['fn']} | {mc['vp']} |

Detección por tipo de ataque. "Tipo correcto" es la fracción de los detectados a los que las reglas
de clasificación les asignaron el nombre correcto:

| Tipo | Casos | Detectados | Tipo correcto |
| --- | --- | --- | --- |
{filas_tipo}

Interpretación: el recall indica cuántos ataques se detectan; la precisión, cuántas alertas son
ataques reales. En las pruebas, los falsos positivos fueron ventanas de muy poca actividad (5 eventos
o menos, a menudo con un intento bloqueado) y las reglas no les asignan nombre de ataque: aparecen
como "Comportamiento inusual" o "Intentos bloqueados", fáciles de distinguir en el panel de alertas.
"""


def guardar_reporte(m: dict, carpeta: str | Path) -> None:
    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)
    (carpeta / "evaluacion.json").write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    (carpeta / "evaluacion.md").write_text(reporte_markdown(m), encoding="utf-8")
