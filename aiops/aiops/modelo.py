"""Detector de anomalías basado en Isolation Forest.

Por qué Isolation Forest:
  - Es no supervisado: no necesita ejemplos etiquetados de cada ataque, solo tráfico normal.
  - Aísla puntos raros con pocas particiones aleatorias; un escaneo de 500 puertos
    queda aislado en muy pocos cortes, mientras que la navegación normal requiere muchos.
  - Es liviano (entrena en segundos) y explica su salida con un puntaje continuo.

Las características de conteo tienen colas largas, por eso se aplica log1p antes de entrenar.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from .caracteristicas import NOMBRES

# Índices de las columnas de conteo (se les aplica log1p)
_CONTEOS = [NOMBRES.index(n) for n in ("eventos", "puertos_destino", "hosts_destino", "max_mismo_puerto", "bytes_medios")]


def _log_conteos(x: np.ndarray) -> np.ndarray:
    x = np.array(x, dtype=float, copy=True)
    x[:, _CONTEOS] = np.log1p(x[:, _CONTEOS])
    return x


@dataclass
class Detector:
    pipeline: Pipeline
    umbral: float              # puntaje del bosque por debajo del cual una ventana es anómala
    techo: np.ndarray          # por característica: máximo "normal" (percentil 99.9, ya escalado)
    margen: float = 1.0        # desviaciones estándar de tolerancia sobre el techo

    @classmethod
    def entrenar(cls, x_normal: np.ndarray, contaminacion: float = 0.002, semilla: int = 42) -> "Detector":
        pipeline = Pipeline([
            ("log", FunctionTransformer(_log_conteos)),
            ("escala", StandardScaler()),
            ("bosque", IsolationForest(n_estimators=200, contamination=contaminacion, random_state=semilla)),
        ])
        pipeline.fit(x_normal)
        # El umbral es el que IsolationForest fija según la contaminación esperada (offset_).
        umbral = float(pipeline.named_steps["bosque"].offset_)
        techo = np.percentile(pipeline[:-1].transform(x_normal), 99.9, axis=0)
        return cls(pipeline=pipeline, umbral=umbral, techo=techo)

    def _componentes(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        z = self.pipeline[:-1].transform(x)
        bosque = self.pipeline.named_steps["bosque"].score_samples(z) - self.umbral
        # Isolation Forest no distingue valores más extremos que los vistos al entrenar: un punto
        # fuera de rango recibe el mismo puntaje que el borde de los datos. La envolvente cubre
        # ese caso: cuánto supera la peor característica su techo normal.
        exceso = np.max(z - self.techo, axis=1) - self.margen
        return bosque, exceso

    def puntajes(self, x: np.ndarray) -> np.ndarray:
        """Más bajo = más anómalo; negativo = anomalía. Combina el bosque y la envolvente."""
        if len(x) == 0:
            return np.empty(0)
        bosque, exceso = self._componentes(x)
        # La envolvente solo interviene cuando se rebasa el techo; si no, manda el bosque.
        # /10 lleva el exceso (desviaciones estándar) a la escala del puntaje del bosque.
        return np.where(exceso > 0, np.minimum(bosque, -exceso / 10), bosque)

    def predecir(self, x: np.ndarray) -> np.ndarray:
        return self.puntajes(x) < 0

    def explicar(self, x: np.ndarray) -> list[str]:
        """Tipo probable de cada ventana. El modelo decide SI algo es anómalo; estas reglas,
        explícitas y auditables, solo le ponen nombre para el operador."""
        return [clasificar(dict(zip(NOMBRES, fila))) for fila in np.asarray(x, dtype=float)]


    def guardar(self, ruta: str | Path) -> None:
        Path(ruta).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "umbral": self.umbral, "techo": self.techo,
                     "margen": self.margen, "caracteristicas": NOMBRES}, ruta)

    @classmethod
    def cargar(cls, ruta: str | Path) -> "Detector":
        datos = joblib.load(ruta)
        if datos.get("caracteristicas") != NOMBRES:
            raise ValueError("El modelo se entrenó con otras características; vuelve a entrenarlo.")
        return cls(pipeline=datos["pipeline"], umbral=datos["umbral"], techo=datos["techo"], margen=datos["margen"])


def clasificar(f: dict) -> str:
    """Reglas sobre las características crudas, en orden de especificidad."""
    if f["puertos_destino"] >= 10 and f["ratio_udp"] >= 0.8:
        return "Inundación UDP"
    if f["puertos_destino"] >= 10:
        return "Escaneo de puertos"
    if f["hosts_destino"] >= 20 and f["puertos_destino"] <= 2:
        return "Barrido de red"
    if f["max_mismo_puerto"] >= 30 and f["ratio_bloqueo"] >= 0.5:
        return "Fuerza bruta"
    if f["ratio_syn"] >= 0.8 and f["eventos"] >= 100:
        return "Inundación SYN"
    if f["ratio_udp"] >= 0.8 and f["eventos"] >= 100:
        return "Inundación UDP"
    if f["ratio_bloqueo"] >= 0.5:
        return "Intentos bloqueados"
    return "Comportamiento inusual"
