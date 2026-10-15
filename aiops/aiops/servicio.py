"""Servicio AIOps en tiempo real.

  pfSense --syslog UDP--> este servicio --cada ventana--> InfluxDB --> Grafana

- Escucha syslog en UDP (5514 dentro del contenedor; docker-compose publica el 514 del host).
- Agrupa los eventos de filterlog por IP de origen en ventanas de 60 s.
- Al cerrar cada ventana calcula las características, el puntaje del modelo y escribe:
    aiops_ventana   una fila por IP: puntaje y características (para graficar)
    aiops_alerta    una fila por anomalía: IP, tipo probable y puntaje
    firewall        conteo de eventos por acción e interfaz (pass/block)
- Guarda cada línea recibida en un archivo para reentrenar luego con datos reales.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from .caracteristicas import NOMBRES, Acumulador
from .filterlog import parsear_linea
from .modelo import Detector

log = logging.getLogger("aiops")


class Ventanas:
    """Acumula eventos por (inicio de ventana, IP) y entrega las ventanas ya cerradas."""

    def __init__(self, ventana_s: int = 60, gracia_s: int = 5):
        self.ventana_s = ventana_s
        self.gracia_s = gracia_s
        self.grupos: dict[tuple[int, str], Acumulador] = defaultdict(Acumulador)
        self.firewall: dict[int, Counter] = defaultdict(Counter)

    def agregar(self, ts: float, linea: str) -> bool:
        e = parsear_linea(linea)
        if e is None:
            return False
        inicio = int(ts // self.ventana_s) * self.ventana_s
        self.firewall[inicio][(e.accion, e.interfaz)] += 1
        if e.direccion == "in":
            self.grupos[(inicio, e.origen)].agregar(e)
        return True

    def cerradas(self, ahora: float):
        """Saca y devuelve las ventanas que terminaron hace más de `gracia_s` segundos."""
        limite = ahora - self.ventana_s - self.gracia_s
        listas = {k: self.grupos.pop(k) for k in [k for k in self.grupos if k[0] <= limite]}
        fw = {k: self.firewall.pop(k) for k in [k for k in self.firewall if k <= limite]}
        return listas, fw


def analizar(detector: Detector, grupos: dict) -> list[dict]:
    """Devuelve un resultado por (ventana, IP) con puntaje, anomalía y tipo probable."""
    if not grupos:
        return []
    claves = sorted(grupos)
    x = np.array([grupos[k].vector() for k in claves], dtype=float)
    puntajes = detector.puntajes(x)
    tipos = detector.explicar(x)
    return [
        {"inicio": k[0], "ip": k[1], "puntaje": float(p), "anomalia": bool(p < 0), "tipo": t,
         "caracteristicas": dict(zip(NOMBRES, fila))}
        for k, p, t, fila in zip(claves, puntajes, tipos, x.tolist())
    ]


class Escritor:
    """Escribe en InfluxDB 2.x. Sin INFLUX_URL, solo registra en consola (útil en pruebas)."""

    def __init__(self):
        self.url = os.environ.get("INFLUX_URL")
        self.bucket = os.environ.get("INFLUX_BUCKET", "monitoreo")
        self.org = os.environ.get("INFLUX_ORG", "prepago")
        self.api = None
        if self.url:
            from influxdb_client import InfluxDBClient
            from influxdb_client.client.write_api import SYNCHRONOUS
            cliente = InfluxDBClient(url=self.url, token=os.environ["INFLUX_TOKEN"], org=self.org)
            self.api = cliente.write_api(write_options=SYNCHRONOUS)

    def escribir(self, resultados: list[dict], firewall: dict[int, Counter]) -> None:
        from influxdb_client import Point, WritePrecision

        puntos = []
        for r in resultados:
            ts = r["inicio"] + 60  # se registra al cierre de la ventana
            p = Point("aiops_ventana").tag("ip", r["ip"]).field("puntaje", r["puntaje"]).field("anomalia", int(r["anomalia"]))
            for nombre, valor in r["caracteristicas"].items():
                p = p.field(nombre, float(valor))
            puntos.append(p.time(ts, WritePrecision.S))
            if r["anomalia"]:
                puntos.append(
                    Point("aiops_alerta").tag("ip", r["ip"]).tag("tipo", r["tipo"])
                    .field("puntaje", r["puntaje"]).field("eventos", r["caracteristicas"]["eventos"])
                    .time(ts, WritePrecision.S)
                )
        for inicio, conteo in firewall.items():
            for (accion, interfaz), n in conteo.items():
                puntos.append(Point("firewall").tag("accion", accion).tag("interfaz", interfaz)
                              .field("eventos", n).time(inicio + 60, WritePrecision.S))

        if self.api is not None and puntos:
            self.api.write(bucket=self.bucket, record=puntos)


class ReceptorSyslog(asyncio.DatagramProtocol):
    def __init__(self, ventanas: Ventanas, archivo):
        self.ventanas = ventanas
        self.archivo = archivo
        self.recibidas = 0

    def datagram_received(self, datos: bytes, origen) -> None:
        ahora = time.time()
        for linea in datos.decode("utf-8", errors="replace").splitlines():
            if self.ventanas.agregar(ahora, linea):
                self.recibidas += 1
                if self.archivo:
                    self.archivo.write(f"{ahora:.3f}\t{linea}\n")


async def servir(detector: Detector, puerto: int = 5514, ventana_s: int = 60, archivo_log: str | None = None) -> None:
    ventanas = Ventanas(ventana_s)
    escritor = Escritor()
    archivo = None
    if archivo_log:
        Path(archivo_log).parent.mkdir(parents=True, exist_ok=True)
        archivo = open(archivo_log, "a", encoding="utf-8", buffering=1)

    loop = asyncio.get_running_loop()
    transporte, receptor = await loop.create_datagram_endpoint(
        lambda: ReceptorSyslog(ventanas, archivo), local_addr=("0.0.0.0", puerto)
    )
    log.info("Escuchando syslog en UDP %s · InfluxDB: %s", puerto, escritor.url or "deshabilitado")
    try:
        while True:
            await asyncio.sleep(5)
            grupos, firewall = ventanas.cerradas(time.time())
            if not grupos and not firewall:
                continue
            resultados = analizar(detector, grupos)
            for r in resultados:
                if r["anomalia"]:
                    log.warning("ANOMALÍA %s · %s · puntaje %.3f · %d eventos",
                                r["ip"], r["tipo"], r["puntaje"], r["caracteristicas"]["eventos"])
            try:
                escritor.escribir(resultados, firewall)
            except Exception as e:  # InfluxDB caído: se registra y se sigue escuchando
                log.error("No se pudo escribir en InfluxDB: %s", e)
            log.info("Ventana analizada: %d IPs, %d anomalías, %d eventos recibidos en total",
                     len(resultados), sum(r["anomalia"] for r in resultados), receptor.recibidas)
    finally:
        transporte.close()
        if archivo:
            archivo.close()
