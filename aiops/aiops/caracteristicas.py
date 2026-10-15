"""Convierte eventos del firewall en un vector de características por IP de origen y ventana de tiempo.

Cada fila representa "lo que hizo una IP durante una ventana" (60 s por defecto). Las
características se eligieron porque separan los ataques típicos de una red de acceso:

  eventos            volumen total de paquetes registrados
  puertos_destino    puertos distintos contactados   -> escaneo de puertos
  hosts_destino      IPs distintas contactadas       -> barrido de red
  ratio_bloqueo      fracción bloqueada por reglas   -> sondeos contra lo prohibido
  ratio_syn          aperturas TCP sin ACK           -> SYN flood / escaneo SYN
  ratio_udp          fracción UDP                    -> inundación UDP
  max_mismo_puerto   máximo de intentos a un puerto  -> fuerza bruta (SSH, WebGUI)
  bytes_medios       tamaño medio de paquete
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

from .filterlog import Evento

NOMBRES = [
    "eventos",
    "puertos_destino",
    "hosts_destino",
    "ratio_bloqueo",
    "ratio_syn",
    "ratio_udp",
    "max_mismo_puerto",
    "bytes_medios",
]


@dataclass
class Acumulador:
    """Estadísticas de una IP de origen dentro de una ventana."""
    eventos: int = 0
    bloqueados: int = 0
    syn: int = 0
    udp: int = 0
    bytes_total: int = 0
    puertos: Counter = field(default_factory=Counter)
    hosts: set = field(default_factory=set)

    def agregar(self, e: Evento) -> None:
        self.eventos += 1
        self.bytes_total += e.longitud
        if e.accion in ("block", "reject"):
            self.bloqueados += 1
        if e.es_syn:
            self.syn += 1
        if e.protocolo == "udp":
            self.udp += 1
        if e.puerto_destino is not None:
            self.puertos[e.puerto_destino] += 1
        self.hosts.add(e.destino)

    def vector(self) -> list[float]:
        n = max(self.eventos, 1)
        return [
            float(self.eventos),
            float(len(self.puertos)),
            float(len(self.hosts)),
            self.bloqueados / n,
            self.syn / n,
            self.udp / n,
            float(max(self.puertos.values(), default=0)),
            self.bytes_total / n,
        ]


def agrupar(eventos_con_tiempo: Iterable[tuple[float, Evento]], ventana_s: int = 60):
    """Agrupa (timestamp, evento) en {(inicio_ventana, ip_origen): Acumulador}.

    Solo se analiza tráfico entrante a pfSense (dirección "in"): es el que generan los
    clientes de la red y los atacantes externos.
    """
    grupos: dict[tuple[int, str], Acumulador] = defaultdict(Acumulador)
    for ts, e in eventos_con_tiempo:
        if e.direccion != "in":
            continue
        inicio = int(ts // ventana_s) * ventana_s
        grupos[(inicio, e.origen)].agregar(e)
    return grupos


def matriz(grupos: dict) -> tuple[np.ndarray, list[tuple[int, str]]]:
    claves = sorted(grupos)
    if not claves:
        return np.empty((0, len(NOMBRES))), []
    return np.array([grupos[k].vector() for k in claves], dtype=float), claves
