"""Línea de comandos del motor AIOps.

  python -m aiops entrenar [--desde-archivo logs.tsv]   entrena y guarda el modelo
  python -m aiops evaluar                               mide precisión, recall y F1
  python -m aiops servir                                servicio en tiempo real (syslog -> InfluxDB)
  python -m aiops simular --destino host:puerto         envía tráfico simulado en tiempo real
  python -m aiops atacar escaneo --destino host:puerto  envía un ataque puntual ahora
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import socket
import sys
import time
from pathlib import Path

from .caracteristicas import agrupar, matriz
from .evaluacion import entrenar_sintetico, evaluar, guardar_reporte, reporte_markdown
from .filterlog import parsear_linea
from .modelo import Detector
from .simulador import TIPOS_ATAQUE, Generador, linea_syslog

MODELO = os.environ.get("AIOPS_MODELO", "datos/modelo.joblib")
LOGS = os.environ.get("AIOPS_LOGS", "datos/filterlog.tsv")
log = logging.getLogger("aiops")


def _destino(texto: str) -> tuple[str, int]:
    host, _, puerto = texto.rpartition(":")
    return host or "127.0.0.1", int(puerto)


def cmd_entrenar(a) -> None:
    if a.desde_archivo:
        # Archivo grabado por el servicio: "<epoch>\t<línea syslog>" por renglón
        eventos = []
        with open(a.desde_archivo, encoding="utf-8") as f:
            for renglon in f:
                ts, _, linea = renglon.rstrip("\n").partition("\t")
                if (e := parsear_linea(linea)) is not None:
                    eventos.append((float(ts), e))
        x, _ = matriz(agrupar(eventos))
        if len(x) < 50:
            sys.exit(f"Solo hay {len(x)} ventanas en {a.desde_archivo}; captura más tráfico normal (al menos 50).")
        detector = Detector.entrenar(x)
        print(f"Entrenado con {len(x)} ventanas reales de {a.desde_archivo}")
    else:
        detector = entrenar_sintetico(minutos=a.minutos)
        print(f"Entrenado con {a.minutos} minutos de tráfico normal simulado")
    detector.guardar(a.modelo)
    print(f"Modelo guardado en {a.modelo}")


def cmd_evaluar(a) -> None:
    detector = Detector.cargar(a.modelo) if Path(a.modelo).exists() else entrenar_sintetico()
    m = evaluar(detector, minutos=a.minutos)
    guardar_reporte(m, a.salida)
    print(reporte_markdown(m))
    print(f"Reporte guardado en {a.salida}/evaluacion.md y evaluacion.json")


def cmd_servir(a) -> None:
    if not Path(a.modelo).exists():
        log.warning("No hay modelo en %s: entrenando con tráfico simulado (reentrena luego con datos reales).", a.modelo)
        entrenar_sintetico().guardar(a.modelo)
    detector = Detector.cargar(a.modelo)
    asyncio.run(_servir(detector, a))


async def _servir(detector, a):
    from .servicio import servir
    await servir(detector, puerto=a.puerto, archivo_log=None if a.sin_grabar else a.grabar)


def _enviar(sock, destino, lineas):
    for linea in lineas:
        sock.sendto(linea.encode(), destino)


def cmd_simular(a) -> None:
    """Tráfico normal continuo; cada `--cada` minutos, un ataque de un tipo al azar."""
    destino = _destino(a.destino)
    gen = Generador(int(time.time()))
    clientes = [f"10.10.20.{100 + i}" for i in range(a.clientes)] + [f"2001:db8:acad:20::{0x100 + i:x}" for i in range(a.clientes // 4)]
    perfiles = {ip: random.choice(["ligero", "ligero", "navegacion", "streaming"]) for ip in clientes}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Simulando {len(clientes)} clientes hacia {destino}; ataque cada {a.cada} min. Ctrl+C para detener.")
    minuto = 0
    while True:
        ts0 = time.time()
        lote = []
        for ip in clientes:
            if random.random() < 0.7:
                lote += gen.cliente_normal(ts0, ip, perfiles[ip])
        if a.cada and minuto % a.cada == a.cada - 1:
            tipo = random.choice([t for t in TIPOS_ATAQUE if t != "escaneo_lento"])
            atacante = f"10.10.20.{random.randint(2, 99)}"
            lote += gen.ataque(ts0, atacante, tipo)
            print(f"  ataque simulado: {tipo} desde {atacante}")
        # se envía repartido a lo largo del minuto, en orden temporal
        lote.sort(key=lambda e: e[0])
        for ts, csv in lote:
            espera = ts - time.time()
            if espera > 0:
                time.sleep(espera)
            sock.sendto(linea_syslog(time.time(), csv).encode(), destino)
        minuto += 1


def cmd_atacar(a) -> None:
    destino = _destino(a.destino)
    gen = Generador(int(time.time()))
    atacante = a.origen or f"10.10.20.{random.randint(2, 99)}"
    lineas = [linea_syslog(time.time(), csv) for _, csv in gen.ataque(time.time() - 30, atacante, a.tipo)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i, linea in enumerate(lineas):
        sock.sendto(linea.encode(), destino)
        if i % 200 == 0:
            time.sleep(0.01)  # evita perder datagramas UDP por ráfaga
    print(f"Enviado ataque '{a.tipo}' desde {atacante}: {len(lineas)} eventos a {destino}. Aparece en Grafana al cerrar la ventana (≤ 1 min).")


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="python -m aiops", description="Motor AIOps del portal prepago")
    p.add_argument("--modelo", default=MODELO)
    sub = p.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("entrenar", help="entrena y guarda el modelo")
    s.add_argument("--desde-archivo", help="logs grabados por el servicio (tráfico normal real)")
    s.add_argument("--minutos", type=int, default=240)
    s.set_defaults(fn=cmd_entrenar)

    s = sub.add_parser("evaluar", help="mide precisión, recall y F1 con datos etiquetados")
    s.add_argument("--minutos", type=int, default=240)
    s.add_argument("--salida", default="reportes")
    s.set_defaults(fn=cmd_evaluar)

    s = sub.add_parser("servir", help="servicio en tiempo real")
    s.add_argument("--puerto", type=int, default=int(os.environ.get("SYSLOG_PUERTO", 5514)))
    s.add_argument("--grabar", default=LOGS, help="archivo donde se guardan las líneas recibidas")
    s.add_argument("--sin-grabar", action="store_true")
    s.set_defaults(fn=cmd_servir)

    s = sub.add_parser("simular", help="tráfico simulado continuo hacia el servicio")
    s.add_argument("--destino", default="127.0.0.1:5514")
    s.add_argument("--clientes", type=int, default=30)
    s.add_argument("--cada", type=int, default=3, help="minutos entre ataques (0 = sin ataques)")
    s.set_defaults(fn=cmd_simular)

    s = sub.add_parser("atacar", help="envía un ataque simulado ahora")
    s.add_argument("tipo", choices=TIPOS_ATAQUE)
    s.add_argument("--destino", default="127.0.0.1:5514")
    s.add_argument("--origen", help="IP atacante (por defecto una al azar de la VLAN 20)")
    s.set_defaults(fn=cmd_atacar)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
