"""Generador de logs de pfSense (filterlog) con tráfico normal y ataques etiquetados.

Sirve para dos cosas mientras no exista la maqueta:
  1. Entrenar y evaluar el modelo con datos cuya verdad conocemos (métricas de la rúbrica).
  2. Alimentar el dashboard en vivo durante el desarrollo.

En la maqueta real, los ataques se reproducen con herramientas reales desde el cliente
cableado (nmap, hydra) y el modelo puede reentrenarse con los logs capturados.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

# Red de la maqueta (ver documento de arquitectura)
GATEWAY_USUARIOS = "10.10.20.1"
SERVICIOS = ["10.10.30.10", "10.10.30.11", "10.10.30.20"]
GESTION = ["10.10.10.1", "10.10.10.10"]
IFACE_USUARIOS = "vtnet1.20"
IFACE_WAN = "vtnet0"

TIPOS_ATAQUE = ["escaneo", "barrido", "fuerza_bruta", "inundacion_udp", "inundacion_syn", "escaneo_lento"]

_MESES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def linea_syslog(ts: float, csv: str, pid: int = 4321) -> str:
    """Formato BSD (RFC 3164) que pfSense usa por defecto en el syslog remoto."""
    t = time.gmtime(ts)
    return f"<134>{_MESES[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} filterlog[{pid}]: {csv}"


@dataclass
class Generador:
    semilla: int = 0
    rnd: random.Random = field(init=False)

    def __post_init__(self):
        self.rnd = random.Random(self.semilla)

    # ---------- construcción de una línea CSV ----------

    def _csv(self, *, accion, origen, destino, proto, dport=None, sport=None, flags="S",
             iface=IFACE_USUARIOS, direccion="in", longitud=None) -> str:
        r = self.rnd
        v6 = ":" in origen
        regla = "1000000103" if accion == "block" else "1700000000"
        comun = f"{r.randint(4, 90)},,,{regla},{iface},match,{accion},{direccion}"
        protoid = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58}[proto]
        largo = longitud or {"tcp": r.choice([52, 60, 1500]), "udp": r.randint(60, 1300)}.get(proto, 84)
        if v6:
            ip = f"6,0x00,0x00000,64,{proto},{protoid},{largo},{origen},{destino}"
        else:
            ip = f"4,0x0,,64,{r.randint(1, 65535)},0,DF,{protoid},{proto},{largo},{origen},{destino}"
        sport = sport or r.randint(32768, 65535)
        if proto == "tcp":
            resto = f"{sport},{dport},0,{flags},{r.randint(1, 2**32 - 1)},,64240,,mss;sackOK;TS;nop;wscale"
        elif proto == "udp":
            resto = f"{sport},{dport},{max(largo - 28, 0)}"
        else:
            resto = f"request,{r.randint(1, 65535)},{r.randint(1, 100)}"
        return f"{comun},{ip},{resto}"

    def _ip_externa(self) -> str:
        r = self.rnd
        return f"{r.choice([8, 23, 34, 52, 104, 142, 151, 172, 185, 190])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"

    def _ip_externa_v6(self) -> str:
        r = self.rnd
        return f"2606:4700:{r.randint(1, 0xffff):x}::{r.randint(1, 0xffff):x}"

    # ---------- comportamiento normal de un cliente prepago ----------

    def cliente_normal(self, ts0: float, origen: str, perfil: str) -> list[tuple[float, str]]:
        """Un minuto de actividad de un cliente. perfil: ligero | navegacion | streaming."""
        r = self.rnd
        v6 = ":" in origen
        n = {"ligero": r.randint(2, 15), "navegacion": r.randint(15, 70), "streaming": r.randint(60, 220)}[perfil]
        sitios = [self._ip_externa_v6() if v6 else self._ip_externa() for _ in range(r.randint(2, 12))]
        dns = "2001:db8:acad:20::1" if v6 else GATEWAY_USUARIOS
        lineas = []
        for _ in range(n):
            ts = ts0 + r.random() * 60
            x = r.random()
            if x < 0.15:
                csv = self._csv(accion="pass", origen=origen, destino=dns, proto="udp", dport=53)
            elif x < 0.25 and perfil == "streaming":
                csv = self._csv(accion="pass", origen=origen, destino=r.choice(sitios), proto="udp", dport=443, longitud=1350)
            elif x < 0.992:
                flags = r.choice(["S", "A", "PA", "A", "FA"])
                csv = self._csv(accion="pass", origen=origen, destino=r.choice(sitios), proto="tcp",
                                dport=r.choice([443, 443, 443, 80]), flags=flags)
            else:
                # un intento ocasional a una red privada (bloqueado): ruido realista
                csv = self._csv(accion="block", origen=origen, destino=r.choice(SERVICIOS + GESTION),
                                proto="tcp", dport=r.choice([80, 443]))
            lineas.append((ts, csv))
        return lineas

    # ---------- ataques ----------

    def ataque(self, ts0: float, origen: str, tipo: str) -> list[tuple[float, str]]:
        r = self.rnd
        v6 = ":" in origen
        objetivo = "2001:db8:acad:30::11" if v6 else r.choice(SERVICIOS + [GATEWAY_USUARIOS])
        lineas = []

        def t():
            return ts0 + r.random() * 60

        if tipo == "escaneo":
            for p in r.sample(range(1, 10000), r.randint(150, 900)):
                lineas.append((t(), self._csv(accion="block", origen=origen, destino=objetivo, proto="tcp", dport=p, flags="S", longitud=44)))
        elif tipo == "escaneo_lento":
            # sigiloso: pocos puertos por minuto, difícil de detectar a propósito
            for p in r.sample(range(1, 10000), r.randint(12, 30)):
                lineas.append((t(), self._csv(accion="block", origen=origen, destino=objetivo, proto="tcp", dport=p, flags="S", longitud=44)))
        elif tipo == "barrido":
            base = "2001:db8:acad:20::" if v6 else "10.10.20."
            for h in r.sample(range(2, 255), r.randint(80, 250)):
                destino = f"{base}{h:x}" if v6 else f"{base}{h}"
                lineas.append((t(), self._csv(accion=r.choice(["block", "pass"]), origen=origen, destino=destino,
                                              proto="ipv6-icmp" if v6 else "icmp")))
        elif tipo == "fuerza_bruta":
            puerto = r.choice([22, 443])
            destino = "2001:db8:acad:20::1" if v6 else GATEWAY_USUARIOS
            for _ in range(r.randint(120, 400)):
                lineas.append((t(), self._csv(accion="block", origen=origen, destino=destino, proto="tcp", dport=puerto, flags="S")))
        elif tipo == "inundacion_udp":
            for _ in range(r.randint(600, 2000)):
                lineas.append((t(), self._csv(accion="pass", origen=origen, destino=objetivo, proto="udp",
                                              dport=r.randint(1024, 65535), longitud=r.randint(900, 1400))))
        elif tipo == "inundacion_syn":
            for _ in range(r.randint(800, 2500)):
                lineas.append((t(), self._csv(accion="pass", origen=origen, destino="10.10.30.10", proto="tcp", dport=80, flags="S", longitud=40)))
        else:
            raise ValueError(f"Tipo de ataque desconocido: {tipo}")
        return lineas

    # ---------- escenario completo ----------

    def escenario(self, minutos: int, inicio: float = 1_791_700_000, clientes: int = 40,
                  prob_ataque: float = 0.0) -> tuple[list[tuple[float, str]], dict[tuple[int, str], str]]:
        """Devuelve (líneas syslog ordenadas por tiempo, etiquetas {(inicio_ventana, ip): tipo})."""
        r = self.rnd
        inicio -= inicio % 60  # alinear al minuto: cada ataque cae en una sola ventana etiquetada
        ips = [f"10.10.20.{100 + i}" for i in range(clientes)]
        ips += [f"2001:db8:acad:20::{0x100 + i:x}" for i in range(clientes // 4)]
        perfiles = {ip: r.choices(["ligero", "navegacion", "streaming"], weights=[5, 4, 1])[0] for ip in ips}

        eventos: list[tuple[float, str]] = []
        etiquetas: dict[tuple[int, str], str] = {}
        for m in range(minutos):
            ts0 = inicio + m * 60
            for ip in ips:
                if r.random() < 0.7:  # no todos están activos cada minuto
                    eventos += self.cliente_normal(ts0, ip, perfiles[ip])
            if r.random() < prob_ataque:
                tipo = r.choice(TIPOS_ATAQUE)
                # atacante: un cliente comprometido o una IP de la VLAN de usuarios
                atacante = r.choice([f"10.10.20.{r.randint(2, 99)}", f"2001:db8:acad:20::{r.randint(0x10, 0xff):x}"])
                eventos += self.ataque(ts0, atacante, tipo)
                etiquetas[(int(ts0 // 60) * 60, atacante)] = tipo

        eventos.sort(key=lambda e: e[0])
        return [(ts, linea_syslog(ts, csv)) for ts, csv in eventos], etiquetas
