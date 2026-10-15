"""Parser del log de firewall de pfSense (filterlog).

Formato oficial (Netgate, "Raw Filter Log Format"), una línea CSV por paquete:

  comunes: regla, subregla, ancla, tracker, interfaz, razón, acción, dirección, versión IP
  IPv4:    tos, ecn, ttl, id, offset, flags, id protocolo, protocolo
  IPv6:    clase, flow label, hop limit, protocolo, id protocolo
  ambos:   longitud, IP origen, IP destino
  TCP:     puerto origen, puerto destino, longitud de datos, flags TCP, seq, ack, ventana, urg, opciones
  UDP:     puerto origen, puerto destino, longitud de datos
  ICMP:    tipo, ...

pfSense envía cada línea por syslog remoto, por ejemplo (formato BSD, sin hostname):
  <134>Oct 11 13:00:00 filterlog[4321]: 5,,,1000000103,igb0.20,match,block,in,4,0x0,,64,...
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Evento:
    interfaz: str
    accion: str          # pass | block | reject
    direccion: str       # in | out
    version_ip: int      # 4 | 6
    protocolo: str       # tcp | udp | icmp | ipv6-icmp | ...
    longitud: int
    origen: str
    destino: str
    puerto_origen: Optional[int] = None
    puerto_destino: Optional[int] = None
    flags_tcp: str = ""

    @property
    def es_syn(self) -> bool:
        """SYN sin ACK: intento de abrir una conexión nueva."""
        return self.protocolo == "tcp" and "S" in self.flags_tcp and "A" not in self.flags_tcp


def _entero(valor: str) -> Optional[int]:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def extraer_csv(linea: str) -> Optional[str]:
    """Devuelve la parte CSV de una línea syslog de filterlog, o None si no es de filterlog."""
    marca = linea.find("filterlog")
    if marca == -1:
        return None
    separador = linea.find(": ", marca)
    if separador == -1:
        return None
    return linea[separador + 2:].strip()


def parsear_csv(csv: str) -> Optional[Evento]:
    c = csv.split(",")
    if len(c) < 9:
        return None
    interfaz, accion, direccion = c[4], c[6], c[7]
    version = _entero(c[8])

    if version == 4:
        if len(c) < 20:
            return None
        protocolo = c[16].lower()
        longitud, origen, destino = c[17], c[18], c[19]
        resto = c[20:]
    elif version == 6:
        if len(c) < 17:
            return None
        protocolo = c[12].lower()
        longitud, origen, destino = c[14], c[15], c[16]
        resto = c[17:]
    else:
        return None

    puerto_o = puerto_d = None
    flags = ""
    if protocolo in ("tcp", "udp") and len(resto) >= 2:
        puerto_o, puerto_d = _entero(resto[0]), _entero(resto[1])
        if protocolo == "tcp" and len(resto) >= 4:
            flags = resto[3]

    return Evento(
        interfaz=interfaz,
        accion=accion,
        direccion=direccion,
        version_ip=version,
        protocolo=protocolo,
        longitud=_entero(longitud) or 0,
        origen=origen,
        destino=destino,
        puerto_origen=puerto_o,
        puerto_destino=puerto_d,
        flags_tcp=flags,
    )


def parsear_linea(linea: str) -> Optional[Evento]:
    """Línea syslog completa o CSV crudo. Devuelve None si no es un evento válido."""
    csv = extraer_csv(linea)
    if csv is None:
        # también se acepta el CSV sin encabezado syslog (archivos de prueba)
        csv = linea.strip()
    try:
        return parsear_csv(csv)
    except Exception:  # una línea corrupta nunca debe detener el servicio
        return None
