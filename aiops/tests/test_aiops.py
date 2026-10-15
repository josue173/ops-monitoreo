import asyncio
import socket
import time

import numpy as np
import pytest

from aiops.caracteristicas import NOMBRES, agrupar, matriz
from aiops.evaluacion import entrenar_sintetico, evaluar, reporte_markdown, ventanas
from aiops.filterlog import parsear_linea
from aiops.modelo import Detector
from aiops.servicio import Ventanas, analizar
from aiops.simulador import Generador, linea_syslog

# Líneas con el formato real de pfSense (Raw Filter Log Format)
TCP4 = "<134>Oct 11 13:00:00 filterlog[4321]: 5,,,1000000103,vtnet1.20,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,10.10.20.50,10.10.30.11,51234,22,0,S,1234567,,64240,,mss;sackOK"
UDP6 = "<134>Oct 11 13:00:01 filterlog[4321]: 9,,,1700000000,vtnet1.20,match,pass,in,6,0x00,0x00000,64,udp,17,72,2001:db8:acad:20::150,2001:db8:acad:20::1,53001,53,32"
ICMP4 = "4,,,1000000103,vtnet0,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,198.51.100.7,10.10.20.1,request,1,1"


@pytest.fixture(scope="module")
def detector():
    return entrenar_sintetico(minutos=90)


def test_parsea_tcp_ipv4():
    e = parsear_linea(TCP4)
    assert (e.accion, e.direccion, e.version_ip, e.protocolo) == ("block", "in", 4, "tcp")
    assert (e.origen, e.destino, e.puerto_origen, e.puerto_destino) == ("10.10.20.50", "10.10.30.11", 51234, 22)
    assert e.es_syn


def test_parsea_udp_ipv6():
    e = parsear_linea(UDP6)
    assert (e.version_ip, e.protocolo, e.puerto_destino, e.longitud) == (6, "udp", 53, 72)
    assert e.origen == "2001:db8:acad:20::150"


def test_parsea_icmp_sin_encabezado_syslog():
    e = parsear_linea(ICMP4)
    assert (e.protocolo, e.puerto_destino, e.interfaz) == ("icmp", None, "vtnet0")


@pytest.mark.parametrize("basura", ["", "hola", "<134>Oct 11 sshd[1]: Accepted", "1,2,3,4,5,6,7,8,9", "1,,,1,em0,match,pass,in,4,x"])
def test_lineas_invalidas_no_rompen(basura):
    assert parsear_linea(basura) is None


def test_simulador_produce_lineas_parseables():
    gen = Generador(7)
    for tipo in ("escaneo", "barrido", "fuerza_bruta", "inundacion_udp", "inundacion_syn"):
        for v in ("10.10.20.9", "2001:db8:acad:20::9"):
            lineas = gen.ataque(0, v, tipo)
            assert all(parsear_linea(linea_syslog(ts, csv)) is not None for ts, csv in lineas), (tipo, v)


def test_caracteristicas_de_un_escaneo():
    gen = Generador(1)
    eventos = [(ts, parsear_linea(csv)) for ts, csv in gen.ataque(0, "10.10.20.66", "escaneo")]
    x, claves = matriz(agrupar(eventos))
    fila = dict(zip(NOMBRES, x[0]))
    assert claves == [(0, "10.10.20.66")]
    assert fila["puertos_destino"] >= 150
    assert fila["ratio_bloqueo"] == 1.0
    assert fila["ratio_syn"] == 1.0


def test_detector_separa_ataques_de_normal(detector):
    m = evaluar(detector, minutos=60, semillas=(5,), prob_ataque=0.3)
    assert m["recall"] >= 0.9
    assert m["tasa_falsos_positivos"] <= 0.01
    assert m["roc_auc"] >= 0.95
    assert "Matriz de confusión" in reporte_markdown(m)


def test_explicacion_del_tipo(detector):
    gen = Generador(3)
    casos = {"escaneo": "Escaneo de puertos", "barrido": "Barrido de red", "fuerza_bruta": "Fuerza bruta"}
    for tipo, esperado in casos.items():
        eventos = [(ts, parsear_linea(csv)) for ts, csv in gen.ataque(0, "10.10.20.70", tipo)]
        x, _ = matriz(agrupar(eventos))
        assert detector.predecir(x)[0], tipo
        assert detector.explicar(x)[0] == esperado, tipo


def test_guardar_y_cargar(detector, tmp_path):
    ruta = tmp_path / "m.joblib"
    detector.guardar(ruta)
    otro = Detector.cargar(ruta)
    x, _ = ventanas(Generador(9).escenario(5)[0])
    np.testing.assert_allclose(detector.puntajes(x), otro.puntajes(x))


def test_ventanas_solo_entrega_las_cerradas(detector):
    v = Ventanas(ventana_s=60, gracia_s=5)
    for ts, csv in Generador(2).ataque(120, "10.10.20.80", "escaneo"):
        v.agregar(ts, linea_syslog(ts, csv))
    assert v.cerradas(ahora=180)[0] == {}           # la ventana 120-180 sigue abierta
    grupos, firewall = v.cerradas(ahora=186)
    assert list(grupos) == [(120, "10.10.20.80")]
    assert firewall[120][("block", "vtnet1.20")] > 100
    r = analizar(detector, grupos)
    assert r[0]["anomalia"] and r[0]["tipo"] == "Escaneo de puertos"


def test_servicio_recibe_por_udp(detector, tmp_path, monkeypatch):
    """Arranca el servicio real, envía syslog por UDP y verifica que lo graba."""
    monkeypatch.delenv("INFLUX_URL", raising=False)
    from aiops import servicio

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        puerto = s.getsockname()[1]
    archivo = tmp_path / "logs.tsv"

    async def escenario():
        tarea = asyncio.create_task(servicio.servir(detector, puerto=puerto, archivo_log=str(archivo)))
        await asyncio.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            for linea in (TCP4, UDP6, "basura"):
                c.sendto(linea.encode(), ("127.0.0.1", puerto))
        await asyncio.sleep(0.3)
        tarea.cancel()
        with pytest.raises(asyncio.CancelledError):
            await tarea

    asyncio.run(escenario())
    grabado = archivo.read_text().splitlines()
    assert len(grabado) == 2  # la basura no se graba
    ts, _, linea = grabado[0].partition("\t")
    assert abs(float(ts) - time.time()) < 10 and "filterlog" in linea
