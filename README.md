# Monitoreo y AIOps (srv-ops)

Stack de monitoreo y motor de inteligencia artificial del proyecto **Ecosistema Empresarial de Internet Prepago con Portal Cautivo y pfSense** (Telecomunicaciones, UMG). Cubre dos criterios de la rúbrica: el dashboard en tiempo real y el componente de IA.

```
pfSense ──syslog UDP 514──▶ aiops (Python) ──┐
pfSense ──Telegraf────────────────────────── ┼──▶ InfluxDB ──▶ Grafana (http://<srv-ops>:3000)
telegraf local (ping, portal, red) ──────────┘
```

| Carpeta | Contenido |
| --- | --- |
| `aiops/` | Motor AIOps: parser de logs de pfSense, características, modelo, servicio, simulador y 15 pruebas |
| `grafana/` | Fuente de datos y dashboard que Grafana carga solo al arrancar |
| `telegraf/local.conf` | Telegraf de srv-ops: latencia a Internet, disponibilidad del portal, ancho de banda |
| `telegraf/pfsense.conf` | Bloque para el paquete Telegraf de pfSense |
| `reportes/` | Reporte de evaluación del modelo (precisión, recall, F1, matriz de confusión) |

## Probarlo en tu laptop (sin maqueta)

Requiere Docker Desktop. Desde esta carpeta:

```powershell
copy .env.example .env
docker compose --profile demo up -d --build
```

- Grafana: `http://localhost:3000` (usuario `admin`; la clave está en `.env`). El dashboard **Ecosistema prepago** es la página de inicio y también se ve sin iniciar sesión.
- El perfil `demo` agrega el **simulador**: 30 clientes navegando y un ataque cada 3 minutos. A los 1–2 minutos aparecen datos de firewall y AIOps.
- Si el portal (`portal-prepago`) también está corriendo, los paneles de disponibilidad y tiempo de respuesta muestran las réplicas de `localhost:8081` y `8082`. Detén una réplica y verás caer su disponibilidad.

Para lanzar un ataque puntual (por ejemplo, durante la defensa):

```powershell
docker compose exec aiops python -m aiops atacar escaneo
# tipos: escaneo, barrido, fuerza_bruta, inundacion_udp, inundacion_syn, escaneo_lento
```

Para detener: `docker compose --profile demo down`. Para borrar también los datos: añade `-v`.

## El motor AIOps

**Qué hace.** Lee cada línea de `filterlog` que pfSense envía por syslog. Agrupa los eventos por IP de origen en ventanas de 60 s y calcula 8 características por ventana: eventos, puertos distintos, hosts distintos, proporción bloqueada, proporción de SYN, proporción UDP, máximo de intentos a un mismo puerto y tamaño medio. Con esas características, un modelo decide si la ventana es anómala. Funciona igual con IPv4 e IPv6.

**Por qué Isolation Forest.**
- No es supervisado: aprende qué es "normal" solo con tráfico normal, sin necesitar ejemplos de cada ataque.
- Aísla los puntos raros con pocas particiones aleatorias.
- Entrena en segundos.

Tiene una limitación conocida: no distingue valores más extremos que los vistos al entrenar. Por eso se combina con una **envolvente de rango**, que marca cualquier característica que supere en más de una desviación estándar el percentil 99.9 del tráfico normal.

**Tipo probable.** Una vez que el modelo marca una ventana, unas reglas explícitas le ponen nombre: escaneo de puertos, barrido de red, fuerza bruta, inundación UDP o SYN. El modelo decide *si* hay anomalía; las reglas solo la nombran para el operador.

**Resultados.** Evaluado con datos simulados que el modelo nunca vio: 3 escenarios de 4 horas, 25 405 ventanas, 179 con ataque.

| Precisión | Recall | F1 | ROC AUC | Falsos positivos |
| --- | --- | --- | --- | --- |
| 77.8 % | 100 % | 0.875 | 1.0 | 0.20 % de las ventanas normales |

El detalle está en `reportes/evaluacion.md`. Los falsos positivos fueron ventanas de 5 eventos o menos, y las reglas no les asignan nombre de ataque. Son resultados con datos simulados: en la maqueta conviene repetir la evaluación con tráfico real (ver abajo).

### Comandos

Dentro del contenedor (`docker compose exec aiops ...`) o en local con Python 3.12:

```powershell
cd aiops
py -m venv .venv; .venv\Scripts\activate
pip install -r requirements.txt pytest
python -m pytest                     # 15 pruebas
python -m aiops entrenar             # entrena con tráfico normal simulado
python -m aiops evaluar              # escribe reportes/evaluacion.md y .json
python -m aiops servir               # escucha syslog en UDP 5514 (sin INFLUX_URL solo registra en consola)
python -m aiops simular              # en otra terminal: tráfico simulado hacia 127.0.0.1:5514
```

### Reentrenar con tráfico real de la maqueta

El servicio guarda cada línea recibida en `datos/filterlog.tsv`. Deja la red funcionando con tráfico normal (al menos una hora, sin ataques) y luego ejecuta:

```powershell
docker compose exec aiops python -m aiops entrenar --desde-archivo datos/filterlog.tsv
docker compose restart aiops
```

Para medir con tráfico real, lanza ataques reales desde el cliente cableado (por ejemplo `nmap -sS 10.10.30.11`), anota la hora y la IP, y compara con las alertas del dashboard.

## Despliegue en srv-ops (maqueta)

1. Copia esta carpeta a la VM `srv-ops` (10.10.30.20). Crea `.env` a partir de `.env.example` y cambia las claves y el token.
2. En `.env`, apunta Telegraf al portal real:
   `PORTAL_A_URL=http://10.10.30.11:8081/api/salud` y `PORTAL_B_URL=http://10.10.30.11:8082/api/salud`.
3. Ejecuta `docker compose up -d --build`, esta vez sin el perfil `demo`.
4. **Syslog en pfSense.** En Status › System Logs › Settings › Remote Logging Options:
   - activa *Send log messages to remote syslog server*;
   - servidor `10.10.30.20:514`;
   - contenido: *Firewall Events*.
   Las reglas cuyo tráfico quieras analizar deben tener activado *Log packets that are handled by this rule*, incluidas las de bloqueo por defecto.
5. **Telegraf en pfSense.** Instala el paquete `telegraf` y pega `telegraf/pfsense.conf` en la configuración adicional del servicio, con el token de `.env`. Revisa los nombres de interfaz en Interfaces › Assignments.
6. **Firewall.** pfSense debe poder llegar a 10.10.30.20 en UDP 514 y TCP 8086. Grafana (TCP 3000) debe quedar accesible solo desde GESTION.

## Qué falta verificar en tu máquina

Las consultas Flux del dashboard y la configuración de Grafana, InfluxDB y Telegraf no se pudieron ejecutar en el entorno donde se escribieron. El motor AIOps sí: tiene pruebas automatizadas y una prueba de escritura contra un endpoint compatible con InfluxDB. Si un panel muestra "No data" o un error, abre el panel en Grafana, revisa el mensaje de la consulta y ajusta.
