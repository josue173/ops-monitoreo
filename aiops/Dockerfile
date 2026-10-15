FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AIOPS_MODELO=/app/datos/modelo.joblib \
    AIOPS_LOGS=/app/datos/filterlog.tsv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY aiops ./aiops
RUN mkdir -p datos reportes
# Syslog sin privilegios dentro del contenedor; docker-compose publica el 514/udp del host
EXPOSE 5514/udp
CMD ["python", "-m", "aiops", "servir"]
