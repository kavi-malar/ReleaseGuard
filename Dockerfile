FROM python:3.12-slim
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip
COPY . .
RUN useradd -m rg && mkdir -p instance && chown -R rg /app
USER rg
ENV RG_DB=/app/instance/releaseguard.db
EXPOSE 5000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:5000/api/health')"
CMD ["python", "run.py"]