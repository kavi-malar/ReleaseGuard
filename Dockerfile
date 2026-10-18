FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m rg && mkdir -p instance && chown -R rg /app
USER rg
ENV RG_DB=/app/instance/releaseguard.db
EXPOSE 5000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:5000/api/health')"
CMD ["python", "run.py"]
