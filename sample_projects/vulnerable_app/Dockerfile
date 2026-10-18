FROM python:latest
USER root
ADD https://example.com/setup.tar.gz /tmp/
RUN curl -sSL https://example.com/install.sh | sh
RUN chmod 777 /app
COPY . /app
EXPOSE 22
CMD ["python", "/app/app.py"]
