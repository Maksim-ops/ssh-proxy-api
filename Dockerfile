FROM python:3.12-slim

WORKDIR /app

RUN useradd -m -u 1000 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests
COPY config ./config
COPY policies ./policies
COPY wrapper ./wrapper
COPY sql ./sql

RUN chown -R appuser:appuser /app

USER appuser

ENV HOME=/home/appuser
ENV PYTHONPATH=/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
