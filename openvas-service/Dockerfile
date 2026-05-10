FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN mkdir -p /run/secrets
COPY token.json /run/secrets/token.json

ENV PYTHONUNBUFFERED=1