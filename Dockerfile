FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY crawler ./crawler
RUN pip install --no-cache-dir ".[postgres]"
COPY config ./config

RUN useradd --create-home crawler && mkdir -p /app/data && chown crawler /app/data
USER crawler
EXPOSE 8000
CMD ["uvicorn", "crawler.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
