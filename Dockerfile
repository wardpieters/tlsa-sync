FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY src/pyproject.toml /app/pyproject.toml
RUN uv sync --no-dev --no-install-project

COPY src/ /app/

ENV PYTHONUNBUFFERED=1

VOLUME ["/data"]

CMD ["/app/.venv/bin/python", "/app/main.py"]
