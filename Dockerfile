# syntax=docker/dockerfile:1

# ---- Stage 1: build the React frontend -------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python app ------------------------------------------------------------
FROM python:3.12-slim AS app
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
WORKDIR /app

# Install dependencies first (cached layer), then the project itself.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
COPY migrations/ migrations/
COPY alembic.ini ./
RUN uv sync --frozen --no-dev
COPY --from=frontend /frontend/dist /app/frontend_dist

# Run as an unprivileged user: a compromised process shouldn't own the container.
RUN useradd --system --uid 10001 civicshield
USER civicshield
ENV PATH="/app/.venv/bin:$PATH" CIVICSHIELD_FRONTEND_DIST=/app/frontend_dist
EXPOSE 8000
CMD ["uvicorn", "civicshield.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
