# The public demo website (python -m protocol_toolkit demo). See render.yaml.

# 1. Build the React UI from source into the Python package
FROM node:22-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN mkdir -p ../protocol_toolkit/webapp/static && npm run build

# 2. The Python app
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY protocol_toolkit/ protocol_toolkit/
COPY --from=web /src/protocol_toolkit/webapp/static/ protocol_toolkit/webapp/static/
RUN pip install ".[all]" && useradd --create-home --uid 10001 toolkit
USER toolkit
# Render sets PORT; the demo command reads it
ENV PORT=10000
EXPOSE 10000
CMD ["python", "-m", "protocol_toolkit", "demo"]
