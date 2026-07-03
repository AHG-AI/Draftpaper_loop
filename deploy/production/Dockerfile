FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DRAFTPAPER_HOST=0.0.0.0 \
    DRAFTPAPER_PORT=4888 \
    DRAFTPAPER_PROJECTS_DIR=/data/projects \
    DRAFTPAPER_RUNTIME_DIR=/data/runtime \
    DRAFTPAPER_BACKUPS_DIR=/data/backups \
    DRAFTPAPER_SEARCH_PROVIDERS=semantic_scholar,arxiv \
    DRAFTPAPER_SEARCH_TIMEOUT_SECONDS=6 \
    DRAFTPAPER_SEARCH_MAX_QUERIES=4

RUN addgroup --system draftpaper \
    && adduser --system --ingroup draftpaper --home /home/draftpaper draftpaper \
    && mkdir -p /app /data/projects /data/runtime /data/backups \
    && chown -R draftpaper:draftpaper /app /data /home/draftpaper

WORKDIR /app

COPY --chown=draftpaper:draftpaper pyproject.toml README.md README.zh-CN.md LICENSE NOTICE COMMERCIAL_LICENSE.md COMPLIANCE.md TRADEMARK.md ./
COPY --chown=draftpaper:draftpaper draftpaper_cli ./draftpaper_cli
COPY --chown=draftpaper:draftpaper scripts ./scripts
COPY --chown=draftpaper:draftpaper docs ./docs
COPY --chown=draftpaper:draftpaper codex_skills ./codex_skills

RUN pip install --no-cache-dir .

USER draftpaper

EXPOSE 4888
VOLUME ["/data/projects", "/data/runtime", "/data/backups"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import json,urllib.request; json.load(urllib.request.urlopen('http://127.0.0.1:4888/health', timeout=3))"

CMD ["python", "scripts/serviceconsole_app.py", "--host", "0.0.0.0", "--port", "4888"]
