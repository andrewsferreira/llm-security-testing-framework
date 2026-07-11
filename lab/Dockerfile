# syntax=docker/dockerfile:1
# The lab target image: a deliberately fake, safe-to-attack chatbot/agent (see lab/README.md).
# Build from the repo root: `docker build -f lab/Dockerfile -t llmsec-lab .`

FROM python:3.14-slim-bookworm AS builder

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        "fastapi>=0.115" \
        "uvicorn[standard]>=0.32" \
        "pydantic>=2.9"

FROM python:3.14-slim-bookworm AS runtime

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin lab

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY lab /home/lab/lab

USER lab
WORKDIR /home/lab

ENV LAB_MODE=vulnerable
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "lab.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
