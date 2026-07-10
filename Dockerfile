# syntax=docker/dockerfile:1
# The llmsec framework/CLI image. See lab/Dockerfile for the separate lab target image.

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY payloads ./payloads
COPY templates ./templates

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

FROM python:3.12-slim-bookworm AS runtime

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin llmsec

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/llmsec /usr/local/bin/llmsec

USER llmsec
WORKDIR /home/llmsec

RUN mkdir -p /home/llmsec/reports

CMD ["llmsec", "--help"]
