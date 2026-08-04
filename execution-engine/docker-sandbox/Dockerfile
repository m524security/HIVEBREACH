FROM python:3.11-slim AS runtime

RUN groupadd -r operator && useradd -r -g operator -m -d /workspace -s /bin/bash operator

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    curl \
    wget \
    netcat-openbsd \
    git \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN mkdir -p /workspace && chown -R operator:operator /workspace

USER operator
WORKDIR /workspace

ENV PATH="${PATH}:/home/operator/.local/bin" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

CMD ["tail", "-f", "/dev/null"]
