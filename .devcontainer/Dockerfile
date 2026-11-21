FROM golang:1.27-bookworm

ARG USER_UID=1000
ARG USER_GID=1000

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git jq make python3 python3-pil fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && if ! getent group "${USER_GID}" >/dev/null; then groupadd --gid "${USER_GID}" dev; fi \
    && if ! getent passwd "${USER_UID}" >/dev/null; then \
         useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash dev; \
       fi

ENV HOME=/home/dev \
    GOPATH=/home/dev/go \
    GOCACHE=/home/dev/.cache/go-build

USER dev
WORKDIR /workspace
