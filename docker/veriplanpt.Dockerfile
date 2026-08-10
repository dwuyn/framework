FROM python:3.11.15-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS builder

WORKDIR /opt/build
COPY envelope/requirements.lock /opt/build/requirements.lock
COPY wheelhouse/ /opt/wheelhouse/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-index --require-hashes --no-deps --no-build-isolation \
       --find-links=/opt/wheelhouse -r /opt/build/requirements.lock

FROM python:3.11.15-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba

ARG FRAMEWORK_COMMIT
ARG GIT_TREE_HASH
ARG RECIPE_HASH
ARG DEPENDENCY_LOCK_HASH
ARG ADAPTER_BUNDLE_HASH
ARG GIT_RUNTIME_SHA256
LABEL org.opencontainers.image.title="VeriPlanPT" \
      com.veriplanpt.framework="VeriPlanPT" \
      com.veriplanpt.upstream-commit="$FRAMEWORK_COMMIT" \
      com.veriplanpt.git-tree-hash="$GIT_TREE_HASH" \
      com.veriplanpt.recipe-hash="$RECIPE_HASH" \
      com.veriplanpt.dependency-lock-hash="$DEPENDENCY_LOCK_HASH" \
      com.veriplanpt.adapter-bundle-hash="$ADAPTER_BUNDLE_HASH" \
      com.veriplanpt.git-runtime-sha256="$GIT_RUNTIME_SHA256"

COPY --from=builder /opt/venv /opt/venv
COPY source/ /opt/veriplanpt/
COPY adapter/ /opt/adapter/
COPY toolchain/git /usr/local/bin/git
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/opt/veriplanpt" \
    VERIPLANPT_SOURCE_DIR="/opt/veriplanpt" \
    VERIPLANPT_RUN_DIR="/run/veriplanpt"
RUN addgroup --gid 10001 baseline \
    && adduser --disabled-password --gecos "" --uid 10001 --gid 10001 baseline \
    && mkdir -p /run/veriplanpt /runner \
    && cp /opt/adapter/runtime_entrypoint.py /runner/run \
    && chmod 0555 /usr/local/bin/git \
    && chown -R baseline:baseline /run/veriplanpt /opt/adapter /opt/veriplanpt \
    && chmod 0555 /opt/adapter/entrypoint.sh /runner/run
USER baseline:baseline
ENTRYPOINT ["/opt/adapter/entrypoint.sh"]
CMD ["python", "main.py"]
