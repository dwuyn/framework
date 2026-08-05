FROM python:3.11.15-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba

ARG HOST_UID=10001
ARG HOST_GID=10001
ARG RECIPE_HASH
ARG SOURCE_HASH
ARG IMAGE_UID_POLICY=host_euid_nonroot

LABEL org.opencontainers.image.title="VeriPlanPT gateway relay" \
      com.veriplanpt.relay.recipe-hash="$RECIPE_HASH" \
      com.veriplanpt.relay.source-hash="$SOURCE_HASH" \
      com.veriplanpt.relay.uid-policy="$IMAGE_UID_POLICY"

COPY relay/relay.py /opt/relay/relay.py
RUN test "$HOST_UID" -gt 0 \
    && test "$HOST_GID" -gt 0 \
    && addgroup --gid "$HOST_GID" relay \
    && adduser --disabled-password --gecos "" --uid "$HOST_UID" --gid "$HOST_GID" relay \
    && chown -R "$HOST_UID:$HOST_GID" /opt/relay

USER ${HOST_UID}:${HOST_GID}
WORKDIR /opt/relay
ENTRYPOINT ["python", "/opt/relay/relay.py"]
