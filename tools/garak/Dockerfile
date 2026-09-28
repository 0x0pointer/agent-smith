# NVIDIA Garak — LLM vulnerability scanner, as a standalone image.
#
# Moved out of the Kali image (which it bloated to ~20 GB via torch/ML deps and
# was default-OFF behind INSTALL_AI). As its own image it is independently
# versioned, auto-built on first `scan(tool="garak")` by tools/garak_runner.py,
# and keeps the Kali image lean.
#
# Invoked ephemerally (`docker run --rm`) with a per-call /work volume that holds
# the REST-generator config in and the report.jsonl out. No ENTRYPOINT: the
# runner passes `sh -c "garak ... ; tail report"`.
FROM python:3.11-slim

# Single layer: git (a couple of garak deps resolve from VCS/build sdists on some
# platforms), garak itself, and a CLI sanity check that fails the build if the
# binary isn't on PATH.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir garak==0.15.0 \
    && garak --version

WORKDIR /work
