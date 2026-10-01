# pentest-agent/semgrep — semgrep with curated, multi-language rule packs baked
# into the image, so it runs FULLY OFFLINE (Tool.network="none") with --config=/rules.
#
# Why: under network="none" (AS-13 hardening for untrusted-code analysis) the old
# --config=p/python fetched the ruleset from semgrep.dev, failed DNS, exited 2 with
# empty output, and every scan silently read as "clean" (issue #178). Baking the
# rules into the image fixes that WITHOUT weakening the scan-time sandbox.
#
# The packs are fetched at BUILD time (the build has network; the scan does not)
# and are the curated registry PACKS (p/default + p/secrets), not a clone of the
# whole semgrep-rules repo (whose test/experimental/non-rule YAML makes semgrep
# exit 7 and loads ~2000 files slowly). They are NOT vendored into the repo: the
# packs contain example secrets (Slack webhooks, etc.) as detector test-matches,
# which trip secret scanners / GitHub push protection.
#
# Refresh the rules by rebuilding:
#   docker build -t pentest-agent/semgrep ./tools/semgrep-image/

# Stage 1: fetch the packs over ENFORCED HTTPS. --proto '=https' plus no -L means
# the request cannot be redirected to an insecure (http) URL; -f fails on an HTTP
# error; the grep guards against a saved error page. (Network is available at
# build time; discarded for the scan, which runs network="none".)
FROM alpine:3 AS rules
RUN apk add --no-cache curl \
    && mkdir -p /rules \
    && curl --proto '=https' -fsS https://semgrep.dev/c/p/default -o /rules/default.yaml \
    && curl --proto '=https' -fsS https://semgrep.dev/c/p/secrets -o /rules/secrets.yaml \
    && head -1 /rules/default.yaml | grep -q '^rules:' \
    && head -1 /rules/secrets.yaml | grep -q '^rules:'

# Stage 2: the real semgrep image + the baked packs at /rules.
# Base pinned by digest (not :latest) for reproducible, supply-chain-safe builds,
# as tools/trufflehog.py pins its image. Refresh: docker pull semgrep/semgrep:latest
# then update this digest (`docker inspect --format '{{index .RepoDigests 0}}'`).
FROM semgrep/semgrep@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198
COPY --from=rules /rules /rules

# Run as non-root: the base image already ships a non-root `semgrep` user (uid
# 1000), so just select it. HOME is set because Docker does NOT auto-set it on
# USER and semgrep needs a writable HOME for its settings cache. Defense-in-depth
# on top of the runner's --cap-drop=ALL / no-new-privileges / network=none / --rm.
ENV HOME=/home/semgrep
USER semgrep
