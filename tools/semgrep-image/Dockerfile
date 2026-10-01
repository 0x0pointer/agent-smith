# pentest-agent/semgrep — semgrep with curated, multi-language rule packs baked
# in, so it runs FULLY OFFLINE (Tool.network="none") with --config=/rules.
#
# Why: under network="none" (AS-13 hardening for untrusted-code analysis) the old
# --config=p/python fetched the ruleset from semgrep.dev, failed DNS, exited 2 with
# empty output, and every scan silently read as "clean" (issue #178). Baking the
# rules in fixes that WITHOUT weakening the sandbox.
#
# We bake the curated registry PACKS (merged YAML), not a clone of the whole
# semgrep-rules repo — the repo root contains test/experimental/non-rule YAML that
# makes semgrep exit 7 ("invalid rules") and loads ~2000 files slowly. The packs
# are all-valid, multi-language, and the set semgrep itself recommends.
#
# Tune coverage vs rule-load time by adding/removing packs below, then rebuild:
#   docker build -t pentest-agent/semgrep ./tools/semgrep-image/
# Rules are a point-in-time snapshot; rebuild to refresh them.

# Stage 1: fetch the packs (network is available at BUILD time; -f fails on HTTP
# errors, and the grep guards against a saved error page).
FROM alpine:3 AS rules
RUN apk add --no-cache curl \
    && mkdir -p /rules \
    && curl -fsSL https://semgrep.dev/c/p/default -o /rules/default.yaml \
    && curl -fsSL https://semgrep.dev/c/p/secrets -o /rules/secrets.yaml \
    && head -1 /rules/default.yaml | grep -q '^rules:' \
    && head -1 /rules/secrets.yaml | grep -q '^rules:'

# Stage 2: the real semgrep image + the baked packs at /rules.
FROM semgrep/semgrep:latest
COPY --from=rules /rules /rules
