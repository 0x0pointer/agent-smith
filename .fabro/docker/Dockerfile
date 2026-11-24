# Sandbox image for Fabro runs on agent-smith: Python 3.11, git, gh, Poetry and
# the project's dependencies pre-installed so each run's setup step is fast.
# iputils-ping is there because the host-lane tests run a real `ping`.
# Build from the repo root:
#   docker build -f .fabro/docker/Dockerfile -t agent-smith-fabro:latest .
FROM python:3.11-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates jq make gh iputils-ping \
 && rm -rf /var/lib/apt/lists/*

# Dependencies go into the system interpreter: the sandbox is the virtualenv.
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VIRTUALENVS_CREATE=false POETRY_NO_INTERACTION=1

RUN pip install --no-cache-dir poetry==2.1.3

COPY pyproject.toml poetry.lock /tmp/deps/
RUN cd /tmp/deps && poetry install --with dev --no-root
