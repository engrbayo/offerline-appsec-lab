# Pin the base by digest in real use (FROM python:3.13-slim@sha256:...) so a
# re-tagged upstream image can't change what we ship. Dependabot bumps it.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# Pick up Debian security fixes released since the base image was built.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
# Next step for supply-chain integrity: lock with hashes (pip-compile --generate-hashes)
# and install with --require-hashes.
# pip isn't needed at runtime, and its vendored copies of urllib3, msgpack and
# setuptools (pkg_resources) carry CVEs that Trivy reports against the image.
RUN pip install -r requirements.txt && pip uninstall -y pip
COPY app/ app/

# Run as an unprivileged user; the filesystem can be mounted read-only in ECS.
RUN useradd --system --uid 10001 --no-create-home offerline
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
