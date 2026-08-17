FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Non-root user for the container
RUN useradd -m apiattack
USER apiattack

WORKDIR /workspace
ENTRYPOINT ["apiattack"]
CMD ["--help"]
