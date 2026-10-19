FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --no-cache-dir -r requirements.lock

COPY . .
RUN python -m pip install --no-cache-dir --no-deps .

EXPOSE 8000
CMD ["reachable", "serve", "--demo"]
