# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Minimal runtime image
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application source code
COPY cipherchat/ ./cipherchat/
COPY app.py .
COPY requirements.txt .

EXPOSE 8765

CMD ["sh", "-c", "python -m cipherchat.realtime.admin migrate && exec python -m uvicorn app:app --host ${CIPHERCHAT_BIND_HOST:-0.0.0.0} --port ${CIPHERCHAT_BIND_PORT:-8765}"]
