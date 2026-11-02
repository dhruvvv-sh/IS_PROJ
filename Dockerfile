FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8765

CMD ["sh", "-c", "python -m cipherchat.realtime.admin migrate && exec python -m uvicorn app:app --host ${CIPHERCHAT_BIND_HOST:-0.0.0.0} --port ${CIPHERCHAT_BIND_PORT:-8765}"]
