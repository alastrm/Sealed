FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY database.py main.py models.py schemas.py seed.py ./
COPY routers/ ./routers/

EXPOSE 8000

# Seed database and start uvicorn server
CMD ["sh", "-c", "python seed.py && uvicorn main:app --host 0.0.0.0 --port 8000"]
