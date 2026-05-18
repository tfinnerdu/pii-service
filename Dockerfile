FROM python:3.11-slim

WORKDIR /app

# System deps for spaCy and pdfplumber
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    libpoppler-cpp-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# spaCy model is installed via requirements.txt (en_core_web_lg direct URL)

# Copy source
COPY pii_guard/ ./pii_guard/
COPY workers/ ./workers/
COPY app.py .

ENV PII_SCORE_THRESHOLD=0.5
ENV PII_USE_SPACY=true
ENV PORT=5900
ENV FLASK_ENV=production

EXPOSE 5900

# Pre-warm the spaCy model before accepting requests to avoid cold-start on first call
CMD ["sh", "-c", "python -c 'from pii_guard import PiiGuard; g=PiiGuard(); g._ensure_initialized(); print(\"Model ready\")' && python app.py"]
