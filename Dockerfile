FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install project dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

# Copy tests and local metadata only after dependency install.
# Keeping this separate avoids invalidating dependency layers often.
COPY . .

EXPOSE 8000

CMD ["uvicorn", "usb_analysis.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
