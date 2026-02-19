FROM python:3.12.3-slim
WORKDIR /code

# Install system dependencies for PaddleOCR/OpenCV
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt requirements.txt

# Install Python packages with pip cache for faster rebuilds
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

CMD gunicorn --certfile=/code/certs/cert.pem --keyfile=/code/certs/key.pem --timeout 90 --reload --reload-extra-file /code/templates --reload-extra-file /code/static -b 0.0.0.0:5000 app:app