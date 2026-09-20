# Quantum Safe TLS Middleware
FROM python:3.12-slim

# Environment
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install Linux packages
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first
# (Docker cache optimization)
COPY requirements.txt .

# Copy liboqs
COPY liboqs ./liboqs

# Build liboqs
RUN mkdir -p liboqs/build && \
    cd liboqs/build && \
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        .. && \
    ninja && \
    ninja install && \
    ldconfig

# Copy liboqs-python
COPY liboqs-python ./liboqs-python

# Install liboqs-python
RUN cd liboqs-python && \
    pip install .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY client ./client
COPY common ./common
COPY server ./server
COPY middleware ./middleware
COPY dashboard ./dashboard
COPY certs ./certs
COPY VERSION ./VERSION
COPY backend_http_demo.py ./backend_http_demo.py
COPY backend_tcp_echo.py ./backend_tcp_echo.py

# Expose server port
EXPOSE 5000

# Start middleware
ENTRYPOINT ["python", "-m", "middleware.main"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',5000)); s.close()"
