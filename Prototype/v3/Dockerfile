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

# Pinned to the gitlink SHAs recorded in this repo (no .gitmodules).
ARG LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
ARG LIBOQS_PYTHON_COMMIT=35eceb69d2b363cb0421085cf1ae1c682dee1acc

# Copy liboqs. Folders are often empty gitlinks; clone the pin if so.
COPY liboqs ./liboqs
RUN if [ ! -f liboqs/CMakeLists.txt ]; then \
      rm -rf liboqs && \
      git clone https://github.com/open-quantum-safe/liboqs.git liboqs && \
      git -C liboqs checkout --quiet "${LIBOQS_COMMIT}"; \
    fi && \
    mkdir -p liboqs/build && \
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
RUN if [ ! -f liboqs-python/pyproject.toml ] && [ ! -f liboqs-python/setup.py ]; then \
      rm -rf liboqs-python && \
      git clone https://github.com/open-quantum-safe/liboqs-python.git liboqs-python && \
      git -C liboqs-python checkout --quiet "${LIBOQS_PYTHON_COMMIT}"; \
    fi && \
    cd liboqs-python && \
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
