# Virtual ENV

Create Virtual Environment : python -m venv venv
Activate : venv\Scripts\activate
Install Packages : pip install cryptography pyopenssl

# Run Test (echo server demo)

Terminal 1 : python -m server.server
Terminal 2 : python -m client.client

python -m middleware.main --mode server

# Proxy mode (PQ client → middleware → backend)

# 1) Start any backend that accepts TCP (example: ncat/echo, or your API on 8080)
# 2) Start the PQ-terminating proxy:
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 8080

# Optional: backend over standard TLS
python -m middleware.main --mode proxy --backend-host example.com --backend-port 443 --backend-tls

# 3) Connect with the PQ client (sends message-framed payloads to the backend):
python -m middleware.main --mode client --host 127.0.0.1 --port 5000

# Single Binary/Image

Build : docker build -t pqtls-middleware:1.0.0 .
Run Server : docker run --rm --name pqtls-server-test -p 5000:5000 pqtls-middleware:1.0.0 --mode server
Run Proxy : docker run --rm --name pqtls-proxy-test -p 5000:5000 pqtls-middleware:1.0.0 --mode proxy --backend-host host.docker.internal --backend-port 8080
Run Client : docker run -it --rm --name pqtls-client-test pqtls-middleware:1.0.0 --mode client --host host.docker.internal --port 5000
