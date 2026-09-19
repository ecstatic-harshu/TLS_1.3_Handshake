# Virtual ENV

Create Virtual Environment : python -m venv venv
Activate : venv\Scripts\activate
Install Packages : pip install cryptography pyopenssl

# Run Test (echo server demo)

Terminal 1 : python -m server.server
Terminal 2 : python -m client.client

python -m middleware.main --mode server

# Proxy mode (PQ client → middleware → backend)

# HTTP API backend (recommended for backend_http_demo.py):
# Each typed client message becomes POST /echo immediately.
python backend_http_demo.py
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 8080
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
# then type: Hi

# Raw TCP backend (backend_tcp_echo.py):
python backend_tcp_echo.py
python -m middleware.main --mode proxy --no-backend-http --backend-host 127.0.0.1 --backend-port 8080
python -m middleware.main --mode client --host 127.0.0.1 --port 5000

# Single Binary/Image

Build : docker build -t pqtls-middleware:1.0.0 .
Run Server : docker run --rm --name pqtls-server-test -p 5000:5000 pqtls-middleware:1.0.0 --mode server
Run Proxy : docker run --rm --name pqtls-proxy-test -p 5000:5000 pqtls-middleware:1.0.0 --mode proxy --backend-host host.docker.internal --backend-port 8080
Run Client : docker run -it --rm --name pqtls-client-test pqtls-middleware:1.0.0 --mode client --host host.docker.internal --port 5000
