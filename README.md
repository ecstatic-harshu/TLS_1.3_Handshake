# Virtual ENV

Create Virtual Environment : python -m venv venv
Activate : venv\Scripts\activate
Install Packages : pip install cryptography pyopenssl

# Run Test

Terminal 1 : python -m server.server
Terminal 2 : python -m client.client

python -m middleware.main --mode server

# Single Binary/Image (Client/Server Mode)

Build
docker build -t pqtls-middleware:1.0.0 .
Run Server
docker run --rm --name pqtls-server-test -p 5000:5000 pqtls-middleware:1.0.0 --mode server
Run Client
docker run -it --rm --name pqtls-client-test pqtls-middleware:1.0.0 --mode client --host host.docker.internal --port 5000
