
# Demo
The server includes a complete web demo that works with hardware security keys, platform authenticators (Windows Hello, Touch ID, etc.), and other FIDO2-compatible devices.

# Steps
1. Create the environment
```bash
conda create --name fido2_demo python=3.12 -y
conda activate fido2_demo
pip install fastapi uvicorn webauthn python-multipart itsdangerous h5py numpy pandas
```

2. For HTTPS in development (required for WebAuthn):
```bash
pip install pyopenssl
# Or use ngrok: ngrok http 5000
```

3. Configuration

Update these variables for your deployment:

```
RP_ID: Your domain (e.g., "example.com")
RP_NAME: Your service name
ORIGIN: Your full URL (must be HTTPS in production)
```

4. Run the server
```bash
python fido_server.py
```
or
```bash
uvicorn fido_server:app --host 0.0.0.0 --port 8000 --reload
```

## API end points

Demo UI: GET / - Interactive web interface
API Docs: GET /docs - Swagger UI documentation
Registration: POST /api/register/start & POST /api/register/complete
Authentication: POST /api/authenticate/start & POST /api/authenticate/complete
Status: GET /api/status - Check auth status
Health: GET /health - Server health check

## Usage

1. Run the server: `python fido_server.py`
2. Open `http://localhost:5000` in a browser
3. Register a new authenticator (hardware key, phone, laptop)
4. Authenticate using your registered device

## Production Considerations

* Use a proper database instead of in-memory storage
* Enable HTTPS (required for WebAuthn)
* Add rate limiting and input validation
* Implement proper error handling and logging
* Consider adding user management features

## Supported attestation formats
* Packed: Yes
* TPM: Yes
* Android Key Attestation: Yes
* Android SafetyNet: Yes
* FIDO U2F: Yes
* Apple Anonymous: Yes (if the library is up-to-date)
* None: Yes

## Testing the FIDO2 server using `test_server/index.html`

Create a self-signed certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Run the server using
```bash
uvicorn fido_server:app --host 0.0.0.0 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```
so that it is accessible via `https://0.0.0.0:8000`