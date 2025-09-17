# Demo

The server includes a complete web demo that works with hardware security keys, platform authenticators (Windows Hello,
Touch ID, etc.), and other FIDO2-compatible devices.

# Steps

1. Create the environment

```bash
conda create --name fido2_demo python=3.12 -y
conda activate fido2_demo
pip install fastapi uvicorn webauthn python-multipart itsdangerous h5py numpy pandas
```

2. Metadata
   
Make sure that you download the JSON files from the participating authenticator vendors and place them in the   `metadata_path` directory. In my case, I have:

```
metadata_path
├── Clife_Key_2_FIDO2_v0.10.10.json
├── Clife_Key_2_NFC_FIDO2_v0.10.10.json
├── G+D-FIDO-USB-NFC.json
├── G+D-FIDO-USB-NFC_U2F.json
├── HID-C4000EnterpriseEdition.metadata-FIDO2.1_v1.0.json
├── HID-CKEY_V3EnterpriseEdition.metadata-FIDO2.1_v1.0.json
├── IIST_FIDO2_Authenticator_metadata_250912.json
├── Idemia ID-One_Card_Enterprise_Interop_Root_Secp521r1_EcdsaSha512.json
├── Infineon_SECORA™_ID_V2_Pay_Edition_M.json
├── Korea Quantum_metadata (3).json
├── MARX CryptoTech LP metadata_statement.json
├── NEOWAVE Badgeo FIDO2 (CTAP 2.1) MDS3 - 02.01.0008 - release - Badgeo.json
├── NEOWAVE Winkeo FIDO2 (CTAP 2.1) MDS3 - 02.01.0008 - release - Winkeo-SIM.json
├── TruU_FIDO2_Authenticator_MDS.json
├── WebComm_fido2_metadata_0904.json
└── oppo_ble_metadata_oppo_tee_for_passkey.json
```

3. Configuration
Run the ngrok service (if you don't have ngrok, download it from https://ngrok.com/)
```
ngrok http http://localhost:8080
```
Grab the HTTPS URL from the ngrok terminal (e.g., `https://<NGROK_UUID>.ngrok-free.app `). Update these variables for your deployment in [constants.py](constants.py). Replace `NGROK_UUID` in this file with your actual ngrok UUID.


4. Run the server

```bash
uvicorn fido_server:app --host 0.0.0.0 --port 8080 --reload
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