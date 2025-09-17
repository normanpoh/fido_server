#!/usr/bin/env python3
"""
FIDO WebAuthn Server Implementation with FastAPI
A complete FIDO2/WebAuthn server for passwordless authentication
"""

from fastapi import FastAPI, Request, Depends, Body
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from starlette.middleware.sessions import SessionMiddleware
import secrets
import logging
import uvicorn
import json

from constants import NGROK_UUID, RP_ID, RP_NAME, ORIGIN, H5_FILE
from metadata_loader import MetadataLoader
from store_var_utils import save_data

from fido_utils import (
    RegistrationStartRequest,
    AuthenticationStartRequest,
    CredentialData,
    UserInfo,
    StatusResponse,
    OperationResult,
    FIDOServer,
    MemoryStorage,
)

import os


# Centralized logging configuration
log_path = "fido_server.log"
if os.path.exists(log_path):
    os.remove(log_path)
    print(f"Removed existing log file: {log_path}")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(log_path), logging.StreamHandler()],
)
logger = logging.getLogger("fido_server")
logger.info("Started")
# for uvicorn_logger_name in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
#     uv_logger = logging.getLogger(uvicorn_logger_name)
#     uv_logger.addHandler(file_handler)
#     uv_logger.setLevel(logging.INFO)

# Add this to your existing fido_server.py after the imports
metadata_loader = MetadataLoader()

# Load your specific metadata file
# metadata_loader.load_metadata_file("IIST_FIDO2_Authenticator_metadata_250912.json")
metadata_loader.load_metadata_directory("metadata_path")
logger.info(f"Loaded {len(metadata_loader.metadata_store)} metadata files.")

# FastAPI app setup
app = FastAPI(
    title="FIDO WebAuthn Server",
    description="A complete FIDO2/WebAuthn server for passwordless authentication",
    version="1.0.0",
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32),  # Use a strong, random value in production
    same_site="none",  # Allow cross-origin cookies
    https_only=True,  # Only send cookies over HTTPS
)

# Add CORS middleware: REM: Update allowed origins in production

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # "https://a6ed73aef489.ngrok-free.app",  # previous frontend
        # "https://5c00c315fe75.ngrok-free.app",  # new frontend
        # "https://aa65a7641288.ngrok-free.app",  # backend
        ORIGIN,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def write_ngrok_config(path="test_server/ngrok_config.json"):
    """Write ngrok config for frontend"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    config = {"NGROK_UUID": NGROK_UUID}
    with open(path, "w") as f:
        json.dump(config, f)


write_ngrok_config()

# Initialize FIDO server
memory = MemoryStorage()

metadata_loader = MetadataLoader()
metadata_loader.load_metadata_directory("metadata_path/")

fido_server = FIDOServer(
    RP_ID, RP_NAME, ORIGIN, memory_storage=memory, metadata_loader=metadata_loader
)


# Dependency to get session
def get_session(request: Request):
    return request.session


# Serve static files (JS, CSS, etc.) from test_server directory
app.mount("/static", StaticFiles(directory="test_server"), name="static")


@app.get("/demo")
async def demo():
    return FileResponse(os.path.join("test_server", "index.html"))


# Routes
@app.get("/", response_class=HTMLResponse)
async def index():
    """Demo page"""
    with open("simple_test.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


# Route to serve the log viewer HTML page
@app.get("/logs", response_class=HTMLResponse)
async def logs_page():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Server Log Viewer</title>
        <style>
            body { font-family: monospace; background: #222; color: #eee; }
            #log { white-space: pre-wrap; background: #111; padding: 1em; border-radius: 8px; max-height: 80vh; overflow-y: auto; }
        </style>
    </head>
    <body>
    <h2>Server Log Viewer</h2>
    <p style="color: #ccc; font-size: 1em;">Logs are shown in reverse chronological order (newest first).</p>
    <div id="log">Loading...</div>
        <script>
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
            async function fetchLog() {
                try {
                    const res = await fetch('/api/log');
                    if (res.ok) {
                        const text = await res.text();
                            // Escape HTML and rely on CSS white-space: pre-wrap for proper formatting
                            document.getElementById('log').innerHTML = escapeHtml(text);
                    } else {
                        document.getElementById('log').textContent = 'Failed to load log.';
                    }
                } catch (e) {
                    document.getElementById('log').textContent = 'Error loading log.';
                }
            }
            setInterval(fetchLog, 2000);
            fetchLog();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# Route to serve the log file contents
@app.get("/api/log")
async def get_log():
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            reversed_log = "".join(lines[::-1])
            return PlainTextResponse(reversed_log)
    except Exception as e:
        return PlainTextResponse(f"Error reading log: {e}")


@app.post("/api/register/start")
async def register_start(
    request: RegistrationStartRequest, session: dict = Depends(get_session)
):
    """Start registration process"""
    options = fido_server.start_registration(
        request.username, request.displayName, session
    )
    return options


@app.post("/api/register/complete", response_model=OperationResult)
async def register_complete(
    credential_data: CredentialData, session: dict = Depends(get_session)
):
    """Complete registration process"""
    return fido_server.complete_registration(credential_data, session)


@app.post("/api/authenticate/start")
async def authenticate_start(
    request: AuthenticationStartRequest, session: dict = Depends(get_session)
):
    """Start authentication process"""
    return fido_server.start_authentication(request.username, session)


@app.post("/api/authenticate/complete", response_model=OperationResult)
async def authenticate_complete(
    credential_data: CredentialData, session: dict = Depends(get_session)
):
    """Complete authentication process"""
    return fido_server.complete_authentication(credential_data, session)


@app.get("/api/status", response_model=StatusResponse)
async def status(session: dict = Depends(get_session)):
    """Check authentication status"""
    authenticated = session.get("authenticated", False)
    user = session.get("user")

    if authenticated and user:
        return StatusResponse(authenticated=True, message=f"Authenticated as {user}")
    else:
        return StatusResponse(authenticated=False, message="Not authenticated")


@app.post("/api/logout")
async def logout(session: dict = Depends(get_session)):
    """Logout user"""
    session.clear()
    return {"message": "Logged out successfully"}


@app.get("/api/users")
async def list_users():
    """List registered users with authenticator details"""
    user_list = []
    for username, user_data in memory.users.items():
        credentials = memory.user_credentials.get(username, [])
        authenticator_info = []

        for cred in credentials:
            authenticator_info.append(
                {
                    "aaguid": cred.get("aaguid", "Unknown"),
                    "description": cred.get("authenticator_description", "Unknown"),
                }
            )

        user_list.append(
            UserInfo(
                username=username,
                display_name=user_data["display_name"],
                credentials_count=len(credentials),
                authenticators=authenticator_info,
            )
        )

    return {"users": user_list}


# Add endpoint to your FastAPI app
@app.get("/api/users/{username}/authenticators")
async def get_user_authenticators(username: str):
    """Get authenticator information for a specific user"""
    info = fido_server.get_authenticator_info(username)
    return {"username": username, "authenticators": info}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "server": "FIDO WebAuthn Server"}


# --- FIDO2 Interop Endpoints for test_server/index.html ---
@app.post("/attestation/options")
async def attestation_options(
    request: dict = Body(...), session: dict = Depends(get_session)
):
    logger.info(f"Received attestation_options with request: {request}")

    save_data(H5_FILE, "attestation_options", request=request, session=dict(session))
    # Map to registration start
    display_name = (
        request.get("displayName") or request.get("display_name") or "Test User"
    )
    username = request.get("username") or "test@example.com"
    # Accept attestation and authenticatorSelection but ignore for now
    res = fido_server.start_registration(username, display_name, session)
    logger.info(f"Attestation options response: {res}")
    # Save response to HDF5
    save_data(H5_FILE, "attestation_options_response", response=res)
    return res


@app.post("/attestation/result")
async def attestation_result(
    credential_data: dict = Body(...), session: dict = Depends(get_session)
):
    logger.info(f"Received attestation_result with credential_data: {credential_data}")

    save_data(
        H5_FILE,
        "attestation_result",
        credential_data=credential_data,
        session=dict(session),
    )

    cred = CredentialData(**credential_data)
    # Use Pydantic model for validation
    result = fido_server.complete_registration(cred, session)
    logger.info(f"Registration result: {result}")
    # Save result to HDF5
    save_data(
        H5_FILE,
        "attestation_result_response",
        result=result.dict() if hasattr(result, "dict") else str(result),
    )

    # Interop expects {status: 'ok', ...} on success
    if result.verified or getattr(result, "is_success", False):
        return {"status": "ok", "message": result.message}

    return {"status": "failed", "errorMessage": result.message or "Unknown error"}


@app.post("/assertion/options")
async def assertion_options(
    request: dict = Body(...), session: dict = Depends(get_session)
):
    logger.info(f"Received assertion_options with request: {request}")
    # Save received variables to HDF5
    save_data(H5_FILE, "assertion_options", request=request, session=dict(session))
    # Map to authentication start
    username = request.get("username") or "test@example.com"
    res = fido_server.start_authentication(username, session)
    logger.info(f"Assertion options response: {res}")

    # Save response to HDF5
    save_data(H5_FILE, "assertion_options_response", response=res)
    save_data(H5_FILE, "memory", memory=memory.export())
    return res


@app.post("/assertion/result")
async def assertion_result(
    credential_data: dict = Body(...), session: dict = Depends(get_session)
):
    logger.info(f"Received assertion_result with credential_data: {credential_data}")
    # Save received variables to HDF5
    save_data(
        H5_FILE,
        "assertion_result",
        credential_data=credential_data,
        session=dict(session),
    )
    # Map to authentication complete
    cred = CredentialData(**credential_data)
    result = fido_server.complete_authentication(cred, session)
    # Save result to HDF5
    save_data(
        H5_FILE,
        "assertion_result_response",
        result=result.dict() if hasattr(result, "dict") else str(result),
    )
    save_data(H5_FILE, "memory", memory=memory.export())

    logger.info(f"Authentication result: {result}")
    # Interop expects {status: 'ok', ...} on success
    if result.verified or getattr(result, "is_success", False):
        return {"status": "ok", "message": result.message}
    # Always provide errorMessage for failed status
    return {"status": "failed", "errorMessage": result.message or "Unknown error"}


# Endpoints to access metadata
@app.get("/api/metadata")
async def list_metadata():
    """List all loaded authenticator metadata"""
    metadata = fido_server.metadata_loader.get_all_metadata()
    return {
        "count": len(metadata),
        "authenticators": [
            {
                "aaguid": aaguid,
                "description": data.get("description", "Unknown"),
                "protocolFamily": data.get("protocolFamily", "Unknown"),
            }
            for aaguid, data in metadata.items()
        ],
    }


@app.get("/api/metadata/{aaguid}")
async def get_metadata(aaguid: str):
    """Get metadata for a specific AAGUID"""
    metadata = fido_server.get_authenticator_metadata(aaguid)
    if metadata:
        return metadata
    else:
        return {"error": f"No metadata found for AAGUID: {aaguid}"}


# --- END FIDO2 Interop Endpoints ---


if __name__ == "__main__":
    print(
        f"""
FIDO WebAuthn Server Starting with FastAPI...
==========================================
Server: {ORIGIN}
RP ID: {RP_ID}
RP Name: {RP_NAME}

URLs:
- Demo: {ORIGIN}
- API Docs: {ORIGIN}/docs
- ReDoc: {ORIGIN}/redoc
- Health: {ORIGIN}/health

Requirements:
- pip install fastapi uvicorn webauthn python-multipart
- HTTPS required for production (can use ngrok for testing)
- Authenticator device (hardware key, platform authenticator, etc.)
    """
    )

    # Run server with uvicorn
    uvicorn.run(
        "fido_server:app", host="0.0.0.0", port=8000, reload=True, log_level="info"
    )
