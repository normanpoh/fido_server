import base64
import datetime
import re
import secrets
import json

from dataclasses import dataclass
from typing import Optional, List

from fastapi import HTTPException
from pydantic import BaseModel
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticatorAttestationResponse,
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)

import logging

from metadata_loader import MetadataLoader
from serialize_dict_utils import encode_compact_dict_pickle, decode_compact_dict_pickle

logger = logging.getLogger("fido_server")


@dataclass
class MemoryStorage:
    users: dict
    user_credentials: dict

    def __init__(self, users={}, user_credentials={}):
        self.users = users
        self.user_credentials = user_credentials

    def export(self) -> str:
        """
        Export the memory storage to a serializable format using encode_compact_dict_pickle()
        """
        return encode_compact_dict_pickle(
            {
                "users": self.users,
                "user_credentials": self.user_credentials,
            }
        )

    def import_from(self, payload: str):
        """
        Import the memory storage from a deserialized format using decode_compact_dict_pickle
        """
        mem = decode_compact_dict_pickle(payload)
        self.users = mem["users"]
        self.user_credentials = mem["user_credentials"]
        return


def base64url_to_bytes(val):
    # Remove any padding and use urlsafe_b64decode
    val = re.sub(r"[^A-Za-z0-9_-]", "", val)
    padding = "=" * (-len(val) % 4)
    return base64.urlsafe_b64decode(val + padding)


def fix_base64_padding(s: str) -> str:
    s = s.replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def time_to_custom_str(now: datetime.datetime | None = None) -> str:
    """
    Convert datetime to custom string format YYYYMMDD_HHMMSS

    Example usage with UTC time now:
    dt = datetime.datetime.now(datetime.timezone.utc)
    time_to_custom_str(dt)
    time_to_custom_str()
    """
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y%m%d_%H%M%S")


# Pydantic models


class RegistrationStartRequest(BaseModel):
    username: str
    displayName: str


class AuthenticationStartRequest(BaseModel):
    username: str


class CredentialResponse(BaseModel):
    clientDataJSON: str
    attestationObject: Optional[str] = None
    authenticatorData: Optional[str] = None
    signature: Optional[str] = None
    userHandle: Optional[str] = None


class CredentialData(BaseModel):
    id: str
    rawId: str
    type: str
    response: CredentialResponse


class AuthenticatorInfo(BaseModel):
    aaguid: str
    description: str


class UserInfo(BaseModel):
    username: str
    display_name: str
    credentials_count: int
    authenticators: Optional[List[AuthenticatorInfo]] = []  # Added to account for


class StatusResponse(BaseModel):
    authenticated: bool
    message: str


class OperationResult(BaseModel):
    verified: bool
    message: str


def extract_aaguid_from_attestation(attestation_object_b64: str) -> Optional[str]:
    """
    Extract AAGUID from the attestation object
    Returns None if extraction fails (non-breaking)

    Args:
        attestation_object_b64: Base64 encoded attestation object

    Returns:
        AAGUID as string if found, None otherwise
    """
    try:
        import base64
        import cbor2
        import uuid

        # Decode the attestation object
        attestation_object_bytes = base64.b64decode(attestation_object_b64)
        attestation_object = cbor2.loads(attestation_object_bytes)

        # Get the authenticator data
        auth_data = attestation_object.get("authData")
        if not auth_data:
            return None

        # Ensure we have enough data for AAGUID
        if len(auth_data) < 38:
            return None

        # Check if AT (Attested credential data) flag is set (bit 6)
        flags = auth_data[32]
        at_flag = (flags & 0x40) != 0

        if not at_flag:
            return None

        if len(auth_data) < 54:  # Need at least 54 bytes for AAGUID
            return None

        # Extract AAGUID (bytes 37-53, 16 bytes)
        aaguid_bytes = auth_data[37:53]

        # Convert to UUID string format
        aaguid_uuid = uuid.UUID(bytes=aaguid_bytes)
        aaguid_str = str(aaguid_uuid)

        return aaguid_str

    except Exception as e:
        logger.debug(f"AAGUID extraction failed: {e}")
        return None


class FIDOServer:
    """FIDO WebAuthn Server Implementation"""

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        origin: str,
        memory_storage: MemoryStorage,
        metadata_loader: MetadataLoader,
    ):
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.memory_storage = memory_storage
        self.metadata_loader = metadata_loader

    def generate_user_id(self) -> bytes:
        """Generate a unique user ID"""
        return secrets.token_bytes(32)

    def get_user_credentials(
        self, username: str
    ) -> List[PublicKeyCredentialDescriptor]:
        """Get user's registered credentials"""
        credentials = self.memory_storage.user_credentials.get(username, [])
        return [
            PublicKeyCredentialDescriptor(
                id=base64.b64decode(fix_base64_padding(cred["credential_id"])),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )
            for cred in credentials
        ]

    # Enhanced user info methods that handle missing AAGUID gracefully
    def get_authenticator_info(self, username: str) -> list:
        """Get information about all authenticators registered for a user"""
        credentials = self.memory_storage.user_credentials.get(username, [])
        return [
            {
                "credential_id": cred.get("credential_id", "Unknown"),
                "aaguid": cred.get("aaguid", "Not available"),
                "description": cred.get(
                    "authenticator_description", "Unknown authenticator"
                ),
                "created_at": cred.get("created_at", "Unknown"),
            }
            for cred in credentials
        ]

    def start_registration(
        self, username: str, display_name: str, session: dict
    ) -> dict:
        """Start FIDO registration process"""
        try:
            # Create or update user
            user_id = self.generate_user_id()
            self.memory_storage.users[username] = {
                "id": user_id,
                "username": username,
                "display_name": display_name,
            }

            # Get existing credentials to exclude
            exclude_credentials = self.get_user_credentials(username)

            # Generate registration options
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id,
                user_name=username,
                user_display_name=display_name,
                exclude_credentials=exclude_credentials,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.PREFERRED
                ),
                supported_pub_key_algs=[
                    COSEAlgorithmIdentifier.ECDSA_SHA_256,
                    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                ],
            )

            # Store challenge in session
            session["challenge"] = base64.b64encode(options.challenge).decode("utf-8")
            session["username"] = username

            # Convert options to dict for JSON response
            options_dict = {
                "status": "ok",
                "errorMessage": "",
                "rp": {"id": options.rp.id, "name": options.rp.name},
                "user": {
                    "id": base64.b64encode(options.user.id).decode("utf-8"),
                    "name": options.user.name,
                    "displayName": options.user.display_name,
                },
                "challenge": base64.b64encode(options.challenge).decode("utf-8"),
                "pubKeyCredParams": [
                    {"type": alg.type, "alg": alg.alg}
                    for alg in options.pub_key_cred_params
                ],
                "timeout": options.timeout,
                "excludeCredentials": (
                    [
                        {
                            "type": cred.type,
                            "id": base64.b64encode(cred.id).decode("utf-8"),
                        }
                        for cred in options.exclude_credentials
                    ]
                    if options.exclude_credentials
                    else []
                ),
                "authenticatorSelection": (
                    {
                        "userVerification": (
                            options.authenticator_selection.user_verification.value
                            if options.authenticator_selection.user_verification
                            else "preferred"
                        )
                    }
                    if options.authenticator_selection
                    else {}
                ),
                "attestation": (
                    options.attestation.value if options.attestation else "none"
                ),
            }

            return options_dict

        except Exception as e:
            logger.error(f"Registration start error: {e}")
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "failed",
                    "errorMessage": str(e) or "User does not exists!",
                },
            )

    def extract_aaguid_from_attestation_object(self, attestation_object) -> dict:
        aaguid = None
        authenticator_description = "Unknown"
        metadata = None

        try:
            # Attempt to extract AAGUID (won't break if it fails)
            aaguid = extract_aaguid_from_attestation(
                # credential_data.response.attestationObject
                attestation_object
            )

            if aaguid:
                logger.info(f"Registration attempt with AAGUID: {aaguid}")

                # Try to get metadata for this authenticator
                metadata = self.get_authenticator_metadata(aaguid)
                if metadata:
                    authenticator_description = metadata.get("description", "Unknown")
                    logger.info(
                        f"Found metadata for authenticator: {authenticator_description}"
                    )

                    # Optional: Log additional metadata info for interop testing
                    logger.info(
                        f"Authenticator details - Version: {metadata.get('authenticatorVersion', 'Unknown')}, "
                        f"Protocol: {metadata.get('protocolFamily', 'Unknown')}"
                    )
                else:
                    logger.info(
                        f"No metadata found for AAGUID: {aaguid} (proceeding anyway)"
                    )
            else:
                logger.debug(
                    "Could not extract AAGUID from attestation object (this is normal for some authenticators)"
                )

        except Exception as aaguid_error:
            # AAGUID extraction failed - log but continue with registration
            logger.debug(f"AAGUID extraction failed (non-critical): {aaguid_error}")

        return {
            "aaguid": aaguid,
            "authenticator_description": authenticator_description,
            "metadata": metadata,
        }

    def complete_registration(
        self, credential_data: CredentialData, session: dict
    ) -> OperationResult:
        """Complete FIDO registration process"""
        logger.info(
            f"Completing registration with credential_data: {credential_data} and session: {session}"
        )
        try:
            # Ensure credential_data.response is a CredentialResponse object
            if isinstance(credential_data.response, dict):
                credential_data.response = CredentialResponse(
                    **credential_data.response
                )
            assert isinstance(
                credential_data.response, CredentialResponse
            ), "Invalid response format"
            username = session.get("username")
            challenge = session.get("challenge")

            if not username or not challenge:
                raise HTTPException(status_code=400, detail="Invalid session state")

            # Create a registration credential object
            if not credential_data.response.attestationObject:
                raise HTTPException(
                    status_code=400,
                    detail="Missing attestationObject in registration response",
                )

            # Process the attestationObject
            aaguid_dict = self.extract_aaguid_from_attestation_object(
                credential_data.response.attestationObject
            )

            aaguid = aaguid_dict["aaguid"]
            authenticator_description = aaguid_dict["authenticator_description"]
            metadata = aaguid_dict["metadata"]

            logger.info(f"AAGUID: {aaguid}")
            logger.info(f"Authenticator description: {authenticator_description}")
            logger.info(f"Metadata: {metadata}")

            credential = RegistrationCredential(
                id=credential_data.id,
                raw_id=base64.b64decode(fix_base64_padding(credential_data.rawId)),
                response=AuthenticatorAttestationResponse(
                    client_data_json=base64.b64decode(
                        fix_base64_padding(credential_data.response.clientDataJSON)
                    ),
                    attestation_object=base64.b64decode(
                        fix_base64_padding(credential_data.response.attestationObject)
                    ),
                ),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )

            # Verify registration
            logger.info(
                f"Starting registration for username={username}, challenge={challenge}"
            )
            logger.info(f"CredentialData: {credential_data}")
            try:
                # Extract challenge from clientDataJSON and compare as bytes

                client_data = json.loads(
                    base64.b64decode(
                        fix_base64_padding(credential_data.response.clientDataJSON)
                    )
                )
                client_challenge_b64url = client_data["challenge"]
                client_challenge_bytes = base64url_to_bytes(client_challenge_b64url)

                verification = verify_registration_response(
                    credential=credential,
                    expected_challenge=client_challenge_bytes,  # expected_challenge_bytes,
                    expected_origin=self.origin,
                    expected_rp_id=self.rp_id,
                    # require_user_verification=False,  # Adjust based on your requirements
                )
            except Exception as e:
                logger.error(f"verify_registration_response failed: {e}")
                raise
            logger.info(f"Verification result: {verification}")

            if not verification.user_verified:
                return OperationResult(
                    verified=False, message="Registration verification failed"
                )

            # Store user if not exists (original logic)
            if username not in self.memory_storage.user_credentials:
                self.memory_storage.user_credentials[username] = []

            credential_info = {
                "credential_id": credential_data.rawId,
                "public_key": base64.b64encode(
                    verification.credential_public_key
                ).decode("utf-8"),
                "sign_count": verification.sign_count,
                "credential_device_type": verification.credential_device_type.value,
                "credential_backed_up": verification.credential_backed_up,
            }
            # Add AAGUID info if available (enhancement)
            if aaguid:
                credential_info.update(
                    {
                        "aaguid": aaguid,
                        "authenticator_description": authenticator_description,
                    }
                )

            self.memory_storage.user_credentials[username].append(credential_info)

            # Clear session
            session.pop("challenge", None)
            session.pop("username", None)

            # Set an authenticated session
            session["authenticated"] = True
            session["user"] = username

            if aaguid:
                session["current_aaguid"] = aaguid
                session["authenticator_description"] = authenticator_description

            logger.info(f"Session after registration: {session}")

            # Create a success message with authenticator info if available
            if metadata:
                success_message = (
                    f"Registration successful for {authenticator_description}"
                )
            else:
                success_message = f"Registration successful for user {username}"

            logger.info(f"{success_message}")
            return OperationResult(verified=True, message=success_message)

        except Exception as webauthn_error:
            logger.error(f"WebAuthn verification failed: {webauthn_error}")
            return OperationResult(
                verified=False, message=f"Registration failed: {str(webauthn_error)}"
            )

    def complete_registration_with_authenticator(
        self, credential_data: CredentialData, session: dict
    ) -> OperationResult:
        """
        Complete registration process with optional AAGUID validation
        Preserves original functionality when AAGUID is not present
        """
        try:
            # Get registration session data
            challenge = session.get("challenge")
            username = session.get("registration_username")
            display_name = session.get("registration_display_name")

            if not challenge or not username:
                return OperationResult(
                    verified=False, message="No active registration session found"
                )

            # Optional AAGUID extraction and metadata lookup (non-breaking enhancement)
            aaguid = None
            authenticator_description = "Unknown"
            metadata = None

            try:
                # Attempt to extract AAGUID (won't break if it fails)
                aaguid = extract_aaguid_from_attestation(
                    credential_data.response.attestationObject
                )

                if aaguid:
                    logger.info(f"Registration attempt with AAGUID: {aaguid}")

                    # Try to get metadata for this authenticator
                    metadata = self.get_authenticator_metadata(aaguid)
                    if metadata:
                        authenticator_description = metadata.get(
                            "description", "Unknown"
                        )
                        logger.info(
                            f"Found metadata for authenticator: {authenticator_description}"
                        )

                        # Optional: Log additional metadata info for interop testing
                        logger.info(
                            f"Authenticator details - Version: {metadata.get('authenticatorVersion', 'Unknown')}, "
                            f"Protocol: {metadata.get('protocolFamily', 'Unknown')}"
                        )
                    else:
                        logger.info(
                            f"No metadata found for AAGUID: {aaguid} (proceeding anyway)"
                        )
                else:
                    logger.debug(
                        "Could not extract AAGUID from attestation object (this is normal for some authenticators)"
                    )

            except Exception as aaguid_error:
                # AAGUID extraction failed - log but continue with registration
                logger.debug(f"AAGUID extraction failed (non-critical): {aaguid_error}")

            # Core WebAuthn verification logic (original functionality preserved)
            try:
                # Convert credential data for webauthn library
                verification_json = {
                    "id": credential_data.id,
                    "rawId": credential_data.rawId,
                    "type": credential_data.type,
                    "response": {
                        "clientDataJSON": credential_data.response.clientDataJSON,
                        "attestationObject": credential_data.response.attestationObject,
                    },
                }

                # Perform WebAuthn verification using the py_webauthn library
                verification = verify_registration_response(
                    credential=verification_json,
                    expected_challenge=challenge,
                    expected_origin=self.origin,
                    expected_rp_id=self.rp_id,
                    require_user_verification=False,  # Adjust based on your requirements
                )

                if not verification.user_verified:
                    return OperationResult(
                        verified=False, message="Registration verification failed"
                    )

                time_now = (
                    datetime.datetime.now(datetime.timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                )

                # Store user if not exists (original logic)
                if username not in self.memory_storage.users:
                    self.memory_storage.users[username] = {
                        "display_name": display_name,
                        "created_at": time_now,
                    }

                # Prepare credential info with optional AAGUID data
                credential_info = {
                    "credential_id": credential_data.id,
                    "public_key": verification.credential_public_key,
                    "sign_count": verification.sign_count,
                    "created_at": time_now,
                }

                # Add AAGUID info if available (enhancement)
                if aaguid:
                    credential_info.update(
                        {
                            "aaguid": aaguid,
                            "authenticator_description": authenticator_description,
                        }
                    )

                    # Store in session for immediate reference
                    session["current_aaguid"] = aaguid
                    session["authenticator_description"] = authenticator_description

                # Store credential (original logic with enhancement)
                if username not in self.memory_storage.user_credentials:
                    self.memory_storage.user_credentials[username] = []

                self.memory_storage.user_credentials[username].append(credential_info)

                # Update session (original logic)
                session["authenticated"] = True
                session["user"] = username
                # Clear registration session data
                session.pop("challenge", None)
                session.pop("registration_username", None)
                session.pop("registration_display_name", None)

                # Create a success message with authenticator info if available
                if metadata:
                    success_message = (
                        f"Registration successful for {authenticator_description}"
                    )
                else:
                    success_message = f"Registration successful for user {username}"

                logger.info(f"Registration completed for user: {username}")
                return OperationResult(verified=True, message=success_message)

            except Exception as webauthn_error:
                logger.error(f"WebAuthn verification failed: {webauthn_error}")
                return OperationResult(
                    verified=False, message="Registration verification failed"
                )

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return OperationResult(
                verified=False, message="Registration failed due to server error"
            )

    def start_authentication(self, username: str, session: dict) -> dict:
        """Start FIDO authentication process"""
        logger.info(f"Starting authentication for username={username}")
        try:
            if username not in self.memory_storage.users:
                raise HTTPException(status_code=404, detail="User not found")

            # Get user's credentials
            allow_credentials = self.get_user_credentials(username)

            if not allow_credentials:
                raise HTTPException(
                    status_code=404, detail="No credentials found for user"
                )

            # Generate authentication options
            options = generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

            # Store challenge in session
            session["auth_challenge"] = base64.b64encode(options.challenge).decode(
                "utf-8"
            )
            session["auth_username"] = username

            # Convert options to dict
            options_dict = {
                "status": "ok",
                "errorMessage": "",
                "challenge": base64.b64encode(options.challenge).decode("utf-8"),
                "timeout": options.timeout,
                "rpId": options.rp_id,
                "allowCredentials": (
                    [
                        {
                            "type": (
                                cred.type.value
                                if hasattr(cred.type, "value")
                                else cred.type
                            ),
                            "id": base64.b64encode(cred.id).decode("utf-8"),
                        }
                        for cred in options.allow_credentials
                    ]
                    if options.allow_credentials
                    else []
                ),
                "userVerification": (
                    options.user_verification.value
                    if options.user_verification
                    else "preferred"
                ),
            }

            return options_dict

        except Exception as e:
            logger.error(f"Authentication start error: {e}")
            logger.info(f"Authentication start error: {e}")
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "failed",
                    "errorMessage": str(e) or "User does not exists!",
                },
            )

    def complete_authentication(
        self, credential_data: CredentialData, session: dict
    ) -> OperationResult:
        """Complete FIDO authentication process"""
        try:
            username = session.get("auth_username")
            challenge = session.get("auth_challenge")

            if not username or not challenge:
                raise HTTPException(status_code=400, detail="Invalid session state")

            # Find the credential
            credential_id = credential_data.rawId
            user_creds = self.memory_storage.user_credentials.get(username, [])
            stored_credential = None

            for cred in user_creds:
                if cred["credential_id"] == credential_id:
                    stored_credential = cred
                    break

            if not stored_credential:
                raise HTTPException(status_code=404, detail="Credential not found")

            # Create authentication credential object
            if not credential_data.response.authenticatorData:
                raise HTTPException(
                    status_code=400,
                    detail="Missing authenticatorData in authentication response",
                )
            if not credential_data.response.signature:
                raise HTTPException(
                    status_code=400,
                    detail="Missing signature in authentication response",
                )
            credential = AuthenticationCredential(
                id=credential_data.id,
                raw_id=base64.b64decode(fix_base64_padding(credential_data.rawId)),
                response=AuthenticatorAssertionResponse(
                    client_data_json=base64.b64decode(
                        fix_base64_padding(credential_data.response.clientDataJSON)
                    ),
                    authenticator_data=base64.b64decode(
                        fix_base64_padding(credential_data.response.authenticatorData)
                    ),
                    signature=base64.b64decode(
                        fix_base64_padding(credential_data.response.signature)
                    ),
                    user_handle=(
                        base64.b64decode(
                            fix_base64_padding(credential_data.response.userHandle)
                        )
                        if credential_data.response.userHandle
                        else None
                    ),
                ),
                type=PublicKeyCredentialType.PUBLIC_KEY,
            )

            # Extract and compare challenge from clientDataJSON
            import json

            client_data = json.loads(
                base64.b64decode(
                    fix_base64_padding(credential_data.response.clientDataJSON)
                )
            )
            client_challenge_b64url = client_data["challenge"]
            client_challenge_bytes = base64url_to_bytes(client_challenge_b64url)
            # expected_challenge_bytes = base64.b64decode(fix_base64_padding(challenge))
            # if client_challenge_bytes != expected_challenge_bytes:
            #     raise Exception("Client data challenge was not expected challenge")

            # Verify authentication
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=client_challenge_bytes,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=base64.b64decode(
                    fix_base64_padding(stored_credential["public_key"])
                ),
                credential_current_sign_count=stored_credential["sign_count"],
            )

            if verification.user_verified:
                # Update sign count
                stored_credential["sign_count"] = verification.new_sign_count

                # Clear session
                session.pop("auth_challenge", None)
                session.pop("auth_username", None)

                # Set an authenticated session
                session["authenticated"] = True
                session["user"] = username

                return OperationResult(
                    verified=True, message=f"Successfully authenticated {username}"
                )
            else:
                return OperationResult(
                    verified=False, message="Authentication verification failed"
                )

        except Exception as e:
            logger.error(f"Authentication completion error: {e}")
            return OperationResult(
                verified=False, message=f"Authentication failed: {str(e)}"
            )

    # Methods for metadata handling
    def get_authenticator_metadata(self, aaguid: str):
        """Get metadata for an authenticator by AAGUID"""
        return self.metadata_loader.get_metadata(aaguid)

    def validate_authenticator(self, aaguid: str) -> bool:
        """Check if an authenticator is in our trusted metadata"""
        metadata = self.get_authenticator_metadata(aaguid)
        if metadata:
            logger.info(
                f"Found metadata for authenticator: {metadata.get('description', 'Unknown')}"
            )
            return True
        else:
            logger.warning(f"No metadata found for AAGUID: {aaguid}")
            return False
