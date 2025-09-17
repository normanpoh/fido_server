import base64
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Optional, List

import cbor2
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

    Args:
        attestation_object_b64: Base64 encoded attestation object

    Returns:
        AAGUID as string if found, None otherwise
    """
    try:
        # Decode the attestation object
        attestation_object_bytes = base64.b64decode(attestation_object_b64)
        attestation_object = cbor2.loads(attestation_object_bytes)

        # Get the authenticator data
        auth_data = attestation_object.get("authData")
        if not auth_data:
            logger.warning("No authData found in attestation object")
            return None

        # Parse authenticator data structure
        # Bytes 0-32: rpIdHash (32 bytes)
        # Byte 33: flags (1 byte)
        # Bytes 34-37: signCount (4 bytes, big-endian)
        # If AT flag is set (bit 6 of flags), attested credential data follows:
        #   Bytes 38-53: AAGUID (16 bytes)

        if len(auth_data) < 38:
            logger.warning("AuthData too short to contain AAGUID")
            return None

        # Check if AT (Attested credential data) flag is set (bit 6)
        flags = auth_data[32]
        at_flag = (flags & 0x40) != 0

        if not at_flag:
            logger.warning("AT flag not set, no attested credential data")
            return None

        if len(auth_data) < 54:  # Need at least 54 bytes for AAGUID
            logger.warning("AuthData too short for AAGUID")
            return None

        # Extract AAGUID (bytes 37-53, 16 bytes)
        aaguid_bytes = auth_data[37:53]

        # Convert to UUID string format
        aaguid_uuid = uuid.UUID(bytes=aaguid_bytes)
        aaguid_str = str(aaguid_uuid)

        logger.info(f"Extracted AAGUID: {aaguid_str}")
        return aaguid_str

    except Exception as e:
        logger.error(f"Error extracting AAGUID: {e}")
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

    def get_authenticator_info(self, username: str) -> list:
        """Get information about all authenticators registered for a user"""
        credentials = self.memory_storage.user_credentials.get(username, [])
        return [
            {
                "aaguid": cred.get("aaguid", "Unknown"),
                "description": cred.get("authenticator_description", "Unknown"),
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

            # Create registration credential object
            if not credential_data.response.attestationObject:
                raise HTTPException(
                    status_code=400,
                    detail="Missing attestationObject in registration response",
                )

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
                import json

                client_data = json.loads(
                    base64.b64decode(
                        fix_base64_padding(credential_data.response.clientDataJSON)
                    )
                )
                client_challenge_b64url = client_data["challenge"]
                client_challenge_bytes = base64url_to_bytes(client_challenge_b64url)
                # expected_challenge_bytes = base64.b64decode(
                #     fix_base64_padding(challenge)
                # )
                # if client_challenge_bytes != expected_challenge_bytes:
                #     raise Exception("Client data challenge was not expected challenge")
                verification = verify_registration_response(
                    credential=credential,
                    expected_challenge=client_challenge_bytes,  # expected_challenge_bytes,
                    expected_origin=self.origin,
                    expected_rp_id=self.rp_id,
                )
            except Exception as e:
                logger.error(f"verify_registration_response failed: {e}")
                raise
            logger.info(f"Verification result: {verification}")

            if verification.user_verified:
                # Store credential
                if username not in self.memory_storage.user_credentials:
                    self.memory_storage.user_credentials[username] = []

                self.memory_storage.user_credentials[username].append(
                    {
                        "credential_id": credential_data.rawId,
                        "public_key": base64.b64encode(
                            verification.credential_public_key
                        ).decode("utf-8"),
                        "sign_count": verification.sign_count,
                        "credential_device_type": verification.credential_device_type.value,
                        "credential_backed_up": verification.credential_backed_up,
                    }
                )

                # Clear session
                session.pop("challenge", None)
                session.pop("username", None)

                return OperationResult(
                    verified=True,
                    message=f"Successfully registered authenticator for {username}",
                )
            else:
                return OperationResult(
                    verified=False, message="Registration verification failed"
                )

        except Exception as e:
            logger.error(f"Registration completion error: {e}")
            return OperationResult(
                verified=False, message=f"Registration failed: {str(e)}"
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
