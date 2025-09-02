# translator.py - Production ready version
import base64
import os
import json
import logging
import secrets
import threading
import time
from typing import Dict, Optional
from mythic_container.TranslationBase import (
    TranslationContainer,
    TrGenerateEncryptionKeysMessage,
    TrGenerateEncryptionKeysMessageResponse,
    TrMythicC2ToCustomMessageFormatMessage,
    TrMythicC2ToCustomMessageFormatMessageResponse,
    TrCustomMessageToMythicC2FormatMessage,
    TrCustomMessageToMythicC2FormatMessageResponse,
)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Thread-safe session management with automatic cleanup
class SessionManager:
    def __init__(self, timeout_seconds: int = 3600):
        self._session_keys: Dict[str, bytes] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._timeout = timeout_seconds
        
    def store_key(self, uuid: str, key: bytes):
        """Store session key with timestamp"""
        with self._lock:
            self._session_keys[uuid] = key
            self._timestamps[uuid] = time.time()
            logger.info(f"Stored session key for UUID: {uuid}")
    
    def get_key(self, uuid: str) -> Optional[bytes]:
        """Get session key and update access time"""
        with self._lock:
            if uuid in self._session_keys:
                self._timestamps[uuid] = time.time()
                return self._session_keys[uuid]
            return None
    
    def remove_key(self, uuid: str):
        """Remove session key for specific UUID"""
        with self._lock:
            self._session_keys.pop(uuid, None)
            self._timestamps.pop(uuid, None)
            logger.info(f"Removed session key for UUID: {uuid}")
    
    def cleanup_expired(self):
        """Remove expired session keys"""
        current_time = time.time()
        expired_uuids = []
        
        with self._lock:
            for uuid, timestamp in self._timestamps.items():
                if current_time - timestamp > self._timeout:
                    expired_uuids.append(uuid)
            
            for uuid in expired_uuids:
                self._session_keys.pop(uuid, None)
                self._timestamps.pop(uuid, None)
                logger.info(f"Expired session key for UUID: {uuid}")
    
    def get_stats(self):
        """Get session statistics"""
        with self._lock:
            return {
                "active_sessions": len(self._session_keys),
                "session_uuids": list(self._session_keys.keys())
            }

# Global session manager instance
session_manager = SessionManager()

class MyTranslator(TranslationContainer):
    name = "rsaTranslator"
    description = "RSA bootstrap + AES session crypto with enhanced error handling"
    author = "you"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        """
        Generate RSA keypair for payload encryption bootstrap
        """
        try:
            payload_uuid = getattr(inputMsg, 'PayloadUUID', 'unknown')
            logger.info(f"Generating RSA keypair for UUID: {payload_uuid}")
            
            # Generate RSA keypair with strong security parameters
            private_key = rsa.generate_private_key(
                public_exponent=65537, 
                key_size=2048  # 2048 is sufficient and faster than 4096
            )
            public_key = private_key.public_key()

            # Serialize keys in PEM format
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            response = TrGenerateEncryptionKeysMessageResponse(Success=True)
            # Agent embeds public key to encrypt session key with
            response.EncryptionKey = public_bytes   
            # Mythic stores private key to decrypt session key
            response.DecryptionKey = private_bytes  
            
            logger.info(f"RSA keypair generated successfully for {payload_uuid}")
            return response
            
        except Exception as e:
            logger.error(f"Key generation failed: {str(e)}")
            return TrGenerateEncryptionKeysMessageResponse(
                Success=False,
                Error=f"Key generation error: {str(e)}"
            )

    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Translate agent messages to Mythic format
        Handles both key exchange and encrypted communications
        """
        try:
            # Periodic cleanup of expired sessions
            session_manager.cleanup_expired()
            
            raw = inputMsg.Message
            logger.debug(f"Processing message from UUID: {inputMsg.UUID}, size: {len(raw)} bytes")

            # Try to detect JSON key exchange message
            try:
                decoded_msg = raw.decode('utf-8')
                json_msg = json.loads(decoded_msg)
                
                # Handle RSA key exchange
                if json_msg.get("action") == "key_exchange":
                    logger.info(f"Key exchange detected for UUID: {inputMsg.UUID}")
                    return await self._handle_key_exchange(json_msg, inputMsg)
                    
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not JSON, assume it's encrypted binary data
                logger.debug("Message is binary, attempting AES decryption")

            # Handle encrypted AES communication
            return await self._decrypt_aes_message(raw, inputMsg.UUID)

        except Exception as e:
            logger.error(f"Translation from C2 format failed: {str(e)}")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=False,
                Error=f"Translation error: {str(e)}"
            )

    async def _handle_key_exchange(self, msg: dict, inputMsg) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Handle RSA key exchange from agent
        """
        try:
            # Validate required fields
            if "encrypted_key" not in msg:
                raise ValueError("Missing encrypted_key in key exchange message")
                
            encrypted_session_key = base64.b64decode(msg["encrypted_key"])
            
            # Load private key to decrypt session key
            private_key = serialization.load_pem_private_key(
                inputMsg.DecryptionKey, 
                password=None
            )
            
            # Decrypt the AES session key
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            
            # Validate session key (should be 32 bytes for AES-256)
            if len(session_key) != 32:
                raise ValueError(f"Invalid session key length: {len(session_key)} bytes (expected 32)")
            
            # Store session key
            session_manager.store_key(inputMsg.UUID, session_key)
            
            # Create standard Mythic checkin response
            response_data = {
                "action": "checkin",
                "ip": msg.get("ip", "0.0.0.0"),
                "os": msg.get("os", "unknown"),
                "user": msg.get("user", "unknown"),
                "host": msg.get("host", "unknown"),
                "pid": msg.get("pid", 0),
                "uuid": inputMsg.UUID,
                "architecture": msg.get("architecture", "unknown"),
                "domain": msg.get("domain", "unknown"),
                "integrity_level": msg.get("integrity_level", 2),
                "external_ip": msg.get("external_ip", ""),
                "encryption_key": base64.b64encode(session_key).decode(),
                "decryption_key": base64.b64encode(session_key).decode()
            }
            
            logger.info(f"Key exchange completed successfully for UUID: {inputMsg.UUID}")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=True, 
                Message=json.dumps(response_data).encode('utf-8')
            )
            
        except Exception as e:
            logger.error(f"Key exchange failed for UUID {inputMsg.UUID}: {str(e)}")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=False,
                Error=f"Key exchange error: {str(e)}"
            )

    async def _decrypt_aes_message(self, raw_data: bytes, uuid: str) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Decrypt AES-encrypted message from agent
        """
        try:
            # Get session key
            session_key = session_manager.get_key(uuid)
            if not session_key:
                logger.error(f"No session key found for UUID: {uuid}")
                return TrCustomMessageToMythicC2FormatMessageResponse(
                    Success=False,
                    Error="No session key established - initiate key exchange first"
                )

            # Validate minimum message length
            if len(raw_data) < 17:  # 16 bytes IV + at least 1 byte data
                raise ValueError("Message too short - invalid encrypted format")
                
            # Extract IV and ciphertext
            iv = raw_data[:16]
            ciphertext = raw_data[16:]

            # Decrypt using AES-CFB mode
            decryptor = Cipher(
                algorithms.AES(session_key), 
                modes.CFB(iv)
            ).decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Validate decrypted data is proper JSON
            try:
                decoded_text = plaintext.decode('utf-8')
                parsed_json = json.loads(decoded_text)
                
                # Basic validation for Mythic message structure
                if not isinstance(parsed_json, dict):
                    raise ValueError("Decrypted message is not a JSON object")
                    
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ValueError(f"Decrypted data is not valid JSON: {str(e)}")

            logger.debug(f"Successfully decrypted message for UUID: {uuid}")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=True, 
                Message=plaintext
            )

        except Exception as e:
            logger.error(f"AES decryption failed for UUID {uuid}: {str(e)}")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=False,
                Error=f"Decryption error: {str(e)}"
            )

    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """
        Translate Mythic JSON to agent's custom encrypted format
        """
        try:
            # Periodic cleanup
            session_manager.cleanup_expired()
            
            # Get session key
            session_key = session_manager.get_key(inputMsg.UUID)
            if not session_key:
                logger.error(f"No session key found for UUID: {inputMsg.UUID}")
                return TrMythicC2ToCustomMessageFormatMessageResponse(
                    Success=False,
                    Error="No session key established"
                )

            # Generate cryptographically secure IV
            iv = secrets.token_bytes(16)  # More secure than os.urandom
            
            # Encrypt using AES-CFB mode
            encryptor = Cipher(
                algorithms.AES(session_key), 
                modes.CFB(iv)
            ).encryptor()
            
            ciphertext = encryptor.update(inputMsg.Message) + encryptor.finalize()
            
            # Combine IV + ciphertext
            encrypted_blob = iv + ciphertext

            logger.debug(f"Successfully encrypted response for UUID: {inputMsg.UUID}, size: {len(encrypted_blob)} bytes")
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=True, 
                Message=encrypted_blob
            )

        except Exception as e:
            logger.error(f"Encryption to C2 format failed for UUID {inputMsg.UUID}: {str(e)}")
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=False,
                Error=f"Encryption error: {str(e)}"
            )

    def cleanup_session(self, uuid: str):
        """
        Clean up session key when payload is removed
        """
        session_manager.remove_key(uuid)

    def get_session_stats(self):
        """
        Get current session statistics for debugging
        """
        return session_manager.get_stats()


# Utility functions for debugging and monitoring
def list_active_sessions():
    """Return list of UUIDs with active session keys"""
    return list(session_manager._session_keys.keys())

def get_session_key_info(uuid: str):
    """Get non-sensitive information about a session key"""
    key = session_manager.get_key(uuid)
    if key:
        return {
            "uuid": uuid,
            "key_length": len(key),
            "key_type": "AES-256",
            "cipher_mode": "CFB"
        }
    return None

def force_cleanup_all_sessions():
    """Emergency cleanup of all sessions"""
    with session_manager._lock:
        count = len(session_manager._session_keys)
        session_manager._session_keys.clear()
        session_manager._timestamps.clear()
        logger.warning(f"Force cleaned up {count} sessions")

