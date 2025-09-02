import json
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mythic_container.TranslationBase import *


class SecureTranslation(TranslationContainer):
    name = "SecureTranslation"
    description = "Python translation service with AES-256-GCM encryption"
    author = "@security_researcher"

    def __init__(self):
        super().__init__()
        self.encryption_keys = {}  # Store keys per payload UUID
        
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        """Generate AES-256 encryption keys for the payload"""
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        
        try:
            # Generate a random 32-byte key for AES-256
            encryption_key = AESGCM.generate_key(bit_length=256)
            
            # Store the key for this payload UUID
            payload_uuid = inputMsg.PayloadUUID
            self.encryption_keys[payload_uuid] = encryption_key
            
            # Return the same key for both encryption and decryption
            response.EncryptionKey = encryption_key
            response.DecryptionKey = encryption_key
            
            print(f"Generated new AES-256 key for payload {payload_uuid}")
            
        except Exception as e:
            print(f"Error generating keys: {str(e)}")
            response.Success = False
            response.Error = f"Key generation failed: {str(e)}"
            
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """Encrypt Mythic JSON message to custom C2 format"""
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        try:
            # Get the payload UUID and corresponding key
            payload_uuid = inputMsg.PayloadUUID
            
            if payload_uuid not in self.encryption_keys:
                raise Exception(f"No encryption key found for payload {payload_uuid}")
                
            encryption_key = self.encryption_keys[payload_uuid]
            
            # Convert message to JSON bytes
            message_json = json.dumps(inputMsg.Message)
            plaintext = message_json.encode('utf-8')
            
            # Initialize AESGCM with the key
            aesgcm = AESGCM(encryption_key)
            
            # Generate a random 12-byte nonce for GCM
            nonce = os.urandom(12)
            
            # Encrypt the message
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Combine nonce + ciphertext for transmission
            # Format: [12-byte nonce][encrypted_data]
            encrypted_message = nonce + ciphertext
            
            # Base64 encode for safe transport
            response.Message = base64.b64encode(encrypted_message)
            
            print(f"Encrypted message for payload {payload_uuid}, size: {len(encrypted_message)} bytes")
            
        except Exception as e:
            print(f"Error encrypting message: {str(e)}")
            response.Success = False
            response.Error = f"Encryption failed: {str(e)}"
            
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """Decrypt custom C2 format message to Mythic JSON"""
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        try:
            # Get the payload UUID and corresponding key
            payload_uuid = inputMsg.PayloadUUID
            
            if payload_uuid not in self.encryption_keys:
                raise Exception(f"No decryption key found for payload {payload_uuid}")
                
            decryption_key = self.encryption_keys[payload_uuid]
            
            # Base64 decode the incoming message
            try:
                encrypted_data = base64.b64decode(inputMsg.Message)
            except Exception:
                # If base64 decode fails, try treating as raw bytes
                encrypted_data = inputMsg.Message
                
            if len(encrypted_data) < 13:  # Minimum: 12-byte nonce + 1 byte data
                raise Exception("Message too short to contain valid encrypted data")
            
            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Initialize AESGCM with the key
            aesgcm = AESGCM(decryption_key)
            
            # Decrypt the message
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse the JSON message
            message_str = plaintext.decode('utf-8')
            response.Message = json.loads(message_str)
            
            print(f"Decrypted message for payload {payload_uuid}")
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON after decryption: {str(e)}")
            response.Success = False
            response.Error = f"JSON parsing failed: {str(e)}"
            
        except Exception as e:
            print(f"Error decrypting message: {str(e)}")
            response.Success = False
            response.Error = f"Decryption failed: {str(e)}"
            
        return response

    def cleanup_payload_keys(self, payload_uuid: str):
        """Clean up keys for a specific payload (call when payload is removed)"""
        if payload_uuid in self.encryption_keys:
            del self.encryption_keys[payload_uuid]
            print(f"Cleaned up keys for payload {payload_uuid}")


# Additional utility functions for advanced crypto operations
class AdvancedCrypto:
    """Additional cryptographic utilities for more complex scenarios"""
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> bytes:
        """Derive AES key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_with_rsa_key_exchange():
        """Placeholder for RSA key exchange implementation"""
        # This would implement RSA key exchange for initial key negotiation
        # Useful for scenarios where you can't pre-share AES keys
        pass
    
    @staticmethod
    def add_message_authentication(message: bytes, key: bytes) -> bytes:
        """Add HMAC authentication to messages"""
        from cryptography.hazmat.primitives import hmac
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()
        return message + signature
    
    @staticmethod
    def verify_message_authentication(message_with_mac: bytes, key: bytes) -> bytes:
        """Verify and strip HMAC from messages"""
        from cryptography.hazmat.primitives import hmac
        message = message_with_mac[:-32]  # Remove last 32 bytes (HMAC-SHA256)
        mac = message_with_mac[-32:]
        
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        h.verify(mac)  # Raises exception if verification fails
        return message