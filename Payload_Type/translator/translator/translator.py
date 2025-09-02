import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

from mythic_container.TranslationBase import *


class myPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "Python translation service with AES encryption support"
    author = "@med"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        try:
            # Generate 32-byte (256-bit) keys for AES encryption
            agent_to_server_key = os.urandom(32)
            server_to_agent_key = os.urandom(32)
            
            # Base64 encode for transmission
            response.EncryptionKey = base64.b64encode(agent_to_server_key)
            response.DecryptionKey = base64.b64encode(server_to_agent_key)
            
            return response
        except Exception as e:
            response.Success = False
            response.Error = f"Key generation failed: {str(e)}"
            return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            # Convert Mythic message to JSON
            json_message = json.dumps(inputMsg.Message)
            
            # Handle key exchange response (send unencrypted)
            if inputMsg.Message.get("action") == "key_exchange_response":
                # Key exchange response should be unencrypted base64
                response.Message = base64.b64encode(json_message.encode())
                return response
            
            # Normal encrypted communication
            if inputMsg.CryptoKeys and len(inputMsg.CryptoKeys) > 0:
                # Use the server-to-agent key for encryption
                encryption_key = base64.b64decode(inputMsg.CryptoKeys[0])
                encrypted_data = self._encrypt_data(json_message.encode(), encryption_key)
                
                # Prepend the callback UUID and base64 encode the result
                callback_uuid = inputMsg.Message.get("uuid", "").encode()
                final_message = base64.b64encode(callback_uuid + encrypted_data)
            else:
                # No encryption, just base64 encode
                final_message = base64.b64encode(json_message.encode())
            
            response.Message = final_message
            return response
        except Exception as e:
            response.Success = False
            response.Error = f"Translation to C2 format failed: {str(e)}"
            return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            # Decode base64 message from agent
            decoded_message = base64.b64decode(inputMsg.Message)
            
            # Extract UUID (first part) and remaining data
            decoded_str = decoded_message.decode()
            
            # Look for UUID pattern (36 chars) at start
            if len(decoded_str) >= 36:
                potential_uuid = decoded_str[:36]
                remaining_data = decoded_str[36:]
                
                # Try to parse remaining data as JSON (for key exchange)
                try:
                    parsed_json = json.loads(remaining_data)
                    
                    # If this is a key exchange, return it directly (unencrypted)
                    if parsed_json.get("action") == "key_exchange":
                        response.Message = parsed_json
                        return response
                except json.JSONDecodeError:
                    pass  # Not JSON, must be encrypted data
            
            # Handle encrypted messages (normal communication after key exchange)
            if inputMsg.CryptoKeys and len(inputMsg.CryptoKeys) > 0:
                # Extract UUID and encrypted data as bytes
                uuid_bytes = decoded_message[:36]  # UUID as bytes
                encrypted_data = decoded_message[36:]  # Rest is encrypted
                
                # Use the agent-to-server key for decryption
                decryption_key = base64.b64decode(inputMsg.CryptoKeys[0])
                decrypted_data = self._decrypt_data(encrypted_data, decryption_key)
                if not decrypted_data:
                    raise ValueError("Decryption failed")
                json_message = decrypted_data.decode()
            else:
                # No encryption keys available, treat as unencrypted
                if len(decoded_message) >= 36:
                    json_message = decoded_message[36:].decode()
                else:
                    json_message = decoded_message.decode()
            
            # Parse JSON and return to Mythic
            response.Message = json.loads(json_message)
            return response
        except Exception as e:
            response.Success = False
            response.Error = f"Translation from C2 format failed: {str(e)}"
            return response

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-CBC with HMAC authentication"""
        try:
            iv = os.urandom(16)
            backend = default_backend()
            
            # Encrypt with AES-CBC
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Generate HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            tag = h.finalize()
            
            return iv + ciphertext + tag
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    def _decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-CBC with HMAC verification"""
        try:
            if len(data) < 52:  # 16 (IV) + 16 (min ciphertext) + 32 (HMAC)
                raise ValueError("Data too short for decryption")
            
            iv = data[:16]
            ciphertext = data[16:-32]
            received_tag = data[-32:]
            
            backend = default_backend()
            
            # Verify HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            calculated_tag = h.finalize()
            
            if not hmac.compare_digest(calculated_tag, received_tag):
                raise ValueError("HMAC verification failed")
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")