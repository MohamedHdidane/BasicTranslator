import json
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mythic_container.TranslationBase import *


class SecureTranslation(TranslationContainer):
    name = "SecureTranslation"
    description = "Python translation service with AES-256-GCM encryption"
    author = "@security_researcher"

    def __init__(self):
        super().__init__()
        self.master_key = None  # Store the master encryption key
        
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        """Generate AES-256 encryption keys for the payload"""
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        
        try:
            # Generate a random 32-byte key for AES-256
            encryption_key = AESGCM.generate_key(bit_length=256)
            
            # Store the master key
            self.master_key = encryption_key
            
            # Return the same key for both encryption and decryption
            response.EncryptionKey = encryption_key
            response.DecryptionKey = encryption_key
            
            print(f"Generated new AES-256 key: {len(encryption_key)} bytes")
            
        except Exception as e:
            print(f"Error generating keys: {str(e)}")
            response.Success = False
            response.Error = f"Key generation failed: {str(e)}"
            
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """Encrypt Mythic JSON message to custom C2 format"""
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        try:
            # Use the stored master key
            if self.master_key is None:
                raise Exception("No encryption key available - generate_keys not called")
                
            # Convert message to JSON bytes
            message_json = json.dumps(inputMsg.Message)
            plaintext = message_json.encode('utf-8')
            
            # Initialize AESGCM with the key
            aesgcm = AESGCM(self.master_key)
            
            # Generate a random 12-byte nonce for GCM
            nonce = os.urandom(12)
            
            # Encrypt the message
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Combine nonce + ciphertext for transmission
            # Format: [12-byte nonce][encrypted_data]
            encrypted_message = nonce + ciphertext
            
            # Base64 encode for safe transport
            response.Message = base64.b64encode(encrypted_message)
            
            print(f"Encrypted message, size: {len(encrypted_message)} bytes")
            
        except Exception as e:
            print(f"Error encrypting message: {str(e)}")
            response.Success = False
            response.Error = f"Encryption failed: {str(e)}"
            
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """Decrypt custom C2 format message to Mythic JSON"""
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        try:
            # Use the stored master key
            if self.master_key is None:
                raise Exception("No decryption key available - generate_keys not called")
            
            # Base64 decode the incoming message
            try:
                encrypted_data = base64.b64decode(inputMsg.Message)
            except Exception:
                # If base64 decode fails, try treating as raw bytes
                if isinstance(inputMsg.Message, str):
                    encrypted_data = inputMsg.Message.encode('utf-8')
                else:
                    encrypted_data = inputMsg.Message
                
            if len(encrypted_data) < 13:  # Minimum: 12-byte nonce + 1 byte data
                raise Exception("Message too short to contain valid encrypted data")
            
            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Initialize AESGCM with the key
            aesgcm = AESGCM(self.master_key)
            
            # Decrypt the message
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse the JSON message
            message_str = plaintext.decode('utf-8')
            response.Message = json.loads(message_str)
            
            print(f"Decrypted message successfully")
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON after decryption: {str(e)}")
            response.Success = False
            response.Error = f"JSON parsing failed: {str(e)}"
            
        except Exception as e:
            print(f"Error decrypting message: {str(e)}")
            response.Success = False
            response.Error = f"Decryption failed: {str(e)}"
            
        return response