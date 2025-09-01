import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

from mythic_container.TranslationBase import *


class myPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "python translation service with proper key generation and encryption handling"
    author = "@med"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage):
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        
        # Generate AES key (32 bytes for AES-256)
        aes_key = os.urandom(32)
        
        # Agent expects base64 encoded keys in this format
        key_b64 = base64.b64encode(aes_key).decode()
        
        # Return keys in the format the agent expects
        response.DecryptionKey = key_b64
        response.EncryptionKey = key_b64
        
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage):
        """
        Mythic -> Agent direction
        Takes plaintext from Mythic, encrypts it for the agent
        """
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        try:
            # Serialize Mythic's message to JSON
            plaintext = json.dumps(inputMsg.Message).encode()
            
            # Encrypt using agent's expected format (AES-CBC + HMAC)
            key = base64.b64decode(inputMsg.EncryptionKey)
            iv = os.urandom(16)
            
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            encryptor = cipher.encryptor()
            
            # PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            tag = h.finalize()
            
            # Format: UUID + IV + Ciphertext + HMAC
            encrypted_message = inputMsg.TranslationContainerPayloadUUID.encode() + iv + ciphertext + tag
            
            # Base64 encode the entire message
            response.Message = base64.b64encode(encrypted_message)
            
        except Exception as e:
            response.Success = False
            response.Error = f"Encryption failed: {str(e)}"
            
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage):
        """
        Agent -> Mythic direction  
        Takes encrypted data from agent, decrypts it for Mythic
        """
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        try:
            # Agent sends base64 encoded data
            encrypted_data = base64.b64decode(inputMsg.Message)
            
            # Extract components: UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
            uuid = encrypted_data[:36]
            iv = encrypted_data[36:52]
            ciphertext = encrypted_data[52:-32]
            received_tag = encrypted_data[-32:]
            
            # Verify HMAC
            key = base64.b64decode(inputMsg.DecryptionKey)
            backend = default_backend()
            
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            calculated_tag = h.finalize()
            
            if calculated_tag != received_tag:
                response.Success = False
                response.Error = "HMAC verification failed"
                return response
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Parse JSON and return to Mythic
            response.Message = json.loads(plaintext.decode())
            
        except Exception as e:
            response.Success = False
            response.Error = f"Decryption failed: {str(e)}"
            
        return response