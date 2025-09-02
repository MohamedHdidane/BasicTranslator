import json
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from mythic_container.TranslationBase import *

class MyPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "Python translation service with secure key generation and AES-CBC encryption with HMAC"
    author = "@med"

    def __init__(self):
        super().__init__()
        # Dictionary to store agent keys for each UUID
        self.agent_keys = {}

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        try:
            # Generate 32-byte keys for AES-256
            agent_to_server_key = os.urandom(32)  # Agent encrypts with this
            server_to_agent_key = os.urandom(32)  # Agent decrypts with this

            # Store keys for this payload UUID
            payload_uuid = inputMsg.TranslationContainerPayloadUUID
            self.agent_keys[payload_uuid] = {
                'agent_to_server': agent_to_server_key,
                'server_to_agent': server_to_agent_key
            }

            # Return base64-encoded keys for Mythic
            response.EncryptionKey = base64.b64encode(server_to_agent_key)
            response.DecryptionKey = base64.b64encode(agent_to_server_key)
            print(f"[DEBUG] Generated keys for UUID {payload_uuid}")
        except Exception as e:
            response.Success = False
            response.Error = f"Key generation failed: {str(e)}"
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """
        Mythic -> Agent: Encrypts JSON message from Mythic for agent
        """
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            # Serialize Mythic's JSON message
            plaintext = json.dumps(inputMsg.Message).encode()

            # Get encryption key
            key = base64.b64decode(inputMsg.EncryptionKey)
            iv = os.urandom(16)

            # Encrypt with AES-CBC
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Compute HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            tag = h.finalize()

            # Format: UUID + IV + Ciphertext + HMAC, then base64 encode
            uuid = inputMsg.TranslationContainerPayloadUUID.encode()
            encrypted_message = uuid + iv + ciphertext + tag
            response.Message = base64.b64encode(encrypted_message)
            print(f"[DEBUG] Encrypted message for UUID {inputMsg.TranslationContainerPayloadUUID}")
        except Exception as e:
            response.Success = False
            response.Error = f"Encryption failed: {str(e)}"
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Agent -> Mythic: Decrypts agent's message and returns JSON to Mythic
        """
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            # Handle key exchange or encrypted message
            data = inputMsg.Message
            if isinstance(data, bytes):
                data = data.decode('utf-8')

            # Check for key exchange
            try:
                decoded_data = base64.b64decode(data)
                json_data = decoded_data.decode('utf-8')
                parsed = json.loads(json_data)

                if parsed.get('action') == 'key_exchange':
                    uuid = parsed.get('uuid')
                    print(f"[DEBUG] Key exchange request for UUID: {uuid}")

                    # Generate or retrieve keys
                    if uuid not in self.agent_keys:
                        self.agent_keys[uuid] = {
                            'agent_to_server': os.urandom(32),
                            'server_to_agent': os.urandom(32)
                        }
                        print(f"[DEBUG] Generated new keys for UUID {uuid}")

                    agent_keys = self.agent_keys[uuid]
                    key_response = {
                        "action": "key_exchange_response",
                        "uuid": uuid,
                        "encryption_key": base64.b64encode(agent_keys['agent_to_server']).decode(),
                        "decryption_key": base64.b64encode(agent_keys['server_to_agent']).decode(),
                        "status": "success"
                    }
                    response.Message = key_response
                    print(f"[DEBUG] Key exchange response: {key_response}")
                    return response
            except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                # Not a key exchange, proceed with decryption
                pass

            # Handle encrypted message
            encrypted_data = base64.b64decode(data)
            if len(encrypted_data) < 84:  # UUID(36) + IV(16) + Ciphertext(min 16) + HMAC(32)
                response.Success = False
                response.Error = "Message too short for encrypted format"
                return response

            # Extract components
            uuid = encrypted_data[:36].decode()
            iv = encrypted_data[36:52]
            ciphertext = encrypted_data[52:-32]
            received_tag = encrypted_data[-32:]

            # Verify HMAC
            key = base64.b64decode(inputMsg.DecryptionKey)
            backend = default_backend()
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            calculated_tag = h.finalize()

            if not hmac.compare_digest(calculated_tag, received_tag):
                response.Success = False
                response.Error = "HMAC verification failed"
                return response

            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # Parse JSON
            response.Message = json.loads(plaintext.decode())
            print(f"[DEBUG] Decrypted message from UUID {uuid}")
        except Exception as e:
            response.Success = False
            response.Error = f"Decryption failed: {str(e)}"
        return response