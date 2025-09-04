import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from mythic_container.TranslationBase import *

class MyTranslator(TranslationContainer):
    name = "rsaTranslator"
    description = "AES-GCM crypto"
    author = "@med"

    # --- 1. Key Generation ---
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        try:
            key = os.urandom(32)  # AES-256 requires 32 bytes
            # Mythic will store these and embed into agent at build time
            response.EncryptionKey = key
            response.DecryptionKey = key
        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    # --- 2. Mythic -> Agent (Encrypt) ---
    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            # --- 1. Get encryption key from TranslationContext ---
            key = inputMsg.CryptoKeys[0].EncKey

            # --- 2. Prepare JSON data ---
            plaintext_json = json.dumps(inputMsg.Message).encode()

            # --- 3. Generate nonce and encrypt with GCM ---
            iv = os.urandom(12)  # GCM uses 12-byte nonce
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext_json) + encryptor.finalize()
            tag = encryptor.tag  # GCM authentication tag (16 bytes)

            # --- 4. Prepend UUID + assemble final payload ---
            uuid = inputMsg.UUID.encode()
            full_msg = uuid + iv + ciphertext + tag

            # Base64-encode the full message (Mythic expects this for custom crypto)
            response.Message = base64.b64encode(full_msg)
        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    # --- 3. Agent -> Mythic (Decrypt) ---
    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            key = inputMsg.CryptoKeys[0].DecKey

            # --- 2. Parse message structure from agent (Mythic has already removed UUID) ---
            data = inputMsg.Message  # Raw bytes of iv + ct + tag
            
            iv = data[:12]  # 12 bytes for GCM nonce
            ct = data[12:-16]  # Ciphertext (all but last 16 bytes)
            received_tag = data[-16:]  # Last 16 bytes for GCM authentication tag

            # --- 3. Decrypt and verify with GCM ---
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, received_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            pt = decryptor.update(ct) + decryptor.finalize()  # Will raise exception if authentication fails

            # --- 4. Parse JSON ---
            response.Message = json.loads(pt.decode())
        except AttributeError as ae:
            response.Success = False
            response.Error = f"AttributeError: {str(ae)}"
        except Exception as e:
            response.Success = False
            response.Error = f"{str(e)}"
        return response