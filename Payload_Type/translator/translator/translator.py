import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

from mythic_container.TranslationBase import *

class MyTranslator(TranslationContainer):
    name = "rsaTranslator"
    description = "RSA bootstrap + AES session crypto with enhanced error handling"
    author = "you"

    # --- 1. Key Generation ---
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)

        try:
            key = os.urandom(32)  # AES-256 requires 32 bytes
            b64_key = base64.b64encode(key)

            # Mythic will store these and embed into agent at build time
            response.EncryptionKey = b64_key
            response.DecryptionKey = b64_key

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
            b64_key = inputMsg.TranslationContext.get("EncryptionKey", b"")
            if not b64_key:
                raise ValueError("EncryptionKey not found in TranslationContext")
            key = base64.b64decode(b64_key)

            # --- 2. Prepare JSON data ---
            plaintext_json = json.dumps(inputMsg.Message).encode()

            # --- 3. PKCS7 padding ---
            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext_json) + padder.finalize()

            # --- 4. Generate IV and encrypt ---
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()

            # --- 5. Compute HMAC ---
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            tag = h.finalize()

            # --- 6. Prepend UUID + assemble final payload ---
            uuid = inputMsg.Payload.UUID.encode()
            full_msg = uuid + iv + ciphertext + tag

            response.Message = full_msg

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
            # --- 1. Get decryption key from direct attribute ---
            b64_key = inputMsg.dec_key  # Base64-encoded key provided by Mythic
            if b64_key is None:
                raise ValueError("dec_key is None; no decryption key available")
            key = base64.b64decode(b64_key)

            # --- 2. Parse message structure from agent ---
            data = inputMsg.Message  # Assumes raw bytes; if base64 per docs, add base64.b64decode(inputMsg.Message)
            uuid = data[:36]  # Agent prepends UUID (36 bytes for UUID string)
            iv = data[36:52]  # 16 bytes for IV
            ct = data[52:-32]  # Ciphertext (all but last 32 bytes)
            received_tag = data[-32:]  # Last 32 bytes for HMAC-SHA256 tag

            # --- 3. Verify HMAC ---
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ct)
            h.verify(received_tag)  # Raises exception if mismatch

            # --- 4. Decrypt AES-CBC ---
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            pt = decryptor.update(ct) + decryptor.finalize()

            # --- 5. Remove PKCS7 padding ---
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(pt) + unpadder.finalize()

            # --- 6. Parse JSON ---
            response.Message = json.loads(decrypted.decode())

        except Exception as e:
            response.Success = False
            response.Error = str(e)

        return response