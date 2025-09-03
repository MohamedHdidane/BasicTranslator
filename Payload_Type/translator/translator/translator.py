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

        key = os.urandom(16)  # AES-256 key
        b64_key = base64.b64encode(key)

        # Mythic will store these and embed into agent at build time
        response.EncryptionKey = b64_key
        response.DecryptionKey = b64_key

        return response

    # --- 2. Mythic -> Agent (Encrypt) ---
    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)

        key = base64.b64decode(inputMsg.TranslationInfo.DecryptionKey)        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded = padder.update(json.dumps(inputMsg.Message).encode()) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ct)
        tag = h.finalize()

        response.Message = iv + ct + tag
        return response

    # --- 3. Agent -> Mythic (Decrypt) ---
    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)

        key = base64.b64decode(inputMsg.TranslationInfo.DecryptionKey)        data = inputMsg.Message

        uuid = data[:36]         # agent prepends UUID
        iv = data[36:52]
        ct = data[52:-32]
        received_tag = data[-32:]

        # verify HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ct)
        h.verify(received_tag)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(pt) + unpadder.finalize()

        # agent concatenates UUID + plaintext
        response.Message = json.loads((uuid + decrypted.decode()))
        return response
