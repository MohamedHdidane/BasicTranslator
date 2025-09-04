import os
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mythic_container.TranslationBase import *

class MyTranslator(TranslationContainer):
    name = "rsaTranslator"
    description = "AES-GCM crypto translator"
    author = "@med"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        try:
            # AES-256 key (32 bytes). Use same key for enc & dec (symmetric)
            key = os.urandom(32)

            # Mythic will embed these into the agent's config as base64 typically.
            response.EncryptionKey = key
            response.DecryptionKey = key

        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        """
        Mythic -> Agent (encrypt)
        - inputMsg.Message is a Python object (dict) that we will JSON encode then encrypt.
        - We assemble uuid||nonce||ciphertext_and_tag and base64-encode it (Mythic expects base64 for custom crypto).
        """
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            # Crypto key (bytes). If your framework returns base64 string, decode it.
            key = inputMsg.CryptoKeys[0].EncKey
            if isinstance(key, str):
                key = base64.b64decode(key)

            plaintext = json.dumps(inputMsg.Message).encode()

            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # 12 bytes recommended for GCM
            ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)  # associated_data=None

            uuid = inputMsg.UUID.encode()  # should be 36 bytes
            full_msg = uuid + nonce + ct_and_tag

            # Mythic expects base64 for custom crypto messages — match what you used before.
            response.Message = base64.b64encode(full_msg)
        except Exception as e:
            response.Success = False
            response.Error = str(e)
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        """
        Agent -> Mythic (decrypt)
        - inputMsg.Message may be raw bytes or base64; handle both robustly.
        - Expect layout: uuid(36) || nonce(12) || ciphertext_and_tag
        """
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            key = inputMsg.CryptoKeys[0].DecKey
            if isinstance(key, str):
                key = base64.b64decode(key)

            raw = inputMsg.Message
            # Many Mythic translators send/receive base64; be flexible:
            if isinstance(raw, str):
                # if it's ascii (base64) -> decode
                try:
                    raw = base64.b64decode(raw)
                except Exception:
                    # if it's not base64, try to interpret as bytes string literal
                    raw = raw.encode()

            # If Mythic already stripped UUID, handle both cases:
            if len(raw) < (12 + 16):
                raise ValueError("Message too short for AES-GCM")

            # If first 36 bytes look like a UUID (36 chars including hyphens), parse it.
            uuid_part = None
            if len(raw) >= 36 and all((32 <= raw[i] <= 122) for i in range(36)):  # quick ascii check
                uuid_candidate = raw[:36].decode(errors="ignore")
                # optional: validate format with simple hyphen checks (8-4-4-4-12)
                if uuid_candidate.count("-") == 4:
                    uuid_part = uuid_candidate
                    nonce = raw[36:36+12]
                    ct_and_tag = raw[48:]
                else:
                    # treat as no-uuid case
                    uuid_part = None
            if uuid_part is None:
                # Assume Mythic stripped UUID; entire payload is nonce||ct_and_tag
                nonce = raw[:12]
                ct_and_tag = raw[12:]

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)  # raises exception on auth fail

            # The translator should return a JSON-decoded object
            try:
                response.Message = json.loads(plaintext.decode())
            except Exception:
                # If plaintext isn't JSON, return raw decoded text
                response.Message = plaintext.decode(errors="ignore")

        except Exception as e:
            response.Success = False
            response.Error = f"{str(e)}"
        return response
