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
            key = os.urandom(24)  # AES-256 requires 32 bytes
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
        # Debug: Print attributes of inputMsg to logs to identify available fields (check docker logs for your translation container)
        print("Attributes of inputMsg: " + str(dir(inputMsg)))
        print("Vars of inputMsg: " + str(vars(inputMsg)))  # For more details on field values (if available)

        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)

        try:
            # --- 1. Get decryption key from direct attribute (try 'enc_key' as it may be used for symmetric crypto) ---
            b64_key = inputMsg.CryptoKeys[0].DecKey  # Change to inputMsg.dec_key if this fails; or use the debug output to find the correct field name
            if not b64_key:
                raise ValueError("enc_key not found or empty")
            key = base64.b64decode(b64_key)

            # --- 2. Parse message structure from agent (Mythic has already removed UUID) ---
            data = inputMsg.Message  # Raw bytes of iv + ct + tag; if length errors, try base64.b64decode(inputMsg.Message)
            iv = data[:16]  # 16 bytes for IV
            ct = data[16:-32]  # Ciphertext (all but last 32 bytes)
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

            crypto_key_obj = inputMsg.CryptoKeys[0]
            possible_key_attrs = ['DecryptionKey', 'dec_key', 'key', 'value', 'EncryptionKey']
            b64 = ""
            for attr in possible_key_attrs:
                if hasattr(crypto_key_obj, attr):
                    b64+= attr
                    break

        except AttributeError as ae:
            response.Success = False
            response.Error = f"AttributeError: {str(ae)}. Available attributes: {str(dir(inputMsg))}. Object format: {str(type(inputMsg))} . inputMsg.CryptoKeys: {str(type(inputMsg.CryptoKeys[0]))}. inputMsg.CryptoKeys: {vars(inputMsg.CryptoKeys[0])}**{inputMsg.CryptoKeys[0].EncKey}"

        except Exception as e:
            response.Success = False
            response.Error = f"{str(e)}**DecryptKEy:{inputMsg.CryptoKeys[0].DecKey}**h:{h}**recived_tag:{received_tag}**ct:{ct}**iv:{iv}"

        return response