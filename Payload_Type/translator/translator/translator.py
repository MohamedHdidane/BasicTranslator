import os
import logging
from mythic_container.TranslationBase import (
    TranslationContainer,
    TranslateGenerateKeysMessage,
    TranslateGenerateKeysMessageResponse,
    TranslateToC2FormatMessage,
    TranslateToC2FormatMessageResponse,
    TranslateFromC2FormatMessage,
    TranslateFromC2FormatMessageResponse,
)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG)

class myPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "Igider translation service with custom encryption"
    author = "@med"

    async def generate_keys(
        self,
        request: TranslateGenerateKeysMessage
    ) -> TranslateGenerateKeysMessageResponse:
        """
        Generate encryption keys for the payload
        """
        try:
            # Generate keys
            encryption_key = os.urandom(32)  # 32 bytes for AES-256
            hmac_key = os.urandom(32)        # 32 bytes for HMAC
            iv = os.urandom(16)              # 16 bytes IV for AES CBC

            combined_key = encryption_key + hmac_key + iv

            logging.debug(f"Generated Encryption Key: {encryption_key.hex()}")
            logging.debug(f"Generated HMAC Key: {hmac_key.hex()}")
            logging.debug(f"Generated IV: {iv.hex()}")

            response = TranslateGenerateKeysMessageResponse(
                success=True,
                enc_key=combined_key,  # Pass combined key bytes (encryption + hmac + iv)
                dec_key=combined_key,  # Same for decryption in symmetric encryption
                value=combined_key.hex()  # Optional hex string for debugging/logging
            )
            return response

        except Exception as e:
            logging.error(f"Key generation failed: {str(e)}")
            return TranslateGenerateKeysMessageResponse(
                success=False,
                error=f"Failed to generate keys: {str(e)}"
            )

    async def translate_to_c2_format(
        self,
        request: TranslateToC2FormatMessage
    ) -> TranslateToC2FormatMessageResponse:
        """
        Encrypt outgoing message (Mythic -> C2)
        """
        try:
            message = request.message
            key_material = request.enc_key
            if len(key_material) < 80:
                raise ValueError("Invalid key length, expected at least 80 bytes")

            # Split keys and IV
            enc_key = key_material[:32]
            hmac_key = key_material[32:64]
            iv = key_material[64:80]

            logging.debug(f"translate_to_c2_format: Using Encryption Key: {enc_key.hex()}")
            logging.debug(f"translate_to_c2_format: Using HMAC Key: {hmac_key.hex()}")
            logging.debug(f"translate_to_c2_format: Using IV: {iv.hex()}")

            # Ensure message is bytes
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message

            # PKCS7 Padding
            padding_len = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + bytes([padding_len] * padding_len)

            # AES-256-CBC encryption
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_message) + encryptor.finalize()

            # HMAC for integrity
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + encrypted)
            message_hmac = h.finalize()

            # Combine IV + encrypted message + HMAC
            final_message = iv + encrypted + message_hmac

            return TranslateToC2FormatMessageResponse(
                success=True,
                message=final_message
            )

        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            return TranslateToC2FormatMessageResponse(
                success=False,
                error=f"Failed to encrypt message: {str(e)}"
            )

    async def translate_from_c2_format(
        self,
        request: TranslateFromC2FormatMessage
    ) -> TranslateFromC2FormatMessageResponse:
        """
        Decrypt incoming message (C2 -> Mythic)
        """
        try:
            encrypted_message = request.message
            key_material = request.dec_key

            if len(key_material) < 80:
                raise ValueError("Invalid key length, expected at least 80 bytes")
            if len(encrypted_message) < 80:
                raise ValueError("Invalid encrypted message length")

            # Split keys and IV
            dec_key = key_material[:32]
            hmac_key = key_material[32:64]
            iv = encrypted_message[:16]
            received_hmac = encrypted_message[-32:]
            encrypted_data = encrypted_message[16:-32]

            logging.debug(f"translate_from_c2_format: Using Decryption Key: {dec_key.hex()}")
            logging.debug(f"translate_from_c2_format: Using HMAC Key: {hmac_key.hex()}")
            logging.debug(f"translate_from_c2_format: Using IV: {iv.hex()}")

            # Verify HMAC
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + encrypted_data)
            h.verify(received_hmac)

            # Decrypt AES-256-CBC
            cipher = Cipher(
                algorithms.AES(dec_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_len = decrypted_padded[-1]
            if padding_len < 1 or padding_len > 16:
                raise ValueError("Invalid padding length detected")
            decrypted = decrypted_padded[:-padding_len]

            # Attempt UTF-8 decode
            try:
                message_str = decrypted.decode('utf-8')
            except UnicodeDecodeError:
                message_str = decrypted  # Raw bytes fallback

            return TranslateFromC2FormatMessageResponse(
                success=True,
                message=message_str
            )

        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            return TranslateFromC2FormatMessageResponse(
                success=False,
                error=f"Failed to decrypt message: {str(e)}"
            )
