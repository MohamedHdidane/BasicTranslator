from mythic_container.TranslationBase import *
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class myPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "Igider translation service with custom encryption"
    author = "@med"
    
    # Store keys per agent UUID
    agent_keys = {}
    
    async def generate_keys(
        request: TranslateGenerateKeysMessage
    ) -> TranslateGenerateKeysMessageResponse:
        """
        Generate encryption keys for the payload
        
        Args:
            request: TranslateGenerateKeysMessage containing payload UUID and other info
            
        Returns:
            TranslateGenerateKeysMessageResponse with generated keys as byte arrays
        """
        try:
            # Generate a 32-byte AES-256 key
            encryption_key = os.urandom(32)
            
            # Generate a 32-byte HMAC key for message integrity
            hmac_key = os.urandom(32)
            
            # You can also generate other keys based on your encryption scheme
            # For example, IV for AES if needed
            iv = os.urandom(16)
            
            # Combine keys if needed (this is just an example)
            # In practice, you might want to keep them separate
            combined_key = encryption_key + hmac_key + iv
            
            # Return the keys as byte arrays (Mythic 3.0+ expects byte arrays, not base64)
            response = TranslateGenerateKeysMessageResponse(
                success=True,
                enc_key=encryption_key,  # Encryption key as bytes
                dec_key=encryption_key,  # Decryption key (same as enc for symmetric)
                # You can add additional keys to the 'value' field if needed
                value=combined_key.hex()  # Optional: additional key data as hex string
            )
            
            return response
            
        except Exception as e:
            return TranslateGenerateKeysMessageResponse(
                success=False,
                error=f"Failed to generate keys: {str(e)}"
            )


    async def translate_to_c2_format(
        request: TranslateToC2FormatMessage
    ) -> TranslateToC2FormatMessageResponse:
        """
        Translate message from Mythic format to C2 format (encrypt outgoing messages)
        
        Args:
            request: TranslateToC2FormatMessage with message to encrypt
            
        Returns:
            TranslateToC2FormatMessageResponse with encrypted message
        """
        try:
            # Get the message and encryption key
            message = request.message
            enc_key = request.enc_key[:32]  # Use first 32 bytes for AES-256
            hmac_key = request.enc_key[32:64]  # Next 32 bytes for HMAC
            
            # Convert message to bytes if it's a string
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # Generate a random IV for this message
            iv = os.urandom(16)
            
            # Encrypt the message using AES-256-CBC
            cipher = Cipher(
                algorithms.AES(enc_key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad the message to AES block size (16 bytes)
            padding_length = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + bytes([padding_length]) * padding_length
            
            # Encrypt the padded message
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
            
            # Create HMAC for integrity checking
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + encrypted_message)
            message_hmac = h.finalize()
            
            # Combine IV + encrypted message + HMAC
            final_message = iv + encrypted_message + message_hmac
            
            return TranslateToC2FormatMessageResponse(
                success=True,
                message=final_message
            )
            
        except Exception as e:
            return TranslateToC2FormatMessageResponse(
                success=False,
                error=f"Failed to encrypt message: {str(e)}"
            )


    async def translate_from_c2_format(
        request: TranslateFromC2FormatMessage
    ) -> TranslateFromC2FormatMessageResponse:
        """
        Translate message from C2 format to Mythic format (decrypt incoming messages)
        
        Args:
            request: TranslateFromC2FormatMessage with encrypted message
            
        Returns:
            TranslateFromC2FormatMessageResponse with decrypted message
        """
        try:
            # Get the encrypted message and decryption key
            encrypted_message = request.message
            dec_key = request.dec_key[:32]  # Use first 32 bytes for AES-256
            hmac_key = request.dec_key[32:64]  # Next 32 bytes for HMAC
            
            # Extract IV (first 16 bytes)
            iv = encrypted_message[:16]
            
            # Extract HMAC (last 32 bytes)
            received_hmac = encrypted_message[-32:]
            
            # Extract encrypted data (middle portion)
            encrypted_data = encrypted_message[16:-32]
            
            # Verify HMAC for integrity
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + encrypted_data)
            try:
                h.verify(received_hmac)
            except Exception:
                return TranslateFromC2FormatMessageResponse(
                    success=False,
                    error="HMAC verification failed - message may be corrupted or tampered with"
                )
            
            # Decrypt the message using AES-256-CBC
            cipher = Cipher(
                algorithms.AES(dec_key), 
                modes.CBC(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and remove padding
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = decrypted_padded[-1]
            decrypted_message = decrypted_padded[:-padding_length]
            
            # Convert back to string if needed
            try:
                message_str = decrypted_message.decode('utf-8')
            except UnicodeDecodeError:
                # If it can't be decoded as UTF-8, return as bytes
                message_str = decrypted_message
            
            return TranslateFromC2FormatMessageResponse(
                success=True,
                message=message_str
            )
            
        except Exception as e:
            return TranslateFromC2FormatMessageResponse(
                success=False,
                error=f"Failed to decrypt message: {str(e)}"
            )