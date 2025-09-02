# translator.py
import base64
import os
from mythic_container.TranslationBase import (
    TranslationContainer,
    TrCustomToMythicC2MessageFormatMessage,
    TrMythicC2ToCustomMessageFormatMessage,
    TrGenerateEncryptionKeysMessage,
    TrEncryptMessage,
    TrDecryptMessage,
)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# simple in-memory dict for UUID → session key mapping
SESSION_KEYS = {}

class MyTranslator(TranslationContainer):
    name = "rsaTranslator"
    description = "RSA bootstrap + AES session crypto"
    author = "you"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage):
        # generate RSA keypair for this payload
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()

        # serialize
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        resp = TrGenerateEncryptionKeysMessageResponse(Success=True)
        # Mythic stores these with the payload UUID
        resp.EncryptionKey = pub_bytes   # give agent the public key
        resp.DecryptionKey = priv_bytes  # Mythic keeps the private key
        return resp

    async def translate_from_c2_format(self, inputMsg: TrCustomToMythicC2MessageFormatMessage):
        raw = inputMsg.Message

        # detect key exchange message
        try:
            msg = json.loads(raw.decode())
        except Exception:
            return TrCustomToMythicC2MessageFormatMessageResponse(Success=False)

        if msg.get("action") == "key_exchange":
            enc_session = base64.b64decode(msg["encrypted_key"])
            # load private key for this UUID
            priv = serialization.load_pem_private_key(inputMsg.DecryptionKey, password=None)
            session_key = priv.decrypt(
                enc_session,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            SESSION_KEYS[inputMsg.UUID] = session_key
            return TrCustomToMythicC2MessageFormatMessageResponse(Success=True, Message=b'{"status":"ok"}')

        # otherwise assume AES-encrypted JSON
        key = SESSION_KEYS.get(inputMsg.UUID, None)
        if not key:
            return TrCustomToMythicC2MessageFormatMessageResponse(Success=False)

        iv = raw[:16]
        ct = raw[16:]
        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        plain = decryptor.update(ct) + decryptor.finalize()

        return TrCustomToMythicC2MessageFormatMessageResponse(Success=True, Message=plain)

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage):
        key = SESSION_KEYS.get(inputMsg.UUID, None)
        if not key:
            return TrMythicC2ToCustomMessageFormatMessageResponse(Success=False)

        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        ct = encryptor.update(inputMsg.Message) + encryptor.finalize()
        blob = iv + ct

        return TrMythicC2ToCustomMessageFormatMessageResponse(Success=True, Message=blob)
