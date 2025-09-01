import json
import base64
from Crypto.Cipher import AES
import base64, json
import os

from mythic_container.TranslationBase import *


class myPythonTranslation(TranslationContainer):
    # name = "myPythonTranslation"
    # description = "python translation service that doesn't change anything"
    # author = "@med"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage):
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        # Generate random AES key + IV
        aes_key = os.urandom(32)  # 256-bit AES
        iv = os.urandom(16)

        response.DecryptionKey = aes_key + iv
        response.EncryptionKey = aes_key + iv
        return response




    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage):
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)

        # Serialize Mythic’s dict
        plaintext = json.dumps(inputMsg.Message).encode()

        # Example AES encrypt (same key from generate_keys)
        key = inputMsg.EncryptionKey[:32]
        iv = inputMsg.EncryptionKey[32:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher.encrypt(plaintext)

        # Prepend UUID + Base64 encode
        msg = inputMsg.TranslationContainerPayloadUUID.encode() + ciphertext
        response.Message = base64.b64encode(msg)

        return response


    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage):
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)

        data = base64.b64decode(inputMsg.Message)

        # First 36 bytes = UUID (or however long your UUID is)
        uuid = data[:36].decode()
        ciphertext = data[36:]

        key = inputMsg.DecryptionKey[:32]
        iv = inputMsg.DecryptionKey[32:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        plaintext = cipher.decrypt(ciphertext)

        response.Message = json.loads(plaintext.decode())
        return response