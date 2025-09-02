import json
import base64
import os
from mythic_container.TranslationBase import *

class myPythonTranslation(TranslationContainer):
    name = "myPythonTranslation"
    description = "Python translation service with dynamic key generation"
    author = "@its_a_feature_"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        # Generate random 32-byte keys for AES-256
        new_key = os.urandom(32)
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        response.DecryptionKey = new_key
        response.EncryptionKey = new_key
        
        # Debug output
        print(f"[Translator] Generated new key: {base64.b64encode(new_key).decode('utf-8')}")
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        response.Message = json.dumps(inputMsg.Message).encode()
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        response.Message = json.loads(inputMsg.Message)
        return response