from mythic_container.TranslationBase import *
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

class IgiderTranslation(TranslationContainer):
    name = "igider_translator"
    description = "Igider translation service with custom encryption"
    author = "@med"
    
    # Store keys per agent UUID
    agent_keys = {}
    
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        
        try:
            # Generate 32-byte AES key
            encryption_key = get_random_bytes(32)
            
            # Store keys for this agent
            agent_id = inputMsg.C2ProfileName + "_" + str(inputMsg.PayloadUUID)
            self.agent_keys[agent_id] = {
                "enc_key": encryption_key,
                "dec_key": encryption_key  # Same key for AES
            }
            
            response.EncryptionKey = encryption_key
            response.DecryptionKey = encryption_key
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        try:
            # Get agent keys
            agent_id = inputMsg.C2ProfileName + "_" + str(inputMsg.PayloadUUID)
            
            if agent_id not in self.agent_keys:
                response.Success = False
                response.Error = "No encryption keys found for agent"
                return response
                
            keys = self.agent_keys[agent_id]
            
            # Encrypt Mythic's JSON message
            json_data = json.dumps(inputMsg.Message).encode()
            
            # AES encryption
            cipher = AES.new(keys["enc_key"], AES.MODE_CBC)
            padded_data = pad(json_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Create custom message format
            custom_message = {
                "uuid": str(inputMsg.PayloadUUID),
                "iv": base64.b64encode(cipher.iv).decode(),
                "data": base64.b64encode(encrypted_data).decode()
            }
            
            response.Message = json.dumps(custom_message).encode()
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        try:
            # Parse incoming message from agent
            message_str = inputMsg.Message.decode() if isinstance(inputMsg.Message, bytes) else inputMsg.Message
            
            # Handle base64 encoded messages
            try:
                decoded_message = base64.b64decode(message_str).decode()
                message_json = json.loads(decoded_message)
            except:
                message_json = json.loads(message_str)
            
            agent_uuid = message_json.get("uuid")
            agent_id = inputMsg.C2ProfileName + "_" + agent_uuid
            
            if agent_id not in self.agent_keys:
                response.Success = False
                response.Error = "No decryption keys found for agent"
                return response
                
            keys = self.agent_keys[agent_id]
            
            # Decrypt the message if it contains encrypted data
            if "iv" in message_json and "data" in message_json:
                iv = base64.b64decode(message_json["iv"])
                encrypted_data = base64.b64decode(message_json["data"])
                
                cipher = AES.new(keys["dec_key"], AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                
                mythic_message = json.loads(decrypted_data.decode())
            else:
                # Handle unencrypted data (like initial checkin)
                mythic_message = message_json.get("data", message_json)
            
            response.Message = mythic_message
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            
        return response