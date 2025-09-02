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
    
    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        
        try:
            # Generate 32-byte AES key
            encryption_key = get_random_bytes(32)
            
            # Store keys for this agent using PayloadUUID only
            # Note: C2ProfileName is not available in generate_keys message
            agent_id = str(inputMsg.PayloadUUID)
            self.agent_keys[agent_id] = {
                "enc_key": encryption_key,
                "dec_key": encryption_key  # Same key for AES
            }
            
            response.EncryptionKey = encryption_key
            response.DecryptionKey = encryption_key
            
            print(f"Generated keys for agent: {agent_id}")
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            print(f"Error generating keys: {str(e)}")
            
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        
        try:
            # Use PayloadUUID to find keys (C2ProfileName is available here)
            agent_id = str(inputMsg.PayloadUUID)
            
            if agent_id not in self.agent_keys:
                # Try with C2ProfileName prefix if simple UUID lookup fails
                agent_id_with_profile = inputMsg.C2ProfileName + "_" + str(inputMsg.PayloadUUID)
                if agent_id_with_profile not in self.agent_keys:
                    response.Success = False
                    response.Error = f"No encryption keys found for agent {agent_id}"
                    print(f"Available agent keys: {list(self.agent_keys.keys())}")
                    return response
                else:
                    agent_id = agent_id_with_profile
                    
            keys = self.agent_keys[agent_id]
            
            # Check if Mythic is handling encryption
            if inputMsg.MythicEncrypts:
                # Mythic will encrypt our output, so just convert to bytes
                response.Message = json.dumps(inputMsg.Message).encode()
            else:
                # We need to encrypt the message ourselves
                json_data = json.dumps(inputMsg.Message).encode()
                
                # AES encryption
                cipher = AES.new(keys["enc_key"], AES.MODE_CBC)
                padded_data = pad(json_data, AES.block_size)
                encrypted_data = cipher.encrypt(padded_data)
                
                # Create custom message format that agent expects
                custom_message = str(inputMsg.PayloadUUID) + base64.b64encode(cipher.iv + encrypted_data).decode()
                response.Message = custom_message.encode()
            
            print(f"Translated message to C2 format for agent: {agent_id}")
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            print(f"Error translating to C2 format: {str(e)}")
            
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        
        try:
            # Parse incoming message from agent
            message_str = inputMsg.Message.decode() if isinstance(inputMsg.Message, bytes) else inputMsg.Message
            
            # Agent sends: UUID + base64(encrypted_data)
            # Extract UUID (first 36 characters typically)
            agent_uuid = None
            encrypted_part = None
            
            # Try to extract UUID from the message
            if len(message_str) > 36:
                potential_uuid = message_str[:36]
                encrypted_part = message_str[36:]
                agent_uuid = potential_uuid
            else:
                # Fallback: try to decode as base64 JSON
                try:
                    decoded_json = json.loads(base64.b64decode(message_str).decode())
                    agent_uuid = decoded_json.get("uuid")
                    encrypted_part = decoded_json.get("data")
                except:
                    pass
            
            if not agent_uuid:
                response.Success = False
                response.Error = "Could not extract agent UUID from message"
                return response
                
            # Find agent keys
            agent_id = agent_uuid
            if agent_id not in self.agent_keys:
                # Try with C2ProfileName prefix
                agent_id_with_profile = inputMsg.C2ProfileName + "_" + agent_uuid
                if agent_id_with_profile in self.agent_keys:
                    agent_id = agent_id_with_profile
                else:
                    response.Success = False
                    response.Error = f"No decryption keys found for agent {agent_uuid}"
                    print(f"Available agent keys: {list(self.agent_keys.keys())}")
                    return response
                    
            keys = self.agent_keys[agent_id]
            
            # Check if Mythic handled decryption
            if inputMsg.MythicEncrypts:
                # Mythic already decrypted, just parse JSON
                mythic_message = json.loads(inputMsg.Message.decode())
            else:
                # We need to decrypt the message ourselves
                try:
                    # Decode base64 encrypted data
                    encrypted_data = base64.b64decode(encrypted_part)
                    
                    # Extract IV (first 16 bytes) and ciphertext
                    iv = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]
                    
                    # Decrypt
                    cipher = AES.new(keys["dec_key"], AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    
                    mythic_message = json.loads(decrypted_data.decode())
                    
                except Exception as e:
                    response.Success = False
                    response.Error = f"Decryption failed: {str(e)}"
                    return response
            
            response.Message = mythic_message
            print(f"Translated message from C2 format for agent: {agent_id}")
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            print(f"Error translating from C2 format: {str(e)}")
            
        return response