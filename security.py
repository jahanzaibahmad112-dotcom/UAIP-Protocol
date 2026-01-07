import nacl.signing
import nacl.encoding
import json
import time

class UAIPSecurity:
    """Handles Identity and Tamper-Proof Signatures."""
    
    @staticmethod
    def generate_keys():
        signing_key = nacl.signing.SigningKey.generate()
        verify_key = signing_key.verify_key
        return signing_key.encode(nacl.encoding.HexEncoder).decode(), verify_key.encode(nacl.encoding.HexEncoder).decode()

    @staticmethod
    def sign_packet(payload, private_key_hex):
        signing_key = nacl.signing.SigningKey(private_key_hex, encoder=nacl.encoding.HexEncoder)
        payload['timestamp'] = time.time()
        message = json.dumps(payload, sort_keys=True).encode('utf-8')
        signed = signing_key.sign(message)
        return signed.signature.hex()

    @staticmethod
    def verify_packet(payload, signature_hex, public_key_hex):
        try:
            verify_key = nacl.signing.VerifyKey(public_key_hex, encoder=nacl.encoding.HexEncoder)
            message = json.dumps(payload, sort_keys=True).encode('utf-8')
            verify_key.verify(message, bytes.fromhex(signature_hex))
            
            # Replay protection: packet must be under 60 seconds old
            if time.time() - payload.get('timestamp', 0) > 60:
                return False
            return True
        except Exception:
            return False