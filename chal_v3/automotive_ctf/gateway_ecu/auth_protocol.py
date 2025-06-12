import hmac
import hashlib
import time
import secrets

class AuthProtocol:
    def __init__(self):
        self.secret_key = b"CTF_CAN_GATEWAY_SECRET_2024"
        self.challenges = {}
        
    def generate_challenge(self):
        challenge = secrets.token_hex(16)
        self.challenges[challenge] = time.time()
        return challenge
        
    def verify_response(self, response, challenge):
        if challenge not in self.challenges:
            return False
            
        expected = hmac.new(
            self.secret_key,
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(response, expected)
