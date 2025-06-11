import hmac
import hashlib
import time
import secrets
import json

class AuthProtocol:
    """Simple authentication protocol for CTF"""
    
    def __init__(self):
        # In a real scenario, this would be stored securely
        self.secret_key = b"CTF_CAN_GATEWAY_SECRET_2024"
        self.challenges = {}
        self.challenge_timeout = 300  # 5 minutes
        
    def generate_challenge(self):
        """Generate a random challenge for authentication"""
        challenge = secrets.token_hex(16)
        timestamp = time.time()
        
        self.challenges[challenge] = {
            'timestamp': timestamp,
            'used': False
        }
        
        # Clean up old challenges
        self.cleanup_challenges()
        
        return challenge
        
    def verify_response(self, response, challenge):
        """Verify the authentication response"""
        if challenge not in self.challenges:
            return False
            
        challenge_data = self.challenges[challenge]
        
        # Check if challenge is expired
        if time.time() - challenge_data['timestamp'] > self.challenge_timeout:
            return False
            
        # Check if challenge was already used
        if challenge_data['used']:
            return False
            
        # Calculate expected response
        expected = hmac.new(
            self.secret_key,
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if hmac.compare_digest(response, expected):
            # Mark challenge as used
            self.challenges[challenge]['used'] = True
            return True
            
        return False
        
    def cleanup_challenges(self):
        """Remove expired challenges"""
        current_time = time.time()
        expired = []
        
        for challenge, data in self.challenges.items():
            if current_time - data['timestamp'] > self.challenge_timeout:
                expired.append(challenge)
                
        for challenge in expired:
            del self.challenges[challenge]
            
    def get_auth_hint(self):
        """Provide hint for CTF players"""
        return {
            'hint': 'Authentication uses HMAC-SHA256',
            'format': 'hmac(secret_key, challenge)',
            'encoding': 'hex'
        }