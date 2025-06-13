#!/usr/bin/env python3
"""
게이트웨이 ECU - 인증 및 메시지 필터링
"""
import time
import threading
import struct

class GatewayECU:
    def __init__(self):
        self.authenticated_sessions = {}
        
    def start(self):
        print("Gateway ECU started")
        # 실제로는 CAN 브로커가 인증 로직을 처리
        # 이 서비스는 추가적인 게이트웨이 기능을 담당
        
        while True:
            time.sleep(1)
            self.cleanup_expired_sessions()
    
    def cleanup_expired_sessions(self):
        """만료된 세션 정리"""
        current_time = time.time()
        expired = []
        
        for session_id, auth_time in self.authenticated_sessions.items():
            if current_time - auth_time > 300:  # 5분 타임아웃
                expired.append(session_id)
        
        for session_id in expired:
            del self.authenticated_sessions[session_id]
            print(f"Session {session_id} expired")

if __name__ == "__main__":
    gateway = GatewayECU()
    gateway.start()
