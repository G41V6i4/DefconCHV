#!/usr/bin/env python3
import unittest
import requests
import socket
import time
import subprocess

class ECUCTFIntegrationTest(unittest.TestCase):
    def setUp(self):
        """테스트 설정"""
        self.base_url = "http://localhost:8080"
        self.session_data = None
    
    def test_01_manager_health(self):
        """관리 서버 상태 확인"""
        try:
            response = requests.get(f"{self.base_url}/admin/status", timeout=5)
            self.assertEqual(response.status_code, 200)
            print("✓ Manager server is healthy")
        except Exception as e:
            self.fail(f"Manager server health check failed: {e}")
    
    def test_02_session_creation(self):
        """세션 생성 테스트"""
        response = requests.post(f"{self.base_url}/start")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn('session_id', data)
        self.assertIn('port', data)
        
        self.session_data = data
        print(f"✓ Session created: {data['session_id']}")
    
    def test_03_firmware_download(self):
        """펌웨어 다운로드 테스트"""
        if not self.session_data:
            self.skipTest("No session data available")
        
        response = requests.get(f"{self.base_url}/firmware/{self.session_data['session_id']}")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.content), 0)
        print("✓ Firmware download works")
    
    def test_04_infotainment_connection(self):
        """인포테인먼트 연결 테스트"""
        if not self.session_data:
            self.skipTest("No session data available")
        
        # 컨테이너 시작 대기
        time.sleep(15)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            result = sock.connect_ex(('localhost', self.session_data['port']))
            self.assertEqual(result, 0)
            print(f"✓ Infotainment connection successful on port {self.session_data['port']}")
        finally:
            sock.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)

