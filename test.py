#!/usr/bin/env python3

from pwn import *
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Any
from collections import defaultdict

context.log_level = 'debug'

@dataclass
class SessionInfo:
    session_id: str
    port: int
    firmware_url: str
    
@dataclass
class CANTestResult:
    session_id: str
    port: int
    success: bool
    sent_data: str
    received_responses: List[str] = field(default_factory=list)
    error_msg: str = ""

class MultiSessionCANTester:
    def __init__(self, api_url: str = "http://localhost:8080", num_sessions: int = 6):
        self.api_url = api_url
        self.num_sessions = num_sessions
        self.sessions = []
        self.all_responses = defaultdict(list)
        self.lock = threading.Lock()
        
    def create_sessions(self) -> List[SessionInfo]:
        print(f"Creating {self.num_sessions} sessions...")
        sessions = []
        
        for i in range(self.num_sessions):
            try:
                response = requests.post(f"{self.api_url}/start", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    session = SessionInfo(
                        session_id=data['session_id'],
                        port=data['infotainment_port'],
                        firmware_url=data['firmware_download']
                    )
                    sessions.append(session)
                    print(f"✅ Session {i+1}: {session.session_id} -> Port {session.port}")
                else:
                    print(f"❌ Failed to create session {i+1}: HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Session {i+1} creation error: {e}")
        
        return sessions
    
    def connect_to_ecu(self, port: int):
        try:
            conn = remote("localhost", port, timeout=10)
            response = conn.recvuntil(b'Choice:', timeout=10)
            print(response)
            print(f"[DEBUG] Port {port} - Menu: {response[-30:].decode(errors='ignore')}")
            
            hidden_options = [b"4", b"5", b"9", b"debug", b"dev", b"admin"]
            
            for option in hidden_options:
                print(f"[DEBUG] Port {port} - Trying: {option.decode()}")
                conn.sendline(option)
                time.sleep(1)
                
                try:
                    test_response = conn.recv(timeout=3)
                    response_text = test_response.decode(errors='ignore')
                    print(f"[DEBUG] Port {port} - Response: {response_text[:50]}")
                    
                    if '$' in response_text or '#' in response_text or 'shell' in response_text.lower():
                        print(f"[SUCCESS] Port {port} - Shell access with {option.decode()}")
                        return conn
                    
                    if 'invalid' not in response_text.lower() and 'error' not in response_text.lower():
                        conn.sendline(b"help")
                        time.sleep(1)
                        help_response = conn.recv(timeout=2).decode(errors='ignore')
                        print(f"[DEBUG] Port {port} - Help: {help_response[:30]}")
                        
                        if any(cmd in help_response.lower() for cmd in ['ls', 'echo', 'whoami']):
                            print(f"[SUCCESS] Port {port} - Commands available")
                            return conn
                    
                except Exception as e:
                    print(f"[DEBUG] Port {port} - No response to {option.decode()}")
                    continue
            
            print(f"[INFO] Port {port} - Using basic connection")
            return conn
            
        except Exception as e:
            print(f"[ERROR] Port {port} - Connection failed: {e}")
            return None
    
    def execute_command(self, conn, cmd):
        try:
            print(f"[CMD] Executing: {cmd}")
            conn.sendline(cmd.encode())
            time.sleep(1)
            result = conn.recv(timeout=3)
            output = result.decode(errors='ignore').strip()
            print(f"[CMD] Output: {output[:50]}...")
            return output
        except Exception as e:
            print(f"[CMD] Error: {e}")
            return ""
    
    def test_can_isolation(self, session: SessionInfo, test_value: int) -> CANTestResult:
        print(f"\n[TEST] {session.session_id} - Testing with value 0x{test_value:02X}")
        
        try:
            cmd_conn = self.connect_to_ecu(session.port)
            dump_conn = self.connect_to_ecu(session.port)
            
            if not cmd_conn or not dump_conn:
                return CANTestResult(
                    session_id=session.session_id,
                    port=session.port,
                    success=False,
                    sent_data="",
                    error_msg="Connection failed"
                )
            
            print(f"[INFO] {session.session_id} - Starting candump")
            dump_conn.sendline(b"candump vcan0 &")
            time.sleep(2)
            
            can_data = f"0227{test_value:02X}0000"
            can_message = f"cansend vcan0 7DF#{can_data}"
            
            print(f"[INFO] {session.session_id} - Sending: {can_message}")
            self.execute_command(cmd_conn, can_message)
            time.sleep(3)
            
            received_responses = []
            try:
                can_output = dump_conn.recv(timeout=5).decode(errors='ignore')
                print(f"[CAN] {session.session_id} - Output: {can_output[:100]}...")
                
                for line in can_output.split('\n'):
                    line = line.strip()
                    if 'vcan0' in line and ('7E8' in line or '7DF' in line):
                        received_responses.append(line)
                        print(f"[CAN] {session.session_id} - Received: {line}")
                        
                        with self.lock:
                            self.all_responses[session.session_id].append({
                                'line': line,
                                'test_value': test_value,
                                'timestamp': time.time()
                            })
                            
            except Exception as e:
                print(f"[ERROR] {session.session_id} - CAN receive error: {e}")
            
            cmd_conn.close()
            dump_conn.close()
            
            print(f"[SUCCESS] {session.session_id} - Test completed, {len(received_responses)} responses")
            
            return CANTestResult(
                session_id=session.session_id,
                port=session.port,
                success=True,
                sent_data=can_data,
                received_responses=received_responses
            )
            
        except Exception as e:
            print(f"[ERROR] {session.session_id} - Test failed: {e}")
            return CANTestResult(
                session_id=session.session_id,
                port=session.port,
                success=False,
                sent_data="",
                error_msg=str(e)
            )
    
    def analyze_isolation(self, results: List[CANTestResult]):
        print("\n" + "="*60)
        print("ISOLATION ANALYSIS")
        print("="*60)
        
        contamination_found = False
        unique_responses = True
        seen_responses = set()
        
        for result in results:
            if not result.success:
                continue
                
            print(f"\nSession: {result.session_id}")
            print(f"Sent: 7DF#{result.sent_data}")
            print(f"Responses: {len(result.received_responses)}")
            
            for response in result.received_responses:
                print(f"  - {response}")
                
                if '7E8#' in response:
                    hex_data = response.split('7E8#')[1].split()[0]
                    if hex_data in seen_responses:
                        print(f"  ❌ DUPLICATE RESPONSE: {hex_data}")
                        unique_responses = False
                    else:
                        seen_responses.add(hex_data)
            
            for other_session_id, other_responses in self.all_responses.items():
                if other_session_id != result.session_id:
                    for resp_data in other_responses:
                        if resp_data['test_value'] != int(result.sent_data[4:6], 16):
                            for own_resp in result.received_responses:
                                if resp_data['line'] in own_resp:
                                    print(f"  ⚠️  CONTAMINATION: Received {other_session_id}'s data")
                                    contamination_found = True
            
            if not contamination_found:
                print(f"  🔒 No contamination detected")
        
        return not contamination_found and unique_responses
    
    def run_test(self):
        print("ECU Multi-Session CAN Isolation Test")
        print("="*60)
        
        self.sessions = self.create_sessions()
        
        if len(self.sessions) < 2:
            print("❌ Need at least 2 sessions")
            return False
        
        print(f"\n✅ Created {len(self.sessions)} sessions")
        test_values = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        pause()
        with ThreadPoolExecutor(max_workers=len(self.sessions)) as executor:
            futures = []
            
            for i, session in enumerate(self.sessions):
                test_value = test_values[i % len(test_values)]
                future = executor.submit(self.test_can_isolation, session, test_value)
                futures.append(future)
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        print("\n" + "="*60)
        print("RESULTS SUMMARY")
        print("="*60)
        
        successful_tests = [r for r in results if r.success]
        failed_tests = [r for r in results if not r.success]
        
        print(f"Total sessions: {len(results)}")
        print(f"Successful tests: {len(successful_tests)}")
        print(f"Failed tests: {len(failed_tests)}")
        
        if failed_tests:
            print("\nFailed sessions:")
            for result in failed_tests:
                print(f"  - {result.session_id}: {result.error_msg}")
        
        if len(successful_tests) >= 2:
            isolation_passed = self.analyze_isolation(results)
            
            print("\n" + "="*60)
            print("FINAL VERDICT")
            print("="*60)
            
            if isolation_passed:
                print("🟢 ISOLATION TEST: PASSED")
                print("✅ Each session receives unique responses")
                print("✅ No cross-contamination detected")
                return True
            else:
                print("🔴 ISOLATION TEST: FAILED")
                print("❌ Isolation breach detected")
                return False
        else:
            print("🟡 INSUFFICIENT DATA")
            print("⚠️  Need at least 2 successful sessions")
            return False

def main():
    tester = MultiSessionCANTester()
    
    try:
        success = tester.run_test()
        if success:
            print("\n🏆 CAN isolation working correctly!")
        else:
            print("\n💥 CAN isolation compromised!")
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")

if __name__ == "__main__":
    main()