from flask import Flask, jsonify, request
import subprocess
import random
import json
import os
import time
from threading import Timer

app = Flask(__name__)

# 설정
DOCKER_IMAGE_INFOTAINMENT = "ecu_infotainment:latest"
DOCKER_IMAGE_GATEWAY = "ecu_gateway:latest"
DOCKER_IMAGE_ENGINE = "ecu_engine:latest"
PORT_RANGE = (20000, 30000)
CONTAINER_TIMEOUT = 3600  # 1시간

# 활성 세션 관리
active_sessions = {}

def get_unused_port():
    used_ports = [session['port'] for session in active_sessions.values()]
    while True:
        port = random.randint(*PORT_RANGE)
        if port not in used_ports:
            return port

def cleanup_session(session_id):
    """세션 정리 (인포테인먼트 컨테이너만)"""
    if session_id in active_sessions:
        session = active_sessions[session_id]
        # 인포테인먼트 컨테이너만 정리 (공유 컨테이너는 유지)
        for container in session['containers']:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        del active_sessions[session_id]

# 공유 ECU 네트워크 (한 번만 생성)
SHARED_NETWORK = "ecu_shared_network"
SHARED_CONTAINERS = ["gateway_shared", "engine_shared"]

def ensure_shared_infrastructure():
    """공유 인프라스트럭처 확인 및 생성"""
    try:
        # 공유 네트워크 확인/생성
        result = subprocess.run(["docker", "network", "ls", "--filter", f"name={SHARED_NETWORK}"], 
                              capture_output=True, text=True)
        if SHARED_NETWORK not in result.stdout:
            subprocess.run([
                "docker", "network", "create", 
                "--driver", "bridge",
                SHARED_NETWORK
            ], check=True)
        
        # Gateway ECU 확인/생성
        result = subprocess.run(["docker", "ps", "-a", "--filter", f"name=gateway_shared"], 
                              capture_output=True, text=True)
        if "gateway_shared" not in result.stdout:
            subprocess.run([
                "docker", "run", "-d",
                "--name", "gateway_shared",
                "--network", SHARED_NETWORK,
                "--cap-add=NET_ADMIN",
                "--restart", "unless-stopped",
                DOCKER_IMAGE_GATEWAY
            ], check=True)
            
            # CAN 인터페이스 설정
            setup_can_interface("gateway_shared")
        
        # Engine ECU 확인/생성
        result = subprocess.run(["docker", "ps", "-a", "--filter", f"name=engine_shared"], 
                              capture_output=True, text=True)
        if "engine_shared" not in result.stdout:
            subprocess.run([
                "docker", "run", "-d",
                "--name", "engine_shared",
                "--network", SHARED_NETWORK,
                "--cap-add=NET_ADMIN",
                "--restart", "unless-stopped",
                DOCKER_IMAGE_ENGINE
            ], check=True)
            
            # CAN 인터페이스 설정
            setup_can_interface("engine_shared")
            
    except subprocess.CalledProcessError as e:
        print(f"Error setting up shared infrastructure: {e}")
        raise

def setup_can_interface(container_name):
    """컨테이너에 CAN 인터페이스 설정"""
    subprocess.run([
        "docker", "exec", container_name,
        "modprobe", "can"
    ], capture_output=True)
    subprocess.run([
        "docker", "exec", container_name,
        "modprobe", "can_raw"
    ], capture_output=True)
    subprocess.run([
        "docker", "exec", container_name,
        "modprobe", "vcan"
    ], capture_output=True)
    subprocess.run([
        "docker", "exec", container_name,
        "ip", "link", "add", "dev", "vcan0", "type", "vcan"
    ], capture_output=True)
    subprocess.run([
        "docker", "exec", container_name,
        "ip", "link", "set", "up", "vcan0"
    ], capture_output=True)

@app.route("/start", methods=["POST"])
def start_environment():
    session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
    port = get_unused_port()
    
    try:
        # 공유 인프라스트럭처 확인
        ensure_shared_infrastructure()
        
        # 인포테인먼트 ECU만 사용자별로 생성
        infotainment_name = f"infotainment_{session_id}"
        subprocess.run([
            "docker", "run", "-d",
            "--name", infotainment_name,
            "--network", SHARED_NETWORK,
            "--cap-add=NET_ADMIN",
            "-p", f"{port}:1234",
            DOCKER_IMAGE_INFOTAINMENT
        ], check=True)
        
        # 인포테인먼트 컨테이너에 CAN 인터페이스 설정
        setup_can_interface(infotainment_name)
        
        # 세션 정보 저장 (인포테인먼트 컨테이너만)
        active_sessions[session_id] = {
            'port': port,
            'containers': [infotainment_name],  # 인포테인먼트만 관리
            'created_at': time.time()
        }
        
        # 자동 정리 타이머 설정
        timer = Timer(CONTAINER_TIMEOUT, cleanup_session, [session_id])
        timer.start()
        
        return jsonify({
            "session_id": session_id,
            "host": "your.ctf.server",
            "port": port,
            "firmware_download": f"http://your.ctf.server:8080/firmware/{session_id}",
            "timeout": CONTAINER_TIMEOUT
        })
        
    except subprocess.CalledProcessError as e:
        # 오류시 생성된 리소스 정리
        cleanup_session(session_id)
        return jsonify({"error": "Failed to start environment"}), 500

@app.route("/firmware/<session_id>")
def download_firmware(session_id):
    """펌웨어 바이너리 다운로드"""
    if session_id not in active_sessions:
        return "Session not found", 404
    
    # 실제로는 미리 준비된 펌웨어 바이너리를 제공
    firmware_path = "/opt/ctf/firmware/infotainment_firmware.bin"
    if os.path.exists(firmware_path):
        return app.send_static_file(firmware_path)
    else:
        return "Firmware not found", 404

@app.route("/status/<session_id>")
def get_status(session_id):
    """세션 상태 확인"""
    if session_id not in active_sessions:
        return jsonify({"status": "not_found"}), 404
    
    session = active_sessions[session_id]
    uptime = time.time() - session['created_at']
    remaining = CONTAINER_TIMEOUT - uptime
    
    return jsonify({
        "status": "active",
        "uptime": int(uptime),
        "remaining_time": int(remaining),
        "port": session['port']
    })

@app.route("/admin/reset", methods=["POST"])
def reset_shared_infrastructure():
    """공유 인프라스트럭처 재시작 (관리자용)"""
    try:
        # 모든 사용자 세션 정리
        for session_id in list(active_sessions.keys()):
            cleanup_session(session_id)
        
        # 공유 컨테이너들 재시작
        for container in SHARED_CONTAINERS:
            subprocess.run(["docker", "restart", container], capture_output=True)
        
        return jsonify({"status": "success", "message": "Shared infrastructure reset"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # 서버 시작 시 공유 인프라스트럭처 초기화
    print("Initializing shared ECU infrastructure...")
    try:
        ensure_shared_infrastructure()
        print("Shared infrastructure ready")
    except Exception as e:
        print(f"Failed to initialize shared infrastructure: {e}")
        exit(1)
    
    app.run(host="0.0.0.0", port=8080)
