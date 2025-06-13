from flask import Flask, jsonify, request, Response
import subprocess
import random
import json
import os
import time
import socket
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

def get_can_broker_host():
    """CAN 브로커 호스트 주소 반환"""
    # Flask 앱이 같은 Docker 네트워크에 있는지 확인
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('gateway_shared', 9999))
        sock.close()
        if result == 0:
            return 'gateway_shared'
    except:
        pass
    
    # 호스트에서 실행 중이면 localhost 사용
    return 'localhost'
    """CAN 브로커가 준비될 때까지 대기"""
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Flask 앱이 컨테이너에서 실행 중인지 호스트에서 실행 중인지 확인
            try:
                # 먼저 컨테이너 이름으로 시도 (Flask가 같은 네트워크의 컨테이너에서 실행될 때)
                result = sock.connect_ex(('gateway_shared', 9999))
                if result == 0:
                    sock.close()
                    print("CAN broker is ready (container network)")
                    return True
            except:
                pass
            
            sock.close()
            
            # 컨테이너 이름 연결 실패 시 localhost 시도 (Flask가 호스트에서 실행될 때)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', 9999))
                sock.close()
                
                if result == 0:
                    print("CAN broker is ready (localhost)")
                    return True
            except:
                pass
                
        except Exception:
            pass
            
        time.sleep(1)
        
    print("CAN broker failed to start")
    return False
def wait_for_can_broker():
    """CAN 브로커가 준비될 때까지 대기"""
    broker_host = get_can_broker_host()
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((broker_host, 9999))
            sock.close()
            
            if result == 0:
                print("CAN broker is ready")
                return True
                
        except Exception:
            pass
            
        time.sleep(1)
        
    print("CAN broker failed to start")
    return False
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
        
        # Gateway ECU 확인/생성 (CAN 브로커 포함)
        result = subprocess.run(["docker", "ps", "-a", "--filter", f"name=gateway_shared"], 
                              capture_output=True, text=True)
        if "gateway_shared" not in result.stdout:
            subprocess.run([
                "docker", "run", "-d",
                "--name", "gateway_shared",
                "--network", SHARED_NETWORK,
                "--restart", "unless-stopped",
                "-p", "9999:9999",  # CAN 브로커 포트 노출
                DOCKER_IMAGE_GATEWAY
            ], check=True)
        else:
            # 컨테이너가 중지되어 있다면 시작
            subprocess.run(["docker", "start", "gateway_shared"], capture_output=True)
        
        # Engine ECU 확인/생성
        result = subprocess.run(["docker", "ps", "-a", "--filter", f"name=engine_shared"], 
                              capture_output=True, text=True)
        if "engine_shared" not in result.stdout:
            subprocess.run([
                "docker", "run", "-d",
                "--name", "engine_shared",
                "--network", SHARED_NETWORK,
                "--restart", "unless-stopped",
                DOCKER_IMAGE_ENGINE
            ], check=True)
        else:
            # 컨테이너가 중지되어 있다면 시작
            subprocess.run(["docker", "start", "engine_shared"], capture_output=True)
            
    except subprocess.CalledProcessError as e:
        print(f"Error setting up shared infrastructure: {e}")
        raise

@app.route("/start", methods=["POST"])
def start_environment():
    session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
    port = get_unused_port()
    
    try:
        # 공유 인프라스트럭처 확인
        ensure_shared_infrastructure()
        
        # CAN 브로커가 준비될 때까지 대기
        if not wait_for_can_broker():
            return jsonify({"error": "CAN broker failed to start"}), 500
        
        # 인포테인먼트 ECU만 사용자별로 생성
        infotainment_name = f"infotainment_{session_id}"
        subprocess.run([
            "docker", "run", "-d",
            "--name", infotainment_name,
            "--network", SHARED_NETWORK,
            "-p", f"{port}:1234",
            "-e", f"SESSION_ID={session_id}",  # 세션 ID 환경변수로 전달
            DOCKER_IMAGE_INFOTAINMENT
        ], check=True)
        
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
            "infotainment_host": "localhost",  # 실제로는 서버 IP
            "infotainment_port": port,
            "firmware_download": f"http://localhost:8080/firmware/{session_id}",
            "timeout": CONTAINER_TIMEOUT,
            "instructions": {
                "step1": "Download and analyze firmware",
                "step2": f"Connect to infotainment: nc localhost {port}",
                "step3": "Find debug mode and enable developer commands",
                "step4": "Use custom CAN tools: cansend/candump vcan0",
                "step5": "Authenticate with gateway and access engine ECU"
            }
        })
        
    except subprocess.CalledProcessError as e:
        # 오류시 생성된 리소스 정리
        cleanup_session(session_id)
        return jsonify({"error": f"Failed to start environment: {str(e)}"}), 500

@app.route("/firmware/<session_id>")
def download_firmware(session_id):
    """펌웨어 바이너리 다운로드"""
    if session_id not in active_sessions:
        return "Session not found", 404
    
    # 취약한 펌웨어 바이너리 생성 (실제 CTF에서는 미리 준비)
    firmware_content = f"""
INFOTAINMENT_FIRMWARE_V1.2.3
BUILD_DATE: 2024-12-01
DEBUG_MODE_DISABLED
hidden_debug_string: debug_enable_dev_mode
MANUFACTURER: SecureAuto Corp
admin_backdoor_cmd: dev_shell
buffer_overflow_test: {"A" * 100}
encryption_key: DEADBEEF
session_id: {session_id}
""".encode()
    
    response = app.response_class(
        firmware_content,
        mimetype='application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename=infotainment_{session_id}.bin'
        }
    )
    return response

@app.route("/status/<session_id>")
def get_status(session_id):
    """세션 상태 확인"""
    if session_id not in active_sessions:
        return jsonify({"status": "not_found"}), 404
    
    session = active_sessions[session_id]
    uptime = time.time() - session['created_at']
    remaining = CONTAINER_TIMEOUT - uptime
    
    # 컨테이너 상태 확인
    container_status = {}
    for container in session['containers']:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True
        )
        container_status[container] = result.stdout.strip() if result.returncode == 0 else "not_found"
    
    return jsonify({
        "status": "active",
        "uptime": int(uptime),
        "remaining_time": int(remaining),
        "infotainment_port": session['port'],
        "containers": container_status,
        "can_broker_status": "running" if wait_for_can_broker() else "down"
    })

@app.route("/admin/sessions")
def list_sessions():
    """활성 세션 목록 (관리자용)"""
    sessions_info = {}
    for session_id, session in active_sessions.items():
        uptime = time.time() - session['created_at']
        remaining = CONTAINER_TIMEOUT - uptime
        sessions_info[session_id] = {
            "port": session['port'],
            "uptime": int(uptime),
            "remaining": int(remaining),
            "containers": session['containers']
        }
    
    return jsonify({
        "active_sessions": len(active_sessions),
        "sessions": sessions_info
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
        
        # CAN 브로커 준비 대기
        if wait_for_can_broker():
            return jsonify({"status": "success", "message": "Shared infrastructure reset"})
        else:
            return jsonify({"status": "warning", "message": "Infrastructure reset but CAN broker not responding"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/admin/logs/<container_name>")
def get_container_logs(container_name):
    """컨테이너 로그 조회 (관리자용)"""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "100", container_name],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            return jsonify({
                "status": "success",
                "logs": result.stdout
            })
        else:
            return jsonify({
                "status": "error", 
                "message": "Container not found or access denied"
            }), 404
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/health")
def health_check():
    """서비스 헬스 체크"""
    try:
        # Docker 상태 확인
        result = subprocess.run(["docker", "version"], capture_output=True)
        docker_ok = result.returncode == 0
        
        # 공유 인프라 상태 확인
        shared_containers_status = {}
        for container in SHARED_CONTAINERS:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container],
                capture_output=True, text=True
            )
            shared_containers_status[container] = result.stdout.strip() if result.returncode == 0 else "not_found"
        
        # CAN 브로커 상태
        can_broker_ok = wait_for_can_broker()
        
        return jsonify({
            "status": "healthy" if docker_ok and can_broker_ok else "degraded",
            "docker": "ok" if docker_ok else "error",
            "can_broker": "ok" if can_broker_ok else "error", 
            "shared_containers": shared_containers_status,
            "active_sessions": len(active_sessions)
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# CAN 브로커 모니터링 관련 엔드포인트들

@app.route("/admin/can_broker/status")
def can_broker_status():
    """CAN 브로커 상태 확인"""
    try:
        # CAN 브로커에 상태 요청
        broker_host = get_can_broker_host()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # 브로커 연결 테스트
        result = sock.connect_ex((broker_host, 9999))
        sock.close()
        
        if result == 0:
            broker_status = "running"
        else:
            broker_status = "down"
        
        # 게이트웨이 컨테이너 상태
        gateway_result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", "gateway_shared"],
            capture_output=True, text=True
        )
        gateway_status = gateway_result.stdout.strip() if gateway_result.returncode == 0 else "not_found"
        
        return jsonify({
            "broker_status": broker_status,
            "gateway_container": gateway_status,
            "broker_host": broker_host,
            "port": 9999
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "broker_status": "error"
        }), 500

@app.route("/admin/can_broker/logs")
def can_broker_logs():
    """CAN 브로커 로그 조회"""
    try:
        # 컨테이너 로그 조회
        result = subprocess.run(
            ["docker", "logs", "--tail", "200", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            logs = result.stdout.split('\n')
            
            # CAN 브로커 관련 로그만 필터링
            broker_logs = []
            for line in logs:
                if any(keyword in line for keyword in ['CANBroker', 'CAN Broker', 'Session', 'Gateway auth', 'Routing', 'CAN message']):
                    broker_logs.append(line)
            
            return jsonify({
                "status": "success",
                "logs": broker_logs[-100:],  # 최근 100줄
                "total_lines": len(broker_logs)
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get container logs",
                "error": result.stderr
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e)
        }), 500

@app.route("/admin/can_broker/logs/live")
def can_broker_logs_live():
    """실시간 CAN 브로커 로그 (SSE)"""
    def generate_logs():
        try:
            # docker logs -f로 실시간 로그 스트리밍
            process = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "50", "gateway_shared"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            for line in iter(process.stdout.readline, ''):
                if any(keyword in line for keyword in ['CANBroker', 'CAN Broker', 'Session', 'Gateway auth', 'Routing', 'CAN message']):
                    yield f"data: {json.dumps({'log': line.strip(), 'timestamp': time.time()})}\n\n"
                    
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(generate_logs(), mimetype='text/event-stream')

@app.route("/admin/can_broker/sessions")
def can_broker_sessions():
    """활성 CAN 세션 목록"""
    try:
        # 간접적으로 세션 정보 수집 (로그 파싱)
        result = subprocess.run(
            ["docker", "logs", "--tail", "100", "gateway_shared"],
            capture_output=True, text=True
        )
        
        sessions = {}
        auth_sessions = set()
        
        if result.returncode == 0:
            logs = result.stdout.split('\n')
            
            for line in logs:
                # 연결된 세션 파싱
                if "connected from" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.startswith("session_"):
                            session_id = part
                            if i+1 < len(parts):
                                session_type = parts[i+1].strip("()")
                                sessions[session_id] = {
                                    "type": session_type,
                                    "status": "connected"
                                }
                
                # 인증된 세션 파싱
                if "authenticated successfully" in line:
                    for part in line.split():
                        if part.startswith("session_"):
                            auth_sessions.add(part)
        
        # 인증 상태 업데이트
        for session_id in auth_sessions:
            if session_id in sessions:
                sessions[session_id]["authenticated"] = True
        
        return jsonify({
            "status": "success",
            "active_sessions": len(sessions),
            "authenticated_sessions": len(auth_sessions),
            "sessions": sessions
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/can_broker/traffic")
def can_broker_traffic():
    """CAN 메시지 트래픽 통계"""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "500", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            logs = result.stdout.split('\n')
            
            traffic_stats = {
                "total_messages": 0,
                "auth_attempts": 0,
                "engine_forwards": 0,
                "unauthorized_attempts": 0,
                "message_types": {}
            }
            
            for line in logs:
                if "CAN message from" in line:
                    traffic_stats["total_messages"] += 1
                    
                    # CAN ID 추출
                    if "ID=0x" in line:
                        try:
                            can_id = line.split("ID=0x")[1].split(",")[0][:3]
                            if can_id in traffic_stats["message_types"]:
                                traffic_stats["message_types"][can_id] += 1
                            else:
                                traffic_stats["message_types"][can_id] = 1
                        except:
                            pass
                
                if "Gateway authentication request" in line:
                    traffic_stats["auth_attempts"] += 1
                
                if "Forwarding to engine ECU" in line:
                    traffic_stats["engine_forwards"] += 1
                
                if "Unauthorized engine access" in line:
                    traffic_stats["unauthorized_attempts"] += 1
            
            return jsonify({
                "status": "success",
                "traffic": traffic_stats
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get traffic stats"
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/can_broker/debug/<session_id>")
def can_broker_debug_session(session_id):
    """특정 세션 디버그 정보"""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "1000", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            logs = result.stdout.split('\n')
            
            session_logs = []
            session_info = {
                "session_id": session_id,
                "connected": False,
                "authenticated": False,
                "message_count": 0,
                "last_activity": None,
                "auth_attempts": 0
            }
            
            for line in logs:
                if session_id in line:
                    session_logs.append(line)
                    
                    if "connected from" in line:
                        session_info["connected"] = True
                    
                    if "authenticated successfully" in line:
                        session_info["authenticated"] = True
                    
                    if "CAN message from" in line:
                        session_info["message_count"] += 1
                    
                    if "Gateway authentication request" in line:
                        session_info["auth_attempts"] += 1
                    
                    # 타임스탬프 추출
                    if line.startswith("20"):  # 로그 타임스탬프
                        try:
                            session_info["last_activity"] = line.split()[0] + " " + line.split()[1]
                        except:
                            pass
            
            return jsonify({
                "status": "success",
                "session_info": session_info,
                "logs": session_logs[-50:],  # 최근 50개 로그
                "total_logs": len(session_logs)
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get session logs"
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/can_broker/restart", methods=["POST"])
def restart_can_broker():
    """CAN 브로커 재시작"""
    try:
        # 게이트웨이 컨테이너 재시작
        result = subprocess.run(
            ["docker", "restart", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            # 브로커가 준비될 때까지 대기
            time.sleep(3)
            
            if wait_for_can_broker():
                return jsonify({
                    "status": "success",
                    "message": "CAN broker restarted successfully"
                })
            else:
                return jsonify({
                    "status": "warning", 
                    "message": "Container restarted but broker not responding"
                }), 500
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to restart container",
                "error": result.stderr
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/can_broker/dashboard")
def can_broker_dashboard():
    """CAN 브로커 모니터링 대시보드"""
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>CAN Broker Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .status-card { 
            border: 1px solid #ddd; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px; 
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .status-ok { border-left: 5px solid #28a745; }
        .status-error { border-left: 5px solid #dc3545; }
        .logs { 
            height: 400px; 
            overflow-y: scroll; 
            border: 1px solid #ccc; 
            padding: 10px; 
            background-color: #f8f9fa; 
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
        }
        .refresh-btn { 
            background-color: #007bff; 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            cursor: pointer; 
            border-radius: 3px;
            margin-bottom: 10px;
        }
        .refresh-btn:hover { background-color: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .metric { display: inline-block; margin-right: 20px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚗 CAN Broker Dashboard</h1>
        
        <div class="status-card" id="status-card">
            <h3>🔧 Broker Status</h3>
            <div id="broker-status">Loading...</div>
        </div>
        
        <div class="status-card">
            <h3>👥 Active Sessions</h3>
            <div id="sessions-info">Loading...</div>
        </div>
        
        <div class="status-card">
            <h3>📊 Traffic Statistics</h3>
            <div id="traffic-stats">Loading...</div>
        </div>
        
        <div class="status-card">
            <h3>📝 Recent Logs</h3>
            <button class="refresh-btn" onclick="refreshLogs()">🔄 Refresh Logs</button>
            <button class="refresh-btn" onclick="toggleLiveMode()">📡 Live Mode</button>
            <div class="logs" id="logs-container">Loading...</div>
        </div>
    </div>
    
    <script>
        let liveMode = false;
        let eventSource = null;
        
        function updateStatus() {
            fetch('/admin/can_broker/status')
                .then(response => response.json())
                .then(data => {
                    const statusCard = document.getElementById('status-card');
                    const statusDiv = document.getElementById('broker-status');
                    
                    if (data.broker_status === 'running') {
                        statusCard.className = 'status-card status-ok';
                        statusDiv.innerHTML = `
                            <div class="metric">
                                <div class="metric-value">✅</div>
                                <div class="metric-label">Broker Running</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${data.gateway_container}</div>
                                <div class="metric-label">Container Status</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${data.port}</div>
                                <div class="metric-label">Port</div>
                            </div>
                        `;
                    } else {
                        statusCard.className = 'status-card status-error';
                        statusDiv.innerHTML = `
                            <div class="metric">
                                <div class="metric-value">❌</div>
                                <div class="metric-label">Broker ${data.broker_status}</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${data.gateway_container}</div>
                                <div class="metric-label">Container Status</div>
                            </div>
                        `;
                    }
                })
                .catch(error => {
                    console.error('Error updating status:', error);
                });
        }
        
        function updateSessions() {
            fetch('/admin/can_broker/sessions')
                .then(response => response.json())
                .then(data => {
                    const sessionsDiv = document.getElementById('sessions-info');
                    
                    if (data.status === 'success') {
                        let html = `
                            <div class="metric">
                                <div class="metric-value">${data.active_sessions}</div>
                                <div class="metric-label">Active Sessions</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${data.authenticated_sessions}</div>
                                <div class="metric-label">Authenticated</div>
                            </div>
                        `;
                        
                        if (Object.keys(data.sessions).length > 0) {
                            html += '<table><tr><th>Session ID</th><th>Type</th><th>Status</th></tr>';
                            for (const [sessionId, info] of Object.entries(data.sessions)) {
                                const authStatus = info.authenticated ? '🔓 Authenticated' : '🔒 Not Authenticated';
                                html += `<tr><td>${sessionId}</td><td>${info.type}</td><td>${authStatus}</td></tr>`;
                            }
                            html += '</table>';
                        }
                        
                        sessionsDiv.innerHTML = html;
                    } else {
                        sessionsDiv.innerHTML = `<p>❌ Error: ${data.message}</p>`;
                    }
                })
                .catch(error => {
                    console.error('Error updating sessions:', error);
                });
        }
        
        function updateTraffic() {
            fetch('/admin/can_broker/traffic')
                .then(response => response.json())
                .then(data => {
                    const trafficDiv = document.getElementById('traffic-stats');
                    
                    if (data.status === 'success') {
                        const stats = data.traffic;
                        let html = `
                            <div class="metric">
                                <div class="metric-value">${stats.total_messages}</div>
                                <div class="metric-label">Total Messages</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${stats.auth_attempts}</div>
                                <div class="metric-label">Auth Attempts</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${stats.engine_forwards}</div>
                                <div class="metric-label">Engine Forwards</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${stats.unauthorized_attempts}</div>
                                <div class="metric-label">Unauthorized</div>
                            </div>
                        `;
                        
                        if (Object.keys(stats.message_types).length > 0) {
                            html += '<h4>📨 Message Types:</h4><ul>';
                            for (const [canId, count] of Object.entries(stats.message_types)) {
                                html += `<li><strong>0x${canId}:</strong> ${count} messages</li>`;
                            }
                            html += '</ul>';
                        }
                        
                        trafficDiv.innerHTML = html;
                    } else {
                        trafficDiv.innerHTML = `<p>❌ Error: ${data.message}</p>`;
                    }
                })
                .catch(error => {
                    console.error('Error updating traffic:', error);
                });
        }
        
        function refreshLogs() {
            if (liveMode) return;
            
            fetch('/admin/can_broker/logs')
                .then(response => response.json())
                .then(data => {
                    const logsDiv = document.getElementById('logs-container');
                    
                    if (data.status === 'success') {
                        logsDiv.innerHTML = data.logs.join('\\n');
                        logsDiv.scrollTop = logsDiv.scrollHeight;
                    } else {
                        logsDiv.innerHTML = `❌ Error: ${data.message}`;
                    }
                })
                .catch(error => {
                    console.error('Error refreshing logs:', error);
                });
        }
        
        function toggleLiveMode() {
            const logsDiv = document.getElementById('logs-container');
            
            if (!liveMode) {
                // 라이브 모드 시작
                liveMode = true;
                eventSource = new EventSource('/admin/can_broker/logs/live');
                logsDiv.innerHTML = '📡 Live mode started...\\n';
                
                eventSource.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.log) {
                        logsDiv.innerHTML += data.log + '\\n';
                        logsDiv.scrollTop = logsDiv.scrollHeight;
                    } else if (data.error) {
                        logsDiv.innerHTML += '❌ Error: ' + data.error + '\\n';
                    }
                };
                
                eventSource.onerror = function(event) {
                    console.error('EventSource error:', event);
                    liveMode = false;
                    eventSource.close();
                };
                
            } else {
                // 라이브 모드 종료
                liveMode = false;
                if (eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                logsDiv.innerHTML += '\\n📡 Live mode stopped.\\n';
            }
        }
        
        // 자동 새로고침 (라이브 모드가 아닐 때만)
        setInterval(() => {
            if (!liveMode) {
                updateStatus();
                updateSessions();
                updateTraffic();
            }
        }, 5000);
        
        // 초기 로드
        updateStatus();
        updateSessions();
        updateTraffic();
        refreshLogs();
    </script>
</body>
</html>
    """
    
    return Response(html_content, mimetype='text/html')

if __name__ == "__main__":
    # 서버 시작 시 공유 인프라스트럭처 초기화
    print("Initializing shared ECU infrastructure...")
    try:
        ensure_shared_infrastructure()
        if wait_for_can_broker():
            print("Shared infrastructure ready")
        else:
            print("Warning: CAN broker not responding")
    except Exception as e:
        print(f"Failed to initialize shared infrastructure: {e}")
        exit(1)
    
    app.run(host="0.0.0.0", port=8080, debug=True)