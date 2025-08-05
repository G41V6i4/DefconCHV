from flask import Flask, jsonify, request, Response, render_template, session, redirect, url_for
import subprocess
import random
import json
import os
import time
import socket
import secrets
import hashlib
import hmac
from threading import Timer
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)

# 보안 설정
app.secret_key = secrets.token_hex(32)  # 랜덤 시크릿 키 생성
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS에서만 쿠키 전송
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript에서 쿠키 접근 불가
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF 보호
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30분 세션 타임아웃

# Rate limiting 설정
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # 메모리 기반 (프로덕션에서는 Redis 사용 권장)
)
limiter.init_app(app)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('admin_access.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 설정
DOCKER_IMAGE_INFOTAINMENT = "ecu_infotainment:latest"
DOCKER_IMAGE_GATEWAY = "ecu_gateway:latest"
DOCKER_IMAGE_ENGINE = "ecu_engine:latest"
PORT_RANGE = (20000, 30000)
CONTAINER_TIMEOUT = 3600  # 1시간

# 어드민 계정 설정 (환경변수에서 읽기, 없으면 기본값)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', 
    generate_password_hash('SecureAdmin2024!@#'))  # 기본 비밀번호, 프로덕션에서는 반드시 변경

# 활성 세션 관리
active_sessions = {}
failed_login_attempts = {}  # IP별 로그인 실패 횟수 추적
admin_sessions = {}  # 어드민 세션 관리

# 보안 함수들
def generate_csrf_token():
    """CSRF 토큰 생성"""
    return secrets.token_hex(32)

def verify_csrf_token(token):
    """CSRF 토큰 검증"""
    stored_token = session.get('csrf_token')
    return stored_token and hmac.compare_digest(stored_token, token)

def is_ip_blocked(ip):
    """IP가 차단되었는지 확인"""
    if ip not in failed_login_attempts:
        return False
    
    attempts = failed_login_attempts[ip]
    if attempts['count'] >= 5:  # 5회 실패시 차단
        # 30분 차단
        if time.time() - attempts['last_attempt'] < 1800:
            return True
        else:
            # 차단 시간 만료, 카운터 리셋
            failed_login_attempts[ip] = {'count': 0, 'last_attempt': time.time()}
            return False
    return False

def record_failed_login(ip):
    """로그인 실패 기록"""
    if ip not in failed_login_attempts:
        failed_login_attempts[ip] = {'count': 0, 'last_attempt': time.time()}
    
    failed_login_attempts[ip]['count'] += 1
    failed_login_attempts[ip]['last_attempt'] = time.time()
    
    logger.warning(f"Failed login attempt from IP: {ip}, attempt count: {failed_login_attempts[ip]['count']}")

def clear_failed_login(ip):
    """로그인 성공시 실패 기록 초기화"""
    if ip in failed_login_attempts:
        del failed_login_attempts[ip]

def require_admin_auth(f):
    """어드민 인증 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # IP 차단 확인
        client_ip = get_remote_address()
        if is_ip_blocked(client_ip):
            logger.warning(f"Blocked IP {client_ip} attempted to access admin area")
            return jsonify({"error": "IP blocked due to too many failed attempts"}), 429
        
        # 세션 확인
        if 'admin_authenticated' not in session or not session['admin_authenticated']:
            logger.warning(f"Unauthorized admin access attempt from IP: {client_ip}")
            return redirect(url_for('admin_login'))
        
        # 세션 타임아웃 확인
        if 'last_activity' in session:
            if time.time() - session['last_activity'] > 1800:  # 30분
                session.clear()
                logger.info(f"Admin session expired for IP: {client_ip}")
                return redirect(url_for('admin_login'))
        
        # 활동 시간 업데이트
        session['last_activity'] = time.time()
        session.permanent = True
        
        return f(*args, **kwargs)
    return decorated_function

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

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # 로그인 시도 제한
def admin_login():
    """어드민 로그인 페이지"""
    client_ip = get_remote_address()
    
    # IP 차단 확인
    if is_ip_blocked(client_ip):
        logger.warning(f"Blocked IP {client_ip} attempted to access login page")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Blocked</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f8f9fa; }
                .error { color: #dc3545; font-size: 1.2rem; }
            </style>
        </head>
        <body>
            <div class="error">
                <h2>🚫 Access Blocked</h2>
                <p>Your IP has been temporarily blocked due to too many failed login attempts.</p>
                <p>Please try again in 30 minutes.</p>
            </div>
        </body>
        </html>
        """), 429
    
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_token = request.form.get('csrf_token', '')
        
        # CSRF 토큰 검증
        if not verify_csrf_token(csrf_token):
            logger.warning(f"CSRF token validation failed from IP: {client_ip}")
            record_failed_login(client_ip)
            return render_template('admin_login.html', 
                error="Security token validation failed", csrf_token=generate_csrf_token()), 400
        
        # 입력 검증
        if not username or not password:
            logger.warning(f"Empty credentials from IP: {client_ip}")
            record_failed_login(client_ip)
            return render_template('admin_login.html', 
                error="Username and password are required", csrf_token=generate_csrf_token()), 400
        
        # 인증 확인
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            # 로그인 성공
            session['admin_authenticated'] = True
            session['admin_username'] = username
            session['last_activity'] = time.time()
            session['csrf_token'] = generate_csrf_token()
            session.permanent = True
            
            clear_failed_login(client_ip)
            logger.info(f"Successful admin login from IP: {client_ip}, username: {username}")
            
            return redirect(url_for('admin_dashboard'))
        else:
            # 로그인 실패
            record_failed_login(client_ip)
            logger.warning(f"Invalid credentials from IP: {client_ip}, username: {username}")
            
            return render_template('admin_login.html', 
                error="Invalid username or password", csrf_token=generate_csrf_token()), 401
    
    # GET 요청 - 로그인 폼 표시
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    
    return render_template('admin_login.html', csrf_token=csrf_token)


@app.route("/admin/logout", methods=["POST"])
@require_admin_auth
def admin_logout():
    """어드민 로그아웃"""
    client_ip = get_remote_address()
    admin_username = session.get('admin_username', 'unknown')
    
    logger.info(f"Admin logout: {admin_username} from IP: {client_ip}")
    
    session.clear()
    return redirect(url_for('admin_login'))

@app.route("/admin")
@require_admin_auth
def admin_dashboard():
    """관리자 대시보드"""
    html_content = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefCon CHV Admin Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f6fa;
            color: #2c3e50;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .container { 
            max-width: 1200px; 
            margin: 20px auto; 
            padding: 0 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }
        .stat-label {
            font-size: 1.1rem;
            color: #666;
        }
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        .panel {
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .panel-header {
            background: #34495e;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-body {
            padding: 20px;
        }
        .session-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: grid;
            grid-template-columns: 1fr auto auto;
            align-items: center;
            gap: 15px;
        }
        .session-item:last-child {
            border-bottom: none;
        }
        .session-id {
            font-family: monospace;
            font-weight: bold;
            color: #2c3e50;
        }
        .session-details {
            font-size: 0.9rem;
            color: #666;
        }
        .status-badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-running {
            background: #d4edda;
            color: #155724;
        }
        .status-error {
            background: #f8d7da;
            color: #721c24;
        }
        .btn {
            padding: 8px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: #3498db;
            color: white;
        }
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        .logs-container {
            height: 400px;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            font-family: monospace;
            font-size: 0.8rem;
            overflow-y: auto;
            border-radius: 5px;
        }
        .log-entry {
            margin-bottom: 5px;
            line-height: 1.4;
        }
        .log-error { color: #e74c3c; }
        .log-info { color: #3498db; }
        .log-success { color: #27ae60; }
        .refresh-btn {
            background: #27ae60;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-bottom: 15px;
        }
        .refresh-btn:hover {
            background: #229954;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        .system-status {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .status-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #28a745;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-error-item {
            border-left-color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🛠️ DefCon CHV Admin Dashboard</h1>
                <p>실시간 시스템 모니터링 및 관리</p>
            </div>
            <div style="text-align: right;">
                <p style="margin-bottom: 10px; opacity: 0.8;">Welcome, Admin</p>
                <form method="POST" action="/admin/logout" style="display: inline;">
                    <button type="submit" style="
                        background: rgba(255,255,255,0.2);
                        color: white;
                        border: 1px solid rgba(255,255,255,0.3);
                        padding: 8px 15px;
                        border-radius: 5px;
                        cursor: pointer;
                        font-size: 0.9rem;
                    ">🚪 Logout</button>
                </form>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="totalSessions">-</div>
                <div class="stat-label">활성 세션</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="systemStatus">-</div>
                <div class="stat-label">시스템 상태</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="dockerStatus">-</div>
                <div class="stat-label">Docker 상태</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="canBrokerStatus">-</div>
                <div class="stat-label">CAN 브로커</div>
            </div>
        </div>

        <div class="main-content">
            <div class="panel">
                <div class="panel-header">
                    <span>👥 활성 세션</span>
                    <button class="btn btn-primary" onclick="refreshSessions()">새로고침</button>
                </div>
                <div class="panel-body">
                    <div id="sessionsContainer">
                        <div class="empty-state">세션 정보를 로딩 중...</div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <span>🔧 시스템 제어</span>
                    <button class="btn btn-danger" onclick="resetInfrastructure()">인프라 재시작</button>
                </div>
                <div class="panel-body">
                    <div class="system-status" id="systemStatusGrid">
                        <!-- 시스템 상태가 여기에 표시됩니다 -->
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <h4>빠른 작업</h4>
                        <button class="btn btn-primary" onclick="viewCanBrokerDashboard()" style="margin: 5px;">
                            CAN 브로커 대시보드
                        </button>
                        <button class="btn btn-primary" onclick="checkHealth()" style="margin: 5px;">
                            헬스 체크
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div class="panel" style="margin-top: 30px;">
            <div class="panel-header">
                <span>📊 실시간 모니터링</span>
                <button class="refresh-btn" onclick="refreshLogs()">로그 새로고침</button>
            </div>
            <div class="panel-body">
                <div class="logs-container" id="logsContainer">
                    <div class="log-entry">시스템 로그를 로딩 중...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let refreshInterval;

        function refreshSessions() {
            fetch('/admin/sessions')
                .then(response => response.json())
                .then(data => {
                    updateSessionsDisplay(data);
                    document.getElementById('totalSessions').textContent = data.active_sessions;
                })
                .catch(error => {
                    console.error('Error fetching sessions:', error);
                    document.getElementById('sessionsContainer').innerHTML = 
                        '<div class="empty-state">❌ 세션 정보를 가져올 수 없습니다</div>';
                });
        }

        function updateSessionsDisplay(data) {
            const container = document.getElementById('sessionsContainer');
            
            if (data.active_sessions === 0) {
                container.innerHTML = '<div class="empty-state">활성 세션이 없습니다</div>';
                return;
            }

            let html = '';
            for (const [sessionId, session] of Object.entries(data.sessions)) {
                const remainingMinutes = Math.floor(session.remaining / 60);
                const remainingSeconds = session.remaining % 60;
                
                html += `
                    <div class="session-item">
                        <div>
                            <div class="session-id">${sessionId}</div>
                            <div class="session-details">
                                포트: ${session.port} | 
                                업타임: ${Math.floor(session.uptime / 60)}분 | 
                                남은시간: ${remainingMinutes}분 ${remainingSeconds}초
                            </div>
                        </div>
                        <div class="status-badge status-running">실행중</div>
                        <button class="btn btn-primary" onclick="viewSessionDetails('${sessionId}')">
                            상세보기
                        </button>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }

        function checkHealth() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    updateSystemStatus(data);
                })
                .catch(error => {
                    console.error('Error checking health:', error);
                });
        }

        function updateSystemStatus(data) {
            const statusGrid = document.getElementById('systemStatusGrid');
            
            document.getElementById('systemStatus').textContent = data.status === 'healthy' ? '✅' : '❌';
            document.getElementById('dockerStatus').textContent = data.docker === 'ok' ? '✅' : '❌';
            document.getElementById('canBrokerStatus').textContent = data.can_broker === 'ok' ? '✅' : '❌';
            
            let html = `
                <div class="status-item ${data.docker !== 'ok' ? 'status-error-item' : ''}">
                    <span>Docker</span>
                    <span>${data.docker === 'ok' ? '✅ 정상' : '❌ 오류'}</span>
                </div>
                <div class="status-item ${data.can_broker !== 'ok' ? 'status-error-item' : ''}">
                    <span>CAN 브로커</span>
                    <span>${data.can_broker === 'ok' ? '✅ 정상' : '❌ 오류'}</span>
                </div>
            `;
            
            for (const [container, status] of Object.entries(data.shared_containers)) {
                const isRunning = status === 'running';
                html += `
                    <div class="status-item ${!isRunning ? 'status-error-item' : ''}">
                        <span>${container}</span>
                        <span>${isRunning ? '✅ ' + status : '❌ ' + status}</span>
                    </div>
                `;
            }
            
            statusGrid.innerHTML = html;
        }

        function resetInfrastructure() {
            if (!confirm('인프라스트럭처를 재시작하시겠습니까? 모든 활성 세션이 종료됩니다.')) {
                return;
            }

            fetch('/admin/reset', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    refreshSessions();
                    checkHealth();
                })
                .catch(error => {
                    console.error('Error resetting infrastructure:', error);
                    alert('인프라 재시작 실패: ' + error.message);
                });
        }

        function viewCanBrokerDashboard() {
            window.open('/admin/can_broker/dashboard', '_blank');
        }

        function viewSessionDetails(sessionId) {
            window.open(`/admin/can_broker/debug/${sessionId}`, '_blank');
        }

        function refreshLogs() {
            // 간단한 시스템 로그 표시 (실제로는 더 복잡한 로그 시스템 필요)
            const logsContainer = document.getElementById('logsContainer');
            const timestamp = new Date().toLocaleString();
            
            logsContainer.innerHTML = `
                <div class="log-entry log-info">[${timestamp}] 시스템 상태 체크 완료</div>
                <div class="log-entry log-success">[${timestamp}] 활성 세션: ${document.getElementById('totalSessions').textContent}개</div>
                <div class="log-entry log-info">[${timestamp}] Docker 상태: ${document.getElementById('dockerStatus').textContent}</div>
                <div class="log-entry log-info">[${timestamp}] CAN 브로커 상태: ${document.getElementById('canBrokerStatus').textContent}</div>
            `;
        }

        // 자동 새로고침 설정
        function startAutoRefresh() {
            refreshSessions();
            checkHealth();
            
            refreshInterval = setInterval(() => {
                refreshSessions();
                checkHealth();
            }, 10000); // 10초마다 새로고침
        }

        // 페이지 로드 시 초기화
        document.addEventListener('DOMContentLoaded', function() {
            startAutoRefresh();
            refreshLogs();
        });

        // 페이지 언로드 시 인터벌 정리
        window.addEventListener('beforeunload', function() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
    </script>
</body>
</html>
    """
    return Response(html_content, mimetype='text/html')

@app.route("/admin/sessions")
@require_admin_auth
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
@require_admin_auth
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
@require_admin_auth
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

@app.route("/")
def index():
    """메인 웹 페이지"""
    return render_template('index.html')

# Static file serving
@app.route('/static/<path:filename>')
def static_files(filename):
    """정적 파일 서빙"""
    return app.send_static_file(filename)
        # 폴백 HTML
        html_content = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefCon CHV Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            color: #fff;
        }
        .container { 
            max-width: 800px; 
            margin: 0 auto; 
            padding: 20px;
            position: relative;
            z-index: 1;
        }
        .header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid rgba(255,255,255,0.1);
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        .main-section {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .start-button {
            width: 100%;
            padding: 20px;
            font-size: 1.5rem;
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            color: white;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .start-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        .start-button:disabled {
            background: #666;
            cursor: not-allowed;
            transform: none;
        }
        .session-info {
            display: none;
            margin-top: 20px;
            padding: 20px;
            background: rgba(0,255,0,0.1);
            border-radius: 10px;
            border: 1px solid rgba(0,255,0,0.3);
        }
        .info-item {
            margin: 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .info-label {
            font-weight: bold;
        }
        .info-value {
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 5px 10px;
            border-radius: 5px;
        }
        .download-button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(45deg, #4facfe, #00f2fe);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.2rem;
            margin-top: 10px;
        }
        .download-button:hover {
            transform: translateY(-1px);
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-running { background-color: #00ff00; }
        .status-stopped { background-color: #ff0000; }
        .status-pending { background-color: #ffff00; }
        .instructions {
            margin-top: 20px;
            padding: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            border-left: 4px solid #ffd700;
        }
        .step {
            margin: 10px 0;
            padding: 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚗 DefCon CHV Manager</h1>
            <p>Automotive Security Challenge Environment</p>
        </div>
        
        <div class="main-section">
            <h2>Start Environment</h2>
            <p style="margin-bottom: 20px; opacity: 0.8;">
                Start Challenge
            </p>
            
            <button id="startBtn" class="start-button" onclick="startEnvironment()">
                🚀 Start Service
            </button>
            
            <div id="sessionInfo" class="session-info">
                <h3>🎯 Info Session</h3>
                <div class="info-item">
                    <span class="info-label">Session ID:</span>
                    <span id="sessionId" class="info-value">-</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Port:</span>
                    <span id="infotainmentPort" class="info-value">-</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Status:</span>
                    <span id="sessionStatus" class="info-value">
                        <span class="status-indicator status-running"></span>실행 중
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">Remaining Time:</span>
                    <span id="remainingTime" class="info-value">-</span>
                </div>
                
                <button id="downloadBtn" class="download-button" onclick="downloadFirmware()">
                    📥 펌웨어 다운로드
                </button>
            </div>
        </div>
        
        <div id="instructions" class="instructions" style="display: none;">
            <h3>📋 Challenge Steps</h3>
            <div class="step">
                <strong>Step 1:</strong> Download and analyze firmware
                <br><small>Use hexdump, strings etc. to analyze firmware</small>
            </div>
            <div class="step">
                <strong>Step 2:</strong> Connect to infotainment system
                <br><small id="connectCmd">nc localhost [port]</small>
            </div>
            <div class="step">
                <strong>Step 3:</strong> Enable debug mode
                <br><small>Use commands found in firmware</small>
            </div>
            <div class="step">
                <strong>Step 4:</strong> Use CAN tools
                <br><small>cansend/candump vcan0 commands</small>
            </div>
            <div class="step">
                <strong>Step 5:</strong> Gateway authentication and engine ECU access
                <br><small>Final objective</small>
            </div>
        </div>
    </div>

    <script>
        let currentSessionId = null;
        let statusTimer = null;

        function startEnvironment() {
            const btn = document.getElementById('startBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="loading"></span> Loading';

            fetch('/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.session_id) {
                    currentSessionId = data.session_id;
                    displaySessionInfo(data);
                    startStatusUpdates();
                } else {
                    alert('Failed to start environment: ' + (data.error || 'Invalid Error') + '\n Please Contact Admin');
                    resetButton();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to start environment: ' + error.message + '\n Please Contact Admin');
                resetButton();
            });
        }

        function displaySessionInfo(data) {
            document.getElementById('sessionId').textContent = data.session_id;
            document.getElementById('infotainmentPort').textContent = data.infotainment_port;
            document.getElementById('connectCmd').textContent = `nc localhost ${data.infotainment_port}`;
            
            document.getElementById('sessionInfo').style.display = 'block';
            document.getElementById('instructions').style.display = 'block';
            
            const btn = document.getElementById('startBtn');
            btn.innerHTML = '✅ Running Env';
            btn.style.background = '#28a745';
        }

        function downloadFirmware() {
            if (!currentSessionId) {
                alert('Please Create Session');
                return;
            }
            
            const url = `/firmware/${currentSessionId}`;
            const a = document.createElement('a');
            a.href = url;
            a.download = `infotainment_${currentSessionId}.bin`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        function updateStatus() {
            if (!currentSessionId) return;

            fetch(`/status/${currentSessionId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'active') {
                        const minutes = Math.floor(data.remaining_time / 60);
                        const seconds = data.remaining_time % 60;
                        document.getElementById('remainingTime').textContent = 
                            `${minutes}min ${seconds}sec`;
                    } else {
                        document.getElementById('sessionStatus').innerHTML = 
                            '<span class="status-indicator status-stopped"></span>Terminated';
                        clearInterval(statusTimer);
                        resetButton();
                    }
                })
                .catch(error => {
                    console.error('Status update error:', error);
                });
        }

        function startStatusUpdates() {
            statusTimer = setInterval(updateStatus, 5000);
            updateStatus();
        }

        function resetButton() {
            const btn = document.getElementById('startBtn');
            btn.disabled = false;
            btn.innerHTML = '🚀 Start Env';
            btn.style.background = 'linear-gradient(45deg, #ff6b6b, #ee5a24)';
            
            document.getElementById('sessionInfo').style.display = 'none';
            document.getElementById('instructions').style.display = 'none';
            currentSessionId = null;
        }
    </script>
</body>
</html>
    """
    return Response(html_content, mimetype='text/html')

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
@require_admin_auth
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
@require_admin_auth
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
                if any(keyword in line for keyword in ['CANBroker', 'CAN Broker', 'Session', 'Gateway auth', 'Routing', 'CAN from', 'key', 'Generated', 'Sent', 'Security','Error']):
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
@require_admin_auth
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
                if any(keyword in line for keyword in ['CANBroker', 'CAN Broker', 'Session', 'Gateway auth', 'Routing', 'CAN from', 'key', 'Generated', 'Sent', 'Security','Error']):
                    yield f"data: {json.dumps({'log': line.strip(), 'timestamp': time.time()})}\n\n"
                    
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(generate_logs(), mimetype='text/event-stream')

@app.route("/admin/can_broker/sessions")
@require_admin_auth
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
@require_admin_auth
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
@require_admin_auth
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
@require_admin_auth
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
@require_admin_auth
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