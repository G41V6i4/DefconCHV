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
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = False  # 개발환경에서는 HTTP 허용
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# Rate limiting 설정
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
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
CONTAINER_TIMEOUT = 3600

# 어드민 계정 설정
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', 
    generate_password_hash('SecureAdmin2024!@#'))

# 활성 세션 관리
active_sessions = {}
failed_login_attempts = {}
admin_sessions = {}

# 공유 ECU 네트워크
SHARED_NETWORK = "ecu_shared_network"
SHARED_CONTAINERS = ["gateway_shared", "engine_shared"]

# 보안 함수들
def generate_csrf_token():
    return secrets.token_hex(32)

def verify_csrf_token(token):
    stored_token = session.get('csrf_token')
    return stored_token and hmac.compare_digest(stored_token, token)

def is_ip_blocked(ip):
    if ip not in failed_login_attempts:
        return False
    
    attempts = failed_login_attempts[ip]
    if attempts['count'] >= 5:
        if time.time() - attempts['last_attempt'] < 1800:
            return True
        else:
            failed_login_attempts[ip] = {'count': 0, 'last_attempt': time.time()}
            return False
    return False

def record_failed_login(ip):
    if ip not in failed_login_attempts:
        failed_login_attempts[ip] = {'count': 0, 'last_attempt': time.time()}
    
    failed_login_attempts[ip]['count'] += 1
    failed_login_attempts[ip]['last_attempt'] = time.time()
    
    logger.warning(f"Failed login attempt from IP: {ip}, attempt count: {failed_login_attempts[ip]['count']}")

def clear_failed_login(ip):
    if ip in failed_login_attempts:
        del failed_login_attempts[ip]

def require_admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_remote_address()
        if is_ip_blocked(client_ip):
            logger.warning(f"Blocked IP {client_ip} attempted to access admin area")
            return jsonify({"error": "IP blocked due to too many failed attempts"}), 429
        
        if 'admin_authenticated' not in session or not session['admin_authenticated']:
            logger.warning(f"Unauthorized admin access attempt from IP: {client_ip}")
            return redirect(url_for('admin_login'))
        
        if 'last_activity' in session:
            if time.time() - session['last_activity'] > 1800:
                session.clear()
                logger.info(f"Admin session expired for IP: {client_ip}")
                return redirect(url_for('admin_login'))
        
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
    if session_id in active_sessions:
        session = active_sessions[session_id]
        for container in session['containers']:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        del active_sessions[session_id]

def get_can_broker_host():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('gateway_shared', 9999))
        sock.close()
        if result == 0:
            return 'gateway_shared'
    except:
        pass
    return 'localhost'

def wait_for_can_broker():
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
                "--restart", "unless-stopped",
                "-p", "9999:9999",
                DOCKER_IMAGE_GATEWAY
            ], check=True)
        else:
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
            subprocess.run(["docker", "start", "engine_shared"], capture_output=True)
            
    except subprocess.CalledProcessError as e:
        print(f"Error setting up shared infrastructure: {e}")
        raise

# 라우트들
@app.route("/")
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)

@app.route("/start", methods=["POST"])
def start_environment():
    session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
    port = get_unused_port()
    
    try:
        ensure_shared_infrastructure()
        
        if not wait_for_can_broker():
            return jsonify({"error": "CAN broker failed to start"}), 500
        
        infotainment_name = f"infotainment_{session_id}"
        subprocess.run([
            "docker", "run", "-d",
            "--name", infotainment_name,
            "--network", SHARED_NETWORK,
            "-p", f"{port}:1234",
            "-e", f"SESSION_ID={session_id}",
            DOCKER_IMAGE_INFOTAINMENT
        ], check=True)
        
        active_sessions[session_id] = {
            'port': port,
            'containers': [infotainment_name],
            'created_at': time.time()
        }
        
        timer = Timer(CONTAINER_TIMEOUT, cleanup_session, [session_id])
        timer.start()
        
        return jsonify({
            "session_id": session_id,
            "infotainment_host": "localhost",
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
        cleanup_session(session_id)
        return jsonify({"error": f"Failed to start environment: {str(e)}"}), 500

@app.route("/firmware/<session_id>")
def download_firmware(session_id):
    if session_id not in active_sessions:
        return "Session not found", 404
    
    firmware_path = "firmware/system.img"
    
    # 파일이 존재하는지 확인
    if not os.path.exists(firmware_path):
        return "Firmware file not found", 404
    
    try:
        # 파일을 읽어서 전송
        with open(firmware_path, 'rb') as f:
            firmware_content = f.read()
        
        response = app.response_class(
            firmware_content,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename=system_{session_id}.img'
            }
        )
        return response
    except Exception as e:
        return f"Error reading firmware file: {str(e)}", 500

@app.route("/status/<session_id>")
def get_status(session_id):
    if session_id not in active_sessions:
        return jsonify({"status": "not_found"}), 404
    
    session = active_sessions[session_id]
    uptime = time.time() - session['created_at']
    remaining = CONTAINER_TIMEOUT - uptime
    
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
@limiter.limit("10 per minute")
def admin_login():
    client_ip = get_remote_address()
    
    if is_ip_blocked(client_ip):
        logger.warning(f"Blocked IP {client_ip} attempted to access login page")
        return render_template('blocked.html'), 429
    
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_token = request.form.get('csrf_token', '')
        
        if not verify_csrf_token(csrf_token):
            logger.warning(f"CSRF token validation failed from IP: {client_ip}")
            record_failed_login(client_ip)
            return render_template('admin_login.html', 
                error="Security token validation failed", csrf_token=generate_csrf_token()), 400
        
        if not username or not password:
            logger.warning(f"Empty credentials from IP: {client_ip}")
            record_failed_login(client_ip)
            return render_template('admin_login.html', 
                error="Username and password are required", csrf_token=generate_csrf_token()), 400
        
        # 디버그 정보 (개발용)
        print(f"DEBUG: Login attempt - Username: '{username}', Expected: '{ADMIN_USERNAME}'")
        print(f"DEBUG: Password check result: {check_password_hash(ADMIN_PASSWORD_HASH, password)}")
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_authenticated'] = True
            session['admin_username'] = username
            session['last_activity'] = time.time()
            session['csrf_token'] = generate_csrf_token()
            session.permanent = True
            
            clear_failed_login(client_ip)
            logger.info(f"Successful admin login from IP: {client_ip}, username: {username}")
            
            return redirect(url_for('admin_dashboard'))
        else:
            record_failed_login(client_ip)
            logger.warning(f"Invalid credentials from IP: {client_ip}, username: {username}")
            
            return render_template('admin_login.html', 
                error="Invalid username or password", csrf_token=generate_csrf_token()), 401
    
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    
    return render_template('admin_login.html', csrf_token=csrf_token)

@app.route("/admin/logout", methods=["POST"])
@require_admin_auth
def admin_logout():
    client_ip = get_remote_address()
    admin_username = session.get('admin_username', 'unknown')
    
    logger.info(f"Admin logout: {admin_username} from IP: {client_ip}")
    
    session.clear()
    return redirect(url_for('admin_login'))

@app.route("/admin")
@require_admin_auth
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route("/admin/sessions")
@require_admin_auth
def list_sessions():
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

@app.route("/admin/session/<session_id>/logs")
@require_admin_auth
def get_session_logs(session_id):
    """특정 세션의 게이트웨이 로그 조회 (세션 관련 로그만 필터링)"""
    if session_id not in active_sessions:
        return jsonify({"error": "Session not found"}), 404
    
    try:
        # 게이트웨이 컨테이너 로그 가져오기
        result = subprocess.run(
            ["docker", "logs", "--tail", "500", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            all_logs = result.stdout.split('\n')
            
            # 해당 세션 관련 로그만 필터링
            session_logs = []
            for log in all_logs:
                if log.strip() and session_id in log:
                    session_logs.append(log)
            
            # 세션 관련 로그가 없으면 최근 게이트웨이 로그도 포함
            if len(session_logs) < 10:
                # CAN 관련 키워드로 필터링된 최근 로그 추가
                for log in all_logs[-50:]:  # 최근 50줄에서
                    if log.strip() and any(keyword in log for keyword in 
                        ['CAN', 'Gateway', 'auth', 'Session', 'Routing', 'Security', 'Error']):
                        if log not in session_logs:
                            session_logs.append(log)
            
            return jsonify({
                "status": "success",
                "session_id": session_id,
                "container": "gateway_shared",
                "logs": session_logs[-100:],  # 최근 100줄
                "total_lines": len(session_logs),
                "filtered": True
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get gateway logs",
                "error": result.stderr
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/session/<session_id>/details")
@require_admin_auth
def get_session_details(session_id):
    """세션 상세 정보 페이지"""
    if session_id not in active_sessions:
        return render_template('session_not_found.html', session_id=session_id), 404
    
    session_data = active_sessions[session_id]
    uptime = time.time() - session_data['created_at']
    remaining = CONTAINER_TIMEOUT - uptime
    
    # 컨테이너 상태 확인
    container_status = {}
    for container in session_data['containers']:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True
        )
        container_status[container] = result.stdout.strip() if result.returncode == 0 else "not_found"
    
    session_info = {
        'session_id': session_id,
        'port': session_data['port'],
        'created_at': session_data['created_at'],
        'uptime': int(uptime),
        'remaining_time': int(remaining),
        'containers': session_data['containers'],
        'container_status': container_status
    }
    
    return render_template('session_details.html', session=session_info)

@app.route("/admin/gateway/logs")
@require_admin_auth
def gateway_logs_page():
    """게이트웨이 로그 모니터링 페이지"""
    return render_template('gateway_logs.html')

@app.route("/admin/gateway/logs/api")
@require_admin_auth
def gateway_logs_api():
    """게이트웨이 로그 API"""
    try:
        # 게이트웨이 컨테이너 로그 가져오기
        result = subprocess.run(
            ["docker", "logs", "--tail", "200", "gateway_shared"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            logs = result.stdout.split('\n')
            # 빈 줄 제거하고 최근 순으로 정렬
            logs = [log for log in logs if log.strip()]
            
            return jsonify({
                "status": "success",
                "logs": logs,
                "total_lines": len(logs),
                "container": "gateway_shared"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to get gateway logs",
                "error": result.stderr
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/admin/gateway/logs/live")
@require_admin_auth
def gateway_logs_live():
    """실시간 게이트웨이 로그 스트리밍 (SSE)"""
    def generate_logs():
        try:
            # docker logs -f로 실시간 로그 스트리밍
            process = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "10", "gateway_shared"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    yield f"data: {json.dumps({'log': line.strip(), 'timestamp': time.time()})}\n\n"
                    
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(generate_logs(), mimetype='text/event-stream')

@app.route("/health")
def health_check():
    try:
        result = subprocess.run(["docker", "version"], capture_output=True)
        docker_ok = result.returncode == 0
        
        shared_containers_status = {}
        for container in SHARED_CONTAINERS:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container],
                capture_output=True, text=True
            )
            shared_containers_status[container] = result.stdout.strip() if result.returncode == 0 else "not_found"
        
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

if __name__ == "__main__":
    print("=" * 50)
    print("DefCon CHV Manager Starting...")
    print("=" * 50)
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"Default Password: SecureAdmin2024!@#")
    print(f"Admin Login URL: http://localhost:8080/admin/login")
    print("=" * 50)
    
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