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

# 메모리 효율적인 로깅 설정
logging.basicConfig(
    level=logging.WARNING,  # WARNING 이상만 로그 (메모리 절약)
    format='%(asctime)s - %(levelname)s - %(message)s',  # 간단한 포맷
    handlers=[
        logging.FileHandler('admin_access.log', maxBytes=10*1024*1024, backupCount=2),  # 10MB 로테이션
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 메모리 모니터링
import psutil
import gc

def get_memory_usage():
    """현재 메모리 사용량 반환"""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024  # MB 단위

def force_garbage_collection():
    """강제 가비지 컬렉션"""
    gc.collect()
    return gc.get_count()

# 메모리 최적화 설정
DOCKER_IMAGE_INFOTAINMENT = "ecu_infotainment:latest"
DOCKER_IMAGE_GATEWAY = "ecu_gateway:latest"
DOCKER_IMAGE_ENGINE = "ecu_engine:latest"
PORT_RANGE = (20000, 30000)
CONTAINER_TIMEOUT = 1800  # 30분으로 단축 (메모리 절약)
MAX_CONCURRENT_SESSIONS = 100
MEMORY_LIMIT_CONTAINER = "128m"  # 컨테이너당 128MB 제한
CPU_LIMIT_CONTAINER = "0.5"     # CPU 0.5 코어 제한

# 어드민 계정 설정
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', 
    generate_password_hash('SecureAdmin2024!@#'))

# 메모리 효율적인 세션 관리
active_sessions = {}
failed_login_attempts = {}
# admin_sessions 제거 (중복 데이터)

# 공유 ECU 네트워크 (모든 세션이 공유)
SHARED_NETWORK = "ecu_shared_network"
SHARED_CONTAINERS = ["gateway_shared", "engine_shared"]

# 메모리 효율적인 CSRF 관리
csrf_tokens = {}

# 세션 풀링을 위한 설정
POOLED_CONTAINERS = {}  # 재사용 가능한 컨테이너 풀
MAX_POOL_SIZE = 50      # 풀 최대 크기

def generate_csrf_token():
    # 세션별 고유한 CSRF 토큰 생성
    token = secrets.token_hex(32)
    session_id = session.get('session_id')
    if not session_id:
        session_id = secrets.token_hex(16)
        session['session_id'] = session_id
    
    csrf_tokens[session_id] = {
        'token': token,
        'created_at': time.time(),
        'used_count': 0,
        'max_uses': 10,  # 토큰 재사용 제한
        'expires_at': time.time() + 1800  # 30분 만료
    }
    
    session['csrf_token'] = token
    session['csrf_created_at'] = time.time()
    
    # 만료된 토큰 정리
    cleanup_expired_csrf_tokens()
    
    return token

def verify_csrf_token(token):
    if not token:
        return False
        
    session_id = session.get('session_id')
    if not session_id or session_id not in csrf_tokens:
        return False
    
    csrf_data = csrf_tokens[session_id]
    stored_token = csrf_data['token']
    
    # 토큰 값 비교
    if not hmac.compare_digest(stored_token, token):
        return False
    
    # 만료 시간 확인
    if time.time() > csrf_data['expires_at']:
        del csrf_tokens[session_id]
        return False
    
    # 사용 횟수 확인
    csrf_data['used_count'] += 1
    if csrf_data['used_count'] > csrf_data['max_uses']:
        del csrf_tokens[session_id]
        return False
    
    # 세션의 토큰과도 비교 (이중 검증)
    session_token = session.get('csrf_token')
    if not session_token or not hmac.compare_digest(session_token, token):
        return False
    
    # 토큰 생성 시간 확인 (세션 탈취 방지)
    token_age = time.time() - session.get('csrf_created_at', 0)
    if token_age > 1800:  # 30분 이상 된 토큰 거부
        return False
    
    return True

def cleanup_expired_csrf_tokens():
    """메모리 효율적인 CSRF 토큰 정리"""
    current_time = time.time()
    # 만료된 토큰들을 한 번에 정리
    global csrf_tokens
    csrf_tokens = {
        session_id: data for session_id, data in csrf_tokens.items()
        if current_time <= data['expires_at']
    }
    
    # CSRF 토큰이 100개를 넘으면 가장 오래된 것부터 정리
    if len(csrf_tokens) > 100:
        sorted_tokens = sorted(csrf_tokens.items(), key=lambda x: x[1]['created_at'])
        csrf_tokens = dict(sorted_tokens[-100:])  # 최신 100개만 유지

def require_fresh_csrf():
    """중요한 작업을 위한 신선한 CSRF 토큰 요구"""
    session_id = session.get('session_id')
    if session_id in csrf_tokens:
        csrf_data = csrf_tokens[session_id]
        token_age = time.time() - csrf_data['created_at']
        return token_age < 300  # 5분 이내 생성된 토큰만 허용
    return False

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

def require_csrf_protection(require_fresh=False):
    """CSRF 보호 데코레이터"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                # POST 요청에서 CSRF 토큰 확인
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not token:
                    logger.warning(f"Missing CSRF token from IP: {get_remote_address()}")
                    return jsonify({"error": "Missing CSRF token"}), 400
                
                if not verify_csrf_token(token):
                    logger.warning(f"Invalid CSRF token from IP: {get_remote_address()}")
                    return jsonify({"error": "Invalid CSRF token"}), 400
                
                # 중요한 작업의 경우 신선한 토큰 요구
                if require_fresh and not require_fresh_csrf():
                    logger.warning(f"Stale CSRF token used for sensitive operation from IP: {get_remote_address()}")
                    return jsonify({"error": "Fresh CSRF token required for this operation"}), 400
                
                # 토큰 사용 로깅
                logger.info(f"Valid CSRF token used by IP: {get_remote_address()}")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_unused_port():
    used_ports = [session['port'] for session in active_sessions.values()]
    while True:
        port = random.randint(*PORT_RANGE)
        if port not in used_ports:
            return port

def get_pooled_container():
    """재사용 가능한 컨테이너를 풀에서 가져오기"""
    if POOLED_CONTAINERS and len(POOLED_CONTAINERS) > 0:
        container_name = list(POOLED_CONTAINERS.keys())[0]
        container_info = POOLED_CONTAINERS.pop(container_name)
        return container_name, container_info['port']
    return None, None

def return_to_pool(container_name, port):
    """컨테이너를 풀에 반환"""
    if len(POOLED_CONTAINERS) < MAX_POOL_SIZE:
        POOLED_CONTAINERS[container_name] = {
            'port': port,
            'last_used': time.time()
        }
        return True
    else:
        # 풀이 가득 찬 경우 컨테이너 삭제
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return False

def cleanup_session(session_id):
    if session_id in active_sessions:
        session = active_sessions[session_id]
        
        # 컨테이너를 풀에 반환 시도
        for container in session['containers']:
            if not return_to_pool(container, session.get('port')):
                # 풀 반환 실패 시 삭제
                subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        
        del active_sessions[session_id]

def cleanup_old_pooled_containers():
    """오래된 풀 컨테이너 정리 (30분 이상 미사용)"""
    current_time = time.time()
    old_containers = [
        name for name, info in POOLED_CONTAINERS.items()
        if current_time - info['last_used'] > 1800
    ]
    
    for container_name in old_containers:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        del POOLED_CONTAINERS[container_name]

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
    # 동시 세션 제한 확인
    if len(active_sessions) >= MAX_CONCURRENT_SESSIONS:
        return jsonify({"error": f"Maximum {MAX_CONCURRENT_SESSIONS} concurrent sessions reached"}), 429
    
    session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
    
    try:
        ensure_shared_infrastructure()
        
        if not wait_for_can_broker():
            return jsonify({"error": "CAN broker failed to start"}), 500
        
        # 풀에서 컨테이너 재사용 시도
        pooled_container, pooled_port = get_pooled_container()
        
        if pooled_container:
            # 기존 컨테이너 재사용
            infotainment_name = pooled_container
            port = pooled_port
            
            # 컨테이너 재시작하여 새 세션 ID 적용
            subprocess.run([
                "docker", "restart", infotainment_name
            ], check=True)
            
            # 환경 변수 업데이트 (재시작 후)
            subprocess.run([
                "docker", "exec", infotainment_name,
                "sh", "-c", f"export SESSION_ID={session_id}"
            ], capture_output=True)
            
        else:
            # 새 컨테이너 생성 (메모리 제한 적용)
            port = get_unused_port()
            infotainment_name = f"infotainment_{session_id}"
            subprocess.run([
                "docker", "run", "-d",
                "--name", infotainment_name,
                "--network", SHARED_NETWORK,
                "-p", f"{port}:1234",
                "-e", f"SESSION_ID={session_id}",
                "--memory", MEMORY_LIMIT_CONTAINER,
                "--cpus", CPU_LIMIT_CONTAINER,
                "--restart", "no",  # 자동 재시작 비활성화
                DOCKER_IMAGE_INFOTAINMENT
            ], check=True)
        
        active_sessions[session_id] = {
            'port': port,
            'containers': [infotainment_name],
            'created_at': time.time(),
            'memory_usage': 0  # 메모리 사용량 추적용
        }
        
        # 세션 만료 타이머
        timer = Timer(CONTAINER_TIMEOUT, cleanup_session, [session_id])
        timer.start()
        
        # 정기적으로 풀 정리
        cleanup_old_pooled_containers()
        
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
@require_csrf_protection(require_fresh=True)
def admin_logout():
    client_ip = get_remote_address()
    admin_username = session.get('admin_username', 'unknown')
    session_id = session.get('session_id')
    
    logger.info(f"Admin logout: {admin_username} from IP: {client_ip}")
    
    # CSRF 토큰 정리
    if session_id and session_id in csrf_tokens:
        del csrf_tokens[session_id]
    
    session.clear()
    return redirect(url_for('admin_login'))

@app.route("/admin")
@require_admin_auth
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route("/admin/csrf-token")
@require_admin_auth
def admin_csrf_token():
    """신선한 CSRF 토큰 제공"""
    csrf_token = generate_csrf_token()
    return jsonify({"csrf_token": csrf_token})

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
        # 메모리 정리 실행
        force_garbage_collection()
        cleanup_expired_csrf_tokens()
        cleanup_old_pooled_containers()
        
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
        
        # 메모리 사용량 체크
        memory_mb = get_memory_usage()
        memory_status = "ok" if memory_mb < 20000 else "high"  # 20GB 이상이면 high
        
        return jsonify({
            "status": "healthy" if docker_ok and can_broker_ok else "degraded",
            "docker": "ok" if docker_ok else "error",
            "can_broker": "ok" if can_broker_ok else "error", 
            "shared_containers": shared_containers_status,
            "active_sessions": len(active_sessions),
            "pooled_containers": len(POOLED_CONTAINERS),
            "memory_usage_mb": round(memory_mb, 1),
            "memory_status": memory_status,
            "csrf_tokens": len(csrf_tokens)
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def memory_cleanup_scheduler():
    """정기적인 메모리 정리 스케줄러"""
    import threading
    import time
    
    def cleanup_task():
        while True:
            try:
                # 5분마다 메모리 정리
                time.sleep(300)
                
                memory_usage = get_memory_usage()
                logger.warning(f"Current memory usage: {memory_usage:.1f}MB")
                
                # 메모리 사용량이 18GB를 넘으면 강제 정리
                if memory_usage > 18000:
                    logger.warning("High memory usage detected, performing cleanup")
                    
                    # 오래된 세션 강제 정리 (1시간 이상)
                    current_time = time.time()
                    old_sessions = [
                        sid for sid, data in active_sessions.items()
                        if current_time - data['created_at'] > 3600
                    ]
                    
                    for session_id in old_sessions:
                        cleanup_session(session_id)
                        logger.warning(f"Cleaned up old session: {session_id}")
                    
                    # 강제 가비지 컬렉션
                    force_garbage_collection()
                    cleanup_expired_csrf_tokens()
                    cleanup_old_pooled_containers()
                    
                    logger.warning(f"Cleanup completed, memory usage: {get_memory_usage():.1f}MB")
                    
            except Exception as e:
                logger.error(f"Memory cleanup error: {e}")
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    return cleanup_thread

if __name__ == "__main__":
    print("=" * 50)
    print("DefCon CHV Manager Starting (Memory Optimized for 100 users)...")
    print("=" * 50)
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"Default Password: SecureAdmin2024!@#")
    print(f"Admin Login URL: http://localhost:8080/admin/login")
    print(f"Max Concurrent Sessions: {MAX_CONCURRENT_SESSIONS}")
    print(f"Container Memory Limit: {MEMORY_LIMIT_CONTAINER}")
    print(f"Container CPU Limit: {CPU_LIMIT_CONTAINER}")
    print(f"Container Pool Size: {MAX_POOL_SIZE}")
    print("=" * 50)
    
    # 메모리 정리 스케줄러 시작
    memory_cleanup_scheduler()
    
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
    
    # 초기 메모리 사용량 로깅
    print(f"Initial memory usage: {get_memory_usage():.1f}MB")
    
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)