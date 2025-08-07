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

function viewSessionDetails(sessionId) {
    window.open(`/admin/session/${sessionId}/details`, '_blank');
}

function viewGatewayLogs() {
    window.open('/admin/gateway/logs', '_blank');
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

function confirmLogout() {
    return confirm('정말로 로그아웃하시겠습니까?');
}

function fetchCSRFToken() {
    fetch('/admin/csrf-token')
        .then(response => response.json())
        .then(data => {
            if (data.csrf_token) {
                document.getElementById('csrf_token').value = data.csrf_token;
            }
        })
        .catch(error => {
            console.error('Error fetching CSRF token:', error);
        });
}

// 페이지 로드 시 초기화
document.addEventListener('DOMContentLoaded', function() {
    fetchCSRFToken();
    startAutoRefresh();
});

// 페이지 언로드 시 인터벌 정리
window.addEventListener('beforeunload', function() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});