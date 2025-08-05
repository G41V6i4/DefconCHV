let currentSessionId = null;
let statusTimer = null;

function startEnvironment() {
    const btn = document.getElementById('startBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Loading...';

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
            alert('Failed to start environment: ' + (data.error || 'Invalid Error'));
            resetButton();
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to start environment: ' + error.message);
        resetButton();
    });
}

function displaySessionInfo(data) {
    document.getElementById('sessionId').textContent = data.session_id;
    document.getElementById('infotainmentPort').textContent = data.infotainment_port;
    document.getElementById('connectCmd').textContent = 'nc localhost ' + data.infotainment_port;
    
    document.getElementById('sessionInfo').style.display = 'block';
    document.getElementById('instructions').style.display = 'block';
    
    const btn = document.getElementById('startBtn');
    btn.innerHTML = '✅ Running';
    btn.style.background = '#28a745';
}

function downloadFirmware() {
    if (!currentSessionId) {
        alert('Please create session first');
        return;
    }
    
    const url = '/firmware/' + currentSessionId;
    const a = document.createElement('a');
    a.href = url;
    a.download = 'system_' + currentSessionId + '.img';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function updateStatus() {
    if (!currentSessionId) return;

    fetch('/status/' + currentSessionId)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'active') {
                const minutes = Math.floor(data.remaining_time / 60);
                const seconds = data.remaining_time % 60;
                document.getElementById('remainingTime').textContent = 
                    minutes + 'min ' + seconds + 'sec';
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
    btn.innerHTML = '🚀 Start Service';
    btn.style.background = 'linear-gradient(45deg, #ff6b6b, #ee5a24)';
    
    document.getElementById('sessionInfo').style.display = 'none';
    document.getElementById('instructions').style.display = 'none';
    currentSessionId = null;
}