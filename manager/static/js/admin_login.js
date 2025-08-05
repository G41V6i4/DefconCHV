// 기본 보안 조치
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
        e.preventDefault();
    }
});

// 폼 제출 후 입력 필드 클리어
document.querySelector('form').addEventListener('submit', function() {
    setTimeout(() => {
        document.getElementById('password').value = '';
    }, 100);
});