#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>

// 상수 정의
#define XOR_KEY 0x37
#define MAX_INPUT 256
#define MAX_VOLUME 30
#define MAX_BRIGHTNESS 100

// 사용자 타입 구조체
typedef struct {
    int type;           // 0: normal, 1: admin
    char name[32];
    float auth_code;    // 타입 컨퓨전 취약점을 위한 변수
} user_t;

// 전역 변수
static user_t current_user = {0};
static int g_volume = 15;
static int g_brightness = 80;
static char g_current_song[256] = {0};
static int g_system_locked = 0;

// anti-debugging
void check_debugger() {
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(1);
    }
}

// 문자열 암호화/복호화
char* decrypt_str(char* str) {
    static char decrypted[256];
    int i;
    for(i = 0; str[i]; i++) {
        decrypted[i] = str[i] ^ XOR_KEY;
    }
    decrypted[i] = '\0';
    return decrypted;
}

// 가짜 함수들 (리버싱 방해용)
void fake_function1() {
    volatile int x = 1;
    while(x < 1000) {
        x = x * 2 - 1;
    }
}

void fake_function2() {
    char buf[128];
    memset(buf, 0x41, sizeof(buf));
}

// 인증 처리
void auth_handler() {
    char input[16];
    printf("Enter auth code (float): ");
    fgets(input, sizeof(input), stdin);
    
    current_user.auth_code = atof(input);
    // 타입 컨퓨전 취약점
    // float 4012.123456을 입력하면 int로 변환 시 0x41424344가 됨
    if((int)current_user.auth_code == 0x41424344) {
        current_user.type = 1;
        printf("Admin access granted!\n");
    } else {
        printf("Invalid auth code\n");
    }
}

// 메뉴 함수들
void media_player() {
    char input[256];
    int cmd = 0;
    char playlist[128];
    
    printf("\n=== Media Player ===\n");
    printf("1. Play/Pause\n");
    printf("2. Load Playlist\n");
    printf("3. Set Volume\n");
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
    cmd = atoi(input);
    
    if(cmd == 2) {
        printf("Enter playlist path: ");
        read(0, playlist, 0x200);  // 버퍼 오버플로우 취약점
    }
}

void navigation_menu() {
    char dest[64] = {0};
    int waypoints = 0;
    
    printf("\n=== Navigation ===\n");
    printf("Number of waypoints: ");
    scanf("%d", &waypoints);
    
    if(waypoints > 0 && waypoints < 5) {
        char input[32];
        for(int i = 0; i < waypoints; i++) {
            printf("Waypoint %d: ", i+1);
            strcat(dest, gets(input)); // 취약점: bounds check 없음, gets 사용
        }
    }
}

void settings_menu() {
    char input[16];
    int choice;
    
    printf("\n=== System Settings ===\n");
    printf("1. Display Settings\n");
    printf("2. Audio Settings\n");
    printf("3. Auth Settings\n");
    printf("4. System Information\n");
    printf("Choice: ");
    
    read(0, input, 0x100);  // 버퍼 오버플로우 취약점
    choice = atoi(input);
    
    switch(choice) {
        case 1:
            printf("Brightness: %d%%\n", g_brightness);
            break;
        case 2:
            printf("Volume: %d\n", g_volume);
            break;
        case 3:
            auth_handler();
            break;
        case 4:
            if(current_user.type == 1) {
                system("/bin/sh");  // 쉘 실행 (admin만 가능)
            } else {
                printf("Access denied\n");
            }
            break;
    }
}

void admin_menu() {
    if(current_user.type != 1) {
        printf("Access denied\n");
        return;
    }
    
    char cmd[128];
    printf("Enter system command: ");
    gets(cmd);  // 취약점: gets 사용
    system(cmd);
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    int choice;
    char input[16];
    
    // anti-debugging
    check_debugger();
    
    printf("=== Vehicle Infotainment System v2.1.7 ===\n");
    printf("Initializing...\n");
    sleep(1);
    
    while(1) {
        printf("\nMain Menu:\n");
        printf("1. Media Player\n");
        printf("2. Navigation\n");
        printf("3. Settings\n");
        printf("4. Admin Menu\n");
        printf("0. Exit\n");
        printf("Choice: ");
        
        fgets(input, sizeof(input), stdin);
        choice = atoi(input);
        
        switch(choice) {
            case 0:
                printf("Shutting down...\n");
                return 0;
            case 1:
                media_player();
                break;
            case 2:
                navigation_menu();
                break;
            case 3:
                settings_menu();
                break;
            case 4:
                admin_menu();
                break;
            default:
                printf("Invalid selection.\n");
                break;
        }
    }
    
    return 0;
}