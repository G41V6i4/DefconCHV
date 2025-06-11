#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#define BUFFER_SIZE 512
#define FIRMWARE_VERSION "2.1.337"

// 숨겨진 디버그 패스워드 (Stage 1)
const char hidden_password[] = {0x04, 0x23, 0x16, 0x23, 0x0c, 0x30, 0x10, 0x23, 0x12, 0x3f, 0x0d, 0x30, 0x04, 0x23, 0x00};

typedef struct {
    int debug_mode;
    int can_unlocked;   
    char username[32];
} session_t;

int can_socket = -1;

// CAN 통신 초기화
void init_can_connection() {
    struct hostent *host;
    struct sockaddr_in addr;
    
    host = gethostbyname("can_bridge");
    if (!host) {
        return;
    }
    
    can_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (can_socket < 0) {
        return;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);
    
    if (connect(can_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(can_socket);
        can_socket = -1;
        return;
    }
    
    // ECU 타입 등록
    send(can_socket, "INFOTAINMENT\n", 13, 0);
}

// 숨겨진 함수 (Stage 1 - 리버싱으로 찾아야 함)
void secret_debug_menu() {
    char input[64];
    char decoded[16];
    
    printf("=== Developer Mode ===\n");
    printf("Password: ");
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\n")] = 0;
    
    // XOR 디코딩
    for (int i = 0; i < 14; i++) {
        decoded[i] = hidden_password[i] ^ 0x42;
    }
    decoded[14] = 0;
    
    if (strcmp(input, decoded) == 0) {
        printf("Debug mode activated!\n");
        printf("New commands available: diag, can_unlock\n");
        return;
    }
    
    printf("Invalid password!\n");
}

// Stage 2 - 취약한 진단 함수
void diagnostic_service(session_t *session, char *command) {
    char buffer[64];
    
    printf("=== Diagnostic Service ===\n");
    printf("Enter diagnostic data: ");
    fflush(stdout);
    
    // 취약점: 버퍼 오버플로우
    gets(buffer);
    
    printf("Processing: %s\n", buffer);
    
    // 숨겨진 기능
    if (strstr(buffer, "UNLOCK_CAN_ACCESS")) {
        session->can_unlocked = 1;
        printf("CAN interface unlocked!\n");
        
        // CAN 연결 초기화
        if (can_socket < 0) {
            init_can_connection();
            if (can_socket >= 0) {
                printf("Connected to CAN network!\n");
                
                // Stage 3를 위한 힌트 메시지 전송
                unsigned char hint_msg[13] = {0};
                hint_msg[0] = 0x00; hint_msg[1] = 0x00; hint_msg[2] = 0x03; hint_msg[3] = 0xFF;
                hint_msg[4] = 8;
                strcpy((char*)&hint_msg[5], "UNLOCKED");
                send(can_socket, hint_msg, 13, 0);
            }
        }
    }
}

// Win 함수 (Stage 2 목표)
void grant_shell_access() {
    printf("\n[+] Congratulations! You've gained shell access!\n");
    printf("[+] Stage 2 Complete!\n");
    printf("[+] Flag 1: FLAG{Inf0t41nm3nt_Pwn3d}\n\n");
    
    printf("Spawning shell...\n");
    system("/bin/sh");
}

void print_banner() {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║    Automotive Infotainment System      ║\n");
    printf("║         Firmware v%s              ║\n", FIRMWARE_VERSION);
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    session_t session = {0};
    char command[BUFFER_SIZE];
    
    print_banner();
    
    printf("Commands: help, status, media, nav, settings, exit\n");
    printf("\n");
    
    while (1) {
        printf("infotainment> ");
        
        if (!fgets(command, sizeof(command), stdin)) break;
        command[strcspn(command, "\n")] = 0;
        
        if (strcmp(command, "exit") == 0) {
            printf("Shutting down...\n");
            break;
        }
        else if (strcmp(command, "help") == 0) {
            printf("Available commands:\n");
            printf("  help     - Show this help\n");
            printf("  status   - System status\n");
            printf("  media    - Media player\n");
            printf("  nav      - Navigation\n");
            printf("  settings - System settings\n");
            printf("  exit     - Exit system\n");
            if (session.debug_mode) {
                printf("  diag     - Diagnostic service\n");
                printf("  can_unlock - Unlock CAN interface\n");
            }
        }
        else if (strcmp(command, "status") == 0) {
            printf("System Status:\n");
            printf("  Firmware: v%s\n", FIRMWARE_VERSION);
            printf("  Debug Mode: %s\n", session.debug_mode ? "Enabled" : "Disabled");
            printf("  CAN Access: %s\n", session.can_unlocked ? "Unlocked" : "Locked");
        }
        else if (strcmp(command, "d3v") == 0) {
            // Stage 1: 숨겨진 명령어
            secret_debug_menu();
            session.debug_mode = 1;
        }
        else if (strcmp(command, "diag") == 0 && session.debug_mode) {
            diagnostic_service(&session, command);
        }
        else if (strcmp(command, "can_unlock") == 0 && session.debug_mode) {
            printf("Use the diagnostic service to unlock CAN access.\n");
        }
        else if (strcmp(command, "media") == 0) {
            printf("Media Player: No media found\n");
        }
        else if (strcmp(command, "nav") == 0) {
            printf("Navigation: GPS signal not found\n");
        }
        else if (strcmp(command, "settings") == 0) {
            printf("Settings: Access restricted\n");
        }
        else {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
    }
    
    if (can_socket >= 0) {
        close(can_socket);
    }
    
    return 0;
}