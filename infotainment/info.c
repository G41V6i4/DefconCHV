#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define PORT 1234
#define BUFFER_SIZE 256

// 취약점: 버퍼 오버플로우
char global_buffer[64];
int debug_mode = 0;

void show_menu() {
    printf("=== Infotainment System v1.2.3 ===\n");
    printf("1. Radio Control\n");
    printf("2. Navigation\n");
    printf("3. Diagnostics\n");
    if (debug_mode) {
        printf("9. Debug Menu (DEV ONLY)\n");
    }
    printf("0. Exit\n");
    printf("Choice: ");
}

void debug_menu() {
    char command[128];
    printf("Debug mode activated!\n");
    printf("Available commands: status, caninfo, shell\n");
    printf("debug> ");
    
    // 취약점: 명령 인젝션
    fgets(command, sizeof(command), stdin);
    
    if (strncmp(command, "shell", 5) == 0) {
        printf("Dropping to shell...\n");
        system("/bin/bash");
    } else if (strncmp(command, "caninfo", 7) == 0) {
        system("ip link show vcan0");
        system("candump vcan0 -n 10");
    }
}

void handle_diagnostics() {
    char input[256];
    printf("Enter diagnostic command: ");
    
    // 취약점: 버퍼 오버플로우 (global_buffer는 64바이트)
    fgets(input, sizeof(input), stdin);
    strcpy(global_buffer, input);
    
    // 숨겨진 디버그 모드 활성화 코드
    if (strstr(global_buffer, "ENABLE_DEBUG_MODE_12345") != NULL) {
        debug_mode = 1;
        printf("Debug mode enabled!\n");
        return;
    }
    
    printf("Diagnostic result: %s", global_buffer);
}

void send_can_message(int can_socket, int can_id, char* data, int len) {
    struct can_frame frame;
    frame.can_id = can_id;
    frame.can_dlc = len;
    memcpy(frame.data, data, len);
    
    write(can_socket, &frame, sizeof(struct can_frame));
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // CAN 소켓 설정
    int can_socket;
    struct sockaddr_can can_addr;
    struct ifreq ifr;
    
    can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(can_socket, SIOCGIFINDEX, &ifr);
    can_addr.can_family = AF_CAN;
    can_addr.can_ifindex = ifr.ifr_ifindex;
    bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr));
    
    // TCP 서버 설정
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_socket, 5);
    
    printf("Infotainment system listening on port %d\n", PORT);
    
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        // 클라이언트별 처리 (간단하게 fork 사용)
        if (fork() == 0) {
            close(server_socket);
            dup2(client_socket, STDIN_FILENO);
            dup2(client_socket, STDOUT_FILENO);
            dup2(client_socket, STDERR_FILENO);
            
            int choice;
            while (1) {
                show_menu();
                scanf("%d", &choice);
                getchar(); // 개행문자 제거
                
                switch (choice) {
                    case 1:
                        printf("Radio: Playing FM 101.5\n");
                        break;
                    case 2:
                        printf("Navigation: GPS Ready\n");
                        break;
                    case 3:
                        handle_diagnostics();
                        break;
                    case 9:
                        if (debug_mode) {
                            debug_menu();
                        } else {
                            printf("Invalid option\n");
                        }
                        break;
                    case 0:
                        printf("Goodbye!\n");
                        exit(0);
                    default:
                        printf("Invalid option\n");
                }
            }
        }
        close(client_socket);
    }
    
    return 0;
}
