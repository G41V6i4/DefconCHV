#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>

#define PORT 1234
#define BUFFER_SIZE 1024

// 좀비 프로세스 방지
void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    char *menu = "=== Infotainment System v1.2.3 ===\n"
                 "1. Radio Control\n"
                 "2. Navigation\n" 
                 "3. Diagnostics\n"
                 "0. Exit\n"
                 "Choice: ";
    
    while (1) {
        // 메뉴 전송
        if (send(client_socket, menu, strlen(menu), 0) < 0) break;
        
        // 입력 받기
        memset(buffer, 0, BUFFER_SIZE);
        int bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) break;
        
        buffer[bytes] = '\0';
        int choice = atoi(buffer);
        
        switch (choice) {
            case 1:
                send(client_socket, "Radio: Playing FM 101.5\n\n", 25, 0);
                break;
            case 2:
                send(client_socket, "Navigation: GPS Ready\n\n", 23, 0);
                break;
            case 3: {
                send(client_socket, "Enter diagnostic command: ", 26, 0);
                memset(buffer, 0, BUFFER_SIZE);
                bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                if (bytes <= 0) break;
                
                buffer[bytes] = '\0';
                
                if (strstr(buffer, "ENABLE_DEBUG_MODE_12345") != NULL) {
                    send(client_socket, "Debug mode enabled!\nDebug> ", 28, 0);
                    memset(buffer, 0, BUFFER_SIZE);
                    bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                    if (bytes <= 0) break;
                    
                    buffer[bytes] = '\0';
                    
                    if (strstr(buffer, "shell") != NULL) {
                        send(client_socket, "Shell access granted! Use 'exit' to return.\n", 45, 0);
                        // 간단한 쉘 시뮬레이션
                        send(client_socket, "$ ", 2, 0);
                        while (1) {
                            memset(buffer, 0, BUFFER_SIZE);
                            bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                            if (bytes <= 0) break;
                            buffer[bytes] = '\0';
                            
                            if (strstr(buffer, "exit")) {
                                send(client_socket, "Exiting shell...\n\n", 18, 0);
                                break;
                            } else if (strstr(buffer, "ls")) {
                                send(client_socket, "firmware.bin  debug.log  secrets.txt\n$ ", 39, 0);
                            } else if (strstr(buffer, "cat secrets.txt")) {
                                send(client_socket, "CTF{infotainment_compromised}\n$ ", 32, 0);
                            } else {
                                send(client_socket, "Command not found\n$ ", 19, 0);
                            }
                        }
                    } else {
                        send(client_socket, "Unknown debug command\n\n", 23, 0);
                    }
                } else {
                    send(client_socket, "Diagnostic completed\n\n", 22, 0);
                }
                break;
            }
            case 0:
                send(client_socket, "Goodbye!\n", 9, 0);
                close(client_socket);
                return;
            default:
                send(client_socket, "Invalid option\n\n", 16, 0);
        }
    }
    
    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // 시그널 핸들러 설정
    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);
    
    printf("Starting Infotainment ECU Service...\n");
    
    // 소켓 생성
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    // 주소 재사용 설정
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        return 1;
    }
    
    // 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 바인드
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }
    
    // 리슨
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        return 1;
    }
    
    printf("Infotainment system listening on port %d\n", PORT);
    fflush(stdout);
    
    // 클라이언트 처리 루프
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        printf("Client connected\n");
        fflush(stdout);
        
        // fork로 클라이언트 처리
        pid_t pid = fork();
        if (pid == 0) {
            // 자식 프로세스
            close(server_socket);
            handle_client(client_socket);
            exit(0);
        } else if (pid > 0) {
            // 부모 프로세스
            close(client_socket);
        } else {
            perror("Fork failed");
            close(client_socket);
        }
    }
    
    close(server_socket);
    return 0;
}