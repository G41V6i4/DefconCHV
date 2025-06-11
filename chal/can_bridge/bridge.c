#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/can.h>  // CAN 프레임 구조체 정의를 위해

#define SERVER_PORT 12345
#define MAX_CLIENTS 20
#define BUFFER_SIZE 1024

typedef struct {
    int sock;
    struct sockaddr_in addr;
    char id[32];  // 식별자 (ip:port)
} client_t;

// 클라이언트 관리
client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// 종료 플래그
volatile sig_atomic_t running = 1;

// CAN 메시지 로깅 함수
void log_can_frame(struct can_frame *frame, const char *direction, const char *client_id) {
    printf("[%s] %s CAN ID: 0x%X, DLC: %d, Data: ", 
           client_id, direction, frame->can_id, frame->can_dlc);
    
    for (int i = 0; i < frame->can_dlc; i++) {
        printf("%02X ", frame->data[i]);
    }
    printf("\n");
}

// SIGINT 핸들러
void sigint_handler(int sig) {
    running = 0;
}

// 클라이언트 스레드 함수
void *client_handler(void *arg) {
    client_t *client = (client_t *)arg;
    struct can_frame frame;
    ssize_t bytes_read;
    
    printf("[+] Client thread started for %s\n", client->id);
    
    while (running) {
        // CAN 프레임 수신
        bytes_read = recv(client->sock, &frame, sizeof(struct can_frame), 0);
        
        if (bytes_read <= 0) {
            // 연결 종료 또는 오류
            break;
        }
        
        if (bytes_read == sizeof(struct can_frame)) {
            // 수신된 CAN 프레임 로깅
            log_can_frame(&frame, "RX", client->id);
            
            // 다른 모든 클라이언트에게 전달
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < client_count; i++) {
                if (clients[i].sock != client->sock) {
                    // 로깅
                    log_can_frame(&frame, "TX", clients[i].id);
                    
                    // 전송
                    if (send(clients[i].sock, &frame, sizeof(struct can_frame), 0) < 0) {
                        perror("Failed to forward CAN frame");
                    }
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }
    }
    
    // 클라이언트 연결 종료 처리
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sock == client->sock) {
            // 클라이언트 제거
            printf("[-] Client disconnected: %s\n", clients[i].id);
            close(clients[i].sock);
            
            // 마지막 클라이언트를 현재 위치로 이동
            if (i < client_count - 1) {
                clients[i] = clients[client_count - 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    return NULL;
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;
    
    // SIGINT 핸들러 설정
    signal(SIGINT, sigint_handler);
    
    // 서버 소켓 생성
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Failed to create socket");
        return 1;
    }
    
    // SO_REUSEADDR 옵션 설정
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_sock);
        return 1;
    }
    
    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    // 바인딩
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return 1;
    }
    
    // 리스닝
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return 1;
    }
    
    printf("[+] CAN Bridge Server started on port %d\n", SERVER_PORT);
    printf("[+] Waiting for connections...\n");
    
    // 클라이언트 연결 수락 루프
    while (running) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_sock < 0) {
            if (running) {
                perror("Accept failed");
            }
            continue;
        }
        
        pthread_mutex_lock(&clients_mutex);
        
        if (client_count < MAX_CLIENTS) {
            // 새 클라이언트 추가
            clients[client_count].sock = client_sock;
            clients[client_count].addr = client_addr;
            
            // 클라이언트 ID 생성 (IP:PORT)
            snprintf(clients[client_count].id, sizeof(clients[client_count].id), 
                    "%s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            
            printf("[+] New client connected: %s\n", clients[client_count].id);
            
            // 클라이언트 핸들러 스레드 생성
            if (pthread_create(&thread_id, NULL, client_handler, &clients[client_count]) != 0) {
                perror("Failed to create thread");
                close(client_sock);
            } else {
                pthread_detach(thread_id);
                client_count++;
            }
        } else {
            printf("[!] Too many clients. Connection rejected.\n");
            close(client_sock);
        }
        
        pthread_mutex_unlock(&clients_mutex);
    }
    
    // 종료 처리
    printf("\n[*] Shutting down server...\n");
    
    // 모든 클라이언트 연결 종료
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        printf("[-] Closing connection to %s\n", clients[i].id);
        close(clients[i].sock);
    }
    pthread_mutex_unlock(&clients_mutex);
    
    // 서버 소켓 종료
    close(server_sock);
    
    printf("[*] Server shutdown complete.\n");
    return 0;
}