#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h> 
// 기존 CAN 관련 헤더 파일들은 그대로 유지 (호환성을 위해)
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#define TCP_PORT 1337
#define MAX_CLIENTS 5
#define BUFFER_SIZE 512
#define DIAG_BUFFER_SIZE 64
#define CMD_BUFFER_SIZE 256
#define CAN_INTERFACE "vcan0"
#define CAN_BRIDGE_HOST "can_bridge"
#define CAN_BRIDGE_PORT 12345

int server_fd;
int can_bridge_socket = -1;  // CAN 브릿지 서버와의 TCP 소켓
pthread_t can_thread;
volatile sig_atomic_t running = 1;

typedef struct {
    int sock_fd;
    struct sockaddr_in addr;
    int diagnostic_mode;
    int security_level;
    char session_id[17]; // 16 chars + null terminator
    time_t session_start;
    time_t last_activity;
    int command_count;
    int failed_auth_attempts;
} client_session_t;

// 세션 ID를 포함하여 메시지 전송하는 헬퍼 함수
void send_with_session(client_session_t *client, const char *message) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE, "[%s] %s", client->session_id, message);
    send(client->sock_fd, buffer, strlen(buffer), 0);
}

// 로그에 세션 ID 포함하는 헬퍼 함수
void log_with_session(client_session_t *client, const char *format, ...) {
    char message[BUFFER_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(message, BUFFER_SIZE, format, args);
    va_end(args);
    
    printf("[*] Session %s - %s\n", client->session_id, message);
}

void handle_client(int client_fd, struct sockaddr_in client_addr);
char* process_command(client_session_t *client, char *cmd);
void *can_monitor_thread(void *arg);

// CAN 메시지를 TCP를 통해 브릿지 서버로 전송하는 함수
int send_can_message(struct can_frame *frame) {
    if (can_bridge_socket < 0) {
        return -1;
    }
    
    return send(can_bridge_socket, frame, sizeof(struct can_frame), 0);
}

// CAN 브릿지 서버에 연결하는 함수
int connect_to_can_bridge() {
    struct sockaddr_in server_addr;
    struct hostent *he;
    
    // 이미 연결되어 있으면 재사용
    if (can_bridge_socket >= 0) {
        return 0;
    }
    
    // TCP 소켓 생성
    can_bridge_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (can_bridge_socket < 0) {
        perror("Failed to create CAN bridge socket");
        return -1;
    }
    
    // 호스트 이름 해석
    he = gethostbyname(CAN_BRIDGE_HOST);
    if (he == NULL) {
        perror("Failed to resolve CAN bridge hostname");
        close(can_bridge_socket);
        can_bridge_socket = -1;
        return -1;
    }
    
    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CAN_BRIDGE_PORT);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    // 연결
    if (connect(can_bridge_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to connect to CAN bridge");
        close(can_bridge_socket);
        can_bridge_socket = -1;
        return -1;
    }
    
    printf("[+] Connected to CAN bridge at %s:%d\n", CAN_BRIDGE_HOST, CAN_BRIDGE_PORT);
    return 0;
}

void sigint_handler(int sig) {
    running = 0;
}

void* client_thread_func(void *arg) {
    int *fds = (int*)arg;
    handle_client(fds[0], *(struct sockaddr_in*)&fds[1]);
    free(arg);
    return NULL;
}

int main() {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sock;
    
    srand(time(NULL));
    
    // CAN 브릿지 서버에 연결
    if (connect_to_can_bridge() == 0) {
        // CAN 모니터링 스레드 시작
        if (pthread_create(&can_thread, NULL, can_monitor_thread, NULL) != 0) {
            perror("Failed to create CAN monitoring thread");
            close(can_bridge_socket);
            can_bridge_socket = -1;
        }
    } else {
        printf("[!] Warning: Could not connect to CAN bridge. CAN functionality will be limited.\n");
    }
    
    // TCP 서버 초기화
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket");
        return 1;
    }
    
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }
    
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }
    
    printf("[+] ECU Simulator server started at port %d\n", TCP_PORT);
    
    signal(SIGINT, sigint_handler);
    
    while (running) {
        client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR)
                continue;
            perror("Accept failed");
            break;
        }
        
        printf("[+] New client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        int *thread_args = malloc(sizeof(int) + sizeof(struct sockaddr_in));
        if (thread_args == NULL) {
            perror("Failed to allocate memory");
            close(client_sock);
            continue;
        }
        
        thread_args[0] = client_sock;
        memcpy(&thread_args[1], &client_addr, sizeof(struct sockaddr_in));
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, client_thread_func, thread_args) != 0) {
            perror("Failed to create client thread");
            free(thread_args);
            close(client_sock);
            continue;
        }
        
        pthread_detach(client_thread);
    }
    
    close(server_fd);
    if (can_bridge_socket >= 0) {
        close(can_bridge_socket);
        pthread_cancel(can_thread);
        pthread_join(can_thread, NULL);
    }
    
    printf("[-] Server shut down\n");
    return 0;
}

void *can_monitor_thread(void *arg) {
    struct can_frame frame;
    ssize_t nbytes;
    
    printf("[+] CAN monitoring started via bridge\n");
    
    while (running && can_bridge_socket >= 0) {
        // CAN 브릿지로부터 메시지 수신
        nbytes = recv(can_bridge_socket, &frame, sizeof(struct can_frame), 0);
        if (nbytes <= 0) {
            if (running) {
                printf("[!] Connection to CAN bridge lost. Attempting to reconnect...\n");
                close(can_bridge_socket);
                can_bridge_socket = -1;
                
                // 재연결 시도
                if (connect_to_can_bridge() == 0) {
                    printf("[+] Reconnected to CAN bridge\n");
                    continue;
                } else {
                    printf("[!] Failed to reconnect to CAN bridge. Monitoring stopped.\n");
                    break;
                }
            }
            break;
        }
        
        if (nbytes == sizeof(struct can_frame)) {
            printf("[<] CAN RX: ID=0x%03X, Data=", frame.can_id);
            for (int i = 0; i < frame.can_dlc; i++)
                printf("%02X ", frame.data[i]);
            printf("\n");
        }
        
        usleep(10000);
    }
    
    printf("[-] CAN monitoring stopped\n");
    return NULL;
}

void diagnostic_service(client_session_t *client, char *param) {
    char response[BUFFER_SIZE];
    char buffer[64];
    
    strcpy(buffer, param); // 취약점 함수긴 한데 발전필요
    
    snprintf(response, BUFFER_SIZE, 
             "Diagnostic service executed: %s\n"
             "Result: Processing complete\n"
             "Session: %s\n"
             "Diagnostic Mode: %d", 
             buffer, client->session_id, client->diagnostic_mode);
    
    send(client->sock_fd, response, strlen(response), 0);
    
    log_with_session(client, "Executed diagnostic service: %s", buffer);
}

char* process_command(client_session_t *client, char *cmd) {
    static char output[BUFFER_SIZE];
    memset(output, 0, BUFFER_SIZE);
    
    client->command_count++;
    client->last_activity = time(NULL);
    
    if (strncmp(cmd, "help", 4) == 0) {
        snprintf(output, BUFFER_SIZE, 
            "Available commands:\n"
            "help - Display help\n"
            "status - Check system status\n"
            "session - Show session information\n"
            "exit - Close connection\n"
            "enable_diag_mode [password] - Enable diagnostic mode\n"
            "diag_service [command] - Execute diagnostic service (diagnostic mode required)\n"
            "can_send [ID] [DATA] - Send CAN message (diagnostic mode required)\n"
        );
    }
    else if (strncmp(cmd, "session", 7) == 0) {
        time_t current_time = time(NULL);
        snprintf(output, BUFFER_SIZE, 
                "Session Information:\n"
                "  Session ID: %s\n"
                "  Client: %s:%d\n"
                "  Connected for: %ld seconds\n"
                "  Commands executed: %d\n"
                "  Failed auth attempts: %d\n"
                "  Current mode: %s\n"
                "  Security level: %d",
                client->session_id,
                inet_ntoa(client->addr.sin_addr),
                ntohs(client->addr.sin_port),
                current_time - client->session_start,
                client->command_count,
                client->failed_auth_attempts,
                client->diagnostic_mode ? "Diagnostic" : "Normal",
                client->security_level);
    }
    else if (strncmp(cmd, "status", 6) == 0) {
        const char *mode_str = client->diagnostic_mode ? "Diagnostic" : "Normal";
        
        snprintf(output, BUFFER_SIZE, 
                "System status: %s\n"
                "Security level: %d\n"
                "Session ID: %s\n"
                "CAN Bridge: %s",
                mode_str, client->security_level, client->session_id,
                can_bridge_socket >= 0 ? "Connected" : "Disconnected");
    }
    else if (strncmp(cmd, "enable_diag_mode", 16) == 0) {
        char password[32];
        sscanf(cmd, "enable_diag_mode %31s", password);
        
        if (strcmp(password, "master123") == 0) {
            client->diagnostic_mode = 1;
            client->security_level = 1;
            snprintf(output, BUFFER_SIZE, 
                    "Diagnostic mode activated successfully!\n"
                    "Session ID: %s\n"
                    "You can now use diag_service and can_send commands.",
                    client->session_id);
            log_with_session(client, "Diagnostic mode enabled");
        } else {
            client->failed_auth_attempts++;
            snprintf(output, BUFFER_SIZE, 
                    "Invalid password.\n"
                    "Failed attempts: %d",
                    client->failed_auth_attempts);
            log_with_session(client, "Failed authentication attempt (%d)", 
                            client->failed_auth_attempts);
        }
    }
    else if (strncmp(cmd, "diag_service", 12) == 0) {
        if (!client->diagnostic_mode) {
            snprintf(output, BUFFER_SIZE, 
                    "Error: Diagnostic mode is not activated.\n"
                    "Session ID: %s", 
                    client->session_id);
            return output;
        }
        
        char *param = cmd + 12;
        while (*param && (*param == ' ' || *param == '\t')) param++;
        
        if (*param) {
            diagnostic_service(client, param);
            snprintf(output, BUFFER_SIZE, "");
        } else {
            snprintf(output, BUFFER_SIZE, "Usage: diag_service [command]");
        }
    }
    else if (strncmp(cmd, "can_send", 8) == 0) {
        if (!client->diagnostic_mode) {
            snprintf(output, BUFFER_SIZE, 
                    "Error: Diagnostic mode is not activated.\n"
                    "Session ID: %s", 
                    client->session_id);
            return output;
        }
        
        if (can_bridge_socket < 0) {
            // CAN 브릿지에 연결 시도
            if (connect_to_can_bridge() != 0) {
                snprintf(output, BUFFER_SIZE, "Error: CAN bridge not available. Unable to send CAN messages.");
                return output;
            }
        }
        
        unsigned int can_id;
        char data_str[64];
        
        if (sscanf(cmd, "can_send %x %63s", &can_id, data_str) == 2) {
            unsigned char data[8];
            memset(data, 0, sizeof(data));
            
            size_t len = strlen(data_str);
            if (len > 16) len = 16;
            
            for (size_t i = 0; i < len/2; i++) {
                unsigned int byte;
                if (sscanf(data_str + i*2, "%2x", &byte) == 1) {
                    data[i] = (unsigned char)byte;
                }
            }
            
            struct can_frame frame;
            memset(&frame, 0, sizeof(frame));
            
            // 세션 ID를 확장 CAN ID에 인코딩
            unsigned int session_hash = 0;
            for (int i = 0; i < 16; i++) {
                session_hash = session_hash * 31 + client->session_id[i];
            }
            session_hash &= 0xFFFF;  // 16비트로 제한
            
            // 확장 CAN ID 생성 (세션 해시 + 원본 ID)
            frame.can_id = 0x80000000 | (session_hash << 11) | (can_id & 0x7FF);
            frame.can_dlc = len/2;
            memcpy(frame.data, data, frame.can_dlc);
            
            // CAN 브릿지로 메시지 전송
            if (send_can_message(&frame) == sizeof(frame)) {
                snprintf(output, BUFFER_SIZE, 
                        "CAN message sent successfully:\n"
                        "  Session: %s (0x%04X)\n"
                        "  Original ID: 0x%X\n"
                        "  Extended ID: 0x%X\n"
                        "  Data: ", 
                        client->session_id, session_hash, can_id, frame.can_id);
                char *p = output + strlen(output);
                for (int i = 0; i < frame.can_dlc; i++) {
                    p += sprintf(p, "%02X ", frame.data[i]);
                }
                log_with_session(client, "CAN message sent: ID=0x%X (Extended: 0x%X)", 
                               can_id, frame.can_id);
            } else {
                snprintf(output, BUFFER_SIZE, "Error: Failed to send CAN message. Check CAN bridge connection.");
            }
        } else {
            snprintf(output, BUFFER_SIZE, "Usage: can_send [ID] [DATA]");
        }
    }
    else if(strncmp(cmd, "shell", 5) == 0) {
        // 쉘이 시작된다는 메시지 전송
        snprintf(output, BUFFER_SIZE, "쉘 세션을 시작합니다...\n");
        send(client->sock_fd, output, strlen(output), 0);
        
        // 입출력 리디렉션 생성
        dup2(client->sock_fd, STDIN_FILENO);
        dup2(client->sock_fd, STDOUT_FILENO);
        dup2(client->sock_fd, STDERR_FILENO);
        
        // 쉘 실행 (대화형 모드)
        system("/bin/sh -i");
        
        // 쉘 종료 후 일반 모드로 복귀
        snprintf(output, BUFFER_SIZE, "\n쉘 세션이 종료되었습니다. ECU 시뮬레이터로 돌아갑니다.\n");
    }
    else {
        snprintf(output, BUFFER_SIZE, "Unknown command. Type 'help' to see available commands.");
    }
    
    return output;
}

void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    client_session_t client = {0};
    
    client.sock_fd = client_fd;
    client.addr = client_addr;
    client.diagnostic_mode = 0;
    client.security_level = 0;
    client.session_start = time(NULL);
    client.last_activity = client.session_start;
    client.command_count = 0;
    client.failed_auth_attempts = 0;
    
    // 세션 ID 생성
    for (int i = 0; i < sizeof(client.session_id) - 1; i++) {
        client.session_id[i] = "0123456789ABCDEF"[rand() % 16];
    }
    client.session_id[sizeof(client.session_id) - 1] = '\0';
    
    snprintf(buffer, BUFFER_SIZE, 
             "Connected to Automotive ECU Simulator\n"
             "Session ID: %s\n"
             "Client: %s:%d\n"
             "Time: %s"
             "CAN Bridge Status: %s\n"
             "Type 'help' for available commands\n"
             "> ", 
             client.session_id,
             inet_ntoa(client_addr.sin_addr),
             ntohs(client_addr.sin_port),
             ctime(&client.session_start),
             can_bridge_socket >= 0 ? "Connected" : "Disconnected");
    send(client_fd, buffer, strlen(buffer), 0);
    
    log_with_session(&client, "Client connected from %s:%d", 
                     inet_ntoa(client_addr.sin_addr), 
                     ntohs(client_addr.sin_port));
    
    while (running) {
        memset(buffer, 0, BUFFER_SIZE);
        nbytes = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        
        if (nbytes <= 0) {
            break;
        }
        
        char *nl = strchr(buffer, '\n');
        if (nl) *nl = '\0';
        nl = strchr(buffer, '\r');
        if (nl) *nl = '\0';
        
        log_with_session(&client, "Command received: %s", buffer);
        
        if (strcmp(buffer, "exit") == 0) {
            snprintf(buffer, BUFFER_SIZE, 
                    "Goodbye!\n"
                    "Session %s terminated.\n"
                    "Total commands: %d\n"
                    "Session duration: %ld seconds\n",
                    client.session_id,
                    client.command_count,
                    time(NULL) - client.session_start);
            send(client_fd, buffer, strlen(buffer), 0);
            break;
        }
        
        char *response = process_command(&client, buffer);
        if (strlen(response) > 0) {
            send(client_fd, response, strlen(response), 0);
            snprintf(buffer, BUFFER_SIZE, "\n[%s]> ", client.session_id);
            send(client_fd, buffer, strlen(buffer), 0);
        }
    }
    
    log_with_session(&client, "Client disconnected. Commands: %d, Duration: %ld seconds",
                     client.command_count,
                     time(NULL) - client.session_start);
    close(client_fd);
}
