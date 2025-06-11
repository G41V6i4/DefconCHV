#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CAN_INTERFACE "vcan0"
#define WEB_PORT 8888
#define MEDIA_PORT 9999

// Global variables
int running = 1;
int can_socket;
int web_server_socket;
char current_user[32] = "guest";
int auth_level = 0;

// Vulnerable media player
typedef struct {
    char title[64];
    char artist[64];
    char album[64];
    int duration;
    char playlist[256];  // Vulnerable!
} media_info_t;

media_info_t current_media = {0};

// Hidden shell function
void spawn_shell() {
    system("/bin/sh");
}

// Vulnerable web server handler
void handle_http_request(int client_socket) {
    char buffer[1024] = {0};
    char response[4096] = {0};
    char method[16], path[256], version[16];
    
    // Read HTTP request
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    // Parse request
    sscanf(buffer, "%s %s %s", method, path, version);
    
    // Vulnerable path handling - directory traversal
    if (strstr(path, "/files/")) {
        char filepath[512];
        sprintf(filepath, "./media%s", path + 6);  // Vulnerable!
        
        FILE *file = fopen(filepath, "r");
        if (file) {
            char file_content[2048];
            fread(file_content, 1, sizeof(file_content) - 1, file);
            fclose(file);
            
            sprintf(response, "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: %ld\r\n"
                            "\r\n%s", 
                            strlen(file_content), file_content);
        } else {
            sprintf(response, "HTTP/1.1 404 Not Found\r\n\r\n");
        }
    }
    // Vulnerable command injection in media control
    else if (strstr(path, "/play?file=")) {
        char *filename = strstr(path, "file=") + 5;
        char command[256];
        
        // Extract filename (URL decode would be here)
        char decoded_filename[128];
        strcpy(decoded_filename, filename);  // Simplified, vulnerable!
        
        // Command injection vulnerability!
        sprintf(command, "mplayer %s", decoded_filename);
        system(command);  // Direct command execution!
        
        sprintf(response, "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "\r\nPlaying: %s", decoded_filename);
    }
    // Vulnerable stack overflow in profile update
    else if (strstr(path, "/profile/update")) {
        char username[32];
        char profile_data[64];  // Small buffer
        
        // Parse POST data (simplified)
        char *post_data = strstr(buffer, "\r\n\r\n");
        if (post_data) {
            post_data += 4;
            
            // Vulnerable sscanf - stack overflow!
            sscanf(post_data, "username=%s&data=%s", username, profile_data);
            
            sprintf(response, "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "\r\nProfile updated for %s", username);
        }
    }
    // Format string vulnerability in logging
    else if (strstr(path, "/log")) {
        char *log_msg = strstr(path, "msg=");
        if (log_msg) {
            log_msg += 4;
            char log_entry[256];
            
            // Format string vulnerability!
            sprintf(log_entry, log_msg);
            printf(log_entry);  // Direct printf!
            
            sprintf(response, "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "\r\nLogged: %s", log_entry);
        }
    }
    else {
        sprintf(response, "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n"
                        "\r\n<html><body><h1>Infotainment System</h1>"
                        "<p>Current User: %s</p>"
                        "<p>Auth Level: %d</p>"
                        "</body></html>", 
                        current_user, auth_level);
    }
    
    send(client_socket, response, strlen(response), 0);
    close(client_socket);
}

// Vulnerable CAN message handler
void process_can_message(struct can_frame *frame) {
    if (frame->can_dlc < 3) return;
    
    uint16_t session_id = (frame->data[0] << 8) | frame->data[1];
    uint8_t *data = frame->data + 2;
    int data_length = frame->can_dlc - 2;
    
    // Media control commands
    if (frame->can_id == 0x300) {
        uint8_t cmd = data[0];
        
        switch (cmd) {
            case 0x01:  // Play media
                if (data_length > 1) {
                    // Vulnerable strcpy!
                    char filename[64];
                    memcpy(filename, data + 1, data_length - 1);
                    filename[data_length - 1] = '\0';
                    
                    strcpy(current_media.playlist, filename);  // Buffer overflow!
                    printf("Playing: %s\n", filename);
                }
                break;
                
            case 0x02:  // Update metadata
                if (data_length > 1) {
                    // Another overflow
                    memcpy(current_media.title, data + 1, data_length - 1);
                }
                break;
                
            case 0x03:  // System command (hidden feature)
                if (auth_level >= 2 && data_length > 1) {
                    char command[128];
                    memcpy(command, data + 1, data_length - 1);
                    command[data_length - 1] = '\0';
                    
                    // Direct command execution!
                    system(command);
                }
                break;
        }
    }
    // Authentication service
    else if (frame->can_id == 0x301) {
        uint8_t auth_cmd = data[0];
        
        if (auth_cmd == 0x01 && data_length > 1) {
            // Simple auth check (vulnerable logic)
            uint32_t password;
            memcpy(&password, data + 1, 4);
            
            if (password == 0xDEADBEEF) {
                auth_level = 1;
                strcpy(current_user, "user");
            } else if (password == 0x13371337) {
                auth_level = 2;
                strcpy(current_user, "admin");
            }
            
            // Send response
            struct can_frame response;
            response.can_id = 0x381;
            response.can_dlc = 4;
            response.data[0] = frame->data[0];
            response.data[1] = frame->data[1];
            response.data[2] = 0x01;  // Auth response
            response.data[3] = auth_level;
            
            write(can_socket, &response, sizeof(response));
        }
    }
    // Firmware update service (vulnerable!)
    else if (frame->can_id == 0x3FF) {
        static uint8_t firmware_buffer[4096];
        static int fw_offset = 0;
        
        uint8_t cmd = data[0];
        
        if (cmd == 0x01) {  // Start update
            fw_offset = 0;
            memset(firmware_buffer, 0, sizeof(firmware_buffer));
        }
        else if (cmd == 0x02) {  // Write data
            if (data_length > 1) {
                // Integer overflow + buffer overflow!
                int write_size = data[1];
                if (fw_offset + write_size <= sizeof(firmware_buffer)) {
                    memcpy(firmware_buffer + fw_offset, data + 2, write_size);
                    fw_offset += write_size;
                }
                // No proper bounds checking!
            }
        }
        else if (cmd == 0x03) {  // Execute update
            // Dangerous! Executes buffer content
            void (*fw_function)() = (void(*)())firmware_buffer;
            fw_function();  // Code execution!
        }
    }
}

// Vulnerable configuration loader
void load_config() {
    char config_buffer[256];
    FILE *config = fopen("infotainment.conf", "r");
    
    if (config) {
        while (fgets(config_buffer, sizeof(config_buffer), config)) {
            char key[64], value[192];
            
            // Vulnerable sscanf
            if (sscanf(config_buffer, "%s = %s", key, value) == 2) {
                if (strcmp(key, "admin_password") == 0) {
                    // Store password insecurely
                    strcpy(current_user, value);  // Overflow!
                }
                else if (strcmp(key, "media_path") == 0) {
                    strcpy(current_media.playlist, value);  // Another overflow!
                }
            }
        }
        fclose(config);
    }
}

// Web server thread
void *web_server_thread(void *arg) {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Create socket
    if ((web_server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return NULL;
    }
    
    // Bind
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(WEB_PORT);
    
    if (bind(web_server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return NULL;
    }
    
    // Listen
    if (listen(web_server_socket, 3) < 0) {
        perror("listen");
        return NULL;
    }
    
    printf("Infotainment web server listening on port %d\n", WEB_PORT);
    
    while (running) {
        int client_socket = accept(web_server_socket, 
                                  (struct sockaddr *)&address, 
                                  (socklen_t*)&addrlen);
        
        if (client_socket >= 0) {
            handle_http_request(client_socket);
        }
    }
    
    return NULL;
}

// CAN receive thread
void *can_receive_thread(void *arg) {
    struct can_frame frame;
    
    while (running) {
        int nbytes = read(can_socket, &frame, sizeof(frame));
        if (nbytes > 0) {
            process_can_message(&frame);
        }
    }
    
    return NULL;
}

// Signal handler
void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    struct sockaddr_can addr;
    struct ifreq ifr;
    pthread_t can_thread, web_thread;
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Print some helpful information
    printf("Infotainment ECU starting...\n");
    printf("Hidden functions:\n");
    printf("  - spawn_shell: %p\n", spawn_shell);
    printf("  - system: %p\n", system);
    
    // Load vulnerable configuration
    load_config();
    
    // Create CAN socket
    can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_socket < 0) {
        perror("socket");
        return 1;
    }
    
    // Get interface index
    strcpy(ifr.ifr_name, CAN_INTERFACE);
    if (ioctl(can_socket, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        return 1;
    }
    
    // Bind socket
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(can_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    printf("Infotainment ECU started on %s\n", CAN_INTERFACE);
    
    // Start threads
    pthread_create(&can_thread, NULL, can_receive_thread, NULL);
    pthread_create(&web_thread, NULL, web_server_thread, NULL);
    
    // Main loop
    while (running) {
        sleep(1);
    }
    
    // Cleanup
    pthread_join(can_thread, NULL);
    pthread_join(web_thread, NULL);
    close(can_socket);
    close(web_server_socket);
    
    return 0;
}