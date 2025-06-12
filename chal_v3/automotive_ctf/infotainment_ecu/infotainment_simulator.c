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

#define CAN_INTERFACE "vcan0"
#define WEB_PORT 8888

int running = 1;
int can_socket;
int web_server_socket;

void spawn_shell() {
    system("/bin/sh");
}

void handle_http_request(int client_socket) {
    char buffer[1024] = {0};
    char response[4096] = {0};
    char method[16], path[256], version[16];
    
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    sscanf(buffer, "%s %s %s", method, path, version);
    
    if (strstr(path, "/play?file=")) {
        char *filename = strstr(path, "file=") + 5;
        char command[256];
        sprintf(command, "mplayer %s", filename);
        system(command);
        
        sprintf(response, "HTTP/1.1 200 OK\r\n\r\nPlaying: %s", filename);
    }
    else if (strstr(path, "/files/")) {
        char filepath[512];
        sprintf(filepath, "./media%s", path + 6);
        
        FILE *file = fopen(filepath, "r");
        if (file) {
            char file_content[2048];
            fread(file_content, 1, sizeof(file_content) - 1, file);
            fclose(file);
            sprintf(response, "HTTP/1.1 200 OK\r\n\r\n%s", file_content);
        }
    }
    else {
        sprintf(response, "HTTP/1.1 200 OK\r\n\r\n<h1>Infotainment System</h1>");
    }
    
    send(client_socket, response, strlen(response), 0);
    close(client_socket);
}

void *web_server_thread(void *arg) {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    web_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(WEB_PORT);
    
    bind(web_server_socket, (struct sockaddr *)&address, sizeof(address));
    listen(web_server_socket, 3);
    
    while (running) {
        int client_socket = accept(web_server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket >= 0) {
            handle_http_request(client_socket);
        }
    }
    return NULL;
}

int main() {
    printf("Infotainment ECU starting...\n");
    printf("Hidden functions: spawn_shell @ %p\n", spawn_shell);
    
    pthread_t web_thread;
    pthread_create(&web_thread, NULL, web_server_thread, NULL);
    
    while (running) {
        sleep(1);
    }
    
    return 0;
}
