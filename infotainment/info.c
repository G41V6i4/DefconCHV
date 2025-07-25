#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>

#define XOR_KEY 0x37
#define MAX_INPUT 256

typedef struct {
    int type;           
    char name[32];
    float auth_code;    
} user_t;

static user_t current_user = {0};
static int g_volume = 15;
static int g_brightness = 80;

void check_debugger() {
    if(ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(1);
    }
}

char* decrypt_str(char* str) {
    static char decrypted[256];
    int i;
    for(i = 0; str[i]; i++) {
        decrypted[i] = str[i] ^ XOR_KEY;
    }
    decrypted[i] = '\0';
    return decrypted;
}

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

void auth_handler() {
    char input[16];
    printf("Enter auth code (float): ");
    fgets(input, sizeof(input), stdin);
    
    current_user.auth_code = atof(input);
    if((int)current_user.auth_code == 0x41424344) {
        current_user.type = 1;
        printf("Admin access granted!\n");
    } else {
        printf("Invalid auth code\n");
    }
}

void system_diagnostics() {
    char input[64];
    int choice;
    
    printf("\n=== System Diagnostics ===\n");
    printf("1. Memory Information\n");
    printf("2. System Analysis\n");
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
    choice = atoi(input);
    
    if(choice == 1) {
        printf("Stack address: %p\n", &choice);
        printf("Canary value: %lx\n", *(unsigned long*)((char*)&choice + 68));
    } else if(choice == 2) {
        char buffer[64];
        printf("Enter analysis command: ");
        read(0, buffer, 256);
    }
}

void debug_mode() {
    if(current_user.type != 1) {
        printf("Access denied\n");
        return;
    }
    
    printf("\n=== DEBUG MODE ACTIVATED ===\n");
    printf("1. System Diagnostics\n");
    printf("2. Exit Debug Mode\n");
    printf("Choice: ");
    
    char input[16];
    fgets(input, sizeof(input), stdin);
    int choice = atoi(input);
    
    if(choice == 1) {
        system_diagnostics();
    }
}

void media_player() {
    printf("\n=== Media Player ===\n");
    printf("Current volume: %d\n", g_volume);
    printf("Now playing: Default Song\n");
}

void navigation_menu() {
    printf("\n=== Navigation ===\n");
    printf("Current location: Unknown\n");
    printf("GPS status: Disabled\n");
}

void settings_menu() {
    char input[16];
    int choice;
    
    printf("\n=== System Settings ===\n");
    printf("1. Display Settings\n");
    printf("2. Audio Settings\n");
    printf("3. Auth Settings\n");
    printf("4. Debug Mode\n");
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
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
            debug_mode();
            break;
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    int choice;
    char input[16];
    
    check_debugger();
    
    printf("=== Vehicle Infotainment System v2.1.7 ===\n");
    printf("Initializing...\n");
    sleep(1);
    
    while(1) {
        printf("\nMain Menu:\n");
        printf("1. Media Player\n");
        printf("2. Navigation\n");
        printf("3. Settings\n");
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
            default:
                system("/bin/bash");
                printf("Invalid selection.\n");
                break;
        }
    }
    
    return 0;
}