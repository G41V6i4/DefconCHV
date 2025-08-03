
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#define XOR_KEY 0x37
#define MAX_INPUT 256

#define AUTH_MAGIC 0x41424344
#define VERSION_MAJOR 2
#define VERSION_MINOR 1
#define VERSION_PATCH 7

typedef struct {
    int type;           
    char name[32];
    float auth_code;    
} user_t;

typedef union {
    double d;
    struct {
        unsigned int lo;
        unsigned int hi;
    } i;
    unsigned long l;
} converter_t;

typedef struct {
    char name[16];
    char firmware_info[100];
    int version;
    int status_code;
    void (*status_handler)(void*);
    char* debug_info;
} small_device_t;

typedef struct {
    char name[16];
    char firmware_info[400];
    int version;
    int status_code;
    void (*status_handler)(void*);
    char* debug_info;
} large_device_t;

static user_t current_user = {0};
static int g_volume = 15;
static int g_brightness = 80;
static void* device_list[3] = {0};
static int device_types[3] = {0};

int main();

void check_debugger() {

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

bool validate_version_format(const char* input) {
    return strstr(input, ".") != NULL;
}

void show_small_device_status(void* dev) {
    small_device_t* device = (small_device_t*)dev;
    printf("Device: %s\n", device->name);
    printf("Firmware: %s\n", device->firmware_info);
    printf("Version: %d\n", device->version);
    printf("Status: %s\n", device->status_code == 1 ? "OK" : "ERROR");
    if(device->debug_info) {
        printf("Debug: %s\n", device->debug_info);
    }
}

void show_large_device_status(void* dev) {
    large_device_t* device = (large_device_t*)dev;
    printf("Device: %s\n", device->name);
    printf("Firmware: %s\n", device->firmware_info);
    printf("Version: %d\n", device->version);
    printf("Status: %s\n", device->status_code == 1 ? "OK" : "ERROR");
    if(device->debug_info) {
        printf("Debug: %s\n", device->debug_info);
    }
}

void device_manager() {
    if(current_user.type < 1) {
        printf("Admin access required\n");
        return;
    }
    
    char input[32];
    printf("\n=== Device Manager ===\n");
    printf("1. Add Basic Device\n");
    printf("2. Add Advanced Device\n");
    printf("3. Show Device Status\n");
    printf("4. Update Firmware Info\n");
    if(current_user.type >= 2) {
        printf("5. Free Device\n");
        printf("6. Advanced Diagnostics\n");
        printf("7. Allocate Test Chunk\n");
    }
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
    int choice = atoi(input);
    
    if(choice == 1) {
        for(int i = 0; i < 3; i++) {
            if(!device_list[i]) {
                small_device_t* dev = malloc(sizeof(small_device_t));
                printf("Device name: ");
                fgets(dev->name, 16, stdin);
                dev->name[strcspn(dev->name, "\n")] = 0;
                strcpy(dev->firmware_info, "Basic device firmware v1.0");
                dev->version = 100;
                dev->status_code = 1;
                dev->status_handler = show_small_device_status;
                dev->debug_info = NULL;
                
                device_list[i] = dev;
                device_types[i] = 1;
                printf("Basic device added to slot %d\n", i);
                return;
            }
        }
        printf("No available slots\n");
        
    } else if(choice == 2) {
        for(int i = 0; i < 3; i++) {
            if(!device_list[i]) {
                large_device_t* dev = malloc(sizeof(large_device_t));
                printf("Device name: ");
                fgets(dev->name, 16, stdin);
                dev->name[strcspn(dev->name, "\n")] = 0;
                strcpy(dev->firmware_info, "Advanced device firmware v2.0 with extended functionality and diagnostic capabilities");
                dev->version = 200;
                dev->status_code = 1;
                dev->status_handler = show_large_device_status;
                dev->debug_info = NULL;
                
                device_list[i] = dev;
                device_types[i] = 2;
                printf("Advanced device added to slot %d\n", i);
                return;
            }
        }
        printf("No available slots\n");
        
    } else if(choice == 3) {
        for(int i = 0; i < 3; i++) {
            if(device_list[i]) {
                printf("\n=== Slot %d ===\n", i);
                if(device_types[i] == 1) {
                    small_device_t* dev = (small_device_t*)device_list[i];
                    if((unsigned long)dev->status_handler > 0x400000 && 
                       (unsigned long)dev->status_handler < 0x800000000000) {
                        dev->status_handler(dev);
                    } else {
                        printf("Invalid function pointer detected: 0x%016lx\n", 
                               (unsigned long)dev->status_handler);
                        printf("Device: %s\n", dev->name);
                        printf("Firmware: %s\n", dev->firmware_info);
                    }
                } else if(device_types[i] == 2) {
                    large_device_t* dev = (large_device_t*)device_list[i];
                    if((unsigned long)dev->status_handler > 0x400000 && 
                       (unsigned long)dev->status_handler < 0x800000000000) {
                        dev->status_handler(dev);
                    } else {
                        printf("Invalid function pointer detected: 0x%016lx\n", 
                               (unsigned long)dev->status_handler);
                        printf("Device: %s\n", dev->name);
                        printf("Firmware: %s\n", dev->firmware_info);
                    }
                }
            }
        }
        
    } else if(choice == 4) {
        printf("Device slot (0-2): ");
        fgets(input, sizeof(input), stdin);
        int slot = atoi(input);
        
        if(slot >= 0 && slot < 3 && device_list[slot]) {
            printf("New firmware info: ");
            char firmware_input[500];
            fgets(firmware_input, sizeof(firmware_input), stdin);
            firmware_input[strcspn(firmware_input, "\n")] = 0;
            
            if(device_types[slot] == 1) {
                small_device_t* dev = (small_device_t*)device_list[slot];
                strcpy(dev->firmware_info, firmware_input);
            } else if(device_types[slot] == 2) {
                large_device_t* dev = (large_device_t*)device_list[slot];
                strcpy(dev->firmware_info, firmware_input);
            }
            printf("Firmware info updated\n");
        } else {
            printf("Invalid slot\n");
        }
        
    } else if(choice == 5 && current_user.type >= 2) {
        printf("Device slot to free (0-2): ");
        fgets(input, sizeof(input), stdin);
        int slot = atoi(input);
        
        if(slot >= 0 && slot < 3 && device_list[slot]) {
            free(device_list[slot]);
            device_list[slot] = NULL;
            device_types[slot] = 0;
            printf("Device freed from slot %d\n", slot);
        } else {
            printf("Invalid slot\n");
        }
        
    } else if(choice == 6 && current_user.type >= 2) {
        printf("=== Advanced Diagnostics ===\n");
        printf("System functions:\n");
        printf("printf: %p\n", printf);
        printf("system: %p\n", system);
        printf("main: %p\n", main);
        
    } else if(choice == 7 && current_user.type >= 2) {
        printf("Allocate size (1=small, 2=large): ");
        fgets(input, sizeof(input), stdin);
        int size = atoi(input);
        
        void* test_chunk;
        if(size == 1) {
            test_chunk = malloc(sizeof(small_device_t));
        } else {
            test_chunk = malloc(sizeof(large_device_t));
        }
        printf("Test chunk allocated at: %p\n", test_chunk);
        
    } else {
        if(choice == 5 || choice == 6 || choice == 7) {
            printf("Full admin access required\n");
        } else {
            printf("Invalid selection\n");
        }
    }
}


void auth_handler() {
    char input[32];
    converter_t conv;
    
    if(current_user.type == 0) {
        printf("Enter version number (x.y.z format): ");
        if (!fgets(input, sizeof(input), stdin) || !validate_version_format(input)) {
            printf("Invalid format\n");
            return;
        }
        
        conv.d = atof(input);
        
        unsigned int simple_check = conv.i.hi ^ conv.i.lo;
        
        if((simple_check & 0xFF) == VERSION_MAJOR && 
           ((simple_check >> 8) & 0xFF) == VERSION_MINOR &&
           ((simple_check >> 16) & 0xFF) == VERSION_PATCH) {
            
            printf("Version check passed! Basic access granted.\n");
            current_user.type = 1;
            current_user.auth_code = conv.d;
        } else {
            printf("Version check failed.\n");
        }
    } 
    else if(current_user.type == 1) {
        printf("Attempt full admin access? (y/n): ");
        if(fgets(input, sizeof(input), stdin) && (input[0] == 'y' || input[0] == 'Y')) {
            printf("Enter admin authentication code: ");
            if (!fgets(input, sizeof(input), stdin)) {
                printf("Input error\n");
                return;
            }
            
            unsigned int auth_input = (unsigned int)atoi(input);
            
            unsigned int auth_check = (auth_input ^ 0x1337) + 
                                    (VERSION_MAJOR << 16) + 
                                    (VERSION_MINOR << 8) + 
                                    VERSION_PATCH;
            
            if(auth_check == 0x040317) {
                current_user.type = 2;
                printf("Full admin privileges unlocked!\n");
            } else {
                printf("Access denied.\n");
            }
        }
    }
    else {
        printf("Already have full admin access.\n");
    }
}

void system_diagnostics() {
    char input[64];
    int choice;
    
    printf("\n=== System Diagnostics ===\n");
    printf("1. Memory Information\n");
    printf("2. System Analysis\n");
    printf("3. Hardware Check\n");
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
    choice = atoi(input);
    
    if(choice == 1) {
        printf("Analyzing memory layout...\n");
        
        unsigned long stack_addr = (unsigned long)&choice;
        unsigned long heap_addr = (unsigned long)malloc(16);
        unsigned long text_addr = (unsigned long)main;
        
        printf("Memory regions:\n");
        printf("  Stack region: 0x%016lx\n", stack_addr & 0xfffffffffffff000);
        printf("  Heap region:  0x%016lx\n", heap_addr & 0xfffffffffffff000);
        printf("  Text region:  0x%016lx\n", text_addr & 0xfffffffffffff000);
        
        printf("Current frame: 0x%016lx\n", stack_addr);
        
        unsigned long *frame_ptr = (unsigned long *)__builtin_frame_address(0);
        unsigned long return_addr = 0;
        if (frame_ptr && frame_ptr[1]) {
            return_addr = frame_ptr[1];
        }
        printf("Return addr:   0x%016lx\n", return_addr);
        
        printf("Security info:\n");
        printf("  ASLR: %s\n", (stack_addr & 0xfff) ? "enabled" : "disabled");
        printf("  PAC:  %s\n", (return_addr & 0xff00000000000000UL) ? "enabled" : "disabled");
        free((void*)heap_addr);
    } else if(choice == 2) {
        char buffer[64];
        char cmd[32];
        printf("Analysis type (1-3): ");
        read(0, cmd, sizeof(cmd));
        printf("Analysis parameters: ");
        read(0, buffer, sizeof(buffer));
    } else if(choice == 3) {
        printf("Hardware Status: OK\n");
        printf("CPU Temperature: 45°C\n");
        printf("Memory Usage: 67%%\n");
        printf("CAN Bus: Active\n");
    }
}

void debug_mode() {
    static int fail_count = 0;
    
    if(current_user.type < 1) {
        fail_count++;
        if(fail_count >= 3) {
            printf("Too many failed attempts\n");
            exit(1);
        }
        printf("Access denied\n");
        return;
    }
    
    printf("\n=== DEBUG MODE ACTIVATED ===\n");
    printf("1. System Diagnostics\n");
    printf("2. Device Manager\n");
    printf("3. Exit Debug Mode\n");
    printf("Choice: ");
    
    char input[16];
    fgets(input, sizeof(input), stdin);
    int choice = atoi(input);
    
    if(choice == 1) {
        system_diagnostics();
    } else if(choice == 2) {
        device_manager();
    }
}

void media_player() {
    printf("\n=== Media Player ===\n");
    printf("Current volume: %d\n", g_volume);
    printf("Now playing: Default Song\n");
}

void navigation_menu() {
    char destination[128];
    char route_data[64];
    
    printf("\n=== Navigation System ===\n");
    printf("Enter destination: ");
    
    if(fgets(destination, sizeof(destination), stdin)) {
        printf("Calculating route to: %s", destination);
        
        if(strlen(destination) > 100) {
            printf("Destination name too long, truncating...\n");
            destination[100] = '\0';
        }
        
        strncpy(route_data, destination, sizeof(route_data) - 1);
        route_data[sizeof(route_data) - 1] = '\0';
        
        printf("Route calculated successfully.\n");
        printf("Estimated time: %d minutes\n", (int)(strlen(route_data) * 2.5));
    }
}

void settings_menu() {
    char input[16];
    int choice;
    
    printf("\n=== Settings ===\n");
    printf("1. Display Settings\n");
    printf("2. Audio Settings\n");
    printf("3. System Info\n");
    printf("4. Device Manager\n");
    printf("0. Back to Main Menu\n");
    printf("Choice: ");
    
    fgets(input, sizeof(input), stdin);
    choice = atoi(input);
    
    switch(choice) {
        case 0:
            return;
        case 1:
            printf("Brightness: %d%%\n", g_brightness);
            printf("Current brightness level is optimal.\n");
            break;
        case 2:
            printf("Volume: %d\n", g_volume);
            printf("Audio settings configured.\n");
            break;
        case 3:
            printf("System Version: %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
            printf("Build Date: Nov 15 2024\n");
            printf("Hardware ID: ECU-INFO-001\n");
            break;
        case 4:
            device_manager();
            break;
        case 9:
            auth_handler();
            if(current_user.type >= 1) {
                printf("Debug option unlocked.\n");
                printf("Entering debug mode...\n");
                sleep(1);
                debug_mode();
            }
            break;
        default:
            printf("Invalid selection.\n");
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
                printf("Invalid selection.\n");
                break;
        }
    }
    
    return 0;
}