#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>

#define OBFUSCATE(x) ((x) ^ 0xDEADBEEF ^ 0x13371337)
#define XOR_KEY_1 0xA5A5A5A5
#define XOR_KEY_2 0x5C5C5C5C
#define XOR_KEY_3 0x3A3A3A3A

typedef struct {
    unsigned int magic;
    unsigned int xor_key;
    unsigned int data_len;
    unsigned char encrypted_data[256];
} obfuscated_config_t;

static unsigned char encrypted_can_config[] = {
    0x8F, 0xB2, 0xC1, 0x45, 0x67, 0x89, 0xAB, 0xCD,
    0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
    0x33, 0x77, 0x22, 0x88, 0x44, 0x99, 0x55, 0xAA,
    0x66, 0xBB, 0x11, 0xCC, 0x00, 0xDD, 0xEE, 0xFF
};

static unsigned char fake_data1[] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

static unsigned char fake_data2[] = {
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0x13, 0x37, 0x42, 0x69, 0x80, 0x08, 0x13, 0x37
};

char global_buffer[64];
int debug_mode = 0;
int key = 0;
int anti_debug_flag = 0;
jmp_buf recovery_point;
unsigned char *decrypted_config = NULL;

__attribute__((constructor))
void init_protection() {
    signal(SIGTRAP, (void*)0x1);
    signal(SIGILL, (void*)0x1);
    
    char *env_check = getenv("LD_PRELOAD");
    if (env_check) exit(1);
    
    if (ptrace(0, 0, 0, 0) == -1) {
        anti_debug_flag = 1;
    }
}

static inline unsigned int rotate_left(unsigned int value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

static inline unsigned int rotate_right(unsigned int value, int shift) {
    return (value >> shift) | (value << (32 - shift));
}

unsigned int complex_hash(const char *data, int len) {
    unsigned int hash = 0x811C9DC5;
    for (int i = 0; i < len; i++) {
        hash ^= (unsigned char)data[i];
        hash = rotate_left(hash, 7);
        hash *= 0x01000193;
        hash ^= rotate_right(hash, 13);
    }
    return hash;
}

void decrypt_layer1(unsigned char *data, int len, unsigned int key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= ((key >> (i % 4 * 8)) & 0xFF);
        data[i] = rotate_left(data[i], 3) & 0xFF;
        data[i] ^= (i * 0x5A);
    }
}

void decrypt_layer2(unsigned char *data, int len) {
    unsigned char prev = 0xCC;
    for (int i = 0; i < len; i++) {
        unsigned char temp = data[i];
        data[i] ^= prev;
        data[i] = ((data[i] << 2) | (data[i] >> 6)) & 0xFF;
        prev = temp;
    }
}

void decrypt_layer3(unsigned char *data, int len, unsigned int seed) {
    unsigned int lfsr = seed;
    for (int i = 0; i < len; i++) {
        unsigned int bit = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1;
        lfsr = (lfsr >> 1) | (bit << 15);
        data[i] ^= (lfsr & 0xFF);
    }
}

unsigned char* decrypt_config() {
    if (decrypted_config != NULL) return decrypted_config;
    
    decrypted_config = malloc(256);
    memcpy(decrypted_config, encrypted_can_config, 32);
    
    unsigned int key1 = complex_hash("infotainment_v2", 15) ^ XOR_KEY_1;
    decrypt_layer1(decrypted_config, 32, key1);
    
    decrypt_layer2(decrypted_config, 32);
    
    unsigned int seed = (key1 ^ XOR_KEY_2) & 0xFFFF;
    decrypt_layer3(decrypted_config, 32, seed);
    
    for (int i = 0; i < 32; i++) {
        decrypted_config[i] ^= XOR_KEY_3 >> ((i % 4) * 8);
    }
    
    return decrypted_config;
}

int verify_integrity() {
    static int check_count = 0;
    check_count++;
    
    if (check_count > 100) return 0;
    
    unsigned int expected_hash = 0x42424242;
    unsigned int actual_hash = complex_hash((char*)&verify_integrity, 64);
    
    if ((actual_hash ^ expected_hash) & 0x0F0F0F0F) {
        return 0;
    }
    
    return 1;
}

void anti_debug_check() {
    static volatile int x = 0;
    x++;
    
    if (anti_debug_flag) {
        printf("System malfunction detected\n");
        exit(1);
    }
    
    char buffer[16];
    sprintf(buffer, "/proc/%d/status", getpid());
    FILE *f = fopen(buffer, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "TracerPid:") && !strstr(line, "TracerPid:\t0")) {
                fclose(f);
                exit(1);
            }
        }
        fclose(f);
    }
}

void timing_check() {
    static unsigned long long last_time = 0;
    unsigned long long current_time;
    
    asm volatile("rdtsc" : "=A"(current_time));
    
    if (last_time != 0) {
        if (current_time - last_time > 1000000) {
            printf("Timing anomaly detected\n");
            exit(1);
        }
    }
    last_time = current_time;
}

void show_menu() {
    anti_debug_check();
    timing_check();
    
    if (!verify_integrity()) {
        printf("Integrity check failed\n");
        exit(1);
    }
    
    printf("=== Infotainment System v1.2.3 ===\n");
    printf("1. Radio Control\n");
    printf("2. Navigation\n");
    printf("3. Diagnostics\n");
    if (debug_mode) {
        printf("9. Debug Menu\n");
    }
    printf("0. Exit\n");
    printf("Choice: ");
    fflush(stdout);
}

void setup_environment() {
    int v1 = 0;
    FILE *urandom;
    
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(&v1, sizeof(int), 1, urandom);
        v1 = v1 % 0xffff;
        fclose(urandom);
    }
    key = v1 ^ OBFUSCATE(0x1337);
    
    if (setjmp(recovery_point) != 0) {
        printf("Recovery mode activated\n");
        exit(0);
    }
}

int complex_login() {
    int idx;
    char ch;
    char id[0x10];
    char pw[0x10];
    
    memset(id, 0, sizeof(id));
    memset(pw, 0, sizeof(pw));

    puts("[*] Id: ");
    idx = 0;
    while (idx < 0x10) {
        read(0, &ch, 1);
        if (ch == '\n') break;
        id[idx] = ch ^ ((idx * 7) & 0xFF);
        idx++;
    }
    
    puts("[*] Password: ");
    idx = 0;
    while (idx < 0x10) {
        read(0, &ch, 1);
        if (ch == '\n') break;
        pw[idx] = ch ^ ((idx * 11) & 0xFF);
        idx++;
    }

    char expected_id[] = {0x43^0, 0x48^7, 0x56^14};
    char expected_pw[] = {0x47^0, 0x34^11, 0x31^22, 0x56^33, 0x36^44, 0x21^55, 0x34^66};
    
    if (memcmp(id, expected_id, 3) == 0 && memcmp(pw, expected_pw, 7) == 0) {
        unsigned char *config = decrypt_config();
        printf("Authentication successful\n");
        return 1;
    } else {
        return 1;
    }
}

int obfuscated_menu() {
    int sel = 0;
    char input[8];
    
    printf("> ");
    fflush(stdout);
    
    if (read(0, input, 7) <= 0) return -1;
    
    for (int i = 0; input[i] && i < 7; i++) {
        if (input[i] >= '0' && input[i] <= '9') {
            sel = sel * 10 + (input[i] - '0');
        }
    }
    
    return sel ^ 0;
}

void extract_can_info() {
    unsigned char *config = decrypt_config();
    if (!config) return;
    
    printf("CAN Configuration:\n");
    
    unsigned int *int_config = (unsigned int*)config;
    printf("Gateway Request ID: 0x%03X\n", (int_config[0] ^ XOR_KEY_1) & 0xFFF);
    printf("Gateway Response ID: 0x%03X\n", (int_config[1] ^ XOR_KEY_2) & 0xFFF);
    printf("Engine Access ID: 0x%03X\n", (int_config[2] ^ XOR_KEY_3) & 0xFFF);
    printf("Engine Response ID: 0x%03X\n", (int_config[3] ^ (XOR_KEY_1 ^ XOR_KEY_2)) & 0xFFF);
    
    printf("Broker Port: %d\n", 9999);
    printf("Session Type: infotainment\n");
    printf("Protocol: UDS over CAN\n");
}

void advanced_diagnostic() {
    printf("Enter diagnostic command: ");
    fflush(stdout);
    
    asm volatile(
        "pushq %%rbp\n\t"
        "movq %%rsp, %%rbp\n\t"
        "subq $64, %%rsp\n\t"
        "leaq -64(%%rbp), %%rdi\n\t"
        "movq $64, %%rsi\n\t"
        "xorq %%rax, %%rax\n\t"
        "syscall\n\t"
        "movq %%rbp, %%rsp\n\t"
        "popq %%rbp\n\t"
        :
        :
        : "memory", "rax", "rdi", "rsi"
    );
    
    if (strstr(global_buffer, "ENABLE_DEBUG_MODE_12345")) {
        debug_mode = 1;
        printf("Debug mode enabled!\n");
    } else if (strstr(global_buffer, "EXTRACT_CAN_CONFIG")) {
        extract_can_info();
    } else {
        printf("Diagnostic result: %s\n", global_buffer);
    }
}

void debug_menu_handler() {
    if (!debug_mode) {
        printf("Access denied!\n");
        return;
    }
    
    char local_buffer[64];
    printf("Debug command: ");
    fflush(stdout);
    
    volatile int canary = 0xDEADBEEF;
    
    read(0, local_buffer, 0x10000);
    
    if (canary != 0xDEADBEEF) {
        printf("Stack corruption detected!\n");
        longjmp(recovery_point, 1);
    }
    
    if (strstr(local_buffer, "DUMP_MEMORY")) {
        printf("Memory dump:\n");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", ((unsigned char*)&decrypt_config)[i]);
        }
        printf("\n");
    }
    
    if (strstr(local_buffer, "GET_CAN_IDS")) {
        extract_can_info();
    }
}

int main() {
    int verify;
    
    setup_environment();
    
    for (int i = 0; i < 5; i++) {
        asm volatile(
            "movl %[key], %%eax\n\t"
            "xorl $0xDEADBEEF, %%eax\n\t"
            "roll $13, %%eax\n\t"
            "xorl $0x13371337, %%eax\n\t"
            "movl %%eax, %[key]\n\t"
            : [key] "+m" (key)
            :
            : "eax", "memory"
        );
    }
    
    verify = complex_login();
    
    while (verify) {
        show_menu();

        switch (obfuscated_menu()) {
            case 1:
                printf("Radio: Playing FM 101.5\n");
                break;
                
            case 2:
                printf("Navigation: GPS Ready\n");
                break;
                
            case 3:
                advanced_diagnostic();
                break;
            
            case 9:
                debug_menu_handler();
                break;
                
            case 0:
                printf("Goodbye!\n");
                if (decrypted_config) free(decrypted_config);
                exit(0);
                
            default:
                printf("Invalid option\n");
        }
    }
    
    return 0;
}