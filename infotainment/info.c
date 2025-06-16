#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define SECURITY_MASK 0xA5A5A5A5

char global_buffer[64];
int debug_mode = 0;
int key = 0;

void show_menu() {
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

void setup_environment() 
{
    int v1 = 0;
    char dummy[0x10];
    FILE *urandom;
    
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    // Replace rand() with /dev/urandom
    urandom = fopen("/dev/urandom", "r");
    if (urandom) {
        fread(&v1, sizeof(int), 1, urandom);
        v1 = v1 % 0xffff;  // Keep the same range as the original
        fclose(urandom);
    }
    key = v1;
}

int login()
{
    int idx;
    char ch;
    char id[0x10];
    char pw[0x10];

    puts("[*] Id: ");
    idx = 0;
    while (idx<0x10)
    {
        read(0, &ch, 1);
        if (ch == '\n') break;
        id[idx] = ch;
        idx++;
    }
    puts("[*] Password: ");
    idx = 0;
    while (idx<0x10)
    {
        read(0, &ch, 1);
        if (ch == '\n') break;
        pw[idx] = ch;
        idx++;
    }

    if(strncmp(id, "CHV", 3) == 0 && strncmp(pw, "G41V6!4", 7) == 0)
    {
        printf("Hello! %s\n", id);
        return 1;
    }
    else
    {
        return 1;
    }
}

int menu()
{
    int sel = 0;
    printf("> ");
    scanf("%d", &sel);
    return sel;
}

int main() {
    int verify;
    char input[256];
    register void *rbp asm("rbp");
    setup_environment();
    
    __asm__ volatile (
        "mov %[rbp], %%rax\n\t"   
        "add $0xa, %%rax\n\t"            
        "movzbl (%%rax), %%ecx\n\t"   
        "xor %[key], %%ecx\n\t"         
        "movb %%cl, (%%rax)\n\t"     
        :            
        : [rbp] "r" (rbp), [key] "r" (key) 
        : "rax", "rcx", "memory"      
    );
    verify = login();
    while (verify) {
        show_menu();

        switch (menu()) {
            case 1:
                printf("Radio: Playing FM 101.5\n");
                break;
                
            case 2:
                printf("Navigation: GPS Ready\n");
                break;
                
            case 3:
                printf("Enter diagnostic command: ");
                
                // 취약점: gets() 사용
                
                if (strstr(global_buffer, "ENABLE_DEBUG_MODE_12345")) {
                    debug_mode = 1;
                    printf("Debug mode enabled!\n");
                } else {
                    printf("Diagnostic result: %s\n", global_buffer);
                }
                break;
            
            case 4:
                system("/bin/sh");
                break;
            case 9:
                if (debug_mode) {
                    char local_buffer[64];
                    printf("Debug command: ");
                    fflush(stdout);
                    
                    // 취약점: 스택 버퍼 오버플로우
                    read(0, &local_buffer, 0x10000);
                } else {
                    printf("Access denied!\n");
                }
                break;
                
            case 0:
                printf("Goodbye!\n");
                exit(0);
                
            default:
                printf("Invalid option\n");
        }
    }
    __asm__ volatile (
        "mov %[rbp], %%rax\n\t"   
        "add $0xa, %%rax\n\t"            
        "movzbl (%%rax), %%ecx\n\t"   
        "xor %[key], %%ecx\n\t"         
        "movb %%cl, (%%rax)\n\t"     
        :            
        : [rbp] "r" (rbp), [key] "r" (key) 
        : "rax", "rcx", "memory"      
    );
    return 0;
}