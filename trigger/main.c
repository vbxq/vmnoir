/**
 * code stolen from my own lib :
 * https://github.com/vbxq/libsyscallresolver/blob/main/main.c
 */
#define SSN_IMPLEMENTATION
#include "ssn.h"

#include <stdio.h>

int main(void)
{
    printf("[*] PID = %lu\n", GetCurrentProcessId());

    /* resolve SSN */
    uint32_t idx = ssn_find_idx("NtQuerySystemInformation");
    if (idx == SSN_INVALID) {
        fprintf(stderr, "[!!] failed to resolve SSN, aborting\n");
        return 1;
    }
    printf("[*] resolved NtQuerySystemInformation SSN = 0x%X\n\n", idx);

    /* execute direct syscall */
    uint8_t buffer[64] = {0};
    uint32_t ret_len = 0;

    NTSTATUS status = SYSCALL("NtQuerySystemInformation",
                              0, buffer, sizeof(buffer), &ret_len);

    printf("[*] NtQuerySystemInformation returned: 0x%lX\n\n", (unsigned long)status);

    if (status == 0) {
        printf("[*] success! returned %u bytes\n", ret_len);
        printf("[*] first bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
               buffer[0], buffer[1], buffer[2], buffer[3],
               buffer[4], buffer[5], buffer[6], buffer[7]);
    }

    printf("\n[*] waiting for VMNoir scan (60s)...\n");
    printf("[*] scan me with: vmnoir.exe %lu\n", GetCurrentProcessId());
    Sleep(60000);

    return 0;
}
