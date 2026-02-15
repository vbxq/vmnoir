#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "utils.h"
#include "engine.h"
#include "scanner.h"
#include "integrity.h"

static void print_banner(void)
{
    printf("\n  VMNoir - proof of concept edr\n");
    printf("  2026, vbxq\n\n");
}

static void print_usage(const char *argv0)
{
    printf("usage: %s <PID> | --self | --help\n\n", argv0);
    printf("  <PID>    scan a process by its pid\n");
    printf("  --self   scan the current process\n");
    printf("  --help   show this help message\n");
}

int main(int argc, char *argv[])
{
    SetConsoleOutputCP(65001);

    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    DWORD pid;
    if (strcmp(argv[1], "--self") == 0) {
        pid = GetCurrentProcessId();
        print_info("scanning self (pid %lu)", pid);
    } else {
        char *end;
        unsigned long val = strtoul(argv[1], &end, 10);
        if (*end != '\0' || val == 0) {
            print_err("invalid pid: %s", argv[1]);
            return 1;
        }
        pid = (DWORD)val;
        print_info("scanning process pid %lu", pid);
    }

    engine_register(&scanner_stage);
    engine_register(&integrity_stage);
    return engine_run_all(pid);
}
