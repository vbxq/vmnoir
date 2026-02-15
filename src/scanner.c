#include "scanner.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <psapi.h>

#define SYSCALL_OP1  0x0F
#define SYSCALL_OP2  0x05
#define SYSENTER_OP2 0x34

static bool find_ntdll(HANDLE hProcess, uintptr_t *base, size_t *size)
{
    HMODULE mods[512];
    DWORD needed;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return false;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, mods[i], name, sizeof(name))) {
            if (_stricmp(name, "ntdll.dll") == 0) {
                MODULEINFO mi;
                if (GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi))) {
                    *base = (uintptr_t)mi.lpBaseOfDll;
                    *size = mi.SizeOfImage;
                    return true;
                }
            }
        }
    }
    return false;
}

static bool is_in_ntdll(uintptr_t addr, uintptr_t ntdll_base, size_t ntdll_size)
{
    return addr >= ntdll_base && addr < ntdll_base + ntdll_size;
}

static void scan_region(HANDLE hProcess, uintptr_t region_base, size_t region_size,
                        uintptr_t ntdll_base, size_t ntdll_size,
                        ScanResult *result)
{
    if (is_in_ntdll(region_base, ntdll_base, ntdll_size))
        return;

    uint8_t *buf = (uint8_t *)malloc(region_size);
    if (!buf) return;

    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)region_base, buf, region_size, &bytes_read)) {
        free(buf);
        return;
    }

    for (size_t i = 0; i + 1 < bytes_read; i++) {
        if (buf[i] == SYSCALL_OP1 && (buf[i + 1] == SYSCALL_OP2 || buf[i + 1] == SYSENTER_OP2)) {

            bool likely_false_positive = false;

            /* 0F 8x jcc near: 0F 05 in the 4-byte displacement */
            for (size_t off = 2; off <= 5 && off <= i; off++) {
                if (buf[i - off] == 0x0F && (buf[i - off + 1] & 0xF0) == 0x80) {
                    likely_false_positive = true;
                    break;
                }
            }

            for (size_t back = 1; back <= 6 && back <= i && !likely_false_positive; back++) {
                uint8_t pb = buf[i - back];
                if (back <= 4 && (pb == 0xE8 || pb == 0xE9))
                    { likely_false_positive = true; break; }
                if (back >= 2 && buf[i - back] == 0xFF) {
                    uint8_t modrm = buf[i - back + 1];
                    if (modrm == 0x15 || modrm == 0x25)
                        { likely_false_positive = true; break; }
                }
            }

            /* RIP-relative [REX] opcode ModRM disp32 */
            for (size_t back = 1; back <= 4 && back <= i && !likely_false_positive; back++) {
                size_t disp_start = i - back;
                if (disp_start < 2) continue;
                uint8_t modrm = buf[disp_start - 1];
                if ((modrm & 0xC7) == 0x05) {
                    uint8_t opcode = buf[disp_start - 2];
                    bool has_rex = (disp_start >= 3 &&
                                    (buf[disp_start - 3] & 0xF0) == 0x40);
                    if (opcode == 0x8D || opcode == 0x8B || opcode == 0x89 ||
                        opcode == 0x3B || opcode == 0x39 || opcode == 0x03 ||
                        opcode == 0x01 || opcode == 0x33 || opcode == 0x31 ||
                        opcode == 0x2B || opcode == 0x29) {
                        likely_false_positive = true; break;
                    }
                    if (has_rex) {
                        likely_false_positive = true; break;
                    }
                }
            }

            /* MOV r32, imm32 (B8+rd) or REX.B + MOV (41 B8+rd) */
            for (size_t back = 0; back <= 3 && back <= i && !likely_false_positive; back++) {
                size_t imm_start = i - back;
                if (imm_start < 1) continue;
                uint8_t opbyte = buf[imm_start - 1];
                if (opbyte >= 0xB8 && opbyte <= 0xBF) {
                    likely_false_positive = true; break;
                }
                if (imm_start >= 2 && (buf[imm_start - 2] & 0xF0) == 0x40 &&
                    opbyte >= 0xB8 && opbyte <= 0xBF) {
                    likely_false_positive = true; break;
                }
            }

            /* ALU eax, imm32 (05/0D/15/1D/25/2D/35/3D) */
            if (!likely_false_positive) {
                for (size_t back = 1; back <= 4 && back <= i; back++) {
                    uint8_t op = buf[i - back];
                    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
                        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D) {
                        likely_false_positive = true; break;
                    }
                }
            }

            /* VEX prefix (C4/C5) */
            if (!likely_false_positive) {
                for (size_t back = 2; back <= 10 && back <= i; back++) {
                    uint8_t vex = buf[i - back];
                    if (vex == 0xC5 || vex == 0xC4) {
                        likely_false_positive = true; break;
                    }
                }
            }
            if (likely_false_positive) continue;
            if (result->count >= MAX_DETECTIONS) break;

            SyscallDetection *det = &result->items[result->count];
            det->address = region_base + i;

            size_t ctx_start = (i >= 4) ? i - 4 : 0;
            size_t ctx_len = 16;
            if (ctx_start + ctx_len > bytes_read)
                ctx_len = bytes_read - ctx_start;
            memset(det->context, 0, sizeof(det->context));
            memcpy(det->context, buf + ctx_start, ctx_len);

            resolve_addr_module(hProcess, det->address, det->module, sizeof(det->module));

            result->count++;
        }
    }

    free(buf);
}

int scan_process(DWORD pid, ScanResult *result)
{
    memset(result, 0, sizeof(*result));

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        print_err("cannot open process %lu (error %lu)", pid, GetLastError());
        return -1;
    }

    BOOL is_wow64 = FALSE;
    IsWow64Process(hProcess, &is_wow64);
    if (is_wow64) {
        print_warn("process %lu is 32-bit (wow64), skipping scan", pid);
        CloseHandle(hProcess);
        return -1;
    }

    uintptr_t ntdll_base = 0;
    size_t ntdll_size = 0;
    if (!find_ntdll(hProcess, &ntdll_base, &ntdll_size)) {
        print_err("cannot find ntdll.dll in process %lu", pid);
        CloseHandle(hProcess);
        return -1;
    }
    print_info("ntdll.dll @ 0x%llX (size 0x%llX)",
               (unsigned long long)ntdll_base,
               (unsigned long long)ntdll_size);

    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int regions_scanned = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            scan_region(hProcess, (uintptr_t)mbi.BaseAddress, mbi.RegionSize,
                        ntdll_base, ntdll_size, result);
            regions_scanned++;
        }

        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;  /* overflow guard */
        addr = next;
    }

    print_info("scanned %d executable regions", regions_scanned);
    CloseHandle(hProcess);
    return 0;
}

/// detection stage callback

static int scanner_run(DWORD pid, StageResult *out)
{
    ScanResult *sr = (ScanResult *)malloc(sizeof(ScanResult));
    if (!sr) { out->ok = -1; return -1; }

    out->ok = scan_process(pid, sr);
    if (out->ok == 0) {
        out->data = sr;
        out->findings = sr->count;
    } else {
        free(sr);
    }
    return out->ok;
}

static void scanner_report(const StageResult *res)
{
    const ScanResult *sr = (const ScanResult *)res->data;

    if (sr->count == 0) {
        print_ok("no direct syscall opcodes detected outside ntdll");
        return;
    }

    printf("\n  ");
    con_color(CLR_ERR);
    printf("syscall detections: %d", sr->count);
    con_reset();
    printf("\n\n");

    for (int i = 0; i < sr->count; i++) {
        const SyscallDetection *d = &sr->items[i];
        print_warn("detection #%d @ 0x%llX [%s]",
                   i + 1, (unsigned long long)d->address, d->module);
        hex_dump(d->context, sizeof(d->context), d->address - 4);
        printf("\n");
    }
}

static void scanner_cleanup(StageResult *res)
{
    free(res->data);
    res->data = NULL;
}

const DetectionStage scanner_stage = {
    .name    = "syscall opcode scan",
    .run     = scanner_run,
    .report  = scanner_report,
    .cleanup = scanner_cleanup
};
