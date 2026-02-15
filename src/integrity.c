#include "integrity.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <psapi.h>

static uint8_t *read_file(const char *path, DWORD *out_size)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(hFile);
        return NULL;
    }

    uint8_t *buf = (uint8_t *)malloc(file_size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read;
    if (!ReadFile(hFile, buf, file_size, &read, NULL) || read != file_size) {
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *out_size = file_size;
    return buf;
}

static uintptr_t find_ntdll_base(HANDLE hProcess)
{
    HMODULE mods[512];
    DWORD needed;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return 0;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, mods[i], name, sizeof(name))) {
            if (_stricmp(name, "ntdll.dll") == 0)
                return (uintptr_t)mods[i];
        }
    }
    return 0;
}

int check_ntdll_integrity(DWORD pid, IntegrityResult *result)
{
    memset(result, 0, sizeof(*result));

    DWORD disk_size = 0;
    uint8_t *disk_ntdll = read_file("C:\\Windows\\System32\\ntdll.dll", &disk_size);
    if (!disk_ntdll) {
        print_err("cannot read ntdll.dll from disk");
        return -1;
    }

    IMAGE_SECTION_HEADER *disk_text = pe_find_section(disk_ntdll, ".text");
    if (!disk_text) {
        print_err("cannot find .text section in disk ntdll.dll");
        free(disk_ntdll);
        return -1;
    }

    DWORD text_rva  = disk_text->VirtualAddress;
    DWORD text_raw  = disk_text->PointerToRawData;
    DWORD text_vsize = disk_text->Misc.VirtualSize;
    DWORD text_rsize = disk_text->SizeOfRawData;
    DWORD text_size  = text_vsize < text_rsize ? text_vsize : text_rsize;

    if (text_raw + text_size > disk_size)
        text_size = disk_size - text_raw;

    print_info("ntdll .text: RVA=0x%lX, RawOffset=0x%lX, Size=0x%lX",
               text_rva, text_raw, text_size);

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        print_err("cannot open process %lu (error %lu)", pid, GetLastError());
        free(disk_ntdll);
        return -1;
    }

    uintptr_t ntdll_base = find_ntdll_base(hProcess);
    if (!ntdll_base) {
        print_err("cannot find ntdll.dll in process %lu", pid);
        CloseHandle(hProcess);
        free(disk_ntdll);
        return -1;
    }

    uint8_t *mem_text = (uint8_t *)malloc(text_size);
    if (!mem_text) {
        CloseHandle(hProcess);
        free(disk_ntdll);
        return -1;
    }

    SIZE_T bytes_read;
    uintptr_t text_addr = ntdll_base + text_rva;
    if (!ReadProcessMemory(hProcess, (LPCVOID)text_addr, mem_text, text_size, &bytes_read)) {
        print_err("cannot read ntdll .text from process memory (error %lu)", GetLastError());
        free(mem_text);
        CloseHandle(hProcess);
        free(disk_ntdll);
        return -1;
    }

    uint8_t *disk_text_data = disk_ntdll + text_raw;
    DWORD compare_size = (DWORD)(bytes_read < text_size ? bytes_read : text_size);
    result->total_compared = (int)compare_size;

    for (DWORD i = 0; i < compare_size; i++) {
        if (disk_text_data[i] != mem_text[i]) {
            if (result->count >= MAX_HOOKS) break;

            HookDetection *h = &result->items[result->count];
            h->offset   = i;
            h->original = disk_text_data[i];
            h->patched  = mem_text[i];

            DWORD rva_in_ntdll = text_rva + i;
            const char *fname = pe_find_export_by_rva(disk_ntdll, rva_in_ntdll);
            if (fname)
                strncpy(h->func_name, fname, sizeof(h->func_name) - 1);
            else
                strncpy(h->func_name, "<unknown>", sizeof(h->func_name) - 1);

            result->count++;
        }
    }

    free(mem_text);
    CloseHandle(hProcess);
    free(disk_ntdll);
    return 0;
}

//// detection stage callback

static int integrity_run(DWORD pid, StageResult *out)
{
    IntegrityResult *ir = (IntegrityResult *)malloc(sizeof(IntegrityResult));
    if (!ir) { out->ok = -1; return -1; }

    out->ok = check_ntdll_integrity(pid, ir);
    if (out->ok == 0) {
        out->data = ir;
        out->findings = ir->count;
    } else {
        free(ir);
    }
    return out->ok;
}

static void integrity_report(const StageResult *res)
{
    const IntegrityResult *ir = (const IntegrityResult *)res->data;

    if (ir->count == 0) {
        print_ok("ntdll.dll integrity ok (%d bytes compared)", ir->total_compared);
        return;
    }

    printf("\n  ");
    con_color(CLR_WARN);
    printf("ntdll hooks detected: %d", ir->count);
    con_reset();
    printf("\n\n");

    for (int i = 0; i < ir->count; i++) {
        const HookDetection *h = &ir->items[i];
        print_warn("hook #%d @ .text+0x%llX : 0x%02X -> 0x%02X  [%s]",
                   i + 1, (unsigned long long)h->offset,
                   h->original, h->patched, h->func_name);
    }
    printf("\n");
}

static void integrity_cleanup(StageResult *res)
{
    free(res->data);
    res->data = NULL;
}

const DetectionStage integrity_stage = {
    .name    = "ntdll integrity check",
    .run     = integrity_run,
    .report  = integrity_report,
    .cleanup = integrity_cleanup
};
