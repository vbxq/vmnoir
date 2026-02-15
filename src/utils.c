#include "utils.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <psapi.h>

void con_color(ConsoleColor c)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)c);
}

void con_reset(void)
{
    con_color(CLR_DEFAULT);
}

static void vprintc(ConsoleColor c, const char *prefix, const char *fmt, va_list ap)
{
    printf("%s ", prefix);
    vprintf(fmt, ap);
    printf("\n");
}

void print_info(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprintc(CLR_INFO, "[*]", fmt, ap);
    va_end(ap);
}

void print_ok(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprintc(CLR_OK, "[+]", fmt, ap);
    va_end(ap);
}

void print_err(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprintc(CLR_ERR, "[-]", fmt, ap);
    va_end(ap);
}

void print_warn(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vprintc(CLR_WARN, "[!]", fmt, ap);
    va_end(ap);
}


////// pe parsing

IMAGE_NT_HEADERS64 *pe_nt_headers(const uint8_t *base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

IMAGE_SECTION_HEADER *pe_find_section(const uint8_t *base, const char *name)
{
    IMAGE_NT_HEADERS64 *nt = pe_nt_headers(base);
    if (!nt) return NULL;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((const char *)sec[i].Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return &sec[i];
    }
    return NULL;
}

const char *pe_find_export_by_rva(const uint8_t *base, DWORD rva)
{
    IMAGE_NT_HEADERS64 *nt = pe_nt_headers(base);
    if (!nt) return NULL;

    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0 || dir->Size == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);

    const char *best_name = NULL;
    DWORD best_rva = 0;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD func_rva = funcs[ords[i]];
        if (func_rva <= rva && func_rva > best_rva) {
            best_rva = func_rva;
            best_name = (const char *)(base + names[i]);
        }
    }
    return best_name;
}

void hex_dump(const uint8_t *data, size_t len, uintptr_t base_addr)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("  %016llX  ", (unsigned long long)(base_addr + i));

        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02X ", data[i + j]);
            else             printf("   ");
            if (j == 7) printf(" ");
        }

        printf(" |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t b = data[i + j];
            printf("%c", (b >= 0x20 && b < 0x7F) ? b : '.');
        }
        printf("|\n");
    }
}

bool resolve_addr_module(HANDLE hProcess, uintptr_t addr, char *out, size_t out_sz)
{
    HMODULE mods[512];
    DWORD needed;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return false;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        MODULEINFO mi;
        if (GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi))) {
            uintptr_t lo = (uintptr_t)mi.lpBaseOfDll;
            uintptr_t hi = lo + mi.SizeOfImage;
            if (addr >= lo && addr < hi) {
                GetModuleBaseNameA(hProcess, mods[i], out, (DWORD)out_sz);
                return true;
            }
        }
    }
    strncpy(out, "<unknown>", out_sz - 1);
    out[out_sz - 1] = '\0';
    return false;
}
