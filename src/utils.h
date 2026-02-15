#ifndef VMNOIR_UTILS_H
#define VMNOIR_UTILS_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CLR_DEFAULT = 7,
    CLR_INFO    = 11,  /* cyan */
    CLR_OK      = 10,  /* green */
    CLR_ERR     = 12,  /* red */
    CLR_WARN    = 14,  /* yellow */
    CLR_BANNER  = 13   /* magenta */
} ConsoleColor;

void con_color(ConsoleColor c);
void con_reset(void);
void print_info(const char *fmt, ...);
void print_ok(const char *fmt, ...);
void print_err(const char *fmt, ...);
void print_warn(const char *fmt, ...);

IMAGE_NT_HEADERS64 *pe_nt_headers(const uint8_t *base);
IMAGE_SECTION_HEADER *pe_find_section(const uint8_t *base, const char *name);
DWORD pe_export_rva_to_name(const uint8_t *base, DWORD rva);
const char *pe_find_export_by_rva(const uint8_t *base, DWORD rva);

void hex_dump(const uint8_t *data, size_t len, uintptr_t base_addr);

bool resolve_addr_module(HANDLE hProcess, uintptr_t addr, char *out, size_t out_sz);

#endif
