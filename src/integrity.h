#ifndef VMNOIR_INTEGRITY_H
#define VMNOIR_INTEGRITY_H

#include <windows.h>
#include <stdint.h>
#include "engine.h"

#define MAX_HOOKS 256

typedef struct {
    uintptr_t offset;
    uint8_t   original;
    uint8_t   patched;
    char      func_name[128];
} HookDetection;

typedef struct {
    HookDetection items[MAX_HOOKS];
    int           count;
    int           total_compared;
} IntegrityResult;

int check_ntdll_integrity(DWORD pid, IntegrityResult *result);

extern const DetectionStage integrity_stage;

#endif
