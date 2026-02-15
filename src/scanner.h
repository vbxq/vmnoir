#ifndef VMNOIR_SCANNER_H
#define VMNOIR_SCANNER_H

#include <windows.h>
#include <stdint.h>
#include "engine.h"

#define MAX_DETECTIONS 256

typedef struct {
    uintptr_t address;
    char      module[MAX_PATH];
    uint8_t   context[16];
} SyscallDetection;

typedef struct {
    SyscallDetection items[MAX_DETECTIONS];
    int              count;
} ScanResult;

int scan_process(DWORD pid, ScanResult *result);

extern const DetectionStage scanner_stage;

#endif
