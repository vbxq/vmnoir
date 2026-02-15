#ifndef VMNOIR_ENGINE_H
#define VMNOIR_ENGINE_H

#include <windows.h>

typedef struct {
    void *data;
    int   findings;
    int   ok;
} StageResult;

typedef struct {
    const char *name;
    int  (*run)(DWORD pid, StageResult *out);
    void (*report)(const StageResult *res);
    void (*cleanup)(StageResult *res);
} DetectionStage;

void engine_register(const DetectionStage *stage);
int  engine_run_all(DWORD pid);

#endif
