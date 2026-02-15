#include "engine.h"
#include "utils.h"
#include <stdio.h>

#define MAX_STAGES 16

static const DetectionStage *stages[MAX_STAGES];
static int stage_count = 0;

void engine_register(const DetectionStage *stage)
{
    if (stage_count < MAX_STAGES)
        stages[stage_count++] = stage;
}

int engine_run_all(DWORD pid)
{
    int total_findings = 0;
    StageResult results[MAX_STAGES] = {0};

    for (int i = 0; i < stage_count; i++) {
        const DetectionStage *s = stages[i];

        printf("\n [*] phase %d: %s\n", i + 1, s->name);

        s->run(pid, &results[i]);

        if (results[i].ok == 0) {
            s->report(&results[i]);
            total_findings += results[i].findings;
        }
    }

    printf("\n [*] summary\n");

    if (total_findings == 0) {
        print_ok("process %lu appears clean", pid);
    } else {
        print_err("process %lu: %d finding(s) detected", pid, total_findings);
        for (int i = 0; i < stage_count; i++) {
            if (results[i].ok == 0 && results[i].findings > 0)
                print_err("  - %s: %d finding(s)", stages[i]->name, results[i].findings);
        }
    }

    for (int i = 0; i < stage_count; i++) {
        if (results[i].ok == 0)
            stages[i]->cleanup(&results[i]);
    }

    printf("\n");
    return total_findings > 0 ? 2 : 0;
}
