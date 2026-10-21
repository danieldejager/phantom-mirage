#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>

struct interface;
extern struct interface fuzz_iface;

void fuzz_honeyd_init(const char *config);
void fuzz_drain_events(void);

#endif
