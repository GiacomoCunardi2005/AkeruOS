#ifndef AKERU_NIKON_V11_MEMDUMP_ONCE_H
#define AKERU_NIKON_V11_MEMDUMP_ONCE_H

#include <stdint.h>

/* Caller supplies a zero-initialized, persistent word owned exclusively by this
 * protocol. The critical-section ABI and memory ownership remain unverified on
 * the camera. Return 1 means an attempt was already claimed; 0 means the task
 * was created, not that the dump succeeded. A creation failure releases claim. */
int akeru_nikon_v11_memdump_start_once(volatile uint32_t *claim,
                                      uint32_t priority, uint32_t *task_id);

#endif
