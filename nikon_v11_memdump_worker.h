#ifndef AKERU_NIKON_V11_MEMDUMP_WORKER_H
#define AKERU_NIKON_V11_MEMDUMP_WORKER_H

#include <stdint.h>

/* Offline prototype: caller must supply one-shot scheduling, a stable writable
 * SD volume and current output path, file ownership and sufficient stack.
 * The worker refuses an invalid base or a base other than exactly "B:"; this
 * separate check cannot prevent a concurrent change of Nikon's current path.
 * The Nikon volume status is checked but does not pin or verify physical SD.
 * Exclusive creation is closed before the Nikon writer reopens: another actor
 * may change the file or path in between. A failed attempt may leave an empty file.
 * Success means task creation only; it does not verify a dump or SD writes. */
int akeru_nikon_v11_memdump_start(uint32_t priority, uint32_t *task_id);

#endif
