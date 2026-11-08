#ifndef AKERU_NIKON_V11_SD_MARKER_H
#define AKERU_NIKON_V11_SD_MARKER_H
#include <stdint.h>

extern uint32_t nikon_v11_fs_wait_original(void *semaphore); /* 0x23ECA4 */
extern uint32_t nikon_v11_fs_post_original(void *semaphore); /* 0x23EE48 */

/* Caller owns a live upper-wrapper r handle opened for B:\AKERUDMP.ON and
 * retains it throughout this check and the subsequent pinned session.
 * 1 identifies its copied root FAT record, 0 rejects, -1 is a semaphore error.
 * No open/create/close, no card write, no guarantee of physical persistence.
 * Never call while holding the FS semaphore: Nikon wait is not recursive.
 * On -1 retain/quarantine the live file: even failed wait may consume a token;
 * do not close or retry blindly with synchronization state unknown.
 */
int akeru_nikon_v11_sd_marker_check(const void *file);
#endif
