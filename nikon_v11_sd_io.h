#ifndef AKERU_NIKON_V11_SD_IO_H
#define AKERU_NIKON_V11_SD_IO_H

#include <stdint.h>

enum akeru_nikon_v11_close_ownership {
    AKERU_NIKON_CLOSE_NOT_CALLED = 0,
    AKERU_NIKON_CLOSE_CONSUMED,
    AKERU_NIKON_CLOSE_RETAINED,
    AKERU_NIKON_CLOSE_REPLACED
};

/* Zero-initialize once in caller-owned memory. The abstract token is this
 * object; native ownership remains here even after close consumes the token.
 * If native remains non-null, this object MUST outlive it. Never reinitialize
 * it to conceal a failed close, and never retry a consumed native wrapper.
 */
struct akeru_nikon_v11_sd_io {
    void *native;
    uint32_t issued, failed;
    uint32_t write_status, file_error, written, close_status;
    enum akeru_nikon_v11_close_ownership close_ownership;
};

/* Linker bindings: original V1.1 upper wrappers, not mocks in a product. */
extern uint32_t nikon_v11_file_write_original(void *file, const uint8_t *buffer,
    uint32_t bytes, uint32_t selector, uint32_t *written); /* 0x12DE3C */
extern uint32_t nikon_v11_file_close_original(void **file); /* 0x12D604 */

/* Transfer an already-owned upper-wrapper file into the adapter; the caller
 * must discard its old copy after success. token must not alias this object.
 * This does
 * not open a file or validate exclusive creation, filename, backend or volume.
 * The future session adapter must establish those preconditions first.
 */
int akeru_nikon_v11_sd_io_take(struct akeru_nikon_v11_sd_io *, void *native,
    void **token);

/* akeru_dump_io callbacks: context and token both point to the object above.
 * A short upper write is a failure: Nikon can return 0 with short/zero count
 * after an error, so the generic dumper must not retry a presumed short write.
 */
int32_t akeru_nikon_v11_sd_io_write(void *context, void *token,
    const uint8_t *buffer, uint32_t bytes);
int akeru_nikon_v11_sd_io_close(void *context, void *token);

#endif
