#include "nikon_v11_sd_io.h"
#include <stddef.h>

static uint32_t file_error(const void *file)
{
    const uint8_t *p = (const uint8_t *)file + 12;
    /* Original generic wrapper+0xC, read only while the wrapper is live. */
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int akeru_nikon_v11_sd_io_take(struct akeru_nikon_v11_sd_io *io, void *native,
    void **token)
{
    if (token == NULL)
        return -1;
    *token = NULL;
    if (io == NULL || native == NULL || io->native != NULL ||
        io->issued != 0u || io->failed != 0u)
        return -1;
    io->native = native;
    io->issued = 1u;
    io->write_status = io->file_error = io->written = io->close_status = 0u;
    io->close_ownership = AKERU_NIKON_CLOSE_NOT_CALLED;
    *token = io;
    return 0;
}

int32_t akeru_nikon_v11_sd_io_write(void *context, void *token,
    const uint8_t *buffer, uint32_t bytes)
{
    struct akeru_nikon_v11_sd_io *io = context;
    if (io == NULL || token != io || io->issued != 1u ||
        io->native == NULL || io->failed != 0u || buffer == NULL ||
        bytes == 0u || bytes > INT32_MAX)
        return -1;
    io->written = 0u;
    io->write_status = nikon_v11_file_write_original(
        io->native, buffer, bytes, 0u, &io->written);
    io->file_error = file_error(io->native);
    if (io->write_status != 0u || io->file_error != 0u || io->written != bytes) {
        io->failed = 1u;
        return -1;
    }
    return (int32_t)bytes;
}

int akeru_nikon_v11_sd_io_close(void *context, void *token)
{
    struct akeru_nikon_v11_sd_io *io = context;
    void *before;
    if (io == NULL || token != io || io->issued != 1u || io->native == NULL)
        return -1;
    before = io->native;
    io->issued = 0u;
    io->close_status = nikon_v11_file_close_original(&io->native);
    if (io->native == NULL)
        io->close_ownership = AKERU_NIKON_CLOSE_CONSUMED;
    else if (io->native == before)
        io->close_ownership = AKERU_NIKON_CLOSE_RETAINED;
    else
        io->close_ownership = AKERU_NIKON_CLOSE_REPLACED;
    /* A null cell proves wrapper consumption, not private FAT cleanup. */
    if (io->close_status != 0u || io->native != NULL) {
        io->failed = 1u;
        return -1;
    }
    return 0;
}
