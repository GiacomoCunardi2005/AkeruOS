#include "nikon_v11_memdump_worker.h"
#include "nikon_v11_runtime.h"
#include <assert.h>
#include <string.h>

static struct akeru_nikon_v11_task_template task;
static unsigned dumps, creates, run_inline;
static uint32_t next_id;
static uint32_t base_error;
static const char *base_path = "B:";
static uint32_t volume_error;
static uint8_t volume_ready = 1;
static unsigned reserve_calls, close_calls, exists, reserve_error, close_error, close_retains, change_path;
static unsigned delay_calls, ready_after;

void nikon_v11_memdump_original(void) { ++dumps; }
uint32_t nikon_v11_volume_status_original(const char *name, uint8_t *ready) {
    assert(strcmp(name, "B:") == 0);
    if (volume_error) return volume_error;
    *ready = volume_ready;
    return 0;
}
uint32_t nikon_v11_output_base_original(char *buffer) {
    if (base_error) return base_error;
    strcpy(buffer, base_path);
    return 0;
}
uint32_t nikon_v11_open_new_original(const char *name, uint32_t mode, void **handle) {
    assert(strcmp(name, "B:\\MEMDUMP.BIN") == 0 && mode == 3 && *handle == 0);
    ++reserve_calls;
    if (reserve_error || exists) return 0x1a00011;
    exists = 1;
    *handle = (void *)(uintptr_t)0x1234;
    return 0;
}
uint32_t nikon_v11_close_original(void **handle) {
    assert(*handle == (void *)(uintptr_t)0x1234);
    ++close_calls;
    if (close_error) return close_error;
    if (!close_retains) *handle = 0;
    if (change_path) base_path = "A:";
    return 0;
}
void nikon_v11_delay_ms_original(uint32_t ms) {
    assert(ms == 1000);
    ++delay_calls;
    if (ready_after && delay_calls == ready_after) volume_ready = 1;
}
void nikon_v11_get_ticks_original(struct akeru_nikon_v11_ticks *t) { (void)t; }
uint32_t nikon_v11_ticks_to_time_original(const struct akeru_nikon_v11_ticks *t,
    struct akeru_nikon_v11_seconds_ms *s) { (void)t; (void)s; return 0; }
uint32_t nikon_v11_create_task_original(uint32_t cpu, uint32_t index,
    const struct akeru_nikon_v11_task_template *record)
{
    assert(cpu == 0 && index == 0);
    ++creates;
    task = *record;
    if (run_inline && next_id != 0) task.entry(task.parameter);
    return next_id;
}

int main(void)
{
    uint32_t id = 99;
    assert(akeru_nikon_v11_memdump_start(17, 0) == AKERU_NIKON_V11_ARGUMENT);
    assert(creates == 0 && dumps == 0);
    next_id = 0;
    assert(akeru_nikon_v11_memdump_start(17, &id) == AKERU_NIKON_V11_CREATE);
    assert(id == 0 && creates == 1 && dumps == 0);
    next_id = 42;
    assert(akeru_nikon_v11_memdump_start(17, &id) == AKERU_NIKON_V11_OK);
    assert(id == 42 && creates == 2 && dumps == 0);
    assert(task.index == 0 && task.parameter == 0 && task.stack_bytes == 0x8000);
    assert(task.priority == 17 && task.attributes == 0 && task.timeslice == 0);
    assert(strcmp(task.name, "MEMDUMP") == 0);
    task.entry(task.parameter);
    assert(dumps == 1);
    assert(exists && reserve_calls == 1 && close_calls == 1);
    volume_ready = 0;
    delay_calls = 0;
    task.entry(task.parameter);
    assert(delay_calls == 29 && dumps == 1);
    volume_ready = 1;
    volume_error = 1;
    task.entry(task.parameter);
    volume_error = 0;
    base_error = 1;
    task.entry(task.parameter);
    base_error = 0;
    base_path = "A:";
    task.entry(task.parameter);
    base_path = "B:\\DCIM";
    task.entry(task.parameter);
    assert(dumps == 1);
    base_path = "B:";
    task.entry(task.parameter); /* existing file: do not start diagnostic */
    assert(dumps == 1 && close_calls == 1);
    exists = 0; reserve_error = 1;
    task.entry(task.parameter);
    reserve_error = 0;
    assert(dumps == 1 && !exists);
    close_error = 1;
    task.entry(task.parameter);
    close_error = 0;
    assert(dumps == 1 && exists);
    exists = 0; close_retains = 1;
    task.entry(task.parameter);
    close_retains = 0;
    assert(dumps == 1 && exists);
    exists = 0; change_path = 1;
    task.entry(task.parameter);
    change_path = 0;
    assert(dumps == 1 && exists && strcmp(base_path, "A:") == 0);
    exists = 0; base_path = "B:";
    run_inline = 1;
    assert(akeru_nikon_v11_memdump_start(19, &id) == AKERU_NIKON_V11_OK);
    assert(id == 42 && task.priority == 19 && dumps == 2 && creates == 3);
    exists = 0; volume_ready = 0; delay_calls = 0; ready_after = 2;
    task.entry(task.parameter);
    assert(delay_calls == 2 && volume_ready == 1 && dumps == 3 && exists);
    return 0;
}
