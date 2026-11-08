#include "nikon_v11_memdump_once.h"
#include "nikon_v11_runtime.h"
#include <assert.h>

static unsigned locked, calls, reenter;
static int create_result;
static volatile uint32_t claim;
void nikon_v11_enter_critical_original(void) { assert(!locked); locked = 1; }
void nikon_v11_leave_critical_original(void) { assert(locked); locked = 0; }
int akeru_nikon_v11_memdump_start(uint32_t priority, uint32_t *id)
{
    assert(!locked && priority == 19);
    ++calls;
    if (reenter) {
        uint32_t nested = 99;
        assert(akeru_nikon_v11_memdump_start_once(&claim, 19, &nested) == 1);
        assert(nested == 0 && calls == 1);
    }
    *id = create_result ? 0 : 42;
    return create_result;
}
int main(void)
{
    uint32_t id = 99;
    assert(akeru_nikon_v11_memdump_start_once(0, 19, &id) == AKERU_NIKON_V11_ARGUMENT);
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, 0) == AKERU_NIKON_V11_ARGUMENT);
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, (uint32_t *)&claim) == AKERU_NIKON_V11_ARGUMENT);
    assert(!calls && !locked && !claim);
    reenter = 1;
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, &id) == 0);
    assert(id == 42 && claim == 1 && calls == 1 && !locked);
    id = 99;
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, &id) == 1);
    assert(id == 0 && calls == 1 && claim == 1 && !locked);
    claim = 0; calls = 0; reenter = 0; create_result = AKERU_NIKON_V11_CREATE;
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, &id) == AKERU_NIKON_V11_CREATE);
    assert(!claim && !locked && calls == 1);
    create_result = 0;
    assert(akeru_nikon_v11_memdump_start_once(&claim, 19, &id) == 0);
    assert(claim == 1 && id == 42 && calls == 2 && !locked);
    return 0;
}
