#include "iris_action.h"

int akeru_iris_apply(enum akeru_action action, unsigned (*setter)(unsigned),
                     unsigned *observed)
{
    unsigned requested, result;
    if (!setter || !observed) return -1;
    if (action == AKERU_IRIS_STATE_1) requested = 1;
    else if (action == AKERU_IRIS_STATE_9) requested = 9;
    else return -1;
    result = setter(requested);
    *observed = result;
    return result == requested;
}
