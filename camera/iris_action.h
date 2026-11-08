#ifndef AKERU_IRIS_ACTION_H
#define AKERU_IRIS_ACTION_H

#include "../ui/menu.h"

/* Reports only whether the setter's software result matches the request. */
int akeru_iris_apply(enum akeru_action action, unsigned (*setter)(unsigned),
                     unsigned *observed);

#endif
