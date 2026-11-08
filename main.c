#include <stdint.h>

volatile uint32_t counter = 0;

void firmware_main(void)
{
    while (1) {
        counter++;
    }
}
