#include <stdint.h>

uint8_t loop_add(uint8_t x, uint8_t n) {
    uint8_t accumulator = x;
    for (uint8_t i = 0; i < n; ++i) accumulator += 3;
    return accumulator;
}

uint8_t loop_xor(uint8_t x, uint8_t n) {
    uint8_t accumulator = x;
    for (uint8_t i = 0; i < n; ++i) accumulator ^= 0xa5;
    return accumulator;
}
