#include <stdint.h>

/* Tiny, deliberately restricted functions for the first binary experiment. */
uint8_t affine(uint8_t x, uint8_t y) { return 6*x + y + 4; }
uint8_t affine_shifts(uint8_t x, uint8_t y) { return (x << 2) + (x << 1) + y + 4; }
uint8_t affine_wrong(uint8_t x, uint8_t y) { return 6*x + y + 5; }
uint8_t add(uint8_t x, uint8_t y) { return x + y; }
uint8_t bitxor(uint8_t x, uint8_t y) { return x ^ y; }
uint8_t bitand(uint8_t x, uint8_t y) { return x & y; }
uint8_t product(uint8_t x, uint8_t y) { return x * y; }
uint8_t quadratic(uint8_t x, uint8_t y) { return 3*x*x + 5*x*y + 7*y + 11; }
uint8_t mixed(uint8_t x, uint8_t y) { return (x*y) ^ (x+y); }
uint8_t subtract(uint8_t x, uint8_t y) { return x - y; }
uint8_t subtract_swapped(uint8_t x, uint8_t y) { return y - x; }

uint32_t affine32(uint32_t x, uint32_t y) { return 6*x + y + 4; }
uint8_t branchy(uint8_t x, uint8_t y) {
    if (x < 128) return 6*x + y + 4;
    return x ^ y;
}
uint8_t branchy_wrong(uint8_t x, uint8_t y) {
    if (x < 127) return 6*x + y + 4;
    return x ^ y;
}
uint8_t boxed_alias(uint8_t *p, uint8_t *q) {
    *p = 7;
    *q = 9;
    return *p;
}
uint16_t boxed_overlap(uint8_t *p, uint8_t *q) {
    p[0] = 0x11;
    p[1] = 0x22;
    q[0] = 0x33;
    return p[0] | ((uint16_t)p[1] << 8);
}
uint8_t loop_example(uint8_t x, uint8_t y) {
    while (y--) x = (x * 3) ^ y;
    return x;
}
