#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <stdint.h>

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define SECRET_SIZE (KEY_SIZE + NONCE_SIZE)

typedef struct {
    uint8_t data[SECRET_SIZE];
    volatile int locked;
} SecureVault;

static void secure_zero(void *s, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)s;
    while (n--) *p++ = 0;
}

SecureVault* vault_create() {
    SecureVault *v = mmap(NULL, sizeof(SecureVault),
                 PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
    if (v == MAP_FAILED) return NULL;
    
    mlock(v, sizeof(SecureVault));
    v->locked = 1;
    return v;
}

void vault_load(SecureVault *v, const uint8_t *secret) {
    if (!v || !v->locked) return;
    for (size_t i = 0; i < SECRET_SIZE; i++) {
        v->data[i] = secret[i];
    }
}

void vault_retrieve(const SecureVault *v, uint8_t *output) {
    if (!v || !v->locked) return;
    for (size_t i = 0; i < SECRET_SIZE; i++) {
        output[i] = v->data[i];
    }
}

void vault_wipe(SecureVault *v) {
    if (!v) return;
    secure_zero(v, sizeof(SecureVault));
    munlock(v, sizeof(SecureVault));
    munmap(v, sizeof(SecureVault));
}
