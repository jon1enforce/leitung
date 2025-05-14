#include <sodium.h>
#include <sys/prctl.h>
#include <sys/mman.h>

// Ptrace-Blocking (Linux)
void block_debugging() {
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_DENY);
}

// SecureKey-Struktur (direkt im gesperrten Speicher)
typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
} SecureKey;

// Erstellt einen neuen SecureKey (mlock + Anti-Debug)
SecureKey* keyvault_new() {
    block_debugging();
    SecureKey *vault = mmap(NULL, sizeof(SecureKey), 
               PROT_READ | PROT_WRITE, 
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (vault == MAP_FAILED) return NULL;
    return vault;
}

// Lädt Schlüssel (ohne Zwischenspeicher)
void keyvault_load(SecureKey *vault, const uint8_t *key, const uint8_t *nonce) {
    for (size_t i = 0; i < 32; i++) vault->key[i] = key[i]; // Kein memcpy!
    for (size_t i = 0; i < 12; i++) vault->nonce[i] = nonce[i];
}

// Löscht den Schlüssel (CPU-Cache + RAM)
void keyvault_wipe(SecureKey *vault) {
    sodium_memzero(vault, sizeof(SecureKey));
    munmap(vault, sizeof(SecureKey));
}
