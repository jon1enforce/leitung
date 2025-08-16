#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#define IV_SIZE 16       // First 16 bytes
#define KEY_SIZE 32      // Last 32 bytes  
#define SECRET_SIZE (IV_SIZE + KEY_SIZE)  // 48 bytes total
#define MAX_SECRETS 10   // Maximum number of named secrets
#define MAX_NAME_LEN 32  // Maximum length for secret names

typedef struct {
    uint8_t data[SECRET_SIZE];  // 0-15: IV, 16-47: Key
    char name[MAX_NAME_LEN];
    volatile int locked;
} SecretEntry;

typedef struct {
    SecretEntry secrets[MAX_SECRETS];
    volatile int locked;
} SecureVault;

#ifdef __cplusplus
extern "C" {
#endif

SecureVault* secure_vault_create(void);
int secure_vault_store_secret(SecureVault *v, const char *name, const uint8_t *secret, size_t len);
int secure_vault_get_secret_parts(SecureVault *v, const char *name, uint8_t *iv, uint8_t *key);
int secure_vault_is_locked(SecureVault *v);
int secure_vault_wipe(SecureVault *v);

#ifdef __cplusplus
}
#endif

static void secure_zero(void *s, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)s;
    while (n--) *p++ = 0;
}

SecureVault* secure_vault_create(void) {
    SecureVault *v = mmap(NULL, sizeof(SecureVault),
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (v == MAP_FAILED) return NULL;
    
    if (mlock(v, sizeof(SecureVault))) {
        munmap(v, sizeof(SecureVault));
        return NULL;
    }
    
    // Initialize all secrets
    for (int i = 0; i < MAX_SECRETS; i++) {
        secure_zero(v->secrets[i].data, SECRET_SIZE);
        v->secrets[i].name[0] = '\0';
        v->secrets[i].locked = 1;
    }
    v->locked = 0; // Vault is unlocked after creation
    return v;
}

int secure_vault_store_secret(SecureVault *v, const char *name, const uint8_t *secret, size_t len) {
    if (!v || !name || !secret || len != SECRET_SIZE || v->locked) return -1;
    
    // Find empty slot or existing entry with same name
    int found_index = -1;
    for (int i = 0; i < MAX_SECRETS; i++) {
        if (v->secrets[i].name[0] == '\0' && found_index == -1) {
            found_index = i;
        } else if (strncmp(v->secrets[i].name, name, MAX_NAME_LEN) == 0) {
            found_index = i;
            break;
        }
    }
    
    if (found_index == -1) return -1; // No space left
    
    // Store the secret
    SecretEntry *entry = &v->secrets[found_index];
    strncpy(entry->name, name, MAX_NAME_LEN - 1);
    entry->name[MAX_NAME_LEN - 1] = '\0';
    memcpy(entry->data, secret, SECRET_SIZE);
    entry->locked = 0;
    
    return 0;
}

int secure_vault_get_secret_parts(SecureVault *v, const char *name, uint8_t *iv, uint8_t *key) {
    if (!v || !name || !iv || !key || v->locked) return -1;
    
    // Find the named secret
    for (int i = 0; i < MAX_SECRETS; i++) {
        if (strncmp(v->secrets[i].name, name, MAX_NAME_LEN) == 0 && !v->secrets[i].locked) {
            memcpy(iv, v->secrets[i].data, IV_SIZE);
            memcpy(key, v->secrets[i].data + IV_SIZE, KEY_SIZE);
            return 0;
        }
    }
    
    return -1; // Secret not found
}

int secure_vault_is_locked(SecureVault *v) {
    if (!v) return 1; // Consider non-existent vault as locked
    return v->locked;
}

int secure_vault_wipe(SecureVault *v) {
    if (!v) return -1;
    
    // Securely wipe all secrets
    for (int i = 0; i < MAX_SECRETS; i++) {
        secure_zero(v->secrets[i].data, SECRET_SIZE);
        v->secrets[i].name[0] = '\0';
        v->secrets[i].locked = 1;
    }
    v->locked = 1;
    
    munlock(v, sizeof(SecureVault));
    munmap(v, sizeof(SecureVault));
    return 0;
}
