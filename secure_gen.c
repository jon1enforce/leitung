#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>  // Für mlock()
#include <errno.h>

void secure_erase(void *ptr, size_t len) {
    volatile char *vptr = (volatile char *)ptr;
    while (len--) *vptr++ = 0;
}

void get_disk_entropy(unsigned char *buf, size_t len) {
    // Alternative Entropiequellen in absteigender Priorität
    const char *sources[] = {
        "/dev/sda", "/dev/nvme0n1",  // Block Devices
        "/var/log/syslog",            // Systemlogs
        "/proc/interrupts",           // Kernel-Statistiken
        NULL
    };
    
    int fd = -1;
    for (int i = 0; sources[i] != NULL; i++) {
        fd = open(sources[i], O_RDONLY);
        if (fd != -1) break;
    }
    
    if (fd == -1) {
        perror("Keine Entropiequelle verfügbar");
        exit(EXIT_FAILURE);
    }
    
    unsigned char temp[256];
    size_t total_read = 0;
    
    while (total_read < len) {
        ssize_t n = read(fd, temp, sizeof(temp));
        if (n <= 0) break;
        
        for (ssize_t i = 0; i < n && total_read < len; i++) {
            buf[total_read++] = temp[i] ^ (total_read % 256);
        }
    }
    
    close(fd);
    secure_erase(temp, sizeof(temp));
}

void generate_secret(unsigned char *output) {
    // Seed: 8B urandom + 8B Disk
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    
    // Erster Teil des Seeds (8B urandom)
    if (read(urandom_fd, output, 8) != 8) {
        perror("Failed to read urandom seed");
        close(urandom_fd);
        exit(EXIT_FAILURE);
    }
    
    // Zweiter Teil des Seeds (8B Disk)
    get_disk_entropy(output + 8, 8);
    
    // Key: 16B urandom + 16B Disk
    if (read(urandom_fd, output + 16, 16) != 16) {
        perror("Failed to read urandom key");
        close(urandom_fd);
        exit(EXIT_FAILURE);
    }
    
    get_disk_entropy(output + 32, 16);
    
    close(urandom_fd);
    
    // Sicherstellen dass das Geheimnis nicht nach swap ausgelagert wird
    if (mlock(output, 48) == -1) {
        perror("Warning: mlock failed");
    }
}
