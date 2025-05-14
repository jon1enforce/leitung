import ctypes
import os

# C-Bibliothek laden
lib = ctypes.CDLL("./keyvault.so")

# SecureKey-Struktur
class SecureKey(ctypes.Structure):
    _fields_ = [("key", ctypes.c_ubyte * 32), 
                ("nonce", ctypes.c_ubyte * 12)]

# Funktionen einbinden
lib.keyvault_new.restype = ctypes.POINTER(SecureKey)
lib.keyvault_load.argtypes = [ctypes.POINTER(SecureKey), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
lib.keyvault_wipe.argtypes = [ctypes.POINTER(SecureKey)]

# Beispiel: Schlüssel speichern ohne Python-Kopie
def main():
    # 1. SecureKey erstellen (direkt im C-Speicher)
    vault = lib.keyvault_new()
    
    # 2. Schlüssel generieren (als C-Array, nie in Python halten!)
    key = (ctypes.c_ubyte * 32).from_buffer_copy(os.urandom(32))
    nonce = (ctypes.c_ubyte * 12).from_buffer_copy(os.urandom(12))
    
    # 3. Schlüssel laden (Referenzübergabe)
    lib.keyvault_load(vault, key, nonce)
    
    # 4. Nutzung (vault->key ist NUR in C zugreifbar!)
    # ... hier käme deine Verschlüsselungslogik ...
    
    # 5. Sicher löschen
    lib.keyvault_wipe(vault)

if __name__ == "__main__":
    main()




#

from ctypes import CDLL, c_void_p

# Keystone-Enklave laden
lib = CDLL("./keystone_vault.so")
lib.secure_enclave.argtypes = []
lib.secure_enclave.restype = c_void_p

# Alles läuft in der Enklave – Python sieht nichts!
lib.secure_enclave()
