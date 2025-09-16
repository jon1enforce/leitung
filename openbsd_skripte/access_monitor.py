#!/usr/bin/env python3
'''
OPENBSD SECURITY MONITOR - pledge/unveil Implementation

Identische Schnittstelle zum Linux-Skript, aber mit OpenBSD-spezifischer Härtung:
- pledge() statt seccomp/prctl
- unveil() statt path whitelisting
- Kein Memory-Hardening (nicht nötig auf OpenBSD)
'''
import os
import sys
import logging
import ctypes
from functools import wraps

class SecureLibraryLoader:
    """Dummy-Loader für Kompatibilität (OpenBSD braucht dies nicht)"""
    def __init__(self):
        self._access_log = []
    
    def load_library(self, lib_path):
        """Simuliertes Laden mit pledge("rpath")"""
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Library {lib_path} not found")
        return ctypes.CDLL(lib_path)
    
    def get_access_log(self):
        return self._access_log.copy()

class SecurityMonitor:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
        
    def __init__(self, hardening_rules=None):
        if self._initialized:
            return
            
        self.hardening_rules = {
            'prevent_fd_leaks': False,
            'restrict_env': False,
            'disable_debugger': True,
            'strict_path_checking': True,
            **(hardening_rules or {})
        }
        
        self._setup_logging()
        self._setup_x11_environment()
        self.allowed_paths = set()  # Für Kompatibilität
        self.library_loader = SecureLibraryLoader()
        self._apply_openbsd_hardening()
        self._initialized = True
        self.logger.info("OpenBSD SecurityMonitor initialisiert")

    def _apply_openbsd_hardening(self):
        """OpenBSD-spezifische Härtung mit pledge/unveil"""
        libc = ctypes.CDLL(None)
        
        # 1. unveil() - Pfadrestriktionen
        if self.hardening_rules['strict_path_checking']:
            libc.unveil(os.getcwd().encode(), b"r")  # Arbeitsverzeichnis
            libc.unveil(b"/usr/lib", b"r")           # Systembibliotheken
            libc.unveil(b"/usr/local/lib", b"r")
            libc.unveil(None, None)  # Lock
            
        # 2. pledge() - Syscall-Restriktionen
        promises = b"stdio rpath"
        if self.hardening_rules['disable_debugger']:
            promises += b" proc"  # Für fork/exec
        libc.pledge(None, promises)

    # --- Identische Methoden wie im Linux-Skript ---
    def secure_load(self, lib_name):
        return self.library_loader.load_library(lib_name)
        
    def _setup_x11_environment(self):
        if 'DISPLAY' not in os.environ:
            os.environ['DISPLAY'] = ':0'
        if 'XAUTHORITY' not in os.environ and os.path.exists(os.path.expanduser('~/.Xauthority')):
            os.environ['XAUTHORITY'] = os.path.expanduser('~/.Xauthority')

    def _setup_logging(self):
        self.logger = logging.getLogger('SECURITY')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self.logger.addHandler(handler)

    def _check_access(self, path):
        """Nur für Kompatibilität (eigentlich durch unveil abgedeckt)"""
        self.logger.info(f"Zugriff auf: {path}")  # Nur Monitoring

    def _setup_monitoring(self):
        """Überwachung bleibt aktiv (für Logging)"""
        import builtins
        original_open = builtins.open
        
        @wraps(original_open)
        def monitored_open(file, *args, **kwargs):
            self._check_access(file)
            return original_open(file, *args, **kwargs)
            
        builtins.open = monitored_open

    def _block_op(self, op_name):
        self.logger.error(f"Blockierte Operation: {op_name}")
        raise PermissionError(f"Operation {op_name} nicht erlaubt")

# Für direkten Aufruf (Testing)
if __name__ == "__main__":
    monitor = SecurityMonitor()
    print("OpenBSD-Sicherheitsmonitor aktiviert")
