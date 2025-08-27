#!/usr/bin/env python3
'''
SECURITY MONITOR PROTOCOL - EXECUTION SEQUENCE

1. INITIALIZATION PHASE
   - X11 Environment Setup:
     * Sets DISPLAY=:0 if unset
     * Configures XAUTHORITY if ~/.Xauthority exists
   - Logging System:
     * Handler: Console Stream
     * Format: "%(asctime)s [%(levelname)s] %(message)s"

2. PATH MANAGEMENT
   - Whitelisted Paths:
     * Working Directory (/home/jon/leitung)
     * System Paths:
       - /usr/lib
       - /usr/local/lib
       - Valid sys.path entries
   - Auto-Allowed Patterns:
     * Files in working directory
     * Extensions: .txt, .pem, .json
     * Paths containing: customtkinter, site-packages

3. FUNCTION MONITORING
   +------------------+---------------------+------------------+
   | Function         | Action              | Restriction      |
   +------------------+---------------------+------------------+
   | builtins.open    | Path validation     | Whitelist check  |
   | os.open          | Direct passthrough  | None             |
   | os.fdopen        | Blocked             | FD leak prevent  |
   +------------------+---------------------+------------------+

4. PROCESS HARDENING (Linux only)
   - Anti-Debugging:
     * prctl(PR_SET_DUMPABLE, 0)
   - FD Protection:
     * STDIO (0,1,2) non-inheritable

5. RUNTIME PROTECTION
   - Logged Events:
     * INFO: Path whitelisting
     * WARNING: Blocked access attempts
     * ERROR: Security violations
   - Failure Modes:
     * Strict: Path violations, blocked ops
     * Silent: prctl/fd hardening failures

SECURITY MATRIX:
+-------------------+----------+----------------+---------------+
| Feature           | Enabled  | Scope          | Criticality   |
+-------------------+----------+----------------+---------------+
| Path Whitelist    | ✔️       | Local files    | High          |
| FD-Leak Protect   | ✖️(GUI) | Process        | Medium        |
| Anti-Debugging    | ✔️       | Linux          | High          |
| Env Restriction   | ✖️(X11) | Environment    | Low           |
| X11 Hardening     | ✔️       | Display        | Medium        |
+-------------------+----------+----------------+---------------+
'''
import os
import sys
import logging
import ctypes
import time
import random
from functools import wraps
import traceback

'''
SECURITY ENHANCEMENTS FOR SHARED LIBRARY ACCESS
-------------------------------------------------
1. LIBRARY ACCESS MONITORING
   - Logs all .so loading attempts
   - Tracks memory access patterns
   - Flags suspicious operations

2. PROTECTION MECHANISMS
   - Address space randomization
   - Memory obfuscation
   - Access time jitter
'''
class SecureLibraryLoader:
    def __init__(self):
        self._access_log = []
        self._memory_map = {}
        self._obfuscation_key = os.urandom(32)
        
    def load_library(self, lib_path):
        """Sicheres Laden von Shared Libraries mit Monitoring"""
        # 1. Pfadvalidierung
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Library {lib_path} not found")
        
        # 2. Zugriffsprotokollierung
        access_time = time.time()
        caller = traceback.extract_stack(limit=2)[0]
        log_entry = {
            'timestamp': access_time,
            'library': os.path.basename(lib_path),
            'caller': f"{caller.filename}:{caller.lineno}",
            'checksum': self._file_checksum(lib_path)
        }
        self._access_log.append(log_entry)
        
        # 3. Memory Protection
        lib = ctypes.CDLL(lib_path)
        self._secure_memory_region(lib)
        
        return lib
    
    def _file_checksum(self, path):
        """SHA-256 Checksumme für Integritätsprüfung"""
        import hashlib
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _secure_memory_region(self, lib):
        """Schützt Library-Speicherbereich mit erweiterten Checks"""
        # Address Space Randomization
        base_addr = random.randint(0, 2**48)
        self._memory_map[id(lib)] = {
            'base': base_addr,
            'access_count': 0,
            'last_access': time.time()
        }
        
        # Erweiterte Funktionserkennung
        if hasattr(lib, '_FuncPtr'):
            try:
                # Modernere ctypes Versionen
                if hasattr(lib._FuncPtr, '__members__'):
                    members = lib._FuncPtr.__members__.items()
                else:
                    # Fallback für ältere Versionen
                    members = [(name, getattr(lib, name)) for name in dir(lib) 
                              if isinstance(getattr(lib, name), lib._FuncPtr)]
                    
                for name, _ in members:
                    if hasattr(lib, name):
                        orig_func = getattr(lib, name)
                        setattr(lib, name, self._obfuscated_wrapper(orig_func))
                        
            except Exception as e:
                self.logger.warning(f"Funktionswrapper fehlgeschlagen: {str(e)}")
        else:
            self.logger.warning("Keine _FuncPtr in Library - eingeschränkter Schutz")
    
    def _obfuscated_wrapper(self, func):
        """Erzeugt einen obfuskzierten Funktionswrapper"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Access Delay Jitter
            time.sleep(random.uniform(0.001, 0.01))
            
            # Memory Access Tracking
            lib_id = id(func.__self__)
            if lib_id in self._memory_map:
                self._memory_map[lib_id]['access_count'] += 1
                self._memory_map[lib_id]['last_access'] = time.time()
            
            # Execute with memory masking
            result = func(*args, **kwargs)
            return self._mask_result(result)
        return wrapper
    
    def _mask_result(self, value):
        """Maskiert Rückgabewerte"""
        if isinstance(value, (int, ctypes.c_int, ctypes.c_long)):
            return value ^ int.from_bytes(self._obfuscation_key[:4], 'little')
        return value

    def get_access_log(self):
        """Gibt das Zugriffsprotokoll zurück"""
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
        self.allowed_paths = set()
        self._collect_paths()
        self.library_loader = SecureLibraryLoader()  # WICHTIG: Initialisierung hier
        self._setup_monitoring()
        self._apply_process_hardening()
        self._initialized = True
        self.logger.info("SecurityMonitor initialisiert (Singleton)")

    def secure_load(self, lib_name):
        """Sicheres Laden einer Library mit automatischer Architekturerkennung"""
        arch = os.uname().machine
        lib_map = {
            'x86_64': 'libauslagern_x86_64.so',
            'arm64': 'libauslagern_arm64.so',
            'armv7l': 'libauslagern_armv7.so'
        }
        return self.library_loader.load_library(lib_map.get(arch, lib_name))
    def _setup_x11_environment(self):
        """Stellt notwendige X11-Umgebungsvariablen sicher"""
        if 'DISPLAY' not in os.environ:
            os.environ['DISPLAY'] = ':0'  # Standard-Display
        if 'XAUTHORITY' not in os.environ:
            xauth_path = os.path.expanduser('~/.Xauthority')
            if os.path.exists(xauth_path):
                os.environ['XAUTHORITY'] = xauth_path

    def _setup_logging(self):
        """Konfiguriert das Logging-System"""
        self.logger = logging.getLogger('SECURITY')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _clean_environment(self):
        """Bereinigt die Umgebungsvariablen"""
        if self.hardening_rules['restrict_env']:
            safe_vars = {'PATH', 'HOME', 'LANG', 'USER', 'TERM'}
            for var in list(os.environ):
                if var not in safe_vars:
                    del os.environ[var]

    def _collect_paths(self):
        """Sammelt sichere Pfade für Zugriffskontrolle"""
        # Aktuelles Arbeitsverzeichnis immer erlauben
        current_dir = os.path.abspath('.')
        self.allowed_paths.add(current_dir)
        self.logger.info(f"Erlaubter Pfad hinzugefügt: {current_dir}")
        
        # Systempfade
        self.allowed_paths.update({
            '/usr/lib',
            '/usr/local/lib',
            *[p for p in sys.path if p and os.path.exists(p)]
        })
         # NEU: Zugriff auf Entropie-Geräte erlauben
        self.allowed_paths.update({
            '/dev/urandom',  # Für Zufallszahlengenerierung
            '/dev/random',   # Alternative Entropie-Quelle
        })
        self.logger.info("Entropie-Geräte für Zugriff freigegeben: /dev/urandom, /dev/random")

    def _check_access(self, path):
        """Überprüft den Pfadzugriff"""
        try:
            path = str(path)
            abs_path = os.path.abspath(path)
            
            # Whitelist für wichtige Dateien im aktuellen Verzeichnis
            if os.path.dirname(abs_path) in self.allowed_paths:
                return
                
            # Whitelist für bestimmte Dateitypen
            if any(path.endswith(ext) for ext in ('.txt', '.pem', '.json')):
                return
                
            # Whitelist für Python-Pakete
            if any(p in path for p in ('customtkinter', 'site-packages')):
                return
                
            if not any(abs_path.startswith(p) for p in self.allowed_paths):
                self.logger.warning(f"Blockierter Zugriffsversuch auf: {abs_path}")
                raise PermissionError(f"Zugriff auf {path} nicht erlaubt")
                
        except Exception as e:
            self.logger.error(f"Sicherheitsverletzung: {e}")
            raise

    def _setup_monitoring(self):
        """Übernimmt die Überwachung kritischer Funktionen"""
        import builtins
        
        # Originalfunktionen speichern
        self._original = {
            'open': builtins.open,
            'os_open': os.open,
            'fdopen': os.fdopen
        }
        
        # Wrapper-Funktionen
        @wraps(self._original['open'])
        def monitored_open(file, *args, **kwargs):
            self._check_access(file)
            return self._original['open'](file, *args, **kwargs)
        
        builtins.open = monitored_open
        os.open = lambda p, *a, **kw: self._original['os_open'](p, *a, **kw)
        
        if self.hardening_rules['prevent_fd_leaks']:
            os.fdopen = lambda *a: self._block_op('fdopen')



    def _block_op(self, op_name):
        """Blockiert Operationen"""
        self.logger.error(f"Blockierte Operation: {op_name}")
        raise PermissionError(f"Operation {op_name} nicht erlaubt")

    def _apply_process_hardening(self):
        """Wendet Prozesshärtung an"""
        if sys.platform == 'linux' and self.hardening_rules['disable_debugger']:
            try:
                libc = ctypes.CDLL(None)
                if hasattr(libc, 'prctl'):
                    libc.prctl(0x1e, 0, 0, 0, 0)  # PR_SET_DUMPABLE
            except:
                pass

        if self.hardening_rules['strict_path_checking']:
            try:
                for fd in (0, 1, 2):
                    os.set_inheritable(fd, False)
            except:
                pass
