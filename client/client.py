from access_monitor import SecurityMonitor
import socket
import threading
from M2Crypto import RSA, BIO, EVP, Rand
from tkinter import ttk, messagebox, filedialog
import json
import os
import time
import sys
import pyaudio
import uuid
import random
import customtkinter as ctk
import binascii
from datetime import datetime
from PIL import ImageFont
import base64
import re
import subprocess
import tkinter as tk
import stun
import struct
import ctypes
import platform
import glob
import mmap
import numpy as np
import traceback
from typing import Optional, NoReturn, Tuple
# Seccomp nur unter Linux importieren
if sys.platform.startswith("linux"):
    try:
        import seccomp
        HAS_SECCOMP = True
    except ImportError:
        HAS_SECCOMP = False
        print("[WARN] seccomp nicht verfügbar - Laufe ohne Sandboxing")
else:
    HAS_SECCOMP = False
from ctypes import CDLL, c_void_p, c_int, c_ubyte, byref, cast, POINTER, create_string_buffer, c_size_t, c_char_p
import hmac
import hashlib
import ipaddress
#fallback für bessere kompatibilität:
try:
    from tkinter import simpledialog
except AttributeError:
    import tkinter as tk
    import tkinter.simpledialog as simpledialog
connected = False
try:
    hashlib.sha3_256(b'').digest()  # Test ob verfügbar
    USE_PYSHA3 = False
except (AttributeError, ValueError):
    # Fallback auf pysha3 für Python 3.5
    try:
        import sha3  # pysha3 Paket
        USE_PYSHA3 = True
    except ImportError:
        raise ImportError(
            "SHA3 benötigt 'pysha3' unter Python 3.5.\n"
            "Installieren mit: pip install pysha3"
        )
BUFFER_SIZE = 4096


# Audio-Einstellungen
FORMAT = pyaudio.paInt16  # 16-Bit-Audio
CHANNELS = 1  # Mono
RATE = 44100  # Abtastrate (44.1 kHz)
CHUNK = 1024  # Grösse der Audioblöcke in Frames

# AES-Einstellungen
ENC_METHOD = "aes_256_cbc"

# Netzwerk-Einstellungen peer to peer:
HOST = "0.0.0.0"  # IP des Empfängers
PORT = 5061  # Port für die Übertragung



# ✅ MÜSSEN IN BEIDEN DATEIEN IDENTISCH SEIN

class VerifyGenerator:
    """Threadsicherer Verify-Code-Generator - Eine Instanz pro Client"""
    
    def __init__(self, seed, client_id=None):
        """
        Initialisiert den Verify-Generator für einen Client
        
        Args:
            seed: Der Seed für die Code-Generierung (z.B. client_name)
            client_id: Eindeutige Client-ID (optional)
        """
        self.seed = str(seed)
        self.client_id = client_id or "default"
        self.counter = 0
        self._lock = threading.Lock()  # ✅ Threadsicherheit pro Instanz
        
        print(f"🔐 [VERIFY] Generator für '{self.client_id}' mit Seed '{self.seed}' und Counter 0 erstellt")
    
    def generate_verify_code(self):
        """
        Generiert einen 4-stelligen hexadezimalen Verify-Code
        
        Returns:
            str: 4-stelliger hexadezimaler Code
        """
        with self._lock:  # ✅ Threadsafe
            base_string = f"{self.seed}:{self.counter}"
            hash_obj = hashlib.sha256(base_string.encode('utf-8'))
            hash_hex = hash_obj.hexdigest()
            code = hash_hex[:4]
            
            current_counter = self.counter
            self.counter += 1
            
            print(f"🔐 [VERIFY] #{current_counter} → #{self.counter} für '{self.client_id}': {code}")
            return code
    
    def verify_code(self, received_code, sync_tolerance=5):
        """
        Verifiziert einen empfangenen Code mit Counter-Synchronisation
        
        Args:
            received_code: Der empfangene Verify-Code
            sync_tolerance: Anzahl der Counter-Schritte für Synchronisation
            
        Returns:
            bool: True wenn Code gültig, False wenn ungültig
        """
        with self._lock:  # ✅ Threadsafe
            # ✅ SYNCHRONISATION: Prüfe mehrere Counter-Werte
            for offset in range(sync_tolerance):
                test_counter = self.counter + offset
                expected_base_string = f"{self.seed}:{test_counter}"
                expected_hash = hashlib.sha256(expected_base_string.encode('utf-8'))
                expected_hash_hex = expected_hash.hexdigest()
                expected_code = expected_hash_hex[:4]
                
                if received_code == expected_code:
                    # ✅ ERFOLG: COUNTER SYNCHRONISIEREN
                    self.counter = test_counter + 1
                    
                    if offset > 0:
                        print(f"✅ [VERIFY] Code #{test_counter} für '{self.client_id}' (sync +{offset}): {received_code}")
                    else:
                        print(f"✅ [VERIFY] Code #{test_counter} für '{self.client_id}': {received_code}")
                    
                    print(f"📊 [STATS] Counter synchronisiert: {self.counter}")
                    return True
            
            # ❌ FEHLER: Kein passender Code gefunden
            print(f"❌ [VERIFY] Code invalid für '{self.client_id}': {received_code}")
            print(f"📊 [STATS] Erwartet Counter ~{self.counter}")
            return False
    
    def get_message_count(self):
        """
        Gibt die Anzahl der Nachrichten für diesen Client zurück
        
        Returns:
            int: Anzahl der generierten/verifizierten Nachrichten
        """
        with self._lock:  # ✅ Threadsafe
            return self.counter
    
    def reset_counter(self):
        """Setzt den Counter für diesen Client zurück"""
        with self._lock:  # ✅ Threadsafe
            old_counter = self.counter
            self.counter = 0
            print(f"🔐 [VERIFY] Counter für '{self.client_id}' zurückgesetzt: {old_counter} → 0")
    
    def get_status(self):
        """
        Gibt den aktuellen Status des Generators zurück
        
        Returns:
            dict: Generator-Statusinformationen
        """
        with self._lock:  # ✅ Threadsafe
            return {
                'client_id': self.client_id,
                'seed': self.seed,
                'counter': self.counter,
                'next_expected_code': self._calculate_expected_code(self.counter)
            }
    
    def _calculate_expected_code(self, counter):
        """Hilfsmethode zur Berechnung des erwarteten Codes für einen Counter"""
        base_string = f"{self.seed}:{counter}"
        hash_obj = hashlib.sha256(base_string.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()
        return hash_hex[:4]
    def debug_info(self):
        """Gibt Debug-Informationen aus"""
        next_code = self._calculate_expected_code(self.counter)
        return f"Client-ID: '{self.client_id}', Seed: '{self.seed}', Counter: {self.counter}, Next: '{next_code}'"

# ✅ Globale Verwaltung der Generator-Instanzen (threadsafe)
_verify_generators = {}
_verify_manager_lock = threading.Lock()

def init_verify_generator(seed, client_id=None):
    """
    Initialisiert oder holt einen Verify-Generator für einen Client
    
    Args:
        seed: Der Seed für die Code-Generierung (MUSS gesetzt sein!)
        client_id: Eindeutige Client-ID
    """
    if not client_id:
        client_id = "default"
    
    # ✅ WICHTIG: Seed muss gesetzt sein!
    if seed is None:
        raise ValueError("Seed cannot be None for verify generator")
    
    with _verify_manager_lock:
        if client_id not in _verify_generators:
            # ✅ NEUER GENERATOR MIT KORREKTEM SEED
            _verify_generators[client_id] = VerifyGenerator(seed, client_id)
            print(f"🔐 [VERIFY] Neuer Generator für '{client_id}' mit Seed '{seed}' erstellt")
        else:
            # ✅ EXISTIERENDEN GENERATOR LADEN
            print(f"🔐 [VERIFY] Existierender Generator für '{client_id}' geladen (Seed: '{_verify_generators[client_id].seed}')")
        
        return _verify_generators[client_id]

def verify_code(received_code, client_id=None, sync_tolerance=5):
    """
    Verifiziert einen Code (Kompatibilitätsfunktion)
    
    Args:
        received_code: Empfangener Code
        client_id: Client-ID
        sync_tolerance: Synchronisationstoleranz
        
    Returns:
        bool: True wenn gültig
    """
    # ✅ KORREKTUR: CLIENT-ID ALS SEED VERWENDEN
    if client_id is None:
        client_id = "default"
    generator = init_verify_generator(client_name, client_name)  # ✅ SEED = CLIENT-ID
    return generator.verify_code(received_code, sync_tolerance)

def get_message_count(client_id=None):
    """
    Gibt Nachrichtenanzahl zurück (Kompatibilitätsfunktion)
    
    Args:
        client_id: Client-ID
        
    Returns:
        int: Nachrichtenanzahl
    """
    # ✅ KORREKTUR: CLIENT-ID ALS SEED VERWENDEN
    if client_id is None:
        client_id = "default"
    generator = init_verify_generator(client_name, client_name)  # ✅ SEED = CLIENT-ID
    return generator.get_message_count()

def reset_client_counter(client_id=None):
    """
    Setzt Counter zurück (Kompatibilitätsfunktion)
    
    Args:
        client_id: Client-ID
    """
    # ✅ KORREKTUR: CLIENT-ID ALS SEED VERWENDEN
    if client_id is None:
        client_id = "default"
    generator = init_verify_generator(client_name, client_name)  # ✅ SEED = CLIENT-ID
    generator.reset_counter()

def get_client_status(client_id=None):
    """
    Gibt Status für Client zurück
    
    Args:
        client_id: Client-ID
        
    Returns:
        dict: Statusinformationen
    """
    # ✅ KORREKTUR: CLIENT-ID ALS SEED VERWENDEN
    if client_id is None:
        client_id = "default"
    generator = init_verify_generator(client_name, client_name)  # ✅ SEED = CLIENT-ID
    return generator.get_status()

def list_all_generators():
    """
    Listet alle aktiven Generator-Instanzen auf
    
    Returns:
        list: Liste aller Client-IDs
    """
    with _verify_manager_lock:
        return list(_verify_generators.keys())

def remove_generator(client_id):
    """
    Entfernt einen Generator (für Cleanup)
    
    Args:
        client_id: Client-ID zu entfernen
    """
    with _verify_manager_lock:
        if client_id in _verify_generators:
            del _verify_generators[client_id]
            print(f"🔐 [VERIFY] Generator für '{client_id}' entfernt")
def secure_random(size):
    """
    Einfache Version die NUR die Zufallsdaten zurückgibt
    """
    state = os.urandom(32)
    result = b''
    counter = 0
    
    while len(result) < size:
        h = hmac.new(
            state, 
            counter.to_bytes(8, 'big') + os.urandom(16),
            hashlib.sha512
        )
        state = h.digest()
        result += state
        counter += 1
    
    return result[:size]  # Nur die Daten zurückgeben, kein Tuple!


def load_client_name():
    """Lädt den Client-Namen aus einer lokalen Datei oder fordert den Benutzer zur Eingabe auf."""
    if os.path.exists("client_name.txt"):
        with open("client_name.txt", "r") as file:
            return file.read().strip()
    else:
        client_name = simpledialog.askstring("Name", "Gib deinen Namen ein:")
        if client_name:
            with open("client_name.txt", "w") as file:
                file.write(client_name)
            return client_name
        else:
            messagebox.showerror("Fehler", "Kein Name eingegeben. Abbruch.")
            return None
# === EINHEITLICHER FRAMING STANDARD ===
def send_frame(sock, data):
    """EINHEITLICHER Frame-Sender für ALLE Nachrichten - KOMPATIBEL FÜR CLIENT UND SERVER"""
    if sock is None or sock.fileno() == -1:
        print("[FRAME ERROR] Socket is closed or invalid")
        return False
    
    # Daten vorbereiten
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        print("[FRAME ERROR] Data must be string or bytes")
        return False
    
    # Header erstellen (4 Bytes Network Byte Order)
    header = struct.pack('!I', len(data))
    full_message = header + data
    
    try:
        # Gesamte Nachricht senden
        total_sent = 0
        while total_sent < len(full_message):
            sent = sock.send(full_message[total_sent:])
            if sent == 0:
                print("[FRAME ERROR] Socket connection broken")
                return False
            total_sent += sent
        
        print(f"[FRAME] Successfully sent {len(data)} bytes (total with header: {len(full_message)} bytes)")
        return True
        
    except (BrokenPipeError, ConnectionResetError, socket.error) as e:
        print(f"[FRAME ERROR] Send failed - connection issue: {e}")
        return False
    except OSError as e:
        print(f"[FRAME ERROR] Send failed - OS error: {e}")
        return False
    except Exception as e:
        print(f"[FRAME ERROR] Send failed - unexpected error: {e}")
        return False

def recv_frame(sock, timeout=30):
    """EINHEITLICHER Frame-Empfänger für ALLE Nachrichten - KOMPATIBEL FÜR CLIENT UND SERVER"""
    original_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    
    try:
        # 1. Header lesen (4 Bytes Network Byte Order)
        header = b''
        start_time = time.time()
        
        while len(header) < 4:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                raise TimeoutError("Header receive timeout")
                
            sock.settimeout(remaining_time)
            chunk = sock.recv(4 - len(header))
            if not chunk:
                print("[FRAME] Connection closed during header reception")
                return None
            header += chunk
        
        # 2. Länge decodieren
        length = struct.unpack('!I', header)[0]
        
        # 3. SICHERHEITSCHECKS (identisch auf beiden Seiten)
        if length == 0:
            print("[FRAME] Empty frame received")
            return b''  # Leerer Frame ist erlaubt
            
        if length > 10 * 1024 * 1024:  # 10MB Maximum (konservativ)
            print(f"[FRAME SECURITY] Frame size suspicious: {length} bytes")
            # Versuche Daten zu lesen und zu verwerfen um Verbindung zu resetten
            try:
                discard_timeout = min(5.0, timeout)  # Max 5 Sekunden zum Verwerfen
                sock.settimeout(discard_timeout)
                bytes_discarded = 0
                while bytes_discarded < length:
                    chunk_size = min(4096, length - bytes_discarded)
                    chunk = sock.recv(chunk_size)
                    if not chunk:
                        break
                    bytes_discarded += len(chunk)
                print(f"[FRAME SECURITY] Discarded {bytes_discarded} bytes")
            except:
                pass
            raise ValueError(f"Frame too large: {length} bytes (max: 10MB)")
        
        # 4. Body lesen
        received = b''
        while len(received) < length:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                raise TimeoutError(f"Body receive timeout after {timeout}s")
                
            sock.settimeout(remaining_time)
            chunk_size = min(4096, length - len(received))
            chunk = sock.recv(chunk_size)
            if not chunk:
                raise ConnectionError(f"Incomplete frame: received {len(received)} of {length} bytes")
            received += chunk
        
        # 5. Erfolgslogging (konsistent)
        if len(received) == length:
            print(f"[FRAME] Successfully received {length} bytes")
        else:
            print(f"[FRAME WARNING] Length mismatch: expected {length}, got {len(received)}")
        
        return received
        
    except socket.timeout:
        print(f"[FRAME TIMEOUT] Timeout after {timeout} seconds")
        raise TimeoutError(f"Frame receive timeout after {timeout}s")
    except ConnectionError as e:
        print(f"[FRAME CONNECTION] Connection error: {e}")
        raise
    except ValueError as e:
        print(f"[FRAME VALIDATION] Validation error: {e}")
        raise
    except Exception as e:
        print(f"[FRAME ERROR] Unexpected error: {e}")
        return None
    finally:
        # 6. Original Timeout immer zurücksetzen
        try:
            sock.settimeout(original_timeout)
        except:
            pass  # Socket könnte bereits geschlossen sein

def get_public_ip():
    nat_type, public_ip, public_port = stun.get_ip_info()
    return public_ip, public_port  # Für SIP-Contact-Header


def normalize_key(key):
    """Improved normalization that matches server's implementation"""
    if not key or not isinstance(key, str):
        return None
    
    key = key.strip()
    if not key:
        return None
        
    # Case 1: Full PEM format
    if "-----BEGIN PUBLIC KEY-----" in key and "-----END PUBLIC KEY-----" in key:
        try:
            key_content = key.split("-----BEGIN PUBLIC KEY-----")[1]
            key_content = key_content.split("-----END PUBLIC KEY-----")[0]
            key_content = ''.join(key_content.split())  # Remove all whitespace
            base64.b64decode(key_content)  # Validate Base64
            return key_content
        except Exception:
            return None
            
    # Case 2: Already just Base64 content
    try:
        if len(key) >= 100 and key[-1] == '=' and key[-2] == '=':
            base64.b64decode(key)
            return key
    except Exception:
        pass
    return None




def is_valid_public_key(key):
    """Strict validation for PEM format public keys with improved formatting"""
    if not isinstance(key, str):
        return False
    
    # Bereinige den Key: Ersetze doppelte Backslashes
    key = key.strip().replace('\\\\n', '\n').replace('\\n', '\n')
    
    # Überprüfe das PEM-Format
    has_valid_start = key.startswith('-----BEGIN PUBLIC KEY-----')
    has_valid_end = key.endswith('-----END PUBLIC KEY-----')
    has_rsa_header = "MII" in key
    has_valid_length = len(key) > 100
    
    print(f"[KEY VALIDATION] Start valid: {has_valid_start}")
    print(f"[KEY VALIDATION] End valid: {has_valid_end}")
    print(f"[KEY VALIDATION] Has RSA header: {has_rsa_header}")
    print(f"[KEY VALIDATION] Length valid: {has_valid_length} ({len(key)} chars)")
    
    return has_valid_start and has_valid_end and has_rsa_header and has_valid_length
def verify_merkle_integrity(all_keys, received_root_hash):
    """Überprüft die Integrität aller Schlüssel mittels Merkle Tree mit erweitertem Logging"""
    print("\n=== CLIENT VERIFICATION ===")
    
    try:
        # 1. Input Validation
        if not all_keys or not received_root_hash:
            print("[ERROR] Missing keys or Merkle root")
            return False
            
        if not isinstance(all_keys, (list, tuple)):
            print("[ERROR] Keys must be in a list")
            return False
            
        if not isinstance(received_root_hash, str):
            print("[ERROR] Merkle root must be a string")
            return False

        # 2. Key Normalization and Deduplication
        normalized_keys = []
        seen_keys = set()
        
        for key in all_keys:
            if not key:
                continue
                
            # Ensure key is string (handle both str and bytes)
            key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
            
            # Normalize the key (matches server's implementation)
            normalized = normalize_key(key_str)
            if normalized and normalized not in seen_keys:
                seen_keys.add(normalized)
                normalized_keys.append(normalized)
                print(f"[Client] Added normalized key: {normalized[:30]}...")
        
        if not normalized_keys:
            print("[ERROR] No valid keys after normalization")
            return False

        # 3. Merge keys with consistent separator (matches server)
        merged = "|||".join(sorted(normalized_keys))  # Consistent sorting
        print(f"[Client] Merged keys (len={len(merged)}): {merged[:100]}...")

        # 4. Calculate Merkle Root (matches server's method)
        calculated_hash = build_merkle_tree([merged])
        print(f"[Client] Calculated hash: {calculated_hash}")
        print(f"[Client] Received hash:   {received_root_hash}")
        
        # 5. Comparison with case and whitespace insensitivity
        is_valid = calculated_hash.strip().lower() == received_root_hash.strip().lower()
        
        if not is_valid:
            print("[SECURITY ALERT] Merkle root mismatch!")
            print("Possible causes:")
            print("- Key manipulation detected")
            print("- Incorrect key normalization")
            print("- Different key order between client and server")
            
        return is_valid

    except Exception as e:
        print(f"[ERROR] Verification failed: {str(e)}")
        traceback.print_exc()
        return False

def debug_print_key(key_type, key_data):
    """Print detailed key information"""
    print(f"\n=== {key_type.upper()} KEY DEBUG ===")
    print(f"Length: {len(key_data)} bytes")
    print(f"First 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[:32])}")
    print(f"First 32 bytes (ascii): {key_data[:32].decode('ascii', errors='replace')}")
    if len(key_data) > 32:
        print(f"Last 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[-32:])}")
    print("="*50)

def validate_key_pair(private_key_pem, public_key_pem):
    """Überprüft ob der private zum öffentlichen Schlüssel passt"""
    try:
        test_msg = b"TEST_MESSAGE_" + os.urandom(16)
        
        # Verschlüsseln mit öffentlichem Schlüssel
        pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(public_key_pem.encode()))
        encrypted = pub_key.public_encrypt(test_msg, RSA.pkcs1_padding)
        
        # Entschlüsseln mit privatem Schlüssel
        priv_key = RSA.load_key_string(private_key_pem.encode())
        decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
        
        return decrypted == test_msg
    except Exception as e:
        print(f"[KEY VALIDATION ERROR] {str(e)}")
        return False
def quantum_safe_hash(data):
    """
    Garantiert konsistenten SHA3-256-Hash:
    - Automatische Handhabung von Strings und Bytes
    - Nutzt pysha3 als Fallback für Python 3.5
    - Klare Fehlermeldung bei fehlender SHA-3-Implementierung
    """
    if isinstance(data, str):
        data = data.encode('utf-8')  # Nur einmal encoden!
    
    try:
        if USE_PYSHA3 == False:
            return hashlib.sha3_256(data).hexdigest()
        else:
            import sha3  # pysha3-Backup
            return sha3.sha3_256(data).hexdigest()
    except ImportError as e:
        raise RuntimeError(
            "SHA3-256 benötigt 'pysha3' unter Python 3.5.\n"
            "Installieren mit: pip install pysha3\n"
            "Originalfehler: " + str(e)
        ) from e
def build_merkle_tree(data_blocks):
    data_blocks = list(data_blocks)
    if not data_blocks:
        return None
    
    # Erstelle die Blattknoten des Merkle Trees
    tree = [quantum_safe_hash(block) for block in data_blocks]

    # Reduziere den Baum, bis nur noch der Root-Hash übrig ist
    while len(tree) > 1:
        if len(tree) % 2 != 0:
            tree.append(tree[-1])  # Dupliziere den letzten Hash, wenn die Anzahl ungerade ist
        tree = [quantum_safe_hash(tree[i] + tree[i + 1]) for i in range(0, len(tree), 2)]

    return tree[0]  # Der Merkle Root-Hash

def generate_secret():
    """
    Erzeuge ein 48-Byte-Geheimnis:
    - Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie.
    - Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festplatten-Entropi e.
    :return: 48-Byte-Geheimnis als Bytes.
    """
    # Erzeuge den Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie
    seed_part1 = secure_random(8)  # 8 Bytes aus os.urandom
    seed_part2 = get_disk_entropy(8)  # 8 Bytes aus der Festplatten-Entropie
    if not seed_part2:
        raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
    seed = seed_part1 + seed_part2  # 16 Bytes Seed

    # Erzeuge den Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festpla tten-Entropie
    key_part1 = secure_random(16)  # 16 Bytes aus os.urandom
    key_part2 = get_disk_entropy(16)  # 16 Bytes aus der Festplatten-Entropie
    if not key_part2:
        raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
    key = key_part1 + key_part2  # 32 Bytes Schlüssel

    # Kombiniere Seed und Schlüssel zu einem 48-Byte-Geheimnis
    secret = seed + key  # 16 + 32 = 48 Bytes
    return secret





def extract_secret(decrypted_data):
    """Extracts the 48-byte secret from decrypted data"""
    prefix = b"+++secret+++"
    prefix_pos = decrypted_data.find(prefix)
    
    if prefix_pos == -1:
        raise ValueError("Secret prefix not found")
    
    secret_start = prefix_pos + len(prefix)
    secret_end = secret_start + 48
    secret = decrypted_data[secret_start:secret_end]
    
    if len(secret) != 48:
        raise ValueError(f"Invalid secret length: {len(secret)} bytes (expected 48)")
    
    return secret



def load_privatekey():
    """Lädt den privaten Client-Schlüssel - VOLLSTÄNDIG KORRIGIERT"""
    try:
        print("[KEY] Loading client private key...")
        
        if not os.path.exists("client_private_key.pem"):
            print("[KEY] No client private key found, generating new key pair...")
            return generate_new_keypair()
        
        # Lade existierenden privaten Schlüssel
        with open("client_private_key.pem", "rb") as f:
            private_key_data = f.read()
        
        private_key_str = private_key_data.decode('utf-8').strip()
        
        print(f"[KEY DEBUG] Private key file content length: {len(private_key_str)}")
        print(f"[KEY DEBUG] First line: {private_key_str.splitlines()[0] if private_key_str.splitlines() else 'EMPTY'}")
        print(f"[KEY DEBUG] Last line: {private_key_str.splitlines()[-1] if private_key_str.splitlines() else 'EMPTY'}")
        
        # ✅ KRITISCHE KORREKTUR: Teste den Schlüssel durch tatsächliches Laden
        try:
            print("[KEY TEST] Testing private key with RSA.load_key_string...")
            priv_key = RSA.load_key_string(private_key_str.encode())
            
            if not priv_key:
                print("[KEY ERROR] RSA.load_key_string returned None - invalid key format")
                raise ValueError("Invalid private key format")
            
            # Teste mit einer kleinen Operation
            test_data = b"TEST_RSA_OPERATION"
            try:
                # Versuche zu signieren (funktiert immer)
                signature = priv_key.sign(hashlib.sha256(test_data).digest(), "sha256")
                if signature and len(signature) > 0:
                    print("[KEY TEST] ✅ Private key RSA test successful")
                else:
                    print("[KEY TEST] ❌ Private key signature test failed")
                    raise ValueError("Private key signature test failed")
            except Exception as sig_error:
                print(f"[KEY TEST WARNING] Signature test failed: {sig_error}")
                # Fallback: Prüfe nur ob Key geladen werden kann
                print("[KEY TEST] ✅ Private key loaded successfully (basic test)")
            
        except Exception as e:
            print(f"[KEY ERROR] Private key RSA test failed: {e}")
            print("[KEY] Regenerating key pair...")
            return regenerate_keypair()
        
        print("[KEY] Client private key loaded and validated successfully")
        return private_key_str
            
    except Exception as e:
        print(f"[KEY ERROR] Failed to load client private key: {str(e)}")
        return regenerate_keypair()
def load_server_publickey():
    """Lädt und normalisiert den öffentlichen Server-Schlüssel"""
    if not os.path.exists("server_public_key.pem"):
        raise FileNotFoundError("Server public key file not found")
    
    try:
        with open("server_public_key.pem", "rb") as f:
            key_data = f.read().decode('utf-8')
        
        # ✅ KRITISCHE KORREKTUR: PEM-Format sicherstellen
        key_data = key_data.strip()
        
        # Falls Key bereits korrektes PEM hat
        if key_data.startswith('-----BEGIN PUBLIC KEY-----') and key_data.endswith('-----END PUBLIC KEY-----'):
            print("[SERVER KEY] Key is in valid PEM format")
            return key_data
        
        # Reparatur: PEM-Header hinzufügen falls fehlend
        if 'BEGIN PUBLIC KEY' not in key_data:
            print("[SERVER KEY] Adding missing PEM headers")
            # Base64-Inhalt extrahieren und neu wrappen
            key_content = key_data.replace('\n', '').replace(' ', '')
            key_data = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
        
        # Validierung: Versuche Key zu laden
        try:
            test_bio = BIO.MemoryBuffer(key_data.encode())
            test_key = RSA.load_pub_key_bio(test_bio)
            print("[SERVER KEY] Key validation successful")
            return key_data
        except Exception as e:
            print(f"[SERVER KEY] Key validation failed: {e}")
            raise ValueError("Invalid server public key format")
            
    except Exception as e:
        print(f"[SERVER KEY ERROR] {str(e)}")
        raise

            
def extract_server_public_key(sip_data, raw_response=None):
    """
    Extrahiert den Server-Public-Key aus SIP-Daten mit Format-Bereinigung
    """
    try:
        # Variante 1: Aus custom_data
        if isinstance(sip_data, dict) and sip_data.get('custom_data'):
            custom_data = sip_data['custom_data']
            if 'SERVER_PUBLIC_KEY' in custom_data:
                key = custom_data['SERVER_PUBLIC_KEY']
                # Bereinige das Format
                key = key.replace('\\\\n', '\n').replace('\\n', '\n')
                
                if '-----BEGIN PUBLIC KEY-----' in key:
                    return key
        
        # Variante 2: Aus dem Body der rohen Response
        if raw_response:
            # Bereinige zuerst das Format
            cleaned_response = raw_response.replace('\\\\n', '\n').replace('\\n', '\n')
            key_start = cleaned_response.find('-----BEGIN PUBLIC KEY-----')
            if key_start != -1:
                key_end = cleaned_response.find('-----END PUBLIC KEY-----', key_start)
                if key_end != -1:
                    key_end += len('-----END PUBLIC KEY-----')
                    key = cleaned_response[key_start:key_end]
                    # Remove any prefix if present
                    if 'SERVER_PUBLIC_KEY:' in key:
                        key = key.replace('SERVER_PUBLIC_KEY:', '').strip()
                    return key
        
        return None
    except Exception as e:
        print(f"[KEY EXTRACT ERROR] {str(e)}")
        return None

def save_client_id(client_id):
    """Speichert die Client-ID in einer lokalen Datei."""
    with open("client_id.txt", "w") as file:
        file.write(client_id)

def load_client_id():
    """Lädt die Client-ID aus einer lokalen Datei."""
    if os.path.exists("client_id.txt"):
        with open("client_id.txt", "r") as file:
            return file.read().strip()
    return None

def generate_new_keypair():
    """Generiert ein neues Schlüsselpaar als Fallback"""
    try:
        print("[KEY] Generating new RSA key pair...")
        bits = 4096
        new_key = RSA.gen_key(bits, 65537)

        # Speichere privaten Schlüssel
        priv_memory = BIO.MemoryBuffer()
        new_key.save_key_bio(priv_memory, cipher=None)
        with open("client_private_key.pem", "wb") as priv_file:
            priv_file.write(priv_memory.getvalue())

        # Speichere öffentlichen Schlüssel
        pub_memory = BIO.MemoryBuffer()
        new_key.save_pub_key_bio(pub_memory)
        public_key_pem = pub_memory.getvalue().decode('utf-8')
        with open("client_public_key.pem", "w") as pub_file:
            pub_file.write(public_key_pem)

        print("[KEY] New key pair generated successfully")
        return public_key_pem
        
    except Exception as e:
        print(f"[KEY ERROR] Failed to generate new key pair: {str(e)}")
        return None
def load_publickey():
    if not os.path.exists("client_public_key.pem") or not os.path.exists("client_private_key.pem"):
        # Generiere neuen RSA-Schlüssel
        bits = 4096
        new_key = RSA.gen_key(bits, 65537)

        # Speichere den öffentlichen Schlüssel im PEM-Format
        pub_memory = BIO.MemoryBuffer()
        new_key.save_pub_key_bio(pub_memory)
        public_key_pem = pub_memory.getvalue().decode('utf-8')  # Als String

        with open("client_public_key.pem", "w") as pubHandle:
            pubHandle.write(public_key_pem)

        # Speichere den privaten Schlüssel
        priv_memory = BIO.MemoryBuffer()
        new_key.save_key_bio(priv_memory, cipher=None)
        with open("client_private_key.pem", "wb") as privHandle:
            privHandle.write(priv_memory.getvalue())
        
        return public_key_pem
    else:
        # Lade den öffentlichen Schlüssel als kompletten PEM-String
        with open("client_public_key.pem", "r") as f:
            public_key = f.read().strip()
        
        # Validierung des Keys
        if not public_key.startswith('-----BEGIN PUBLIC KEY-----') or \
           not public_key.endswith('-----END PUBLIC KEY-----'):
            raise ValueError("Invalid public key format in file")
        
        return public_key

def secure_del(var):
    """Sicheres Löschen durch Überschreiben + del"""
    if isinstance(var, bytes):  # Wenn es bytes ist, in bytearray umwandeln
        var = bytearray(var)   # Jetzt ist es überschreibbar!
    
    if isinstance(var, bytearray):
        for i in range(len(var)):
            var[i] = 0  # Überschreibt jedes Byte mit 0x00
        del var  # Entfernt die Referenz
    
    elif hasattr(var, '__dict__'):
        var.__dict__.clear()  # Falls es ein Objekt ist
        del var
import pyaudio
import sys
import time
import subprocess
import glob

class AudioConfig:
    def __init__(self):
        self.audio = None
        self.input_device_index = None
        self.output_device_index = None
        self.using_pyaudio_fallback = False
        
        # ✅ QUALITÄTSSTUFEN
        self.QUALITY_PROFILES = {
            "highest": {
                "format": pyaudio.paInt32,
                "rate": 192000, 
                "channels": 2,
                "name": "S32_LE @ 192kHz Stereo (Highest Quality - SA9227 Native)",
                "actual_format": "S32_LE"
            },
            "high": {
                "format": pyaudio.paInt24, 
                "rate": 192000, 
                "channels": 2,
                "name": "24-bit @ 192kHz Stereo (High Quality)",
                "actual_format": "24-bit"
            },
            "middle": {
                "format": pyaudio.paInt24, 
                "rate": 48000, 
                "channels": 2,
                "name": "24-bit @ 48kHz Stereo (Middle Quality)",
                "actual_format": "24-bit"
            }, 
            "low": {
                "format": pyaudio.paInt16, 
                "rate": 48000, 
                "channels": 1,
                "name": "16-bit @ 48kHz Mono (Low Quality)",
                "actual_format": "16-bit"
            },
            "openbsd_fallback": {
                "format": pyaudio.paInt16, 
                "rate": 44100, 
                "channels": 1,
                "name": "16-bit @ 44.1kHz Mono (OpenBSD Fallback)",
                "actual_format": "16-bit"
            }
        }
        
        # Standard-Qualität
        self.quality_profile = "middle"
        
        self.CHUNK = 128
        self.PORT = 51821
        
        # Output Format-Check
        self.output_supports_24bit = True
        
        # ✅ NOISE PROFILING & FILTERUNG
        self.noise_profile = {
            'enabled': False,
            'profile_captured': False,
            'noise_threshold': 0.01,
            'noise_profile': None,
            'adaptive_filter': True,
            'aggressive_mode': False,
            'capture_duration': 180
        }
        
        # Filter-Koeffizienten
        self.filter_coefficients = {
            'low_freq_cutoff': 80,
            'high_freq_cutoff': 16000,
            'hum_filter_freq': 50,
        }
        
        # Audio-Statistiken
        self.audio_stats = {
            'rms_level': 0.0,
            'peak_level': 0.0,
            'noise_floor': 0.001,
            'signal_to_noise': 0.0,
            'capture_progress': 0.0
        }
        
        # Initialisiere Audio-System mit robustem Fallback
        self._initialize_audio_system()

    def _initialize_audio_system(self):
        """Robuste Audio-System-Initialisierung mit Fallback-Mechanismus"""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                print(f"[AUDIO] Initialization attempt {attempt + 1}/{max_retries}")
                
                # Versuche PyAudio zu initialisieren
                self.audio = pyaudio.PyAudio()
                
                # OpenBSD-spezifische Konfiguration
                if sys.platform.startswith("openbsd"):
                    success = self._configure_openbsd_with_fallback()
                else:
                    success = self._configure_standard_platform()
                
                if success:
                    print("[AUDIO] ✅ Audio system initialized successfully")
                    self._apply_quality_profile()
                    return True
                else:
                    raise Exception("Platform-specific configuration failed")
                    
            except Exception as e:
                print(f"[AUDIO] ❌ Initialization attempt {attempt + 1} failed: {e}")
                
                # Bereinige fehlgeschlagene Instanz
                if self.audio:
                    try:
                        self.audio.terminate()
                        self.audio = None
                    except:
                        pass
                
                # Warte vor erneutem Versuch
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"[AUDIO] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
        
        # Alle Versuche fehlgeschlagen - kritischer Fallback
        print("[AUDIO] 💥 All initialization attempts failed, using emergency fallback")
        return self._emergency_fallback()

    def _configure_openbsd_with_fallback(self):
        """OpenBSD-Konfiguration mit robustem Fallback-System"""
        print("[AUDIO] Configuring for OpenBSD with fallback support...")
        
        # Test 1: Versuche sndio-basierte Konfiguration
        if self._try_sndio_configuration():
            print("[AUDIO] ✅ sndio configuration successful")
            return True
        
        # Test 2: Versuche PyAudio mit OpenBSD-Devices
        if self._try_pyaudio_openbsd_devices():
            print("[AUDIO] ✅ PyAudio with OpenBSD devices successful") 
            return True
        
        # Test 3: Versuche grundlegende PyAudio-Konfiguration
        if self._try_basic_pyaudio_config():
            print("[AUDIO] ✅ Basic PyAudio configuration successful")
            return True
        
        print("[AUDIO] ❌ All OpenBSD configuration methods failed")
        return False

    def _try_sndio_configuration(self):
        """Versuche sndio-basierte Konfiguration"""
        try:
            # Prüfe ob sndio verfügbar ist
            result = subprocess.run(['which', 'sndioctl'], capture_output=True, timeout=5)
            if result.returncode != 0:
                print("[AUDIO] sndioctl not found, skipping sndio configuration")
                return False
            
            # Prüfe ob sndiod läuft
            result = subprocess.run(['pgrep', 'sndiod'], capture_output=True, timeout=5)
            sndiod_running = (result.returncode == 0)
            
            if not sndiod_running:
                print("[AUDIO] sndiod not running, attempting to start...")
                try:
                    # Versuche sndiod im Hintergrund zu starten
                    subprocess.Popen(['sndiod'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)  # Warte auf Initialisierung
                except Exception as e:
                    print(f"[AUDIO] Failed to start sndiod: {e}")
                    return False
            
            # Teste sndioctl
            try:
                result = subprocess.run(['sndioctl', '-d'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    print("[AUDIO] sndioctl working, using sndio-compatible settings")
                    
                    # sndio-kompatible Einstellungen
                    self.FORMAT = pyaudio.paInt16
                    self.RATE = 44100
                    self.CHANNELS = 1
                    self.CHUNK = 1024
                    self.sample_width = 2
                    self.actual_format = "16-bit"
                    self.sample_format_name = "16-bit @ 44.1kHz (OpenBSD sndio)"
                    
                    self.input_device_index = 0
                    self.output_device_index = 0
                    
                    return True
            except Exception as e:
                print(f"[AUDIO] sndioctl test failed: {e}")
                
        except Exception as e:
            print(f"[AUDIO] sndio configuration failed: {e}")
            
        return False

    def _try_pyaudio_openbsd_devices(self):
        """Versuche PyAudio mit OpenBSD-specific Device-Erkennung"""
        try:
            print("[AUDIO] Attempting PyAudio device detection on OpenBSD...")
            
            # Prüfe verfügbare Geräte
            device_count = self.audio.get_device_count()
            print(f"[AUDIO] Found {device_count} PyAudio devices")
            
            if device_count == 0:
                print("[AUDIO] No PyAudio devices found")
                return False
            
            # Durchsuche nach kompatiblen Geräten
            input_found = False
            output_found = False
            
            for i in range(device_count):
                try:
                    device_info = self.audio.get_device_info_by_index(i)
                    device_name = device_info.get('name', 'Unknown')
                    print(f"[AUDIO] Device {i}: {device_name}")
                    
                    # Prüfe Input
                    if device_info.get('maxInputChannels', 0) > 0 and not input_found:
                        self.input_device_index = i
                        input_found = True
                        print(f"[AUDIO] Using input device {i}: {device_name}")
                    
                    # Prüfe Output
                    if device_info.get('maxOutputChannels', 0) > 0 and not output_found:
                        self.output_device_index = i
                        output_found = True
                        print(f"[AUDIO] Using output device {i}: {device_name}")
                        
                except Exception as e:
                    print(f"[AUDIO] Error checking device {i}: {e}")
                    continue
            
            if not input_found and not output_found:
                print("[AUDIO] No usable input/output devices found")
                return False
            
            # Verwende OpenBSD-kompatible Einstellungen
            self.FORMAT = pyaudio.paInt16
            self.RATE = 44100
            self.CHANNELS = 1
            self.CHUNK = 512
            self.sample_width = 2
            self.actual_format = "16-bit"
            self.sample_format_name = "16-bit @ 44.1kHz (OpenBSD PyAudio)"
            
            return True
            
        except Exception as e:
            print(f"[AUDIO] PyAudio device detection failed: {e}")
            return False

    def _try_basic_pyaudio_config(self):
        """Versuche grundlegende PyAudio-Konfiguration"""
        try:
            print("[AUDIO] Attempting basic PyAudio configuration...")
            
            # Setze Default Devices
            self.input_device_index = 0
            self.output_device_index = 0
            
            # Sehr konservative Einstellungen für maximale Kompatibilität
            self.FORMAT = pyaudio.paInt16
            self.RATE = 44100
            self.CHANNELS = 1
            self.CHUNK = 512
            self.sample_width = 2
            self.actual_format = "16-bit"
            self.sample_format_name = "16-bit @ 44.1kHz (Basic Fallback)"
            
            # Teste die Konfiguration
            return self._test_audio_configuration()
            
        except Exception as e:
            print(f"[AUDIO] Basic PyAudio configuration failed: {e}")
            return False

    def _emergency_fallback(self):
        """Notfall-Fallback für komplett fehlgeschlagene Initialisierung"""
        print("[AUDIO] 🚨 USING EMERGENCY FALLBACK CONFIGURATION")
        
        try:
            # Erstelle eine minimale PyAudio-Instanz
            self.audio = pyaudio.PyAudio()
            self.using_pyaudio_fallback = True
        except:
            print("[AUDIO] 💥 CRITICAL: Cannot create PyAudio instance")
            return False
        
        # Absolute Minimum-Konfiguration
        self.input_device_index = 0
        self.output_device_index = 0
        self.FORMAT = pyaudio.paInt16
        self.RATE = 22050  # Noch niedrigere Rate für Stabilität
        self.CHANNELS = 1
        self.CHUNK = 256
        self.sample_width = 2
        self.actual_format = "16-bit"
        self.sample_format_name = "16-bit @ 22.05kHz (EMERGENCY FALLBACK)"
        self.quality_profile = "openbsd_fallback"
        
        print("[AUDIO] ✅ Emergency fallback configuration applied")
        return True

    def _configure_standard_platform(self):
        """Konfiguration für nicht-OpenBSD Plattformen"""
        try:
            self._apply_quality_profile()
            return self.verify_audio_configuration()
        except Exception as e:
            print(f"[AUDIO] Standard platform configuration failed: {e}")
            return False

    def detect_openbsd_audio_devices(self):
        """OpenBSD-spezifische Audio-Device-Erkennung mit Fallback"""
        try:
            devices_found = []
            
            # 1. Prüfe ob sndiod läuft
            result = subprocess.run(['pgrep', 'sndiod'], capture_output=True, text=True, timeout=5)
            sndiod_running = (result.returncode == 0)
            
            if sndiod_running:
                print("[AUDIO] sndiod läuft")
                try:
                    result = subprocess.run(['sndioctl', '-d'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        devices_found.append("sndio Default (über sndiod)")
                        print("[AUDIO] sndioctl funktioniert")
                except Exception as e:
                    print(f"[AUDIO] sndioctl failed: {e}")
            
            # 2. Raw Devices identifizieren
            raw_devices = glob.glob('/dev/audio*')
            print(f"[AUDIO] Gefundene Raw Devices: {raw_devices}")
            
            # 3. PyAudio Devices prüfen (Fallback)
            try:
                if self.audio:
                    device_count = self.audio.get_device_count()
                    print(f"[AUDIO] PyAudio devices: {device_count}")
                    devices_found.append(f"PyAudio Devices: {device_count}")
            except:
                pass
                
            return len(devices_found) > 0
                
        except Exception as e:
            print(f"[AUDIO] OpenBSD Device Detection fehlgeschlagen: {e}")
            return False

    def get_openbsd_device_info(self):
        """Gibt OpenBSD Device-Informationen zurück mit Fallback"""
        devices = []
        
        try:
            # Kernel Audio Info
            try:
                result = subprocess.run(['sysctl', 'hw.snd'], capture_output=True, text=True, timeout=5)
                if 'default_unit' in result.stdout:
                    default_unit = result.stdout.split('default_unit=')[1].split()[0]
                    devices.append(f"0: Default Audio Unit {default_unit} (sysctl)")
            except:
                pass
            
            # Raw Devices auflisten
            raw_devices = glob.glob('/dev/audio*')
            for i, device in enumerate(raw_devices, 1):
                devices.append(f"{i}: {device} (Raw Device)")
            
            # PyAudio Devices als Fallback
            if self.audio:
                for i in range(self.audio.get_device_count()):
                    try:
                        device_info = self.audio.get_device_info_by_index(i)
                        device_name = device_info.get('name', f'Device {i}')
                        devices.append(f"pyaudio{i}: {device_name} (PyAudio)")
                    except:
                        continue
                
            # Falls keine Devices gefunden
            if not devices:
                devices.append("0: sndio Default (automatisch)")
                    
        except Exception as e:
            print(f"[AUDIO] OpenBSD Device Info Error: {e}")
            devices = ["0: Audio Default (OpenBSD)"]
        
        return devices

    def _test_audio_configuration(self):
        """Testet ob die aktuelle Audio-Konfiguration funktioniert"""
        try:
            # Teste Input Stream
            if self.input_device_index is not None:
                test_stream = self.audio.open(
                    format=self.FORMAT,
                    channels=self.CHANNELS,
                    rate=self.RATE,
                    input=True,
                    frames_per_buffer=self.CHUNK,
                    input_device_index=self.input_device_index
                )
                test_stream.stop_stream()
                test_stream.close()
            
            # Teste Output Stream (immer 16-bit Mono für Kompatibilität)
            if self.output_device_index is not None:
                test_stream = self.audio.open(
                    format=pyaudio.paInt16,
                    channels=1,
                    rate=self.RATE,
                    output=True,
                    frames_per_buffer=self.CHUNK,
                    output_device_index=self.output_device_index
                )
                test_stream.stop_stream()
                test_stream.close()
                
            return True
            
        except Exception as e:
            print(f"[AUDIO TEST] Configuration failed: {e}")
            return False

    def get_input_devices(self):
        """ZENTRALE Methode für Eingabegeräte - MIT ROBUSTEM OPENBSD SUPPORT"""
        # OpenBSD-spezifische Erkennung zuerst
        if sys.platform.startswith("openbsd"):
            return self.get_openbsd_device_info()
        
        # Normale PyAudio-Erkennung für andere Plattformen
        devices = []
        try:
            if self.audio:
                for i in range(self.audio.get_device_count()):
                    device_info = self.audio.get_device_info_by_index(i)
                    if device_info.get('maxInputChannels', 0) > 0:
                        device_name = device_info.get('name', f'Device {i}')
                        devices.append(f"{i}: {device_name} (Input)")
        except Exception as e:
            print(f"[INPUT DEVICES ERROR] {str(e)}")
            devices = ["0: Standard-Mikrofon (Input)"]
        
        if not devices:
            devices = ["0: Default Input Device"]
            
        return devices

    def get_output_devices(self):
        """ZENTRALE Methode für Ausgabegeräte - MIT ROBUSTEM OPENBSD SUPPORT"""
        # OpenBSD-spezifische Erkennung zuerst
        if sys.platform.startswith("openbsd"):
            return self.get_openbsd_device_info()
        
        # Normale PyAudio-Erkennung für andere Plattformen
        devices = []
        try:
            if self.audio:
                for i in range(self.audio.get_device_count()):
                    device_info = self.audio.get_device_info_by_index(i)
                    if device_info.get('maxOutputChannels', 0) > 0:
                        device_name = device_info.get('name', f'Device {i}')
                        
                        # Prüfe 24-bit Support
                        supports_24bit = False
                        try:
                            supports_24bit = self.audio.is_format_supported(
                                48000,
                                output_device=i,
                                output_channels=1, 
                                output_format=pyaudio.paInt24
                            )
                        except:
                            pass
                        
                        bit_info = " [24-bit]" if supports_24bit else " [16-bit]"
                        devices.append(f"{i}: {device_name}{bit_info}")
        except Exception as e:
            print(f"[OUTPUT DEVICES ERROR] {str(e)}")
            devices = ["0: Standard-Lautsprecher (Output)"]
        
        if not devices:
            devices = ["0: Default Output Device"]
            
        return devices

    def verify_audio_configuration(self):
        """Überprüft Audio-Konfiguration OHNE Qualitätseinstellungen zu überschreiben"""
        print("\n=== AUDIO CONFIGURATION VERIFICATION ===")
        
        try:
            # 1. Prüfe verfügbare Geräte (NUR Information)
            device_count = self.audio.get_device_count()
            print(f"[AUDIO] Available devices: {device_count}")
            
            # 2. Device-Erkennung (falls nicht gesetzt) - NUR FALLS NOTWENDIG
            if self.input_device_index is None:
                for i in range(device_count):
                    try:
                        device_info = self.audio.get_device_info_by_index(i)
                        if device_info.get('maxInputChannels', 0) > 0:
                            self.input_device_index = i
                            print(f"[AUDIO] Auto-selected input device {i}: {device_info['name']}")
                            break
                    except:
                        continue
            
            if self.output_device_index is None:
                for i in range(device_count):
                    try:
                        device_info = self.audio.get_device_info_by_index(i)
                        if device_info.get('maxOutputChannels', 0) > 0:
                            self.output_device_index = i
                            print(f"[AUDIO] Auto-selected output device {i}: {device_info['name']}")
                            break
                    except:
                        continue
            
            # 3. ✅ WICHTIG: QUALITÄTSEINSTELLUNGEN BEIBEHALTEN!
            # Speichere die aktuellen Qualitätseinstellungen
            current_format = self.FORMAT
            current_rate = self.RATE
            current_channels = self.CHANNELS
            current_quality = self.quality_profile
            
            print(f"[AUDIO] Current quality settings:")
            print(f"  Format: {current_format} ({self.actual_format})")
            print(f"  Sample Rate: {current_rate} Hz")
            print(f"  Channels: {current_channels}")
            print(f"  Quality Profile: {current_quality}")
            
            # 4. Prüfe ob das gewählte Format unterstützt wird (NUR PRÜFEN!)
            try:
                # Prüfe Input mit den AKTUELLEN Einstellungen
                if self.input_device_index is not None:
                    input_supported = self.audio.is_format_supported(
                        current_rate,
                        input_device=self.input_device_index,
                        input_channels=current_channels,
                        input_format=current_format
                    )
                    print(f"[AUDIO] Input format supported: {input_supported}")
                
                # Prüfe Output (Output immer 16-bit für Kompatibilität)
                if self.output_device_index is not None:
                    output_supported = self.audio.is_format_supported(
                        current_rate,
                        output_device=self.output_device_index,
                        output_channels=1,
                        output_format=pyaudio.paInt16
                    )
                    print(f"[AUDIO] Output format supported: {output_supported}")
                        
            except Exception as e:
                print(f"[AUDIO CHECK WARNING] {e}")
            
            # 5. ✅ QUALITÄTSEINSTELLUNGEN WIEDERHERSTELLEN!
            self.FORMAT = current_format
            self.RATE = current_rate
            self.CHANNELS = current_channels
            self.quality_profile = current_quality
            
            # 6. Chunk-Größe anpassen (ohne Qualität zu ändern)
            if self.RATE >= 96000:
                self.CHUNK = 256
            else:
                self.CHUNK = 128
            
            print(f"[AUDIO] Final configuration (QUALITY PRESERVED):")
            print(f"  Format: {self.FORMAT} ({self.actual_format})")
            print(f"  Sample Rate: {self.RATE} Hz") 
            print(f"  Channels: {self.CHANNELS}")
            print(f"  Chunk Size: {self.CHUNK}")
            print(f"  Quality: {self.sample_format_name}")
            
            return True
            
        except Exception as e:
            print(f"[AUDIO CONFIG ERROR] {e}")
            # Kein Fallback - behalte die gewählte Qualität
            return True

    def _apply_quality_profile(self):
        """Wendet die Qualitätsstufe an MIT Fallback bei Fehlern"""
        profile = self.QUALITY_PROFILES[self.quality_profile]
        
        # Versuche die gewünschte Qualität
        original_quality = self.quality_profile
        
        for attempt in range(3):  # Max 3 Versuche
            try:
                # Setze ALLE Qualitätseinstellungen aus dem Profile
                self.FORMAT = profile["format"]
                self.RATE = profile["rate"] 
                self.CHANNELS = profile["channels"]
                self.sample_format_name = profile["name"]
                self.actual_format = profile["actual_format"]
                
                # Sample Width basierend auf Format
                if self.actual_format == "S32_LE":
                    self.sample_width = 4
                elif self.actual_format == "24-bit":
                    self.sample_width = 3
                else:  # 16-bit
                    self.sample_width = 2
                
                # Chunk-Größe anpassen
                if self.RATE >= 96000:
                    self.CHUNK = 256
                else:
                    self.CHUNK = 128
                
                # ✅ TESTE OB DIE KONFIGURATION FUNKTIONIERT
                if self._test_audio_configuration():
                    print(f"✅ [AUDIO] Applied quality: {self.sample_format_name}")
                    print(f"[AUDIO] Channels: {self.CHANNELS}, Sample Rate: {self.RATE}Hz")
                    return True
                else:
                    raise Exception("Audio configuration test failed")
                    
            except Exception as e:
                print(f"❌ [AUDIO] Quality '{self.quality_profile}' failed: {e}")
                
                # Fallback zu nächstniedrigerer Qualität
                fallback_chain = {
                    "highest": "high",
                    "high": "middle", 
                    "middle": "low",
                    "low": "openbsd_fallback",
                    "openbsd_fallback": "openbsd_fallback"  # Letzter Fallback
                }
                
                fallback = fallback_chain.get(self.quality_profile, "openbsd_fallback")
                if fallback == self.quality_profile:  # Kein weiterer Fallback möglich
                    print("💥 [AUDIO] No working audio configuration found!")
                    return False
                    
                print(f"🔄 [AUDIO] Falling back to: {fallback}")
                self.quality_profile = fallback
                profile = self.QUALITY_PROFILES[fallback]
        
        return False

    def set_quality(self, quality_level):
        """Setzt die Audio-Qualitätsstufe MIT DEBUG"""
        print(f"[DEBUG] set_quality called: {self.quality_profile} -> {quality_level}")
        import traceback
        traceback.print_stack()
        
        if quality_level in self.QUALITY_PROFILES:
            self.quality_profile = quality_level
            self._apply_quality_profile()
            return True
        
        print(f"[AUDIO WARNING] Invalid quality level: {quality_level}")
        return False
        
    def configure_output(self, device_index):
        """Konfiguriert Ausgabegerät und prüft 24-bit Support"""
        self.output_device_index = device_index
        
        try:
            # Prüfe ob 24-bit unterstützt wird
            self.output_supports_24bit = self.audio.is_format_supported(
                self.RATE,
                output_device=device_index,
                output_channels=1,
                output_format=pyaudio.paInt24
            )
            
            if self.output_supports_24bit:
                print("✅ Output device supports 24-bit")
            else:
                print("⚠️ Output device only supports 16-bit, will convert if needed")
                
        except Exception as e:
            print(f"[OUTPUT CHECK ERROR] {e}, assuming 16-bit")
            self.output_supports_24bit = False
    
    def detect_best_format(self, device_index, is_input=True):
        """Erkennt das beste verfügbare Format für ein Gerät"""
        formats_to_try = [
            (pyaudio.paFloat32, 192000),
            (pyaudio.paInt24, 192000),
            (pyaudio.paInt24, 96000),
            (pyaudio.paInt24, 48000),
            (pyaudio.paInt16, 48000),
            (pyaudio.paInt16, 44100),
        ]
        
        for fmt, rate in formats_to_try:
            try:
                if is_input:
                    supported = self.audio.is_format_supported(
                        rate,
                        input_device=device_index,
                        input_channels=1,
                        input_format=fmt
                    )
                else:
                    supported = self.audio.is_format_supported(
                        rate,
                        output_device=device_index,
                        output_channels=1,
                        output_format=fmt
                    )
                
                if supported:
                    print(f"[AUDIO] Best format detected: {fmt} @ {rate}Hz")
                    return fmt, rate
            except:
                continue
        
        # Fallback
        return pyaudio.paInt16, 44100
    
    def auto_configure_input(self, device_index):
        """Automatische Konfiguration für Eingabegerät"""
        self.input_device_index = device_index
        self.FORMAT, self.RATE = self.detect_best_format(device_index, is_input=True)
        
        # Passe Chunk-Größe basierend auf Sample-Rate an
        if self.RATE >= 96000:
            self.CHUNK = 256    
        else:
            self.CHUNK = 128
            
        self._print_config("Input")
    
    def auto_configure_output(self, device_index):
        """Automatische Konfiguration für Ausgabegerät"""
        self.output_device_index = device_index
        self.FORMAT, self.RATE = self.detect_best_format(device_index, is_input=False)
        self._print_config("Output")
    
    def _print_config(self, device_type):
        """Gibt die aktuelle Konfiguration aus"""
        print(f"\n🎵 {device_type} Audio Configuration:")
        print(f"   Format: {self.sample_format_name}")
        print(f"   Sample Rate: {self.RATE} Hz")
        print(f"   Channels: {self.CHANNELS}")
        print(f"   Chunk Size: {self.CHUNK} frames")
        print(f"   Data Rate: {(self.RATE * self.sample_width * self.CHANNELS) / 1000:.1f} kB/s")
    
    def cleanup(self):
        """Ressourcen freigeben mit Fehlerbehandlung"""
        try:
            if self.audio:
                self.audio.terminate()
                self.audio = None
        except Exception as e:
            print(f"[AUDIO CLEANUP WARNING] {e}")

    # ✅ NOISE PROFILING METHODEN
    def enable_noise_filter(self, enabled=True):
        """Aktiviert/Deaktiviert die Rauschfilterung"""
        self.noise_profile['enabled'] = enabled
        print(f"[NOISE FILTER] {'Aktiviert' if enabled else 'Deaktiviert'}")

    def set_aggressive_noise_reduction(self, aggressive=True):
        """Setzt aggressiven Rauschfilter-Modus"""
        self.noise_profile['aggressive_mode'] = aggressive
        print(f"[NOISE FILTER] Aggressive Mode: {aggressive}")

    def capture_noise_profile(self, duration=180, progress_callback=None):
        """
        Erstellt ein Rauschprofil mit 180 Sekunden Clear Room Aufnahme
        """
        try:
            print(f"[NOISE PROFILING] Starte 180 Sekunden Rauschprofil-Erstellung...")
            print("[NOISE PROFILING] Bitte absolute Stille im Raum während der Aufnahme!")
            
            # Temporären Stream für Profil-Erstellung öffnen
            stream = self.audio.open(
                format=self.FORMAT,
                channels=1,
                rate=self.RATE,
                input=True,
                frames_per_buffer=self.CHUNK,
                input_device_index=self.input_device_index
            )
            
            noise_samples = []
            start_time = time.time()
            total_frames = int((self.RATE / self.CHUNK) * duration)
            update_interval = max(1, total_frames // 100)  # 100 Updates
            
            # Sammle Rauschdaten für 180 Sekunden
            for frame_count in range(total_frames):
                try:
                    data = stream.read(self.CHUNK, exception_on_overflow=False)
                    noise_samples.append(data)
                    
                    # Fortschritt berechnen und callback aufrufen
                    if frame_count % update_interval == 0:
                        progress = (frame_count / total_frames) * 100
                        self.audio_stats['capture_progress'] = progress
                        elapsed = time.time() - start_time
                        remaining = (duration - elapsed) if elapsed < duration else 0
                        
                        print(f"[NOISE PROFILING] Fortschritt: {progress:.1f}% - Verbleibend: {remaining:.0f}s")
                        
                        if progress_callback:
                            progress_callback(progress, remaining)
                            
                except Exception as e:
                    print(f"[NOISE PROFILING] Fehler beim Lesen: {e}")
                    break
            
            stream.stop_stream()
            stream.close()
            
            if not noise_samples:
                print("[NOISE PROFILING] Keine Daten gesammelt")
                return False
            
            # Analysiere Rauschprofil
            self._analyze_noise_profile(noise_samples)
            self.noise_profile['profile_captured'] = True
            
            # Profil speichern
            self._save_noise_profile()
            
            total_time = time.time() - start_time
            print(f"[NOISE PROFILING] Profil erfolgreich erstellt ({total_time:.1f}s)")
            print(f"[NOISE PROFILING] Rauschschwelle: {self.noise_profile['noise_threshold']:.6f}")
            print(f"[NOISE PROFILING] Rausch-Level: {self.audio_stats['noise_floor']:.6f}")
            
            return True
            
        except Exception as e:
            print(f"[NOISE PROFILING ERROR] {str(e)}")
            return False

    def _analyze_noise_profile(self, noise_samples):
        """Analysiert die gesammelten Rauschdaten und erstellt Profil"""
        try:
            
            # Kombiniere alle Samples
            all_data = b''.join(noise_samples)
            
            # Konvertiere zu numpy array basierend auf Format
            if self.FORMAT == pyaudio.paFloat32:
                audio_data = np.frombuffer(all_data, dtype=np.float32)
            elif self.FORMAT == pyaudio.paInt24:
                audio_data = self._convert_24bit_to_32float(all_data)
            else:  # paInt16
                audio_data = np.frombuffer(all_data, dtype=np.int16).astype(np.float32) / 32768.0
            
            # Berechne RMS (Root Mean Square) des Rauschens
            rms = np.sqrt(np.mean(audio_data ** 2))
            
            # Setze Rauschschwelle basierend auf RMS mit Sicherheitsmargin
            self.noise_profile['noise_threshold'] = float(rms * 2.0)
            self.audio_stats['noise_floor'] = float(rms)
            self.audio_stats['rms_level'] = float(rms)
            
            # Signal/Rausch-Verhältnis berechnen (theoretisch)
            self.audio_stats['signal_to_noise'] = -20 * np.log10(rms) if rms > 0 else 0
            
            # Detaillierte Frequenzanalyse für 180s Profil
            self._calculate_detailed_frequency_profile(audio_data)
            
        except Exception as e:
            print(f"[NOISE ANALYSIS ERROR] {str(e)}")
            # Fallback-Werte
            self.noise_profile['noise_threshold'] = 0.005
            self.audio_stats['noise_floor'] = 0.002

    def _calculate_detailed_frequency_profile(self, audio_data):
        """Detaillierte Frequenzanalyse für 180s Profil ohne scipy"""
        try:
            # Verwende nur einen Teil der Daten für FFT (Performance)
            sample_size = min(len(audio_data), 44100 * 10)
            analysis_data = audio_data[:sample_size]
            
            # FFT für Frequenzanalyse mit numpy
            fft_data = np.fft.fft(analysis_data)
            frequencies = np.fft.fftfreq(len(analysis_data), 1.0 / self.RATE)
            
            # Power Spectrum
            power_spectrum = np.abs(fft_data) ** 2
            
            # Identifiziere dominante Rauschfrequenzen
            positive_freq = frequencies[:len(frequencies)//2]
            positive_power = power_spectrum[:len(power_spectrum)//2]
            
            # Finde Peaks im Frequenzbereich
            noise_peaks = []
            for i in range(1, len(positive_power)-1):
                if (positive_power[i] > positive_power[i-1] and 
                    positive_power[i] > positive_power[i+1] and
                    positive_power[i] > np.mean(positive_power) * 10):
                    noise_peaks.append((positive_freq[i], positive_power[i]))
            
            self.noise_profile['frequency_profile'] = {
                'frequencies': positive_freq,
                'power': positive_power,
                'peaks': sorted(noise_peaks, key=lambda x: x[1], reverse=True)[:10]
            }
            
            print(f"[NOISE PROFILE] Gefundene Rausch-Peaks: {len(noise_peaks)}")
            
        except Exception as e:
            print(f"[FREQUENCY PROFILE ERROR] {str(e)}")

    def _save_noise_profile(self):
        """Speichert das Rauschprofil in einer kompakten Datei"""
        try:
            
            profile_data = {
                'noise_threshold': self.noise_profile['noise_threshold'],
                'noise_floor': self.audio_stats['noise_floor'],
                'sample_rate': self.RATE,
                'format': self.FORMAT,
                'timestamp': time.time(),
                'duration': 180,
                'frequency_profile': self.noise_profile.get('frequency_profile'),
                'filter_settings': self.filter_coefficients.copy(),
                'audio_stats': self.audio_stats.copy()
            }
            
            with open('noise_profile_180s.pkl', 'wb') as f:
                json.dump(profile_data, f)
            print(f"[NOISE PROFILE] 180s Profil gespeichert: noise_profile_180s.pkl")
            
        except Exception as e:
            print(f"[NOISE PROFILE SAVE ERROR] {str(e)}")

    def load_noise_profile(self, filename='noise_profile_180s.pkl'):
        """Lädt ein gespeichertes Rauschprofil"""
        try:            
            with open(filename, 'rb') as f:
                profile_data = json.load(f)
            
            # Profil-Daten anwenden
            self.noise_profile['noise_threshold'] = profile_data['noise_threshold']
            self.noise_profile['profile_captured'] = True
            self.audio_stats['noise_floor'] = profile_data['noise_floor']
            
            if 'frequency_profile' in profile_data:
                self.noise_profile['frequency_profile'] = profile_data['frequency_profile']
            
            if 'filter_settings' in profile_data:
                self.filter_coefficients.update(profile_data['filter_settings'])
            
            if 'audio_stats' in profile_data:
                self.audio_stats.update(profile_data['audio_stats'])
            
            print(f"[NOISE PROFILE] 180s Profil geladen: {filename}")
            print(f"[NOISE PROFILE] Rauschschwelle: {self.noise_profile['noise_threshold']:.6f}")
            print(f"[NOISE PROFILE] Aufnahmedauer: {profile_data.get('duration', 'unbekannt')}s")
            
            return True
            
        except FileNotFoundError:
            print(f"[NOISE PROFILE] Datei nicht gefunden: {filename}")
            return False
        except Exception as e:
            print(f"[NOISE PROFILE LOAD ERROR] {str(e)}")
            return False

    def apply_noise_filter(self, audio_data):
        """
        Wendet Rauschfilter auf Audio-Daten an
        Gibt gefilterte Daten zurück
        """
        if not self.noise_profile['enabled'] or not self.noise_profile['profile_captured']:
            return audio_data
        
        try:
            # Konvertiere zu numpy array basierend auf Format
            if self.FORMAT == pyaudio.paFloat32:
                data_array = np.frombuffer(audio_data, dtype=np.float32)
            elif self.FORMAT == pyaudio.paInt24:
                data_array = self._convert_24bit_to_32float(audio_data)
            else:  # paInt16
                data_array = np.frombuffer(audio_data, dtype=np.int16).astype(np.float32) / 32768.0
            
            # 1. Spektrale Rauschunterdrückung
            filtered_data = self._apply_spectral_noise_reduction(data_array)
            
            # 2. Adaptives Noise Gate
            filtered_data = self._apply_adaptive_gate(filtered_data)
            
            # 3. Frequenz-basierte Filterung (nur bei aggressivem Modus)
            if self.noise_profile['aggressive_mode']:
                filtered_data = self._apply_frequency_filters(filtered_data)
            
            # Konvertiere zurück zum ursprünglichen Format
            if self.FORMAT == pyaudio.paFloat32:
                return filtered_data.astype(np.float32).tobytes()
            elif self.FORMAT == pyaudio.paInt24:
                return self._convert_32float_to_24bit(filtered_data)
            else:  # paInt16
                return (filtered_data * 32768.0).astype(np.int16).tobytes()
            
        except Exception as e:
            print(f"[NOISE FILTER ERROR] {str(e)}")
            return audio_data

    def _apply_spectral_noise_reduction(self, data):
        """Wendet spektrale Rauschunterdrückung an ohne scipy"""
        try:
            # Einfache spektrale Subtraktion mit numpy
            fft_data = np.fft.fft(data)
            magnitude = np.abs(fft_data)
            phase = np.angle(fft_data)
            
            # Rauschschwelle im Frequenzbereich
            noise_threshold_freq = self.noise_profile['noise_threshold'] * np.mean(magnitude)
            
            # Spektrale Subtraktion
            magnitude_clean = magnitude - noise_threshold_freq
            magnitude_clean = np.maximum(magnitude_clean, 0)
            
            # Rücktransformation
            clean_fft = magnitude_clean * np.exp(1j * phase)
            clean_data = np.real(np.fft.ifft(clean_fft))
            
            return clean_data
            
        except Exception as e:
            # Fallback: einfache Amplituden-Begrenzung
            print(f"[SPECTRAL REDUCTION FALLBACK] {e}")
            threshold = self.noise_profile['noise_threshold']
            return np.where(np.abs(data) < threshold, 0, data)

    def _apply_adaptive_gate(self, data):
        """Wendet adaptives Noise Gate an"""
        rms = np.sqrt(np.mean(data ** 2))
        self.audio_stats['rms_level'] = float(rms)
        
        # Adaptive Schwelle basierend auf Signalstärke
        base_threshold = self.noise_profile['noise_threshold']
        if self.noise_profile['aggressive_mode']:
            base_threshold *= 0.7
        
        adaptive_threshold = base_threshold
        
        # Dynamische Anpassung basierend auf Signalstärke
        if rms > self.audio_stats['noise_floor'] * 20:
            adaptive_threshold *= 0.3
        elif rms > self.audio_stats['noise_floor'] * 10:
            adaptive_threshold *= 0.5
        elif rms < self.audio_stats['noise_floor'] * 3:
            adaptive_threshold *= 3.0
        
        # Noise Gate anwenden
        gated_data = np.where(np.abs(data) < adaptive_threshold, 0, data)
        
        return gated_data

    def _apply_frequency_filters(self, data):
        """Wendet frequenzspezifische Filter an (aggressiver Modus) ohne scipy"""
        try:
            # Einfacher FIR Filter-Ansatz ohne scipy.signal
            # Hochpass-Filter für Tieffrequenz-Rauschen (einfache Implementierung)
            if self.filter_coefficients['low_freq_cutoff'] > 0:
                # Einfacher Differenzfilter als Hochpass-Approximation
                filtered_data = np.zeros_like(data)
                for i in range(1, len(data)):
                    filtered_data[i] = data[i] - 0.95 * data[i-1]
                data = filtered_data
            
            # Einfacher Notch Filter für 50Hz Brummen
            if self.filter_coefficients['hum_filter_freq'] > 0:
                # Grundfrequenz der Netzspannung (50Hz)
                hum_freq = self.filter_coefficients['hum_filter_freq']
                samples_per_hum_period = int(self.RATE / hum_freq)
                
                if samples_per_hum_period > 0:
                    # Einfache Moving Average Subtraktion
                    window_size = samples_per_hum_period
                    if window_size < len(data):
                        hum_reference = np.convolve(data, np.ones(window_size)/window_size, mode='same')
                        data = data - 0.7 * hum_reference
            
            return data
            
        except Exception as e:
            print(f"[FREQUENCY FILTER FALLBACK] {e}")
            return data

    # ✅ KONVERTIERUNGS-METHODEN
    def _convert_24bit_to_32float(self, data_24bit):
        """Konvertiert 24-bit zu 32-bit Float"""
        audio_32int = np.frombuffer(data_24bit, dtype=np.int32)
        return audio_32int.astype(np.float32) / 8388607.0

    def _convert_32float_to_24bit(self, data_32float):
        """Konvertiert 32-bit Float zu 24-bit"""
        
        audio_clipped = np.clip(data_32float, -1.0, 1.0)
        audio_24bit = (audio_clipped * 8388607.0).astype(np.int32)
        return audio_24bit.tobytes()

    def get_noise_profile_info(self):
        """Gibt Informationen über das aktuelle Rauschprofil zurück"""
        if not self.noise_profile['profile_captured']:
            return "Kein Rauschprofil vorhanden"
        
        info = f"""
Rauschprofil Informationen (180s Clear Room):
- Aktiv: {'Ja' if self.noise_profile['enabled'] else 'Nein'}
- Rauschschwelle: {self.noise_profile['noise_threshold']:.6f}
- Rausch-Level: {self.audio_stats['noise_floor']:.6f}
- Signal/Rausch: {self.audio_stats.get('signal_to_noise', 0):.2f} dB
- Aggressiv: {'Ja' if self.noise_profile['aggressive_mode'] else 'Nein'}
- Adaptiv: {'Ja' if self.noise_profile['adaptive_filter'] else 'Nein'}
- Frequenz-Peaks: {len(self.noise_profile.get('frequency_profile', {}).get('peaks', []))}
"""
        return info

    def test_audio_output(self, output_device_index=None, duration=10):
        """Testet Audio-Ausgabe mit 10 Sekunden synthetischem Signal"""
        try:
            print(f"[AUDIO TEST] Starting {duration} second audio output test...")
            
            # Device-Index bestimmen
            if output_device_index is None:
                # Fallback: Verwende das aktuell konfigurierte Output-Device
                output_device_index = self.output_device_index or 0
                print(f"[AUDIO TEST] Using configured device index: {output_device_index}")
            else:
                print(f"[AUDIO TEST] Using provided device index: {output_device_index}")
            
            # Output Stream öffnen
            stream = self.audio.open(
                format=pyaudio.paInt16,  # Immer 16-bit für Kompatibilität
                channels=1,
                rate=44100,  # Standard Sample Rate
                output=True,
                frames_per_buffer=1024,
                output_device_index=output_device_index
            )
            
            print(f"[AUDIO TEST] Output stream opened, generating test signal...")
            
            # Synthetisches Test-Signal erzeugen (440Hz Sinus + 880Hz Oberwelle)
            def generate_test_signal(duration_seconds, sample_rate=44100):
                
                t = np.linspace(0, duration_seconds, int(sample_rate * duration_seconds))
                
                # Hauptfrequenz 440Hz (A4) + Oberwelle 880Hz
                frequency1 = 440.0  # A4
                frequency2 = 880.0  # A5
                
                # Erzeuge Sinus-Wellen mit abnehmender Lautstärke
                signal1 = 0.7 * np.sin(2 * np.pi * frequency1 * t)
                signal2 = 0.3 * np.sin(2 * np.pi * frequency2 * t)
                
                # Kombiniere Signale
                combined_signal = signal1 + signal2
                
                # Fade-In und Fade-Out um Knackgeräusche zu vermeiden
                fade_samples = int(0.1 * sample_rate)  # 100ms Fade
                fade_in = np.linspace(0, 1, fade_samples)
                fade_out = np.linspace(1, 0, fade_samples)
                
                combined_signal[:fade_samples] *= fade_in
                combined_signal[-fade_samples:] *= fade_out
                
                # Konvertiere zu 16-bit Integer
                signal_16bit = (combined_signal * 32767).astype(np.int16)
                
                return signal_16bit.tobytes()
            
            # Signal generieren
            test_signal = generate_test_signal(duration)
            
            print(f"[AUDIO TEST] Test signal generated ({len(test_signal)} bytes)")
            
            # Signal in Chunks abspielen
            chunk_size = 1024
            total_chunks = len(test_signal) // chunk_size
            
            for i in range(total_chunks):
                start_idx = i * chunk_size
                end_idx = start_idx + chunk_size
                
                if end_idx <= len(test_signal):
                    chunk = test_signal[start_idx:end_idx]
                    stream.write(chunk)
                
                # Fortschritt anzeigen
                progress = (i + 1) / total_chunks * 100
                if i % 50 == 0:  # Alle 50 Chunks loggen
                    print(f"[AUDIO TEST] Progress: {progress:.1f}%")
            
            # Stream schließen
            stream.stop_stream()
            stream.close()
            
            print(f"[AUDIO TEST] ✅ Audio output test completed successfully!")
            return True
            
        except Exception as e:
            print(f"[AUDIO TEST ERROR] ❌ Test failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Versuche Stream zu schließen falls geöffnet
            try:
                if 'stream' in locals():
                    stream.stop_stream()
                    stream.close()
            except:
                pass
                
            return False

    def get_audio_status(self):
        """Gibt den aktuellen Audio-Status zurück"""
        status = {
            "platform": sys.platform,
            "initialized": self.audio is not None,
            "using_fallback": self.using_pyaudio_fallback,
            "quality_profile": self.quality_profile,
            "sample_rate": self.RATE,
            "channels": self.CHANNELS,
            "format": self.actual_format,
            "input_device": self.input_device_index,
            "output_device": self.output_device_index
        }
        return status
class ClientRelayManager:
    def __init__(self, client_instance):
        self.client = client_instance
        self.available_servers = {}  # {server_ip: server_data}
        self.best_server = None
        self.server_load_threshold = 80  # Server mit Load > 80% vermeiden
        
        # Feste Seed-Server Liste - gleiche wie im Server
        self.SEED_SERVERS = [
            ("sichereleitung.duckdns.org", 5060),  # Haupt-SIP Port
            ("sichereleitung.duckdns.org", 5061),  # Alternativ-Port
        ]
        
        # Status-Variablen
        self.connection_status = "disconnected"
        self.last_discovery = 0
        self.discovery_interval = 300  # 5 Minuten
        
        print(f"[CLIENT RELAY] Initialized with {len(self.SEED_SERVERS)} seed servers")
    def debug_server_discovery(self):
        """Manuelle Debug-Methode für Server Discovery"""
        try:
            print("\n=== MANUAL SERVER DISCOVERY DEBUG ===")
            
            # ✅ ROBUSTER FALLBACK FÜR CLIENT-NAME
            client_name = getattr(self, '_client_name', None)
            if client_name is None:
                client_name = f"debug_client_{int(time.time())}"
                print(f"⚠️ [DEBUG] Client name not available, using fallback: {client_name}")
            
            for seed_host, seed_port in self.relay_manager.SEED_SERVERS:
                print(f"\nTrying {seed_host}:{seed_port}")
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((seed_host, seed_port))
                    
                    # ✅ DIREKTE GENERATOR VERWENDUNG MIT FALLBACK
                    generator = init_verify_generator(client_name, client_name)  # ✅ DIREKT
                    verify_code = generator.generate_verify_code()
                    print(f"[DEBUG] Generated verify-code: {verify_code}")
                    
                    # Einfache Test-Nachricht MIT VERIFY-CODE IM BODY
                    test_data = {
                        "MESSAGE_TYPE": "GET_SERVERS",
                        "CLIENT_NAME": client_name,
                        "TIMESTAMP": int(time.time()),
                        "verify_code": verify_code  # ✅ VERIFY-CODE IM BODY HINZUFÜGEN
                    }
                    
                    # OHNE additional_headers Parameter
                    test_msg = self.build_sip_message(
                        "MESSAGE", 
                        seed_host, 
                        test_data
                    )
                    
                    print(f"Sending test message to {seed_host}:{seed_port} with verify-code: {verify_code}")
                    if send_frame(sock, test_msg.encode()):
                        response = recv_frame(sock)
                        if response:
                            print(f"Raw response ({len(response)} bytes):")
                            if isinstance(response, bytes):
                                response_str = response.decode('utf-8', errors='ignore')
                            else:
                                response_str = str(response)
                            
                            print(f"First 500 chars: {response_str[:500]}")
                            
                            # Versuche zu parsen
                            try:
                                parsed = self.parse_sip_message(response_str)
                                if parsed:
                                    print("✓ Successfully parsed as SIP")
                                    print(f"Body: {parsed.get('body', 'No body')[:200]}...")
                                else:
                                    print("✗ Failed to parse as SIP")
                            except Exception as e:
                                print(f"✗ Parse error: {e}")
                        else:
                            print("✗ No response received")
                    else:
                        print("✗ Failed to send message")
                        
                    sock.close()
                    
                except Exception as e:
                    print(f"✗ Connection failed: {e}")
            
            print("\n=== END DEBUG ===")
            
        except Exception as e:
            print(f"Debug failed: {e}")
    def discover_servers(self):
        """Entdeckt verfügbare Server von Seed-Servern - verwendet framed SIP"""
        print("[CLIENT RELAY] Starting server discovery...")
        
        discovered_servers = {}
        
        # ✅ ROBUSTER FALLBACK FÜR CLIENT-NAME
        client_name = getattr(self.client, '_client_name', None)
        if client_name is None:
            client_name = f"discovery_client_{int(time.time())}"
            print(f"⚠️ [CLIENT RELAY] Client name not initialized, using fallback: {client_name}")
        
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                print(f"[CLIENT RELAY] Trying {seed_host}:{seed_port}")
                
                # Framed SIP für Discovery
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((seed_host, seed_port))
                
                # ✅ DIREKTE GENERATOR VERWENDUNG MIT FALLBACK
                generator = init_verify_generator(client_name, client_name)  # ✅ DIREKT
                verify_code = generator.generate_verify_code()
                print(f"[CLIENT RELAY] Generated verify-code for discovery: {verify_code}")
                
                # Baue SIP-Nachricht für Server-Liste Anfrage MIT VERIFY-CODE
                request_data = {
                    'type': 'get_servers',
                    'requester_type': 'client',
                    'client_name': client_name,
                    'timestamp': time.time()
                    # ✅ VERIFY-CODE WIRD IM HEADER GESENDET, NICHT IM BODY
                }
                
                # Baue SIP-Nachricht OHNE additional_headers
                sip_message = self.client.build_sip_message(
                    "MESSAGE",
                    seed_host, 
                    request_data
                )
                
                # ✅ MANUELL VERIFY-HEADER HINZUFÜGEN
                lines = sip_message.split('\r\n')
                
                # Finde die Stelle wo wir den Verify-Header einfügen können (vor Content-Headern)
                insert_position = -1
                for i, line in enumerate(lines):
                    if line.startswith('Content-Type:') or line.startswith('Content-Length:'):
                        insert_position = i
                        break
                
                if insert_position != -1:
                    lines.insert(insert_position, f"Verify-Code: {verify_code}")
                else:
                    # Falls keine Content-Header gefunden, vor dem leeren Zeilen-Trenner einfügen
                    for i, line in enumerate(lines):
                        if line == '':
                            lines.insert(i, f"Verify-Code: {verify_code}")
                            break
                    else:
                        # Notfall: am Ende einfügen
                        lines.insert(-1, f"Verify-Code: {verify_code}")
                
                sip_message_with_verify = '\r\n'.join(lines)
                
                print(f"[CLIENT RELAY] Sending discovery request to {seed_host}:{seed_port} with verify-code: {verify_code}")
                
                if send_frame(sock, sip_message_with_verify.encode()):
                    # Empfange Response
                    print(f"[CLIENT RELAY] Waiting for response from {seed_host}:{seed_port}")
                    response_data = recv_frame(sock)
                    
                    if response_data:
                        print(f"[CLIENT RELAY] Received {len(response_data)} bytes from {seed_host}")
                        
                        try:
                            # Versuche zuerst als String zu decodieren
                            if isinstance(response_data, bytes):
                                response_str = response_data.decode('utf-8')
                            else:
                                response_str = str(response_data)
                            
                            print(f"[CLIENT RELAY] Raw response: {response_str[:200]}...")
                            
                            # Parse die SIP Nachricht
                            sip_data = self.client.parse_sip_message(response_str)
                            if not sip_data:
                                print(f"[CLIENT RELAY] Failed to parse SIP message from {seed_host}")
                                continue
                            
                            # Extrahiere den Body
                            body = sip_data.get('body', '')
                            if not body:
                                print(f"[CLIENT RELAY] No body in response from {seed_host}")
                                continue
                            
                            print(f"[CLIENT RELAY] Response body: {body[:200]}...")
                            
                            # Parse JSON Body
                            try:
                                response = json.loads(body)
                                print(f"[CLIENT RELAY] JSON parsed successfully from {seed_host}")
                                
                                if response.get('status') == 'success':
                                    servers = response.get('servers', {})
                                    print(f"[CLIENT RELAY] Found {len(servers)} servers from {seed_host}")
                                    
                                    # Füge gefundene Server hinzu
                                    for server_ip, server_data in servers.items():
                                        if server_ip not in discovered_servers:
                                            discovered_servers[server_ip] = server_data
                                            print(f"[CLIENT RELAY] Added server: {server_ip} - {server_data.get('name', 'Unknown')}")
                                    
                                else:
                                    print(f"[CLIENT RELAY] Server returned error: {response.get('error', 'Unknown error')}")
                                    
                            except json.JSONDecodeError as e:
                                print(f"[CLIENT RELAY] JSON decode error from {seed_host}: {e}")
                                print(f"[CLIENT RELAY] Body content that failed: {body}")
                                continue
                                
                        except Exception as e:
                            print(f"[CLIENT RELAY] Response processing error from {seed_host}: {e}")
                            continue
                        
                    else:
                        print(f"[CLIENT RELAY] No response data from {seed_host}")
                else:
                    print(f"[CLIENT RELAY] Failed to send request to {seed_host}")
                    
                sock.close()
                
            except socket.timeout:
                print(f"[CLIENT RELAY] Timeout connecting to {seed_host}:{seed_port}")
                continue
            except ConnectionRefusedError:
                print(f"[CLIENT RELAY] Connection refused by {seed_host}:{seed_port}")
                continue
            except Exception as e:
                print(f"[CLIENT RELAY ERROR] Discovery from {seed_host}:{seed_port} failed: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        # Aktualisiere verfügbare Server
        self.available_servers = discovered_servers
        self.last_discovery = time.time()
        
        # Wähle besten Server aus
        self._select_best_server()
        
        print(f"[CLIENT RELAY] Discovery complete - {len(self.available_servers)} servers available")
        return self.best_server

    def _select_best_server(self):
        """Wählt besten Server aus - KORRIGIERT für beide Ports"""
        if not self.available_servers:
            self.best_server = None
            return
        
        print("[CLIENT RELAY] Testing server pings on all available ports...")
        
        server_pings = {}
        local_ips = self._get_local_ips()
        
        # Ping alle Server
        threads = []
        for server_ip, server_data in self.available_servers.items():
            # Überspringe Self-Ping
            if server_ip in local_ips:
                print(f"[RELAY] Skipping self-server: {server_ip}")
                continue
                
            thread = threading.Thread(
                target=self._ping_server,
                args=(server_ip, server_data, server_pings),
                daemon=True
            )
            threads.append(thread)
            thread.start()
        
        # Warte auf Threads
        for thread in threads:
            thread.join(timeout=15.0)  # Höheres Timeout für beide Ports
        
        # ✅ FALLBACK: Wenn Ping fehlschlägt aber Server verfügbar ist
        # (kann passieren wenn Firewall Pings blockiert aber Verbindung möglich ist)
        available_servers = []
        for server_ip, server_data in self.available_servers.items():
            current_load = server_data.get('current_load', 100)
            ping_time = server_pings.get(server_ip, float('inf'))
            
            if current_load > self.server_load_threshold:
                print(f"[RELAY] Skipping {server_ip} - load too high: {current_load}%")
                continue
            
            # ✅ KORREKTUR: Auch Server ohne erfolgreichen Ping berücksichtigen
            # (können trotzdem funktionieren, Ping könnte blockiert sein)
            if ping_time == float('inf'):
                print(f"[RELAY] {server_ip}: Ping failed, but server might still be reachable")
                # Simuliere einen mittleren Ping-Wert für Fallback
                simulated_ping = 100.0  # 100ms als Fallback
                available_servers.append({
                    'server_data': server_data,
                    'ping_time': simulated_ping,
                    'load': current_load,
                    'fallback': True  # Markiere als Fallback
                })
                print(f"[RELAY] {server_ip}: Using fallback ping: {simulated_ping}ms")
            else:
                available_servers.append({
                    'server_data': server_data,
                    'ping_time': ping_time,
                    'load': current_load,
                    'fallback': False
                })
                print(f"[RELAY] {server_ip}: ping={ping_time:.2f}ms, load={current_load}%")
        
        if not available_servers:
            print("[RELAY] No suitable servers found")
            self.best_server = None
            return
        
        # Sortiere: Zuerst Server mit echten Pings, dann Fallbacks
        available_servers.sort(key=lambda x: (x.get('fallback', False), x['ping_time']))
        
        # Wähle besten Server
        best_server_info = available_servers[0]
        self.best_server = best_server_info['server_data']
        
        if best_server_info.get('fallback', False):
            print(f"[RELAY] Best server (FALLBACK): {self.best_server.get('name', 'Unknown')} "
                  f"(simulated ping: {best_server_info['ping_time']:.2f}ms, load: {best_server_info['load']}%)")
        else:
            print(f"[RELAY] Best server: {self.best_server.get('name', 'Unknown')} "
                  f"(ping: {best_server_info['ping_time']:.2f}ms, load: {best_server_info['load']}%)")

    def get_detailed_server_info(self):
        """Gibt detaillierte Informationen über alle verfügbaren Server zurück"""
        if not self.available_servers:
            return {"error": "No servers available"}
        
        # Führe erneutes Ping durch für aktuelle Daten
        server_pings = {}
        for server_ip, server_data in self.available_servers.items():
            self._ping_server(server_ip, server_data, server_pings)
        
        # Erstelle detaillierte Liste
        server_list = []
        for server_ip, server_data in self.available_servers.items():
            ping_time = server_pings.get(server_ip, float('inf'))
            current_load = server_data.get('current_load', 100)
            
            server_list.append({
                'name': server_data.get('name', 'Unknown'),
                'ip': server_ip,
                'port': server_data.get('port', 5060),
                'ping_ms': round(ping_time, 2) if ping_time != float('inf') else 'timeout',
                'load_percent': current_load,
                'max_traffic': server_data.get('max_traffic', 100),
                'status': 'available' if current_load <= self.server_load_threshold and ping_time != float('inf') else 'unavailable'
            })
        
        # Sortiere nach Ping-Zeit
        server_list.sort(key=lambda x: x['ping_ms'] if isinstance(x['ping_ms'], (int, float)) else float('inf'))
        
        return {
            'total_servers': len(server_list),
            'available_servers': len([s for s in server_list if s['status'] == 'available']),
            'best_server': server_list[0] if server_list else None,
            'servers': server_list
        }

    def _ping_server(self, server_ip, server_data, results_dict):
        """VERBESSERTES Ping das beide Ports 5060 und 5061 testet MIT VERIFY-CODE"""
        try:
            reported_port = server_data.get('port', 5060)
            
            # ✅ KORREKTUR: Teste beide Ports für DuckDNS
            if "duckdns.org" in server_ip:
                ports_to_test = [5061, 5060]  # ✅ Zuerst 5061, dann 5060 testen
                print(f"[PING] DuckDNS detected, testing ports: {ports_to_test}")
            else:
                ports_to_test = [reported_port]
            
            best_ping = float('inf')
            successful_port = None
            
            for port in ports_to_test:
                try:
                    print(f"[PING] Testing {server_ip}:{port}")
                    
                    # Erstelle temporären Socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)  # Kürzeres Timeout für schnelleres Testen
                    
                    start_time = time.time()
                    sock.connect((server_ip, port))
                    
                    # ✅ VERIFY-CODE FÜR PING-NACHRICHT GENERIEREN
                    client_name = getattr(self, '_client_name', 'ping_tester')
                    generator = init_verify_generator(client_name, client_name)
                    verify_code = generator.generate_verify_code()
                    print(f"🔐 [PING] Ping Verify-Code für {server_ip}:{port}: {verify_code}")
                    
                    # Baue Ping-Nachricht MIT VERIFY-CODE
                    ping_data = {
                        "MESSAGE_TYPE": "PING",
                        "TIMESTAMP": int(start_time),
                        "CLIENT_NAME": client_name
                    }
                    
                    ping_msg = self.client.build_sip_message("MESSAGE", server_ip, ping_data)
                    
                    # ✅ MANUELL VERIFY-HEADER HINZUFÜGEN
                    lines = ping_msg.split('\r\n')
                    
                    # Finde die Stelle wo wir den Verify-Header einfügen können (vor Content-Headern)
                    insert_position = -1
                    for i, line in enumerate(lines):
                        if line.startswith('Content-Type:') or line.startswith('Content-Length:'):
                            insert_position = i
                            break
                    
                    if insert_position != -1:
                        lines.insert(insert_position, f"Verify-Code: {verify_code}")
                    else:
                        # Falls keine Content-Header gefunden, vor dem leeren Zeilen-Trenner einfügen
                        for i, line in enumerate(lines):
                            if line == '':
                                lines.insert(i, f"Verify-Code: {verify_code}")
                                break
                        else:
                            # Notfall: am Ende einfügen
                            lines.insert(-1, f"Verify-Code: {verify_code}")
                    
                    ping_msg_with_verify = '\r\n'.join(lines)
                    
                    # Sende Ping mit Frame
                    if send_frame(sock, ping_msg_with_verify.encode('utf-8')):
                        # Warte auf Pong mit Frame
                        response = recv_frame(sock, timeout=2.0)
                        if response:
                            # ✅ PRÜFE OB ES EINE GÜLTIGE PONG-ANTWORT IST
                            try:
                                response_str = response.decode('utf-8', errors='ignore')
                                if "PONG" in response_str or "pong" in response_str.lower():
                                    end_time = time.time()
                                    ping_time = (end_time - start_time) * 1000
                                    
                                    if ping_time < best_ping:
                                        best_ping = ping_time
                                        successful_port = port
                                        
                                    print(f"[PING] {server_ip}:{port}: {ping_time:.2f}ms - SUCCESS")
                                else:
                                    print(f"[PING] {server_ip}:{port}: Invalid response (not PONG)")
                            except:
                                print(f"[PING] {server_ip}:{port}: Invalid response format")
                        else:
                            print(f"[PING] {server_ip}:{port}: No response")
                    else:
                        print(f"[PING] {server_ip}:{port}: Send failed")
                        
                    sock.close()
                    
                except socket.timeout:
                    print(f"[PING] {server_ip}:{port}: Timeout")
                    continue
                except ConnectionRefusedError:
                    print(f"[PING] {server_ip}:{port}: Connection refused")
                    continue
                except Exception as e:
                    print(f"[PING] {server_ip}:{port}: Error - {e}")
                    continue
            
            # Ergebnis speichern
            if best_ping != float('inf'):
                results_dict[server_ip] = best_ping
                print(f"[PING] {server_ip}: Best ping {best_ping:.2f}ms on port {successful_port}")
            else:
                results_dict[server_ip] = float('inf')
                print(f"[PING] {server_ip}: All ports failed")
            
        except Exception as e:
            results_dict[server_ip] = float('inf')
            print(f"[PING] {server_ip}: Overall error - {e}")

    def _get_local_ips(self):
        """Ermittelt alle lokalen IP-Adressen für Self-Ping-Erkennung"""
        local_ips = set()
        try:
            # Lokale IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.add(s.getsockname()[0])
            s.close()
            
            # Hostname
            hostname = socket.gethostname()
            local_ips.add(hostname)
            try:
                local_ips.add(socket.gethostbyname(hostname))
            except:
                pass
                
            # Alle Netzwerk-Interfaces
            for interface in socket.getaddrinfo(socket.gethostname(), None):
                local_ips.add(interface[4][0])
                
        except Exception as e:
            print(f"[PING] Local IP detection failed: {e}")
        
        # Standard-IPs hinzufügen
        local_ips.update(['127.0.0.1', 'localhost', '0.0.0.0'])
        
        print(f"[PING] Local IPs detected: {local_ips}")
        return local_ips
            
    def get_server_recommendation(self):
        """Gibt Server-Empfehlung für den Client zurück"""
        # Wenn keine aktuelle Discovery oder zu alt, neue durchführen
        if (not self.available_servers or 
            time.time() - self.last_discovery > self.discovery_interval):
            self.discover_servers()
        
        if self.best_server:
            return {
                'recommended': self.best_server,
                'alternatives': len(self.available_servers) - 1,
                'total_servers': len(self.available_servers)
            }
        else:
            return {
                'recommended': None,
                'alternatives': 0,
                'total_servers': 0,
                'error': 'No servers available'
            }

    def get_server_status(self):
        """Gibt Status des Relay-Managers zurück"""
        return {
            'connection_status': self.connection_status,
            'available_servers': len(self.available_servers),
            'best_server': self.best_server.get('name', 'None') if self.best_server else 'None',
            'last_discovery': time.strftime('%H:%M:%S', time.localtime(self.last_discovery)),
            'seed_servers': len(self.SEED_SERVERS)
        }

    def manual_server_selection(self, server_ip, server_port):
        """Erlaubt manuelle Server-Auswahl (Fallback)"""
        manual_server = {
            'ip': server_ip,
            'port': server_port,
            'name': f"Manual-{server_ip}",
            'current_load': 0,  # Unbekannt
            'max_traffic': 100,  # Standard
            'last_seen': time.time()
        }
        
        self.available_servers[server_ip] = manual_server
        self.best_server = manual_server
        
        print(f"[CLIENT RELAY] Manual server selected: {server_ip}:{server_port}")
        return manual_server

    def update_connection_status(self, status):
        """Aktualisiert den Verbindungsstatus"""
        self.connection_status = status
        print(f"[CLIENT RELAY] Connection status: {status}")

    def force_discovery(self):
        """Erzwingt eine neue Server-Discovery"""
        print("[CLIENT RELAY] Forcing new server discovery...")
        self.last_discovery = 0  # Setze zurück um neue Discovery zu erzwingen
        return self.discover_servers()

    def select_specific_server(self, server_ip):
        """Wählt einen spezifischen Server manuell aus (überschreibt Auto-Auswahl)"""
        if server_ip in self.available_servers:
            server_data = self.available_servers[server_ip]
            
            # Prüfe ob Server erreichbar ist
            server_pings = {}
            self._ping_server(server_ip, server_data, server_pings)
            ping_time = server_pings.get(server_ip, float('inf'))
            
            if ping_time != float('inf'):
                self.best_server = server_data
                print(f"[CLIENT RELAY] Manually selected: {server_data.get('name', 'Unknown')} "
                      f"(ping: {ping_time:.2f}ms)")
                return True
            else:
                print(f"[CLIENT RELAY] Manual selection failed - server {server_ip} not reachable")
                return False
        else:
            print(f"[CLIENT RELAY] Manual selection failed - server {server_ip} not in available servers")
            return False



class CALL:
    def __init__(self, client_instance):
        self.client = client_instance
        self.active_call = False
        self.pending_call = None
        self.incoming_call = None
        self.current_secret = None
        self.audio_threads = []
        
        # ✅ Flexible Audio-Konfiguration
        self.audio_config = AudioConfig()
        self.PORT = 51821
        
        # Audio-Streams
        self.input_stream = None
        self.output_stream = None        
        # ✅ SIMPLIFIED: Nur UDP Relay, kein WireGuard
        self.use_udp_relay = False
        self.relay_server_ip = None
        self.relay_server_port = 51822
        
        # ✅ KORREKTUR: Audio Device Management mit Fallback
        try:
            import pyaudio
            self.audio = pyaudio.PyAudio()
            self.audio_available = True
            print("[AUDIO] PyAudio erfolgreich initialisiert")
        except Exception as e:
            print(f"[AUDIO] PyAudio nicht verfügbar: {e}")
            self.audio = None
            self.audio_available = False
            
            # Fallback: Prüfe PySndfile (korrekter Import)
            try:
                import sndfile  # Korrekter Import für PySndfile
                self.audio_available = True
                print("[AUDIO] PySndfile als Fallback verfügbar")
            except ImportError:
                try:
                    # Alternative Import-Versuche
                    import pylibsndfile as sndfile
                    self.audio_available = True
                    print("[AUDIO] pylibsndfile als Fallback verfügbar")
                except ImportError:
                    print("[AUDIO] Kein Audio-Backend verfügbar")
        
        self.selected_input_device = getattr(client_instance, 'selected_input_device', None)
        self.selected_output_device = getattr(client_instance, 'selected_output_device', None)
        self.call_start_time = None
        self.call_timer_running = False
        self.call_timer_after_id = None
        
        # Lock für Thread-Safety
        self.connection_lock = threading.Lock()
        self.connection_state = "disconnected"



    def audio_stream_out(self, target_ip, target_port, iv, key, session_id):
        """Sendet Audio über UDP Relay MIT KORRIGIERTER SYNCHRONISATION"""
        if not self.audio_available:
            print("❌ [AUDIO OUT] Kein Audio-Backend verfügbar")
            return False
            
        audio_socket = None
        
        print(f"[AUDIO OUT] Starting OUTGOING stream for session {session_id}")
        print(f"[AUDIO OUT] Target: {target_ip}:{target_port}")
        print(f"[AUDIO OUT] Initial active_call: {self.active_call}")
        
        # ✅ KORREKTUR: VERKÜRZTER TIMEOUT + BESSERE SYNCHRONISATION
        import time
        wait_start = time.time()
        check_count = 0
        
        while not self.active_call:
            check_count += 1
            current_time = time.time()
            
            # ✅ DETAILIERTES DEBUGGING
            if check_count % 10 == 0:  # Alle 100ms loggen
                print(f"[AUDIO OUT] Waiting for active_call... ({check_count} checks, {current_time - wait_start:.1f}s)")
                print(f"[AUDIO OUT] Current active_call state: {self.active_call}")
            
            if (current_time - wait_start) > 1.5:  # Nur 1.5 Sekunden warten
                print("❌ [AUDIO OUT] Timeout waiting for active_call")
                print(f"[AUDIO OUT] Final state - active_call: {self.active_call}")
                return False
                
            time.sleep(0.01)  # 10ms warten
            
        print(f"✅ [AUDIO OUT] Active call confirmed: {self.active_call}")
        
        try:
            # Input Stream öffnen
            if self.audio_available and self.audio:
                self.input_stream = self.audio_config.audio.open(
                    format=self.audio_config.FORMAT,
                    channels=self.audio_config.CHANNELS,
                    rate=self.audio_config.RATE,
                    input=True,
                    frames_per_buffer=self.audio_config.CHUNK,
                    input_device_index=self.audio_config.input_device_index
                )
                print("✅ [AUDIO OUT] Input stream opened")
            else:
                return False
            
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            audio_socket.settimeout(0.1)
            
            print(f"🎤 [AUDIO OUT] Transmission ACTIVE for session {session_id}")
            packet_counter = 0
            
            while self.active_call and self.audio_available:
                try:
                    raw_data = self.input_stream.read(
                        self.audio_config.CHUNK,
                        exception_on_overflow=False
                    )
                    
                    packet_counter += 1
                    if packet_counter % 100 == 0:
                        print(f"[AUDIO OUT] Session {session_id} - Sent {packet_counter} packets")
                    
                    # Rauschfilterung
                    if (self.audio_config.noise_profile['enabled'] and 
                        self.audio_config.noise_profile['profile_captured']):
                        filtered_data = self.audio_config.apply_noise_filter(raw_data)
                    else:
                        filtered_data = raw_data
                    
                    # Verschlüsseln
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 1)
                    encrypted_data = cipher.update(filtered_data) + cipher.final()
                    
                    # ✅ SESSION-MARKIERUNG MIT 16 BYTES SHA3
                    session_header = session_id.encode('utf-8')
                    packet_with_session = session_header + encrypted_data
                    
                    audio_socket.sendto(packet_with_session, (target_ip, target_port))
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.active_call:
                        print(f"[AUDIO OUT ERROR] Session {session_id}: {str(e)}")
                    break
                        
            print(f"[AUDIO OUT] Session {session_id} ended. Total packets: {packet_counter}")
                            
        except Exception as e:
            print(f"[AUDIO OUT SETUP ERROR] Session {session_id}: {str(e)}")
            return False
        finally:
            if hasattr(self, 'input_stream') and self.input_stream:
                try:
                    self.input_stream.stop_stream()
                    self.input_stream.close()
                    self.input_stream = None
                    print(f"✅ [AUDIO OUT] Session {session_id} - Input stream closed")
                except Exception as e:
                    print(f"[AUDIO OUT CLOSE ERROR] {e}")
            if audio_socket:
                audio_socket.close()
                print(f"✅ [AUDIO OUT] Session {session_id} - Socket closed")
        
        return True
    def audio_stream_in(self, target_ip, listen_port, iv, key, expected_session_id):
        """Empfängt Audio über UDP Relay MIT KORRIGIERTER SYNCHRONISATION"""
        audio_socket = None
        
        if not self.audio_available:
            print("❌ [AUDIO IN] Kein Audio-Backend verfügbar")
            return False
                
        print(f"[AUDIO IN] Starting listener for session {expected_session_id} on port {listen_port}")
        print(f"[AUDIO IN] Initial active_call: {self.active_call}")
        
        # ✅ KORREKTUR: VERKÜRZTER TIMEOUT + BESSERE SYNCHRONISATION
        import time
        wait_start = time.time()
        check_count = 0
        
        while not self.active_call:
            check_count += 1
            current_time = time.time()
            
            # ✅ DETAILIERTES DEBUGGING
            if check_count % 10 == 0:  # Alle 100ms loggen
                print(f"[AUDIO IN] Waiting for active_call... ({check_count} checks, {current_time - wait_start:.1f}s)")
                print(f"[AUDIO IN] Current active_call state: {self.active_call}")
            
            if (current_time - wait_start) > 1.5:  # Nur 1.5 Sekunden warten
                print("❌ [AUDIO IN] Timeout waiting for active_call")
                print(f"[AUDIO IN] Final state - active_call: {self.active_call}")
                return False
                
            time.sleep(0.01)  # 10ms warten
            
        print(f"✅ [AUDIO IN] Active call confirmed: {self.active_call}")
        
        try:
            # Output Stream öffnen
            if self.audio_available and self.audio:
                self.output_stream = self.audio_config.audio.open(
                    format=self.audio_config.FORMAT,
                    channels=self.audio_config.CHANNELS,
                    rate=self.audio_config.RATE,
                    output=True,
                    frames_per_buffer=self.audio_config.CHUNK,
                    output_device_index=self.audio_config.output_device_index
                )
                print(f"✅ [AUDIO IN] Output stream opened for session {expected_session_id}")
            else:
                return False
            
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            try:
                audio_socket.bind(('0.0.0.0', listen_port))
                print(f"✅ [AUDIO IN] Bound to port {listen_port} for session {expected_session_id}")
            except OSError as e:
                print(f"❌ [AUDIO IN] Failed to bind to port {listen_port}: {e}")
                return False
            
            audio_socket.settimeout(0.1)
            
            print(f"🎧 [AUDIO IN] Listener ACTIVE for session {expected_session_id}")
            packet_counter = 0
            wrong_session_counter = 0
            timeout_counter = 0
            
            while self.active_call and self.audio_available:
                try:
                    data, addr = audio_socket.recvfrom(4096)
                    
                    # ✅ SESSION-FILTERUNG: Prüfe ob Paket zu unserer Session gehört (16 Bytes SHA3)
                    if len(data) >= 16:  # 16 Bytes für SHA3 Session-ID
                        received_session_id = data[:16].decode('utf-8', errors='ignore')
                        encrypted_data = data[16:]
                        
                        if received_session_id == expected_session_id:
                            # ✅ KORREKTE SESSION - Verarbeite Paket
                            packet_counter += 1
                            
                            if packet_counter % 50 == 0:
                                print(f"[AUDIO IN] Session {expected_session_id} - Received {packet_counter} packets")
                            
                            # Entschlüsseln
                            cipher = EVP.Cipher("aes_256_cbc", key, iv, 0)
                            received_data = cipher.update(encrypted_data) + cipher.final()
                            
                            # An Ausgabestream senden
                            self.output_stream.write(received_data)
                            
                            wrong_session_counter = 0
                            timeout_counter = 0
                        else:
                            # ❌ FALSCHE SESSION - Verwerfe Paket
                            wrong_session_counter += 1
                            if wrong_session_counter % 50 == 0:
                                print(f"[AUDIO IN] Filtered {wrong_session_counter} packets from wrong sessions")
                            continue
                    else:
                        # ❌ UNGÜLTIGES PAKET - Verwerfe
                        continue
                    
                except socket.timeout:
                    timeout_counter += 1
                    if timeout_counter % 100 == 0:
                        print(f"[AUDIO IN] Session {expected_session_id} - No packets for {timeout_counter} attempts")
                    continue
                except Exception as e:
                    if self.active_call:
                        print(f"[AUDIO IN ERROR] Session {expected_session_id}: {str(e)}")
                    break
                            
            print(f"[AUDIO IN] Session {expected_session_id} ended. Total packets: {packet_counter}")
            print(f"[AUDIO IN] Filtered {wrong_session_counter} packets from wrong sessions")
                            
        except Exception as e:
            print(f"[AUDIO IN SETUP ERROR] Session {expected_session_id}: {str(e)}")
            return False
        finally:
            if hasattr(self, 'output_stream') and self.output_stream:
                try:
                    self.output_stream.stop_stream()
                    self.output_stream.close()
                    self.output_stream = None
                    print(f"✅ [AUDIO IN] Session {expected_session_id} - Output stream closed")
                except Exception as e:
                    print(f"[AUDIO IN CLOSE ERROR] {e}")
            if audio_socket:
                audio_socket.close()
                print(f"✅ [AUDIO IN] Session {expected_session_id} - Socket closed")
        
        return True
    def _start_audio_streams(self):
        """Startet bidirektionale Audio-Streams MIT VERBESSERTER SYNCHRONISATION"""
        try:
            print(f"[AUDIO] Starting audio streams - Initial active_call: {self.active_call}")
            
            if not self.current_secret:
                print("[AUDIO] No session key available")
                return
                
            if not self.audio_available:
                print("[AUDIO] Kein Audio-Backend verfügbar - Call ohne Audio")
                self._start_call_timer()
                self.call_start_time = time.time()
                return
            
            # ✅ SICHERE SESSION-ID MIT SHA3
            import hashlib
            session_id = hashlib.sha3_256(self.current_secret).hexdigest()[:16]
            self.session_id = session_id
            
            if self.use_udp_relay and self.relay_server_ip:
                target_ip = self.relay_server_ip
                
                # Rollen und Ports bestimmen
                if hasattr(self, 'pending_call') and self.pending_call:
                    listen_port = 51821
                    send_to_port = 51822
                    role = "Caller"
                elif hasattr(self, 'incoming_call') and self.incoming_call:
                    listen_port = 51822
                    send_to_port = 51821
                    role = "Callee"
                else:
                    print("[AUDIO] ❌ ERROR: Cannot determine call role!")
                    return
                
                print(f"[AUDIO] {role} mode - Session: {session_id}")
                print(f"[AUDIO] Listen: {listen_port}, Send to: {send_to_port}")
                
            else:
                print("[AUDIO] ❌ ERROR: No UDP relay configured!")
                return
            
            # ✅✅✅ KRITISCHE KORREKTUR: BESSERE SYNCHRONISATION
            print("[AUDIO] Setting active_call to True...")
            self.active_call = True
            self.client.active_call = True
            
            # ✅ VERLÄNGERTE VERZÖGERUNG FÜR THREAD-SYNCHRONISATION
            import time
            time.sleep(0.2)  # 200ms für bessere Synchronisation
            print(f"[AUDIO] Active call confirmed after sync: {self.active_call}")
            
            # Alte Audio-Threads stoppen
            self._stop_audio_streams()
            
            # Starte Timer-Anzeige
            self._start_call_timer()
            
            iv = self.current_secret[:16]
            key = self.current_secret[16:48]
            
            # ✅ SESSION-ID AN AUDIO STREAMS ÜBERGEBEN
            send_thread = threading.Thread(
                target=self.audio_stream_out, 
                args=(target_ip, send_to_port, iv, key, session_id),
                daemon=True,
                name=f"AudioOut_{session_id}"
            )
            
            recv_thread = threading.Thread(
                target=self.audio_stream_in,
                args=(target_ip, listen_port, iv, key, session_id),
                daemon=True,
                name=f"AudioIn_{session_id}"
            )
            
            # ✅ THREADS STARTEN
            send_thread.start()
            recv_thread.start()
            
            self.audio_threads = [send_thread, recv_thread]
            self.call_start_time = time.time()
            
            print(f"[AUDIO] ✅ Session {session_id} started - {role} on ports {listen_port}/{send_to_port}")
            
        except Exception as e:
            print(f"[AUDIO ERROR] Failed to start streams: {e}")
            self.active_call = False
            self.client.active_call = False
    def show_audio_devices_popup(self):
        """Audio-Geräte, Qualitätsauswahl und Rauschfilterung - KORRIGIERTE DPI-VERSION"""
        try:
            # Warte bis das Hauptfenster sichtbar ist
            if hasattr(self.client, 'winfo_viewable') and not self.client.winfo_viewable():
                print("[AUDIO POPUP] Main window not ready, delaying popup...")
                self.client.after(500, self.show_audio_devices_popup)
                return
            
            # Überprüfe ob das Fenster noch existiert
            if not hasattr(self.client, 'tk') or not self.client.winfo_exists():
                print("[AUDIO POPUP] Main window destroyed, aborting...")
                return

            # ✅ KORREKTE DPI-ERKENNUNG - VOR Fenstererstellung
            screen_dpi = self.client.winfo_fpixels('1i')
            base_dpi = 96
            scaling_factor = screen_dpi / base_dpi if screen_dpi > 0 else 1.0
            scaling_factor = min(max(scaling_factor, 0.8), 2.0)
            
            print(f"[DPI] Screen DPI: {screen_dpi:.1f}, Scaling Factor: {scaling_factor:.2f}")
            
            # ✅ DYNAMISCHE GRÖSSEN BASIEREND AUF DPI
            def scaled_size(size):
                return int(size * scaling_factor)
            
            font_sizes = {
                'title': scaled_size(14),
                'heading': scaled_size(12),
                'normal': scaled_size(10),
                'small': scaled_size(9),
                'tiny': scaled_size(8)
            }
            
            widget_sizes = {
                'button_width': scaled_size(15),
                'small_button_width': scaled_size(12),
                'combo_width': scaled_size(65),
                'progress_length': scaled_size(300),
                'wraplength': scaled_size(550)
            }

            # ✅ FENSTERGRÖSSE dynamisch basierend auf DPI
            window_width = scaled_size(600)
            window_height = scaled_size(1000)

            # Erstelle neues Fenster MIT SOFORTIGEM DPI-SETTING
            popup = tk.Toplevel(self.client)
            popup.title("Audio-Einstellungen")
            popup.geometry(f"{window_width}x{window_height}")
            popup.resizable(False, False)
            
            # ✅ SETZE DPI SOFORT nach Fenstererstellung
            try:
                popup.tk.call('tk', 'scaling', scaling_factor)
            except:
                print("[DPI] tk scaling not supported, using manual scaling")

            # ✅ FORCIERE SOFORTIGE AKTUALISIERUNG
            popup.update_idletasks()
            popup.update()
            
            if popup.winfo_viewable():
                popup.transient(self.client)
                popup.grab_set()

            # Zentriere das Fenster
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (window_width // 2)
            y = (popup.winfo_screenheight() // 2) - (window_height // 2)
            popup.geometry(f"+{x}+{y}")

            # ✅ NOCHMAL AKTUALISIEREN für korrekte Darstellung
            popup.update_idletasks()
            popup.update()

            # Separate Variablen für jede Combobox
            input_var = tk.StringVar(popup)
            output_var = tk.StringVar(popup)
            quality_var = tk.StringVar(value=self.audio_config.quality_profile)
            
            # ✅ NOISE FILTER VARIABLEN
            noise_var = tk.BooleanVar(value=self.audio_config.noise_profile['enabled'])
            aggressive_var = tk.BooleanVar(value=self.audio_config.noise_profile['aggressive_mode'])
            
            # ===== AUDIO-QUALITÄTSAUSWAHL =====
            quality_frame = tk.LabelFrame(
                popup, 
                text="Audio-Qualität", 
                font=("Arial", font_sizes['heading'], "bold"), 
                padx=scaled_size(10), 
                pady=scaled_size(10)
            )
            quality_frame.pack(fill="x", padx=scaled_size(20), pady=(scaled_size(20), scaled_size(10)))
            
            # Qualitätsbeschreibungen
            quality_descriptions = {
                "highest": "🏆 Highest Quality: 32-bit Float @ 192kHz (Experimentell, beste Qualität)",
                "high": "🔊 High Quality: 24-bit @ 192kHz (Beste Qualität, höhere Bandbreite)",
                "middle": "🎵 Middle Quality: 24-bit @ 48kHz (Ausgeglichen, empfohlen)",
                "low": "📱 Low Quality: 16-bit @ 48kHz (Geringe Bandbreite, stabil)"
            }
            
            # Qualitäts-Optionen mit skalierter Schrift
            highest_radio = tk.Radiobutton(
                quality_frame, 
                text=quality_descriptions["highest"], 
                variable=quality_var, 
                value="highest", 
                font=("Arial", font_sizes['normal']),
                wraplength=widget_sizes['wraplength']
            )
            highest_radio.pack(anchor="w", pady=scaled_size(5))
            
            high_radio = tk.Radiobutton(
                quality_frame, 
                text=quality_descriptions["high"], 
                variable=quality_var, 
                value="high", 
                font=("Arial", font_sizes['normal']),
                wraplength=widget_sizes['wraplength']
            )
            high_radio.pack(anchor="w", pady=scaled_size(5))
            
            middle_radio = tk.Radiobutton(
                quality_frame, 
                text=quality_descriptions["middle"], 
                variable=quality_var, 
                value="middle", 
                font=("Arial", font_sizes['normal']),
                wraplength=widget_sizes['wraplength']
            )
            middle_radio.pack(anchor="w", pady=scaled_size(5))
            
            low_radio = tk.Radiobutton(
                quality_frame, 
                text=quality_descriptions["low"], 
                variable=quality_var, 
                value="low", 
                font=("Arial", font_sizes['normal']),
                wraplength=widget_sizes['wraplength']
            )
            low_radio.pack(anchor="w", pady=scaled_size(5))
            
            # Aktuelle Qualitäts-Anzeige mit kleinerer Schrift
            current_quality_label = tk.Label(
                quality_frame, 
                text=f"Aktuell: {self.audio_config.QUALITY_PROFILES[self.audio_config.quality_profile]['name']}", 
                font=("Arial", font_sizes['small']), 
                fg="blue"
            )
            current_quality_label.pack(anchor="w", pady=(scaled_size(5), 0))
            
            # ===== GERÄTEAUSWAHL =====
            devices_frame = tk.LabelFrame(
                popup, 
                text="Audio-Geräte", 
                font=("Arial", font_sizes['heading'], "bold"), 
                padx=scaled_size(10), 
                pady=scaled_size(10)
            )
            devices_frame.pack(fill="x", padx=scaled_size(20), pady=scaled_size(10))
            
            # Eingabegeräte (Mikrofone) mit skalierter Schrift
            tk.Label(
                devices_frame, 
                text="Eingabegerät (Mikrofon):", 
                font=("Arial", font_sizes['normal'], "bold")
            ).pack(anchor="w", pady=(scaled_size(5), scaled_size(2)))
            
            input_devices = self.audio_config.get_input_devices()
            
            input_combo = ttk.Combobox(
                devices_frame, 
                textvariable=input_var, 
                values=input_devices, 
                width=widget_sizes['combo_width'],
                state="readonly",
                font=("Arial", font_sizes['normal'])
            )
            input_combo.pack(fill="x", pady=(0, scaled_size(10)))
            
            # Vorauswahl setzen
            current_input = getattr(self.client, 'selected_input_device', None)
            if current_input and current_input in input_devices:
                input_var.set(current_input)
                input_combo.set(current_input)
            elif input_devices:
                input_var.set(input_devices[0])
                input_combo.set(input_devices[0])
            
            # Ausgabegeräte (Lautsprecher/Kopfhörer)
            tk.Label(
                devices_frame, 
                text="Ausgabegerät (Lautsprecher):", 
                font=("Arial", font_sizes['normal'], "bold")
            ).pack(anchor="w", pady=(scaled_size(5), scaled_size(2)))
            
            output_devices = self.audio_config.get_output_devices()
            
            output_combo = ttk.Combobox(
                devices_frame, 
                textvariable=output_var, 
                values=output_devices, 
                width=widget_sizes['combo_width'],
                state="readonly",
                font=("Arial", font_sizes['normal'])
            )
            output_combo.pack(fill="x", pady=(0, scaled_size(5)))
            
            # Vorauswahl setzen
            current_output = getattr(self.client, 'selected_output_device', None)
            if current_output and current_output in output_devices:
                output_var.set(current_output)
                output_combo.set(current_output)
            elif output_devices:
                output_var.set(output_devices[0])
                output_combo.set(output_devices[0])
            
            # ===== RAUSCHFILTER AUSWAHL =====
            noise_frame = tk.LabelFrame(
                popup, 
                text="Rauschfilterung für analoge Mikrofone", 
                font=("Arial", font_sizes['heading'], "bold"), 
                padx=scaled_size(10), 
                pady=scaled_size(10)
            )
            noise_frame.pack(fill="x", padx=scaled_size(20), pady=scaled_size(10))
            
            # Noise Filter Aktivierung mit skalierter Schrift
            noise_check = tk.Checkbutton(
                noise_frame, 
                text="🎤 Rauschfilterung aktivieren (für analoge Mikrofone)", 
                variable=noise_var, 
                font=("Arial", font_sizes['normal'])
            )
            noise_check.pack(anchor="w", pady=scaled_size(5))
            
            # Aggressive Filterung mit kleinerer Schrift
            aggressive_check = tk.Checkbutton(
                noise_frame, 
                text="🔊 Aggressive Rauschunterdrückung (für laute Umgebungen)", 
                variable=aggressive_var, 
                font=("Arial", font_sizes['small'])
            )
            aggressive_check.pack(anchor="w", pady=scaled_size(2))
            
            # Profil-Status Anzeige
            profile_status_label = tk.Label(
                noise_frame, 
                text="", 
                font=("Arial", font_sizes['small'])
            )
            profile_status_label.pack(anchor="w", pady=scaled_size(5))
            
            # Progress Bar für Profil-Erstellung
            progress_frame = tk.Frame(noise_frame)
            progress_frame.pack(fill="x", pady=scaled_size(5))
            
            progress_label = tk.Label(
                progress_frame, 
                text="", 
                font=("Arial", font_sizes['small'])
            )
            progress_label.pack(anchor="w")
            
            progress_bar = ttk.Progressbar(
                progress_frame, 
                orient="horizontal", 
                length=widget_sizes['progress_length'],
                mode="determinate"
            )
            progress_bar.pack(fill="x", pady=scaled_size(2))
            
            # Profil-Buttons
            noise_button_frame = tk.Frame(noise_frame)
            noise_button_frame.pack(fill="x", pady=scaled_size(10))
            
            def update_profile_status():
                """Aktualisiert den Profil-Status"""
                if self.audio_config.noise_profile['profile_captured']:
                    threshold = self.audio_config.noise_profile['noise_threshold']
                    status_text = f"✅ Profil vorhanden - Rauschschwelle: {threshold:.6f}"
                    profile_status_label.config(text=status_text, fg="green")
                else:
                    profile_status_label.config(text="❌ Kein Rauschprofil vorhanden", fg="red")
            
            def capture_profile():
                """Startet 180 Sekunden Rauschprofil-Erstellung"""
                if not input_var.get():
                    messagebox.showerror("Fehler", "Bitte zuerst ein Eingabegerät auswählen!")
                    return
                
                # Bestätigung für 180 Sekunden Aufnahme
                confirm = messagebox.askyesno(
                    "Rauschprofil erstellen", 
                    "Das Rauschprofil wird 180 Sekunden (3 Minuten) aufnehmen.\n\n"
                    "Bitte stellen Sie sicher, dass:\n"
                    "• Absolute Stille im Raum herrscht\n" 
                    "• Keine Geräusche vorhanden sind\n"
                    "• Das Mikrofon nicht bewegt wird\n\n"
                    "Fortfahren mit der 3-minütigen Aufnahme?"
                )
                if not confirm:
                    return
                
                # Progress Bar zurücksetzen
                progress_bar['value'] = 0
                progress_label.config(text="Vorbereitung...")
                popup.update()
                
                def progress_callback(progress, remaining):
                    """Callback für Fortschrittsupdates"""
                    progress_bar['value'] = progress
                    progress_label.config(text=f"Aufnahme läuft... {progress:.1f}% - Noch {remaining:.0f} Sekunden")
                    popup.update()
                
                # Starte Profil-Erstellung in einem separaten Thread
                def capture_thread():
                    try:
                        success = self.audio_config.capture_noise_profile(
                            duration=180, 
                            progress_callback=progress_callback
                        )
                        
                        # UI Updates im Hauptthread
                        popup.after(0, lambda: on_capture_complete(success))
                        
                    except Exception as e:
                        popup.after(0, lambda: on_capture_complete(False, str(e)))
                
                threading.Thread(target=capture_thread, daemon=True).start()
            
            def on_capture_complete(success, error_msg=None):
                """Wird aufgerufen wenn die Profil-Erstellung abgeschlossen ist"""
                progress_bar['value'] = 0
                progress_label.config(text="")
                
                if success:
                    messagebox.showinfo("Rauschprofil", "✅ 180-Sekunden Rauschprofil erfolgreich erstellt!")
                    update_profile_status()
                else:
                    error_text = "Fehler beim Erstellen des Rauschprofils"
                    if error_msg:
                        error_text += f": {error_msg}"
                    messagebox.showerror("Rauschprofil", error_text)
            
            def load_profile():
                """Lädt gespeichertes Rauschprofil"""
                success = self.audio_config.load_noise_profile()
                if success:
                    messagebox.showinfo("Rauschprofil", "✅ Rauschprofil erfolgreich geladen!")
                    update_profile_status()
                else:
                    messagebox.showwarning("Rauschprofil", "❌ Kein Rauschprofil gefunden oder Fehler beim Laden")
            
            def show_profile_info():
                """Zeigt Profil-Informationen"""
                info = self.audio_config.get_noise_profile_info()
                messagebox.showinfo("Rauschprofil Info", info)
            
            def clear_profile():
                """Löscht das aktuelle Rauschprofil"""
                self.audio_config.noise_profile['profile_captured'] = False
                self.audio_config.noise_profile['noise_threshold'] = 0.01
                update_profile_status()
                messagebox.showinfo("Rauschprofil", "Rauschprofil zurückgesetzt")
            
            # Noise Profil Buttons mit skalierten Breiten
            ttk.Button(
                noise_button_frame, 
                text="🎙️ 180s Profil erstellen", 
                command=capture_profile, 
                width=widget_sizes['button_width']
            ).pack(side=tk.LEFT, padx=scaled_size(2))
            
            ttk.Button(
                noise_button_frame, 
                text="📂 Profil laden", 
                command=load_profile, 
                width=widget_sizes['small_button_width']
            ).pack(side=tk.LEFT, padx=scaled_size(2))
            
            ttk.Button(
                noise_button_frame, 
                text="ℹ️ Info", 
                command=show_profile_info, 
                width=widget_sizes['small_button_width']
            ).pack(side=tk.LEFT, padx=scaled_size(2))
            
            ttk.Button(
                noise_button_frame, 
                text="🗑️ Löschen", 
                command=clear_profile, 
                width=widget_sizes['small_button_width']
            ).pack(side=tk.LEFT, padx=scaled_size(2))
            
            # ===== INFO TEXT =====
            info_frame = tk.Frame(popup)
            info_frame.pack(fill="x", padx=scaled_size(20), pady=scaled_size(10))
            
            info_text = (
                "ℹ️ Hinweise:\n"
                "• Qualität wird automatisch an Gesprächspartner angepasst\n"
                "• Highest: 32-bit Float @ 192kHz (nur mit kompatiblen Geräten)\n"
                "• High: 24-bit @ 192kHz (beste Qualität für die meisten Systeme)\n" 
                "• Middle: 24-bit @ 48kHz (ausgeglichene Qualität und Stabilität)\n"
                "• Low: 16-bit @ 48kHz (geringste Bandbreite, stabilste Verbindung)\n"
                "• Rauschfilter: Für analoge Mikrofone - 180s 'Clear Room' Profil empfohlen"
            )
            info_label = tk.Label(
                info_frame, 
                text=info_text, 
                font=("Arial", font_sizes['small']), 
                justify=tk.LEFT, 
                fg="green", 
                wraplength=widget_sizes['wraplength']
            )
            info_label.pack()
            
            # ===== AKTUELLE AUSWAHL ANZEIGE =====
            def update_selection_display():
                input_text = input_var.get() or "Nicht ausgewählt"
                output_text = output_var.get() or "Nicht ausgewählt"
                quality_text = quality_var.get()
                quality_name = self.audio_config.QUALITY_PROFILES[quality_text]['name']
                
                noise_status = "Aktiv" if noise_var.get() else "Inaktiv"
                aggressive_status = "Aktiv" if aggressive_var.get() else "Inaktiv"
                profile_status = "Vorhanden" if self.audio_config.noise_profile['profile_captured'] else "Fehlt"
                
                selection_text = (f"Eingabe: {input_text[:20]}... | "
                                f"Ausgabe: {output_text[:20]}... | "
                                f"Qualität: {quality_name} | "
                                f"Rauschfilter: {noise_status} ({profile_status})")
                selection_label.config(text=selection_text)
            
            selection_label = tk.Label(
                popup, 
                text="", 
                font=("Arial", font_sizes['small']), 
                fg="blue", 
                wraplength=widget_sizes['wraplength']
            )
            selection_label.pack(pady=scaled_size(10))
            update_selection_display()

            # ===== BUTTONS =====
            button_frame = tk.Frame(popup)
            button_frame.pack(pady=scaled_size(20))
            
            def apply_selection():
                """Übernimmt die aktuell ausgewählten Geräte, Qualität und Rauschfilterung"""
                input_selection = input_var.get()
                output_selection = output_var.get()
                quality_selection = quality_var.get()
                
                # Warnung für Highest Quality
                if quality_selection == "highest":
                    confirm = messagebox.askyesno(
                        "Experimentelle Qualität", 
                        "Highest Quality (32-bit Float @ 192kHz) ist experimentell:\n\n"
                        "• Erfordert sehr schnelle Internetverbindung\n"
                        "• Nur mit kompatiblen Gesprächspartnern nutzbar\n"
                        "• Höhere Bandbreite und CPU-Auslastung\n\n"
                        "Fortfahren?"
                    )
                    if not confirm:
                        return
                
                # Geräte speichern
                if input_selection:
                    self.client.selected_input_device = input_selection
                    self.selected_input_device = input_selection
                
                if output_selection:
                    self.client.selected_output_device = output_selection
                    self.selected_output_device = output_selection
                
                # Qualität speichern und anwenden
                if quality_selection in self.audio_config.QUALITY_PROFILES:
                    
                    profile = self.audio_config.QUALITY_PROFILES[quality_selection]
                    self.audio_config.quality_profile = quality_selection
                    self.audio_config.FORMAT = profile["format"]
                    self.audio_config.RATE = profile["rate"]
                    self.audio_config.CHANNELS = profile["channels"]
                    self.audio_config.sample_format_name = profile["name"]
                    self.audio_config.actual_format = profile["actual_format"]
                    print(f"[AUDIO] Quality set: {self.audio_config.sample_format_name}")
                    if hasattr(self.client, 'audio_quality'):
                        self.client.audio_quality = quality_selection
                
                # Rauschfilterung speichern
                self.audio_config.enable_noise_filter(noise_var.get())
                self.audio_config.set_aggressive_noise_reduction(aggressive_var.get())
                
                try:
                    if popup.winfo_exists():
                        popup.destroy()
                    
                    quality_name = self.audio_config.QUALITY_PROFILES[quality_selection]['name']
                    noise_status = "aktiviert" if noise_var.get() else "deaktiviert"
                    profile_status = "mit Profil" if self.audio_config.noise_profile['profile_captured'] else "ohne Profil"
                    
                    messagebox.showinfo("Audio-Einstellungen", 
                                      f"✅ Eingabegerät: {input_selection or 'Standard'}\n"
                                      f"✅ Ausgabegerät: {output_selection or 'Standard'}\n"
                                      f"✅ Qualität: {quality_name}\n"
                                      f"✅ Rauschfilter: {noise_status} {profile_status}")
                except Exception as e:
                    print(f"[AUDIO POPUP CLOSE ERROR] {str(e)}")
            
            def save_as_default():
                """Speichert die aktuellen Einstellungen als dauerhafte Standard-Einstellung"""
                input_selection = input_var.get()
                output_selection = output_var.get()
                quality_selection = quality_var.get()
                
                # Warnung für Highest Quality als Standard
                if quality_selection == "highest":
                    confirm = messagebox.askyesno(
                        "Experimentelle Standard-Einstellung", 
                        "Highest Quality als Standard setzen?\n\n"
                        "Dies kann zu Verbindungsproblemen führen, wenn Ihr Gesprächspartner\n"
                        "diese Qualität nicht unterstützt oder die Bandbreite nicht ausreicht.\n\n"
                        "Trotzdem als Standard setzen?"
                    )
                    if not confirm:
                        return
                
                # Geräte speichern
                if input_selection:
                    self.client.selected_input_device = input_selection
                    self.selected_input_device = input_selection
                
                if output_selection:
                    self.client.selected_output_device = output_selection
                    self.selected_output_device = output_selection
                
                # Qualität speichern
                if quality_selection in self.audio_config.QUALITY_PROFILES:
                    
                    profile = self.audio_config.QUALITY_PROFILES[quality_selection]
                    self.audio_config.quality_profile = quality_selection
                    self.audio_config.FORMAT = profile["format"]
                    self.audio_config.RATE = profile["rate"]
                    self.audio_config.CHANNELS = profile["channels"]
                    self.audio_config.sample_format_name = profile["name"]
                    self.audio_config.actual_format = profile["actual_format"]
                    print(f"[AUDIO] Quality set: {self.audio_config.sample_format_name}")
                    if hasattr(self.client, 'audio_quality'):
                        self.client.audio_quality = quality_selection
                
                # Rauschfilterung speichern
                self.audio_config.enable_noise_filter(noise_var.get())
                self.audio_config.set_aggressive_noise_reduction(aggressive_var.get())
                
                try:
                    if popup.winfo_exists():
                        popup.destroy()
                    
                    quality_name = self.audio_config.QUALITY_PROFILES[quality_selection]['name']
                    noise_status = "aktiviert" if noise_var.get() else "deaktiviert"
                    
                    messagebox.showinfo("Audio-Einstellungen", 
                                      f"✅ Standard-Einstellungen gespeichert:\n"
                                      f"Eingabe: {input_selection or 'Standard'}\n"
                                      f"Ausgabe: {output_selection or 'Standard'}\n"
                                      f"Qualität: {quality_name}\n"
                                      f"Rauschfilter: {noise_status}")
                except Exception as e:
                    print(f"[AUDIO POPUP CLOSE ERROR] {str(e)}")
            
            def cancel_selection():
                """Schließt das Fenster ohne Änderungen"""
                try:
                    if popup.winfo_exists():
                        popup.destroy()
                    print("[AUDIO POPUP] Abgebrochen - keine Änderungen übernommen")
                except Exception as e:
                    print(f"[AUDIO POPUP CLOSE ERROR] {str(e)}")
            
            def use_default():
                """Setzt Standard-Geräte und Qualität für diese Sitzung"""
                self.client.selected_input_device = None
                self.client.selected_output_device = None
                self.selected_input_device = None
                self.selected_output_device = None
                
                # Standard-Qualität (middle)
                self.audio_config.set_quality("middle")
                if hasattr(self.client, 'audio_quality'):
                    self.client.audio_quality = "middle"
                
                # Rauschfilterung deaktivieren
                self.audio_config.enable_noise_filter(False)
                
                try:
                    if popup.winfo_exists():
                        popup.destroy()
                    messagebox.showinfo("Audio-Einstellungen", 
                                      "Standard-Einstellungen werden für diese Sitzung verwendet\n"
                                      "Qualität: Middle (24-bit @ 48kHz)\n"
                                      "Rauschfilter: Deaktiviert")
                except Exception as e:
                    print(f"[AUDIO POPUP CLOSE ERROR] {str(e)}")
            #test
            def test_audio():
                """Testet die Audio-Ausgabe mit 10 Sekunden synthetischem Signal"""
                try:
                    # Zeige Info-Dialog
                    messagebox.showinfo("Audio-Test", 
                                      "Audio-Test wird gestartet:\n\n"
                                      "• 10 Sekunden Test-Signal (440Hz + 880Hz)\n"
                                      "• Nur Lautsprecher-Ausgabe wird getestet\n"
                                      "• Stellen Sie Lautstärke auf angenehme Höhe\n\n"
                                      "OK klicken um Test zu starten...")
                    
                    # Extrahiere Device-Index aus der Auswahl
                    output_selection = output_var.get()
                    device_index = 0  # Default
                    
                    if output_selection and ':' in output_selection:
                        try:
                            device_index = int(output_selection.split(':')[0])
                            print(f"[AUDIO TEST] Using selected device index: {device_index}")
                        except:
                            print("[AUDIO TEST] Using default device index: 0")
                    
                    # Starte Test in separatem Thread
                    def test_thread():
                        success = self.audio_config.test_audio_output(
                            output_device_index=device_index, 
                            duration=10
                        )
                        
                        # Ergebnis im Hauptthread anzeigen
                        def show_result():
                            if success:
                                messagebox.showinfo("Audio-Test", "✅ Audio-Test erfolgreich!\n\n"
                                                                "Das Test-Signal wurde korrekt abgespielt.")
                            else:
                                messagebox.showerror("Audio-Test", "❌ Audio-Test fehlgeschlagen!\n\n"
                                                                  "Bitte überprüfen Sie:\n"
                                                                  "• Ausgabegerät-Auswahl\n"
                                                                  "• Lautsprecher-Verbindung\n"
                                                                  "• System-Lautstärke")
                        
                        popup.after(0, show_result)
                    
                    threading.Thread(target=test_thread, daemon=True).start()
                    
                except Exception as e:
                    messagebox.showerror("Audio-Test", f"❌ Test konnte nicht gestartet werden:\n{str(e)}")
            # ✅ KORREKT SKALIERTE BUTTONS
            # Erster Button-Reihe: Hauptaktionen
            action_frame = tk.Frame(button_frame)
            action_frame.pack(pady=scaled_size(10))
            
            # Große, gut sichtbare Buttons mit skalierten Breiten
            apply_btn = ttk.Button(
                action_frame, 
                text="✅ ÜBERNEHMEN", 
                command=apply_selection, 
                width=widget_sizes['button_width']
            )
            apply_btn.pack(side=tk.LEFT, padx=scaled_size(10))
            
            save_btn = ttk.Button(
                action_frame, 
                text="💾 SPEICHERN", 
                command=save_as_default, 
                width=widget_sizes['button_width']
            )
            save_btn.pack(side=tk.LEFT, padx=scaled_size(10))
            
            cancel_btn = ttk.Button(
                action_frame, 
                text="❌ ABBRECHEN", 
                command=cancel_selection, 
                width=widget_sizes['button_width']
            )
            cancel_btn.pack(side=tk.LEFT, padx=scaled_size(10))
            
            # Zweite Button-Reihe: Zusätzliche Optionen
            options_frame = tk.Frame(button_frame)
            options_frame.pack(pady=scaled_size(5))
            
            test_btn = ttk.Button(
                options_frame, 
                text="🎵 Test", 
                command=test_audio, 
                width=widget_sizes['small_button_width']
            )
            test_btn.pack(side=tk.LEFT, padx=scaled_size(5))
            
            default_btn = ttk.Button(
                options_frame, 
                text="⚙️ Standard", 
                command=use_default, 
                width=widget_sizes['small_button_width']
            )
            default_btn.pack(side=tk.LEFT, padx=scaled_size(5))
            
            # Event-Handler für Änderungen
            def on_input_change(*args):
                update_selection_display()
            
            def on_output_change(*args):
                update_selection_display()
            
            def on_quality_change(*args):
                update_selection_display()
                current_quality_label.config(
                    text=f"Aktuell: {self.audio_config.QUALITY_PROFILES[quality_var.get()]['name']}"
                )
            
            def on_noise_change(*args):
                update_selection_display()
            
            input_var.trace('w', on_input_change)
            output_var.trace('w', on_output_change)
            quality_var.trace('w', on_quality_change)
            noise_var.trace('w', on_noise_change)
            aggressive_var.trace('w', on_noise_change)
            
            # Initiale Anzeige aktualisieren
            update_selection_display()
            update_profile_status()
            
            # Safe error handling
            try:
                popup.mainloop()
            except Exception as e:
                print(f"[AUDIO POPUP MAINLOOP ERROR] {str(e)}")
            
        except Exception as e:
            print(f"[AUDIO DEVICE POPUP ERROR] {str(e)}")
            try:
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showerror("Fehler", f"Audio-Einstellungen fehlgeschlagen: {str(e)}"))
            except:
                pass

    def handle_message(self, raw_message):
        """Zentrale Message-Handling Methode - VOLLSTÄNDIG KORRIGIERT"""
        try:
            print(f"[CALL] Handling raw message type: {type(raw_message)}")
            
            # 1. Nachricht parsen
            if isinstance(raw_message, str):
                if hasattr(self.client, 'parse_sip_message'):
                    msg = self.client.parse_sip_message(raw_message)
                else:
                    if raw_message.strip().startswith('{'):
                        try:
                            msg = json.loads(raw_message)
                        except json.JSONDecodeError:
                            msg = {'custom_data': {}}
                    else:
                        msg = {'custom_data': {}}
            elif isinstance(raw_message, dict):
                msg = raw_message
            else:
                print(f"[CALL WARNING] Unsupported message type: {type(raw_message)}")
                return
            
            if not msg:
                print("[CALL WARNING] Failed to parse message")
                return
                
            # 2. Message-Type extrahieren
            message_type = self._extract_message_type(msg)
            print(f"[CALL] Handling message type: {message_type}")
            
            # 3. Custom Data extrahieren (für alle Handler)
            custom_data = msg.get('custom_data', {})
            if not custom_data and isinstance(msg, dict):
                # Fallback: Wenn keine custom_data, verwende msg direkt
                custom_data = {k: v for k, v in msg.items() if k != 'headers'}
            
            print(f"[CALL DEBUG] custom_data keys: {list(custom_data.keys())}")
            
            # 4. Message Routing MIT KORREKTEN PARAMETERN
            if message_type == 'INCOMING_CALL':
                self.handle_incoming_call(custom_data)
            elif message_type == 'SESSION_KEY':
                self._handle_session_key(custom_data)
            elif message_type == 'CALL_RESPONSE':
                # ✅ KORREKTUR: RICHTIGE METHODE FÜR CLIENT
                # Client benötigt handle_call_response NUR mit custom_data
                if hasattr(self, 'handle_call_response'):
                    # Prüfe die Signatur der Methode
                    import inspect
                    sig = inspect.signature(self.handle_call_response)
                    params = list(sig.parameters.keys())
                    
                    if len(params) == 1:  # Nur custom_data
                        self.handle_call_response(custom_data)
                    elif len(params) == 3:  # custom_data, client_socket, client_name
                        # Verwende Standardwerte für fehlende Parameter
                        self.handle_call_response(custom_data, None, "unknown")
                    else:
                        print(f"[CALL ERROR] Unsupported handle_call_response signature: {params}")
                else:
                    print("[CALL ERROR] No handle_call_response method available")
            elif message_type == 'PUBLIC_KEY_RESPONSE':
                print("[CALL] Received PUBLIC_KEY_RESPONSE, processing...")
                # ✅ KORREKT: custom_data übergeben, nicht msg!
                self.handle_public_key_response(custom_data)
            elif message_type == 'CALL_CONFIRMED':
                self.handle_call_confirmed(custom_data)
            elif message_type == 'CALL_TIMEOUT':
                self.cleanup_call_resources()
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo("Call Failed", "Timeout - Keine Antwort vom Empfänger"))
            elif message_type == 'CALL_END':
                self.cleanup_call_resources()
            elif message_type == 'PONG':
                print("[CALL] Pong received")
            else:
                print(f"[CALL WARNING] Unknown message type: {message_type}")
                print(f"[CALL DEBUG] Full message: {msg}")
                
        except Exception as e:
            print(f"[CALL MSG ERROR] Failed to handle message: {str(e)}")
            import traceback
            traceback.print_exc()

    def _extract_message_type(self, parsed_msg):
        """EINHEITLICHE MESSAGE-TYPE EXTRAKTION"""
        try:
            if not parsed_msg:
                return "UNKNOWN"
            
            custom_data = parsed_msg.get('custom_data', {})
            message_type = custom_data.get('MESSAGE_TYPE')
            
            if message_type:
                return message_type
            
            message_type = parsed_msg.get('MESSAGE_TYPE')
            if message_type:
                return message_type
                
            body = parsed_msg.get('body', '')
            if body.strip().startswith('{'):
                try:
                    body_data = json.loads(body)
                    return body_data.get('MESSAGE_TYPE', 'UNKNOWN')
                except json.JSONDecodeError:
                    pass
            
            headers = parsed_msg.get('headers', {})
            message_type = headers.get('MESSAGE_TYPE')
            if message_type:
                return message_type
                
            return "UNKNOWN"
            
        except Exception as e:
            print(f"[EXTRACT ERROR] {str(e)}")
            return "UNKNOWN"

    def set_connection_state(self, state):
        """Thread-safe connection state management"""
        with self.connection_lock:
            old_state = self.connection_state
            self.connection_state = state
            print(f"[CONNECTION] State changed: {old_state} -> {state}")

    def update_call_ui(self, active, status=None, caller_name=None):
        """Delegate UI updates to the main client instance"""
        try:
            if hasattr(self.client, 'update_call_ui'):
                self.client.update_call_ui(active, status, caller_name)
        except Exception as e:
            print(f"[UI UPDATE ERROR] {str(e)}")

    def on_call_click(self, selected_entry=None):
        """Hauptmethode für Call-Initiation - wird von UI aufgerufen"""
        try:
            if hasattr(self, '_in_call_click') and self._in_call_click:
                return
            self._in_call_click = True
            
            if selected_entry is None and hasattr(self.client, 'selected_entry'):
                selected_entry = self.client.selected_entry
                
            if not selected_entry:
                messagebox.showerror("Error", "Bitte Kontakt auswählen")
                self._in_call_click = False
                return

            print(f"[CALL] Starte Anruf zu {selected_entry.get('name', 'Unknown')}")

            if self.active_call or self.pending_call:
                messagebox.showwarning("Warning", "Bereits in einem Anruf aktiv")
                self._in_call_click = False
                return


            if 'id' not in selected_entry:
                messagebox.showerror("Error", "Ungültiger Kontakt (fehlende ID)")
                self._in_call_click = False
                return

            self.initiate_call(selected_entry)
            
            try:
                if hasattr(self.client, 'update_call_ui'):
                    self.client.update_call_ui(True, "requesting", selected_entry.get('name', 'Unknown'))
            except Exception as e:
                print(f"[UI WARNING] Failed to update UI: {str(e)}")
            
            print(f"[CALL] Anruf initiiert zu {selected_entry.get('name', 'Unknown')}")

        except Exception as e:
            print(f"[CALL ERROR] on_call_click failed: {str(e)}")
            messagebox.showerror("Error", f"Anruf fehlgeschlagen: {str(e)}")
            self.cleanup_call_resources()
        finally:
            if hasattr(self, '_in_call_click'):
                self._in_call_click = False

    def initiate_call(self, recipient):
        """Initiiert Anruf mit EINHEITLICHEM Format - KORRIGIERT"""
        try:
            print(f"[CALL] Starting call to {recipient.get('name', 'Unknown')}")

            if not recipient or 'id' not in recipient:
                raise ValueError("Ungültiger Empfänger (fehlende ID)")

            if self.active_call or self.pending_call:
                raise RuntimeError("Bereits in einem Anruf aktiv")

            # EINHEITLICHE GET_PUBLIC_KEY Nachricht

            key_request_data = {
                "MESSAGE_TYPE": "GET_PUBLIC_KEY",
                "TARGET_CLIENT_ID": recipient['id'],
                "CALLER_NAME": self.client._client_name,
                "CALLER_CLIENT_ID": self.client._find_my_client_id(),
                "AUDIO_CAPABILITIES": {
                    "format": self.audio_config.sample_format_name,
                    "sample_rate": self.audio_config.RATE,
                    "channels": self.audio_config.CHANNELS,
                    "chunk_size": self.audio_config.CHUNK
                }
            }
            
            key_request_msg = self.client.build_sip_message(
                "MESSAGE", 
                "server", 
                key_request_data
            )

            if not self.client._send_message(key_request_msg):
                raise ConnectionError("Konnte Key-Request nicht senden")

            self.pending_call = {
                'recipient': recipient,
                'status': 'requesting_key',
                'start_time': time.time(),
                'timeout': 120
            }

            if hasattr(self.client, 'update_call_ui'):
                self.client.update_call_ui(True, "requesting", recipient.get('name', 'Unknown'))

            print(f"[CALL] Call initiated to {recipient.get('name', 'Unknown')}")

            threading.Thread(target=self._call_timeout_watchdog, daemon=True).start()

        except Exception as e:
            print(f"[CALL ERROR] Initiation failed: {str(e)}")
            self.cleanup_call_resources()
            if hasattr(self.client, 'show_error'):
                self.client.show_error(f"Anruf fehlgeschlagen: {str(e)}")
            raise

    def handle_public_key_response(self, msg):
        """Verarbeitet Public-Key-Antwort - VOLLSTÄNDIG KORRIGIERT"""
        try:
            print(f"\n🎯 [CALL DEBUG] handle_public_key_response CALLED!")
            
            # 1. Prüfe ob ein Call ansteht
            if not self.pending_call:
                print("[CALL WARNING] Unexpected public key response - no pending call")
                return False
                
            if self.pending_call.get('status') != 'requesting_key':
                print(f"[CALL WARNING] Unexpected public key response - wrong status: {self.pending_call.get('status')}")
                return False
                
            print(f"[CALL] Processing public key response...")
            
            # ✅ KORREKTUR: Extrahiere Daten direkt aus msg, nicht aus custom_data
            print(f"[CALL DEBUG] Full message keys: {list(msg.keys())}")
            
            # 2. Extrahiere PUBLIC_KEY direkt aus msg
            public_key = msg.get('PUBLIC_KEY')
            target_id = msg.get('TARGET_CLIENT_ID')
            caller_name = msg.get('CALLER_NAME')
            
            # ✅ KORREKTUR: Fallback für verschiedene Feldnamen
            if not public_key:
                public_key = msg.get('public_key')
            if not target_id:
                target_id = msg.get('target_client_id')
            if not caller_name:
                caller_name = msg.get('caller_name')
                    
            if not public_key:
                print("[CALL ERROR] No public key received in any field")
                print(f"[CALL DEBUG] Available fields in msg: {list(msg.keys())}")
                # Debug: Zeige alle Felder die "KEY" enthalten
                for key, value in msg.items():
                    if 'KEY' in key.upper():
                        print(f"[CALL DEBUG] Key-related field '{key}': {str(value)[:100]}...")
                raise Exception("No public key received from server")
                    
            if not target_id:
                print("[CALL WARNING] No target ID in response")
                target_id = self.pending_call['recipient'].get('id', 'unknown')
                    
            print(f"[CALL] Received public key for client {target_id} (length: {len(public_key)})")
            print(f"[CALL DEBUG] Public key preview: {public_key[:100]}...")
            
            # 3. Public Key Formatierung
            public_key = self._ensure_pem_format(public_key)
            if not public_key:
                raise Exception("Invalid public key format - cannot convert to PEM")
                    
            print(f"[CALL] Formatted public key (PEM): {public_key[:100]}...")
                
            # 4. Session Key generieren (AES)
            session_secret = os.urandom(48)  # 16 IV + 32 AES Key
            iv = session_secret[:16]
            aes_key = session_secret[16:48]
            
            self.current_secret = session_secret  
            print(f"[CALL] Session secret stored in current_secret: {len(session_secret)} bytes")    
            # 5. Call-Daten vorbereiten
            call_data = {
                "caller_name": self.client._client_name,
                "caller_client_id": self.client._find_my_client_id(),
                "aes_iv": base64.b64encode(iv).decode('utf-8'),
                "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                "timestamp": time.time(),
                "call_type": "aes_audio"
            }
                
            print(f"[CALL] Prepared call data for encryption")
            print(f"[CALL DEBUG] Call data keys: {list(call_data.keys())}")
                
            # 6. Mit Public Key des Empfängers verschlüsseln (RSA)
            try:
                print("[CALL] Loading recipient public key...")
                recipient_key = self._load_public_key(public_key)
                if not recipient_key:
                    raise Exception("Failed to load recipient public key")
                        
                call_data_json = json.dumps(call_data).encode('utf-8')
                print(f"[CALL] Call data JSON length: {len(call_data_json)}")
                    
                max_length = 512 - 11  # RSA PKCS#1 Padding
                if len(call_data_json) > max_length:
                    raise Exception(f"Call data too large for RSA encryption: {len(call_data_json)} > {max_length}")
                        
                encrypted_data = recipient_key.public_encrypt(call_data_json, RSA.pkcs1_padding)
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                    
                print(f"[CALL] Call data encrypted successfully (size: {len(encrypted_b64)} chars)")
                    
            except Exception as e:
                print(f"[CALL ERROR] Encryption failed: {str(e)}")
                raise Exception(f"Verschlüsselung fehlgeschlagen: {str(e)}")
                
            # 7. CALL_REQUEST an Server senden
            call_request_data = {
                "MESSAGE_TYPE": "CALL_REQUEST",
                "TARGET_CLIENT_ID": target_id,
                "ENCRYPTED_CALL_DATA": encrypted_b64,
                "CALLER_NAME": self.client._client_name,
                "CALLER_CLIENT_ID": self.client._find_my_client_id(),
                "TIMESTAMP": int(time.time())
            }
                
            call_request_msg = self.client.build_sip_message("MESSAGE", "server", call_request_data)
            
            print(f"[CALL] Sending CALL_REQUEST to server...")
            print(f"[CALL DEBUG] Call request data: {call_request_data}")
                
            if not self.client._send_message(call_request_msg):
                raise Exception("Failed to send CALL_REQUEST to server")
                    
            print("[CALL] CALL_REQUEST sent to server")
                
            # 8. Call-Status aktualisieren
            self.pending_call.update({
                'status': 'request_sent',
                'session_secret': session_secret,
                'target_id': target_id,
                'encrypted_call_data': encrypted_b64
            })
                
            print("[CALL] Waiting for callee response...")
                
            # 9. UI aktualisieren
            recipient_name = self.pending_call['recipient'].get('name', 'Unknown')
            if hasattr(self.client, 'update_call_ui'):
                self.client.update_call_ui(True, "ringing", recipient_name)
                    
            print("✅ [CALL SUCCESS] Public key response processed successfully!")
            return True
                
        except Exception as e:
            print(f"❌ [CALL ERROR] Public key response handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
                
            # Fehler-UI anzeigen
            if hasattr(self.client, 'after'):
                self.client.after(0, lambda: messagebox.showerror(
                    "Call Failed", 
                    f"Verbindungsaufbau fehlgeschlagen: {str(e)}"
                ))
                
            # Ressourcen bereinigen
            self.cleanup_call_resources()
            return False

    def _ensure_pem_format(self, key_data):
        """Stellt sicher dass der Schlüssel im korrekten PEM-Format vorliegt"""
        try:
            if not key_data:
                return None
                
            key_str = key_data.strip()
            
            if key_str.startswith('-----BEGIN PUBLIC KEY-----') and key_str.endswith('-----END PUBLIC KEY-----'):
                print("[PEM] Key is already in valid PEM format")
                return key_str
            
            if 'BEGIN PUBLIC KEY' not in key_str and 'END PUBLIC KEY' not in key_str:
                print("[PEM] Adding PEM headers to base64 key")
                key_content = re.sub(r'\s+', '', key_str)
                try:
                    base64.b64decode(key_content)
                    key_str = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
                    print("[PEM] Successfully converted to PEM format")
                except Exception as e:
                    print(f"[PEM ERROR] Invalid base64: {e}")
                    return None
            
            try:
                bio = BIO.MemoryBuffer(key_str.encode())
                key = RSA.load_pub_key_bio(bio)
                if key:
                    print("[PEM] Key validation successful")
                    return key_str
            except Exception as e:
                print(f"[PEM ERROR] Key validation failed: {e}")
                
            return None
            
        except Exception as e:
            print(f"[PEM ERROR] Formatting failed: {e}")
            return None

    def _load_public_key(self, pem_key):
        """Lädt einen öffentlichen Schlüssel mit Fehlerbehandlung"""
        try:
            if not pem_key:
                return None
                
            pem_key = pem_key.strip()
            pem_key = pem_key.replace('\\\\n', '\n').replace('\\n', '\n')
            
            print(f"[KEY LOAD] Loading key: {pem_key[:100]}...")
            
            bio = BIO.MemoryBuffer(pem_key.encode())
            key = RSA.load_pub_key_bio(bio)
            
            if key:
                print("[KEY LOAD] Successfully loaded public key")
                return key
            else:
                print("[KEY LOAD] Failed to load key")
                return None
                
        except Exception as e:
            print(f"[KEY LOAD ERROR] {str(e)}")
            return None

    def handle_incoming_call(self, msg):
        """Verarbeitet eingehende Anrufe - VOLLSTÄNDIG KORRIGIERT MIT RICHTIGEM PARSING"""
        try:
            print("\n=== INCOMING CALL PROCESSING ===")
            print(f"[CALL] Raw message type: {type(msg)}")
            print(f"[CALL] Raw message preview: {str(msg)[:500]}...")
            
            # ✅ KRITISCH: Unterscheidung zwischen verschiedenen Nachrichtenformaten
            custom_data = {}
            
            # Fall 1: Bereits geparste SIP-Nachricht (Dict)
            if isinstance(msg, dict):
                print("[CALL] Processing pre-parsed SIP message")
                custom_data = msg.get('custom_data', {})
                if not custom_data:
                    # Versuche direkt aus dem Dict zu extrahieren
                    custom_data = {k: v for k, v in msg.items() if k != 'headers'}
            
            # Fall 2: Rohdaten (String oder Bytes) - muss geparst werden
            elif isinstance(msg, (str, bytes)):
                print("[CALL] Parsing raw SIP message...")
                if isinstance(msg, bytes):
                    msg = msg.decode('utf-8')
                
                # Debug: Zeige die komplette Nachricht
                print(f"[CALL DEBUG] Full SIP message:\n{msg}")
                
                # Verwende den einheitlichen SIP-Parser
                sip_data = self.client.parse_sip_message(msg)
                if not sip_data:
                    print("[CALL ERROR] Failed to parse SIP message")
                    return
                    
                print(f"[CALL DEBUG] Parsed SIP keys: {list(sip_data.keys())}")
                
                # Extrahiere custom_data aus verschiedenen möglichen Quellen
                custom_data = sip_data.get('custom_data', {})
                
                # Fallback: Body als JSON parsen
                if not custom_data:
                    body = sip_data.get('body', '')
                    if body and body.strip().startswith('{'):
                        try:
                            custom_data = json.loads(body)
                            print("[CALL DEBUG] Successfully parsed body as JSON")
                        except json.JSONDecodeError as e:
                            print(f"[CALL ERROR] Body JSON parse failed: {e}")
                            print(f"[CALL DEBUG] Body content: {body}")
            
            # Fall 3: Unbekanntes Format
            else:
                print(f"[CALL ERROR] Unsupported message format: {type(msg)}")
                return
            
            # ✅ EXTRAKTION DER CALL-DATEN MIT DETAILIERTEM DEBUGGING
            print(f"[CALL DEBUG] Custom data keys: {list(custom_data.keys())}")
            print(f"[CALL DEBUG] Full custom data: {custom_data}")
            
            # Extrahiere erforderliche Felder mit Fallbacks für verschiedene Feldnamen
            caller_name = None
            caller_id = None
            encrypted_data = None
            
            # Mögliche Feldnamen für Caller Name
            caller_name_fields = ['CALLER_NAME', 'caller_name', 'CallerName', 'from_user']
            for field in caller_name_fields:
                if field in custom_data:
                    caller_name = custom_data[field]
                    print(f"[CALL DEBUG] Found caller_name in field '{field}': {caller_name}")
                    break
            
            # Mögliche Feldnamen für Caller ID
            caller_id_fields = ['CALLER_CLIENT_ID', 'caller_client_id', 'CallerId', 'caller_id']
            for field in caller_id_fields:
                if field in custom_data:
                    caller_id = custom_data[field]
                    print(f"[CALL DEBUG] Found caller_id in field '{field}': {caller_id}")
                    break
            
            # Mögliche Feldnamen für verschlüsselte Daten
            encrypted_fields = ['ENCRYPTED_CALL_DATA', 'encrypted_call_data', 'EncryptedData']
            for field in encrypted_fields:
                if field in custom_data:
                    encrypted_data = custom_data[field]
                    print(f"[CALL DEBUG] Found encrypted_data in field '{field}': {len(encrypted_data)} chars")
                    break
            
            # ✅ VALIDIERUNG MIT DETAILLIERTEM DEBUGGING
            validation_errors = []
            
            if not caller_name:
                validation_errors.append("Missing CALLER_NAME")
                print("[CALL ERROR] Caller name not found in any field")
                print(f"[CALL DEBUG] Available fields: {list(custom_data.keys())}")
                
            if not caller_id:
                validation_errors.append("Missing CALLER_CLIENT_ID")
                print("[CALL ERROR] Caller ID not found in any field")
                
            if not encrypted_data:
                validation_errors.append("Missing ENCRYPTED_CALL_DATA")
                print("[CALL ERROR] Encrypted data not found in any field")
            
            if validation_errors:
                error_msg = f"Invalid INCOMING_CALL message: {', '.join(validation_errors)}"
                print(f"[CALL ERROR] {error_msg}")
                self._send_call_response("error", caller_id)
                return
            
            print(f"[CALL SUCCESS] Valid INCOMING_CALL from {caller_name} ({caller_id})")
            print(f"[CALL DEBUG] Encrypted data length: {len(encrypted_data)}")
            
            # ✅ Speichere die Call-Informationen
            self.incoming_call = {
                'caller_name': caller_name,
                'caller_id': caller_id,
                'encrypted_data': encrypted_data,
                'timestamp': time.time(),
                'custom_data': custom_data  # Für Debugging speichern
            }
            
            # ✅ Zeige den Anruf-Dialog an (im Hauptthread)
            def show_call_dialog():
                try:
                    if not hasattr(self.client, 'winfo_exists') or not self.client.winfo_exists():
                        print("[CALL WARNING] Main window destroyed, cannot show dialog")
                        self._send_call_response("error", caller_id)
                        return
                        
                    self._ask_call_acceptance(caller_name, caller_id, encrypted_data)
                except Exception as e:
                    print(f"[CALL DIALOG ERROR] {str(e)}")
                    self._send_call_response("error", caller_id)
            
            # Immer über after() im Hauptthread aufrufen
            if hasattr(self.client, 'after'):
                self.client.after(0, show_call_dialog)
            else:
                print("[CALL WARNING] No after() method, calling dialog directly")
                show_call_dialog()
                
        except Exception as e:
            print(f"[CALL ERROR] Incoming call handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            try:
                self._send_call_response("error", None)
            except:
                pass

    def _ask_call_acceptance(self, caller_name, caller_id, encrypted_data):
        """Fragt Benutzer nach Annahme des Anrufs - MIT FEHLERBEHANDLUNG"""
        try:
            print(f"[CALL] Showing call dialog for {caller_name}")
            
            # Überprüfe ob das Hauptfenster noch existiert
            if not hasattr(self.client, 'winfo_exists') or not self.client.winfo_exists():
                print("[CALL ERROR] Main window no longer exists")
                self._reject_incoming_call(caller_id)
                return
                
            # Dialog anzeigen
            accept = messagebox.askyesno(
                "Eingehender Anruf",
                f"Eingehender Anruf von {caller_name}.\nAnnehmen?"
            )
            
            if accept:
                print(f"[CALL] User accepted call from {caller_name}")
                self._accept_incoming_call(caller_name, caller_id, encrypted_data)
            else:
                print(f"[CALL] User rejected call from {caller_name}")
                self._reject_incoming_call(caller_id)
                
        except Exception as e:
            print(f"[CALL ERROR] Acceptance dialog failed: {str(e)}")
            # Im Fehlerfall automatisch ablehnen
            self._reject_incoming_call(caller_id)

    def _accept_incoming_call(self, caller_name, caller_id, encrypted_data):
        """Nimmt eingehenden Anruf an - VOLLSTÄNDIG FRAME-SIP KOMPATIBEL"""
        try:
            print(f"[CALL] Accepting incoming call from {caller_name} ({caller_id})")
            
            # 1. Daten entschlüsseln (RSA mit privatem Schlüssel)
            private_key = load_privatekey()
            if not private_key:
                raise Exception("Failed to load private key")
                
            priv_key = RSA.load_key_string(private_key.encode())
            
            try:
                encrypted_bytes = base64.b64decode(encrypted_data)
                print(f"[CALL] Decrypting {len(encrypted_bytes)} bytes of call data")
                
                decrypted_bytes = priv_key.private_decrypt(encrypted_bytes, RSA.pkcs1_padding)
                call_info = json.loads(decrypted_bytes.decode('utf-8'))
                
                print(f"[CALL] Decrypted call info: {list(call_info.keys())}")
                
            except Exception as e:
                print(f"[CALL ERROR] Decryption failed: {str(e)}")
                raise Exception(f"Entschlüsselung fehlgeschlagen: {str(e)}")

            # 2. Session Key speichern
            self.pending_call = {
                'caller_name': caller_name,
                'caller_id': caller_id,
                'aes_iv': base64.b64decode(call_info['aes_iv']),
                'aes_key': base64.b64decode(call_info['aes_key']),
                'status': 'accepted',
                'timestamp': time.time()
            }
            
            self.current_secret = self.pending_call['aes_iv'] + self.pending_call['aes_key']
            
            # 3. ✅ FRAME-SIP KOMPATIBLE Antwort
            success = self._send_call_response("accepted", caller_id)
            
            if success:
                print("[CALL] ✓ Call accepted successfully")
                
                # UI aktualisieren
                if hasattr(self.client, 'update_call_ui'):
                    self.client.update_call_ui(True, "connected", caller_name)
                    
                return True
            else:
                raise Exception("Failed to send acceptance response")
            
        except Exception as e:
            print(f"[CALL ERROR] Acceptance failed: {str(e)}")
            try:
                self._send_call_response("error", caller_id)
            except:
                pass
            self.cleanup_call_resources()
            return False
    def _send_call_response(self, response, caller_id):
        """Sendet Call-Response an Server - FEHLTE IN DER CALL KLASSE"""
        try:
            print(f"[CALL] Preparing {response} response for caller {caller_id}")
            
            # ✅ KORREKT: Einheitliches SIP + JSON Format
            response_data = {
                "MESSAGE_TYPE": "CALL_RESPONSE",
                "RESPONSE": response,
                "CALLER_CLIENT_ID": caller_id,
                "TIMESTAMP": int(time.time()),
                "CLIENT_NAME": getattr(self.client, '_client_name', 'Unknown')
            }
            
            # ✅ KORREKT: SIP-Nachricht mit JSON Body erstellen
            response_msg = self.client.build_sip_message("MESSAGE", "server", response_data)
            
            print(f"[CALL] Built framed SIP message: {len(response_msg)} chars")
            
            # ✅ KORREKT: Immer send_frame verwenden
            if hasattr(self.client, 'client_socket') and self.client.client_socket:
                success = send_frame(self.client.client_socket, response_msg.encode('utf-8'))
                print(f"[CALL] send_frame result: {success}")
                
                if success:
                    print(f"[CALL] ✓ Framed SIP response '{response}' sent successfully")
                else:
                    print(f"[CALL ERROR] ✗ Failed to send framed SIP response")
                    
                return success
            else:
                print("[CALL ERROR] No socket available for framed SIP response")
                return False
            
        except Exception as e:
            print(f"[CALL CRITICAL ERROR] Failed to send framed SIP response: {str(e)}")
            return False
    def _reject_incoming_call(self, caller_id):
        """Lehnt eingehenden Anruf ab - VOLLSTÄNDIG FRAME-SIP KOMPATIBEL"""
        try:
            print(f"[CALL] Rejecting call from {caller_id}")
            
            success = self._send_call_response("rejected", caller_id)
            
            if success:
                print("[CALL] ✓ Call rejected successfully")
            else:
                print("[CALL WARNING] Call rejection may not have reached server")
                
            self.cleanup_call_resources()
            
        except Exception as e:
            print(f"[CALL ERROR] Rejection failed: {str(e)}")
            self.cleanup_call_resources()
    def debug_incoming_message(self, msg):
        """Debug-Hilfe zur Analyse der eingehenden Nachricht"""
        print("\n=== INCOMING MESSAGE DEBUG ===")
        
        def print_deep(obj, prefix="", depth=0, max_depth=3):
            if depth > max_depth:
                print(f"{prefix}... (max depth reached)")
                return
                
            if isinstance(obj, dict):
                for key, value in obj.items():
                    print(f"{prefix}{key}: {type(value)}")
                    if isinstance(value, (dict, list)) and depth < max_depth:
                        print_deep(value, prefix + "  ", depth + 1, max_depth)
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:5]):  # Nur erste 5 Elemente
                    print(f"{prefix}[{i}]: {type(item)}")
                    if isinstance(item, (dict, list)) and depth < max_depth:
                        print_deep(item, prefix + "  ", depth + 1, max_depth)
            else:
                print(f"{prefix}{str(obj)[:200]}...")
        
        print("Message structure:")
        print_deep(msg)
        print("=== END DEBUG ===\n")

    
    def handle_call_response(self, msg):
        """Verarbeitet Call-Antworten - VOLLSTÄNDIG KORRIGIERT FÜR CLIENT"""
        try:
            print(f"[CALL] Handling call response, type: {type(msg)}")
            
            # ✅ EINHEITLICHE DATENEXTRAKTION
            custom_data = msg.get('custom_data', {})
            if not custom_data:
                # Fallback: Verwende msg direkt wenn keine custom_data
                custom_data = {k: v for k, v in msg.items() if k != 'headers'}
            
            response = custom_data.get('RESPONSE')
            caller_id = custom_data.get('CALLER_CLIENT_ID')
            
            print(f"[CALL DEBUG] Response: {response}, Caller ID: {caller_id}")
            print(f"[CALL DEBUG] Custom data keys: {list(custom_data.keys())}")

            if not response:
                print("[CALL ERROR] Missing response in call response")
                return False
            
            # ✅ CLIENT-SPEZIFISCHE VERARBEITUNG (nicht Server!)
            if response == "accepted":
                print(f"[CALL] Call accepted by callee")
                
                # Extrahiere Relay-Informationen falls vorhanden
                use_relay = custom_data.get('USE_AUDIO_RELAY', True)
                relay_ip = custom_data.get('AUDIO_RELAY_IP')
                relay_port = custom_data.get('AUDIO_RELAY_PORT', 51822)
                
                if use_relay and relay_ip:
                    print(f"[CALL] Using UDP Relay: {relay_ip}:{relay_port}")
                    self.use_udp_relay = True
                    self.relay_server_ip = relay_ip
                    self.relay_server_port = relay_port
                    
                    # ✅ KORREKTUR: NUR RELAY KONFIGURIEREN, ABER AUDIO STREAMS NOCH NICHT STARTEN
                    # Die Audio Streams werden erst nach CALL_CONFIRMED gestartet
                    print(f"[CALL] Relay configured, waiting for CALL_CONFIRMED to start audio")
                    
                else:
                    print("[CALL] Direct connection (no relay)")
                    
                # ✅ KORREKTUR: SICHERER UI UPDATE OHNE 'recipient' FIELD
                if hasattr(self.client, 'update_call_ui'):
                    recipient_name = "Unknown"
                    # Verschiedene Möglichkeiten um den Namen zu finden
                    if hasattr(self, 'pending_call') and self.pending_call:
                        if 'recipient' in self.pending_call:
                            recipient_name = self.pending_call['recipient'].get('name', 'Unknown')
                        elif 'caller_name' in self.pending_call:
                            recipient_name = self.pending_call.get('caller_name', 'Unknown')
                        elif hasattr(self.client, 'selected_entry'):
                            recipient_name = self.client.selected_entry.get('name', 'Unknown')
                    
                    self.client.update_call_ui(True, "connected", recipient_name)
                    
            elif response == "rejected":
                print(f"[CALL] Call rejected by callee")
                
                # Fehler-UI anzeigen
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo(
                        "Call Rejected", 
                        "Der Empfänger hat den Anruf abgelehnt."
                    ))
                
                # Ressourcen bereinigen
                self.cleanup_call_resources()
                
            elif response == "error":
                print(f"[CALL] Call error from callee")
                
                error_msg = custom_data.get('ERROR', 'Unknown error')
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showerror(
                        "Call Error", 
                        f"Fehler beim Empfänger: {error_msg}"
                    ))
                
                # Ressourcen bereinigen
                self.cleanup_call_resources()
            
            else:
                print(f"[CALL WARNING] Unknown response type: {response}")
                return False
            
            print(f"[CALL] ✓ Call response '{response}' processed successfully")
            return True
            
        except Exception as e:
            print(f"[CALL ERROR] Call response handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Im Fehlerfall Ressourcen bereinigen
            self.cleanup_call_resources()
            return False



    def handle_call_confirmed(self, msg):
        """Verarbeitet Call-Bestätigung für Angerufene - JETZT MIT UDP RELAY"""
        try:
            print(f"[CALL] CALL_CONFIRMED received, type: {type(msg)}")
            print(f"[CALL] CALL_CONFIRMED keys: {list(msg.keys())}")
            
            # ✅ FLEXIBLE DATENEXTRAKTION: custom_data ODER direkt aus msg
            if isinstance(msg, dict) and 'custom_data' in msg:
                # Nachricht hat custom_data Struktur
                data = msg.get('custom_data', {})
                print(f"[CALL] Using custom_data, keys: {list(data.keys())}")
            else:
                # Nachricht ist bereits custom_data oder Haupt-Body
                data = msg
                print(f"[CALL] Using direct data, keys: {list(data.keys())}")
            
            # ✅ UDP Relay Konfiguration
            use_relay = data.get('USE_AUDIO_RELAY', False)
            relay_ip = data.get('AUDIO_RELAY_IP')
            relay_port = data.get('AUDIO_RELAY_PORT', 51822)
            
            print(f"[CALL] Relay config - use_relay: {use_relay}, ip: {relay_ip}, port: {relay_port}")
            
            if use_relay and relay_ip:
                print(f"[CALL] Call confirmed with UDP Relay: {relay_ip}:{relay_port}")
                self.use_udp_relay = True
                self.relay_server_ip = relay_ip
                self.relay_server_port = relay_port
                
                # ✅ KRITISCH: active_call ZUERST setzen!
                self.active_call = True
                self.client.active_call = True
                print(f"[CALL] Active call set to: {self.active_call}")
                
                # ✅ KORREKTUR: Audio streams MIT current_secret starten
                if hasattr(self, 'current_secret') and self.current_secret:
                    print(f"[CALL] Starting audio streams with session secret ({len(self.current_secret)} bytes)")
                    self._start_audio_streams()
                    if hasattr(self, 'pending_call'):
                        self.pending_call['status'] = 'connected'
                    print("[CALL] UDP Relay call established successfully")
                else:
                    print("[CALL ERROR] No session secret available for audio streams")
                    print(f"[CALL DEBUG] current_secret available: {hasattr(self, 'current_secret')}")
                    
            else:
                print("[CALL ERROR] No relay configuration in confirmation")
                print(f"[CALL DEBUG] use_relay: {use_relay}, relay_ip: {relay_ip}")
                
        except Exception as e:
            print(f"[CALL ERROR] Call confirmation handling failed: {str(e)}")
            import traceback
            traceback.print_exc()

    def _handle_session_key(self, msg):
        """Verarbeitet Session Key vom Server"""
        try:
            custom_data = msg.get('custom_data', {})
            encrypted_session = custom_data.get('ENCRYPTED_SESSION')
            
            if encrypted_session:
                private_key = load_privatekey()
                priv_key = RSA.load_key_string(private_key.encode())
                
                encrypted_bytes = base64.b64decode(encrypted_session)
                decrypted = priv_key.private_decrypt(encrypted_bytes, RSA.pkcs1_padding)
                
                if decrypted.startswith(b"+++session_key+++"):
                    session_secret = decrypted[17:65]
                    self.current_secret = session_secret
                    print("[CALL] Session key received and stored")
                    
                    if hasattr(self, 'pending_call') and self.pending_call.get('status') == 'accepted':
                        self._start_audio_streams()
                        
        except Exception as e:
            print(f"[CALL ERROR] Session key handling failed: {str(e)}")



    def _start_call_timer(self):
        """Startet die Call-Timer-Anzeige auf beiden Clients"""
        try:
            self.call_timer_running = True
            self.call_start_time = time.time()
            
            # Timer in der UI aktualisieren
            if hasattr(self.client, 'start_call_timer'):
                self.client.start_call_timer()
            else:
                self._update_call_timer_ui()
                
        except Exception as e:
            print(f"[TIMER ERROR] Failed to start timer: {str(e)}")

    def _update_call_timer_ui(self):
        """Aktualisiert die Timer-Anzeige in der UI"""
        if not self.call_timer_running or not self.active_call:
            return
            
        try:
            elapsed = int(time.time() - self.call_start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            timer_text = f"Call: {minutes:02d}:{seconds:02d}"
            
            # UI Update - verschiedene mögliche Implementierungen
            if hasattr(self.client, 'status_label'):
                self.client.status_label.configure(text=timer_text)
            elif hasattr(self.client, 'call_timer_label'):
                self.client.call_timer_label.configure(text=timer_text)
            
            # Nächste Aktualisierung in 1 Sekunde
            if hasattr(self.client, 'after'):
                self.call_timer_after_id = self.client.after(1000, self._update_call_timer_ui)
                
        except Exception as e:
            print(f"[TIMER UI ERROR] {str(e)}")

    def stop_call_timer(self):
        """Stoppt die Timer-Anzeige"""
        self.call_timer_running = False
        if self.call_timer_after_id and hasattr(self.client, 'after'):
            self.client.after_cancel(self.call_timer_after_id)
            self.call_timer_after_id = None

    def _stop_audio_streams(self):
        """Stoppt alle Audio-Streams"""
        self.active_call = False
        time.sleep(0.1)
        
        for thread in self.audio_threads:
            try:
                if thread.is_alive():
                    thread.join(timeout=1.0)
            except:
                pass
        self.audio_threads = []

    def _call_timeout_watchdog(self):
        """Überwacht Call-Timeout"""
        timeout = 120
        start_time = time.time()
        
        while (hasattr(self, 'pending_call') and self.pending_call and 
               self.pending_call.get('status') in ['requesting_key', 'request_sent']):
            if time.time() - start_time > timeout:
                print("[CALL] Timeout waiting for call response")
                self.cleanup_call_resources()
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo("Call Failed", "Keine Antwort vom Empfänger"))
                break
            time.sleep(1)

    def cleanup_call_resources(self):
        """Bereinigt alle Call-Ressourcen inklusive Timer"""
        print("[CALL] Cleaning up call resources...")
        self.active_call = False
        self.call_timer_running = False
        
        # Timer stoppen
        self.stop_call_timer()
        
        # Audio-Threads stoppen
        self._stop_audio_streams()
        
        # Variablen zurücksetzen
        self.pending_call = None
        self.incoming_call = None
        self.current_secret = None
        self.use_udp_relay = False
        self.relay_server_ip = None
        self.call_start_time = None
        
        # UI zurücksetzen
        try:
            self._update_ui_wrapper(active=False)
            # Timer-Text zurücksetzen
            if hasattr(self.client, 'status_label'):
                self.client.status_label.configure(text="Bereit")
            elif hasattr(self.client, 'call_timer_label'):
                self.client.call_timer_label.configure(text="")
        except:
            pass
            
        print("[CALL] Cleanup complete")

    def hangup_call(self):
        """Beendet aktiven Anruf"""
        try:
            if self.active_call or self.pending_call:
                print("[CALL] Hanging up call")
                
                # Hangup-Nachricht an Server
                hangup_msg = self.client.build_sip_message("MESSAGE", "server", {
                    "MESSAGE_TYPE": "CALL_END",
                    "TIMESTAMP": int(time.time()),
                    "REASON": "user_hangup"
                })
                
                self.client._send_message(hangup_msg)
                
            self.cleanup_call_resources()
            print("[CALL] Hangup complete")
            
        except Exception as e:
            print(f"[CALL ERROR] Hangup failed: {str(e)}")
            self.cleanup_call_resources()

    def _update_ui_wrapper(self, active, status=None, caller_name=None):
        """Wrapper für UI-Updates mit Fallback"""
        try:
            self.update_call_ui(active, status, caller_name)
        except Exception as e:
            print(f"[UI WRAPPER WARNING] Failed to update UI: {str(e)}")
            try:
                if hasattr(self.client, 'status_label') and self.client.status_label.winfo_exists():
                    if active:
                        self.client.status_label.configure(text="Aktiver Anruf")
                    else:
                        self.client.status_label.configure(text="Bereit")
            except:
                pass


    def on_entry_click(self, entry):
        """Handler für Klicks auf Telefonbucheinträge"""
        try:
            self.client.selected_entry = entry
            print(f"[CALL] Selected entry: {entry.get('name', 'Unknown')}")
        except Exception as e:
            print(f"[CALL ERROR] Entry click failed: {str(e)}")

    def __del__(self):
        """Destruktor für Ressourcen-Cleanup"""
        try:
            if hasattr(self, 'audio'):
                self.audio.terminate()
        except:
            pass
class SecureVault:
    IV_SIZE = 16      # initialisation vector (first 16 bytes)
    KEY_SIZE = 32     # aes key (last 32 bytes)
    SECRET_SIZE = IV_SIZE + KEY_SIZE  # 48 Bytes total

    def __init__(self):
                # Security Monitor Integration
        self.monitor = SecurityMonitor()
        
        # Bibliothek sicher laden
        lib_path = os.path.join(os.path.dirname(__file__), "libauslagern_x86_64.so")
        self.lib = self.monitor.library_loader.load_library(lib_path)
        self._init_function_definitions()
        self.vault = self.lib.secure_vault_create()
        if not self.vault:
            raise RuntimeError("Failed to create vault")

    def _init_function_definitions(self):
        """Initialize C function signatures"""
        self.lib.secure_vault_create.restype = c_void_p
        
        self.lib.secure_vault_store_secret.argtypes = [
            c_void_p,       # vault
            c_char_p,       # name
            POINTER(c_ubyte), # secret
            c_size_t        # length
        ]
        
        self.lib.secure_vault_get_secret_parts.argtypes = [
            c_void_p,       # vault
            c_char_p,       # name
            POINTER(c_ubyte), # iv
            POINTER(c_ubyte)  # key
        ]
        
        self.lib.secure_vault_is_locked.argtypes = [c_void_p]
        self.lib.secure_vault_is_locked.restype = c_int
        
        self.lib.secure_vault_wipe.argtypes = [c_void_p]

    def store_secret_safely(self, secret: bytes, key_name: str = "server_key") -> bool:
        """Store secret with name tracking"""
        if len(secret) != self.SECRET_SIZE:
            raise ValueError(f"Invalid secret size: {len(secret)} (expected {self.SECRET_SIZE})")
            
        buffer = (c_ubyte * self.SECRET_SIZE).from_buffer_copy(secret)
        name_buffer = create_string_buffer(key_name.encode('utf-8'))
        
        result = self.lib.secure_vault_store_secret(
            c_void_p(self.vault),
            name_buffer,
            cast(buffer, POINTER(c_ubyte)),
            self.SECRET_SIZE
        )
        
        return result == 0

    def get_secret_parts(self, key_name: str = "server_key") -> Tuple[bytes, bytes]:
        """Get IV (16B) and Key (32B) for named secret"""
        iv = (c_ubyte * self.IV_SIZE)()
        key = (c_ubyte * self.KEY_SIZE)()
        name_buffer = create_string_buffer(key_name.encode('utf-8'))
        
        if self.lib.secure_vault_get_secret_parts(
            c_void_p(self.vault),
            name_buffer,
            cast(iv, POINTER(c_ubyte)),
            cast(key, POINTER(c_ubyte))
        ) != 0:
            raise RuntimeError(f"Failed to retrieve secret parts for key: {key_name}")
            
        return bytes(iv), bytes(key)

    def is_locked(self) -> bool:
        """Check if the vault is locked"""
        return bool(self.lib.secure_vault_is_locked(c_void_p(self.vault)))

    def wipe(self) -> None:
        """Securely wipe the vault"""
        self.lib.secure_vault_wipe(c_void_p(self.vault))
        self.vault = None

    def __del__(self):
        if hasattr(self, 'vault') and self.vault:
            self.wipe()

class PHONEBOOK(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Vorhandene Initialisierung...
        
        self.phonebook_entries = []  # Wichtig für UI
        self.phonebook_update_signal = None
        self.client_socket = None
        self.server_public_key = None
        self.encrypted_secret = None
        self.private_key = load_privatekey()
        self.aes_iv = None
        self.aes_key = None
        self.title("PHONEBOOK, mein Telefonbuch")
        self.geometry("600x1000")
        self.configure(fg_color='black')
        ctk.set_appearance_mode("dark")
        self.secret_vault = SecureVault()
        self.current_secret = None
        self.selected_entry = None
        
        # KORREKTUR: load_client_name() Funktion aufrufen, nicht self.load_client_name()
        self._client_name = load_client_name()
        if not self._client_name:
            self._client_name = "Unknown"
        self.current_secret = None
        self.server_ip = "127.0.0.1"
        self._message_queue = []
        self._processing_queue = False
        self._queue_size_limit = 120
        self._last_minute_check = time.time()
        self._messages_this_minute = 0
        
        # WireGuard Integration - ENTFERNEN da in CALL-Klasse integriert
        # self.wg_manager = WireGuardManager()  # OBSOLETE
        self.wg_interface_name = "wg-phonebook"
        self.wg_config_path = f"/etc/wireguard/{self.wg_interface_name}.conf"
        self.wg_peer_ip = None
        self.wg_my_ip = None
        
        # Audio-Konstanten definieren
        self.AUDIO_HOST = "10.8.0.0/24"  # WireGuard Netzwerk
        self.AUDIO_FORMAT = pyaudio.paInt16
        self.AUDIO_CHANNELS = 1
        self.AUDIO_RATE = 44100
        self.AUDIO_CHUNK = 1024
        self.AUDIO_IV_LEN = 16
        
        # Thread-Management
        self.audio_threads = []
        self.active_call = False
        
        # CALL Manager initialisieren
        self.call_manager = CALL(self)
        
        # UI setup NACH der Initialisierung aller Attribute
        self.setup_ui()
        self.relay_manager = ClientRelayManager(self)
        self.available_servers = {}
        self.best_server = None
        
    def setup_ui(self):
        # Stile für die UI-Elemente
        self.style = ttk.Style(self)
        self.style.theme_use('alt')
        self.style.configure('TFrame', background='black')
        self.style.configure('TLabel', background='black', foreground='white')
        self.style.configure('TButton', background='black', foreground='white')
        self.style.configure('TEntry', background='gray', foreground='white')
        self.style.configure('TCombobox', background='gray', foreground='white')
        self.style.configure('TNotebook', background='black')
        self.style.configure('TNotebook.Tab', background='black', foreground='white')

        # Menüleiste
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Schließen", command=self.quit)
        self.menu_bar.add_cascade(label="Datei", menu=file_menu)

        settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        settings_menu.add_command(label="Audio-Geräte", command=self.show_audio_devices_settings)
        settings_menu.add_command(label="Sprache", command=self.open_language_settings)
        self.menu_bar.add_cascade(label="Einstellungen", menu=settings_menu)

        # Notebook für Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        # Telefonbuch-Tab
        self.phonebook_tab = ctk.CTkFrame(self.notebook, fg_color='black')
        self.notebook.add(self.phonebook_tab, text="Telefonbuch")
        self.create_phonebook_tab()
        self.relay_status_label = ctk.CTkLabel(
            self.phonebook_tab, 
            text="Bereit für Verbindung",
            font=("Arial", 12),
            text_color="white"
        )
        
    def show_audio_devices_settings(self):
        """Zeigt Audio-Geräte Einstellungen - KORRIGIERT FÜR BEIDE GERÄTE"""
        try:
            # Verwende die CALL-Klasse für Audio-Geräte Management
            if hasattr(self, 'call_manager'):
                self.call_manager.show_audio_devices_popup()
            else:
                # Fallback falls CALL Manager nicht verfügbar
                self._show_audio_devices_dialog()
                
        except Exception as e:
            print(f"[AUDIO SETTINGS ERROR] {str(e)}")
            messagebox.showerror("Fehler", f"Audio-Einstellungen konnten nicht geöffnet werden: {str(e)}")
    def _show_audio_devices_dialog(self):
        """Fallback Audio-Geräte Dialog"""
        try:
            dialog = tk.Toplevel(self)
            dialog.title("Audio-Geräte Einstellungen")
            dialog.geometry("500x400")
            dialog.transient(self)
            dialog.grab_set()
            
            # Zentriere das Fenster
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
            y = (dialog.winfo_screenheight() // 2) - (400 // 2)
            dialog.geometry(f"+{x}+{y}")
            
            # Eingabegeräte (Mikrofone)
            tk.Label(dialog, text="Eingabegerät (Mikrofon):", font=("Arial", 10, "bold")).pack(pady=(20, 5))
            input_devices = audio_config._get_input_devices()
            input_var = tk.StringVar(dialog)
            
            input_combo = ttk.Combobox(dialog, textvariable=input_var, values=input_devices, width=60)
            input_combo.pack(pady=5)
            
            if self.selected_input_device and self.selected_input_device in input_devices:
                input_combo.set(self.selected_input_device)
            elif input_devices:
                input_combo.set(input_devices[0])
            
            # Ausgabegeräte (Lautsprecher/Kopfhörer)
            tk.Label(dialog, text="Ausgabegerät (Lautsprecher):", font=("Arial", 10, "bold")).pack(pady=(20, 5))
            output_devices = audio_config._get_output_devices()
            output_var = tk.StringVar(dialog)
            
            output_combo = ttk.Combobox(dialog, textvariable=output_var, values=output_devices, width=60)
            output_combo.pack(pady=5)
            
            if self.selected_output_device and self.selected_output_device in output_devices:
                output_combo.set(self.selected_output_device)
            elif output_devices:
                output_combo.set(output_devices[0])
            
            # Info Text
            info_text = (
                "Hinweise:\n"
                "• Wählen Sie für Eingabe und Ausgabe dasselbe Gerät (z.B. Headset)\n"
                "• Oder wählen Sie separate Geräte (z.B. Mikrofon + Lautsprecher)\n"
                "• Einstellungen werden für zukünftige Anrufe übernommen"
            )
            info_label = tk.Label(dialog, text=info_text, font=("Arial", 9), 
                                justify=tk.LEFT, fg="blue", wraplength=450)
            info_label.pack(pady=20)
            
            # Buttons
            button_frame = tk.Frame(dialog)
            button_frame.pack(pady=20)
            
            def apply_selection():
                """Übernimmt die aktuell ausgewählten Geräte, Qualität und Rauschfilterung"""
                input_selection = input_var.get()
                output_selection = output_var.get()
                quality_selection = quality_var.get()
                
                # Warnung für Highest Quality
                if quality_selection == "highest":
                    confirm = messagebox.askyesno(
                        "Experimentelle Qualität", 
                        "Highest Quality (32-bit @ 192kHz Stereo) ist experimentell:\n\n"
                        "• Erfordert sehr schnelle Internetverbindung\n"
                        "• Nur mit kompatiblen Gesprächspartnern nutzbar\n"
                        "• Höhere Bandbreite und CPU-Auslastung\n\n"
                        "Fortfahren?"
                    )
                    if not confirm:
                        return
                
                # Geräte speichern
                if input_selection:
                    self.client.selected_input_device = input_selection
                    self.selected_input_device = input_selection
                
                if output_selection:
                    self.client.selected_output_device = output_selection
                    self.selected_output_device = output_selection
                
                # ✅ QUALITÄT SICHER SETZEN (ohne set_quality aufzurufen!)
                if quality_selection in self.audio_config.QUALITY_PROFILES:
                    # Direkt die Werte setzen ohne set_quality Methode
                    profile = self.audio_config.QUALITY_PROFILES[quality_selection]
                    
                    # Nur die Konfigurationswerte setzen
                    self.audio_config.quality_profile = quality_selection
                    self.audio_config.FORMAT = profile["format"]
                    self.audio_config.RATE = profile["rate"] 
                    self.audio_config.CHANNELS = profile["channels"]
                    self.audio_config.sample_format_name = profile["name"]
                    self.audio_config.actual_format = profile["actual_format"]
                    
                    # Sample Width basierend auf Format
                    if self.audio_config.actual_format == "S32_LE":
                        self.audio_config.sample_width = 4
                    elif self.audio_config.actual_format == "24-bit":
                        self.audio_config.sample_width = 3
                    else:  # 16-bit
                        self.audio_config.sample_width = 2
                    
                    # Chunk-Größe anpassen
                    if self.audio_config.RATE >= 96000:
                        self.audio_config.CHUNK = 2048
                    else:
                        self.audio_config.CHUNK = 1024
                    
                    print(f"[AUDIO] Quality set (safe): {self.audio_config.sample_format_name}")
                
                # Rauschfilterung speichern
                self.audio_config.enable_noise_filter(noise_var.get())
                self.audio_config.set_aggressive_noise_reduction(aggressive_var.get())
                
                try:
                    if popup.winfo_exists():
                        popup.destroy()
                    
                    quality_name = self.audio_config.QUALITY_PROFILES[quality_selection]['name']
                    noise_status = "aktiviert" if noise_var.get() else "deaktiviert"
                    profile_status = "mit Profil" if self.audio_config.noise_profile['profile_captured'] else "ohne Profil"
                    
                    messagebox.showinfo("Audio-Einstellungen", 
                                      f"✅ Eingabegerät: {input_selection or 'Standard'}\n"
                                      f"✅ Ausgabegerät: {output_selection or 'Standard'}\n"
                                      f"✅ Qualität: {quality_name}\n"
                                      f"✅ Rauschfilter: {noise_status} {profile_status}")
                except Exception as e:
                    print(f"[AUDIO POPUP CLOSE ERROR] {str(e)}")
            
            def use_same_device():
                selected = input_var.get()
                input_var.set(selected)
                output_var.set(selected)
            
            def use_default():
                self.selected_input_device = None
                self.selected_output_device = None
                
                # Zurücksetzen in CALL Manager
                if hasattr(self, 'call_manager'):
                    self.call_manager.selected_input_device = None
                    self.call_manager.selected_output_device = None
                
                dialog.destroy()
                messagebox.showinfo("Audio-Geräte", "Standard-Geräte werden verwendet")
            
            ttk.Button(button_frame, text="Gleiches Gerät verwenden", command=use_same_device).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Übernehmen", command=apply_selection).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Standard verwenden", command=use_default).pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            print(f"[AUDIO DIALOG ERROR] {str(e)}")
            messagebox.showerror("Fehler", f"Audio-Dialog konnte nicht geöffnet werden: {str(e)}")


    def open_language_settings(self):
        """Spracheinstellungen (kann später erweitert werden)"""
        messagebox.showinfo("Sprache", "Spracheinstellungen (nicht implementiert)")            
    def create_phonebook_tab(self):
        # Frame für das Telefonbuch mit Scrollbar
        self.phonebook_frame = ctk.CTkFrame(self.phonebook_tab, fg_color='black')
        self.phonebook_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Canvas für Scrollbar
        self.canvas = tk.Canvas(self.phonebook_frame, bg='black', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.phonebook_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ctk.CTkFrame(self.canvas, fg_color='black')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Initialisiere phonebook_entries als Instanzattribut falls nicht vorhanden
        if not hasattr(self, 'phonebook_entries'):
            self.phonebook_entries = []
        
        # Phonebook Einträge erstellen
        self.entry_buttons = []
        for entry in self.phonebook_entries:
            btn = ctk.CTkButton(
                self.scrollable_frame,
                text=f"{entry['id']}: {entry['name']}",
                fg_color="#006400",  # Dunkelgrün
                text_color="white",
                font=("Helvetica", 16),
                height=50,
                corner_radius=10,
                command=lambda e=entry: self.on_entry_click(e)
            )
            btn.pack(fill="x", pady=5, padx=5)
            self.entry_buttons.append(btn)
        
        # Buttons am unteren Rand
        self.update_button = ctk.CTkButton(self.phonebook_tab, text="Update", command=self.on_update_click)
        self.setup_button = ctk.CTkButton(self.phonebook_tab, text="Setup", command=self.create_settings)
        self.hangup_button = ctk.CTkButton(self.phonebook_tab, text="Hang Up", command=self.on_hangup_click)
        self.call_button = ctk.CTkButton(self.phonebook_tab, text="Call", command=self.on_call_click)
        
        # Platzierung der Buttons
        buttons = [self.update_button, self.setup_button, self.hangup_button, self.call_button]
        for i, button in enumerate(buttons):
            button.place(relx=i/4, rely=0.95, relwidth=0.25, relheight=0.05, anchor='sw')

    def on_entry_click(self, entry):
        """Handler für Klicks auf Telefonbucheinträge - Delegiert an CALL Manager"""
        try:
            self.selected_entry = entry
            print(f"[PHONEBOOK] Selected entry: {entry.get('name', 'Unknown')}")
            
            # Informiere CALL Manager über Auswahl
            if hasattr(self, 'call_manager'):
                self.call_manager.on_entry_click(entry)
        except Exception as e:
            print(f"[PHONEBOOK ERROR] Entry click failed: {str(e)}")

    def connection_loop(self, client_socket, server_ip, message_handler=None):
        """VERBESSERTE Connection-Loop mit STABILER VERBINDUNG und BESSERER FEHLERBEHANDLUNG"""
        global connected
        connected = True
        print("[CONNECTION] Starting IMPROVED connection loop")
        
        # ✅ VERBESSERTE TIMING WERTE
        ping_interval = 30  # Ausgeglichenes Ping-Intervall
        last_ping_time = time.time()
        last_activity_time = time.time()
        consecutive_errors = 0
        max_consecutive_errors = 5
        ping_timeout_count = 0
        max_ping_timeouts = 3
        
        # ✅ BLOCKING MODUS für stabilere Verbindung
        client_socket.setblocking(True)
        original_timeout = client_socket.gettimeout()
        client_socket.settimeout(5.0)  # Moderate Timeout für Stabilität
        
        print(f"[CONNECTION] Socket configured - blocking: {client_socket.getblocking()}, timeout: {client_socket.gettimeout()}")
        
        try:
            while connected:
                current_time = time.time()
                
                # ✅ INTELLIGENTES PING-MANAGEMENT
                time_since_last_ping = current_time - last_ping_time
                time_since_last_activity = current_time - last_activity_time
                
                # Ping nur senden wenn nötig und Verbindung stabil
                if (time_since_last_ping >= ping_interval and 
                    consecutive_errors < 2 and 
                    ping_timeout_count < max_ping_timeouts):
                    
                    try:
                        ping_data = {
                            "MESSAGE_TYPE": "PING",
                            "TIMESTAMP": int(current_time),
                            "CLIENT_NAME": self._client_name,
                            "CLIENT_ID": getattr(self, '_find_my_client_id', lambda: 'unknown')()
                        }
                        
                        ping_msg = self.build_sip_message("MESSAGE", server_ip, ping_data)
                        
                        print(f"[PING] Sending ping (errors: {consecutive_errors}, timeouts: {ping_timeout_count})")
                        
                        if send_frame(client_socket, ping_msg.encode('utf-8')):
                            last_ping_time = current_time
                            consecutive_errors = 0
                            print("[PING] ✓ Ping sent successfully")
                        else:
                            consecutive_errors += 1
                            print(f"[PING FAILED] #{consecutive_errors} - Send failed")
                            
                    except Exception as e:
                        print(f"[PING ERROR] {e}")
                        consecutive_errors += 1
                
                # ✅ VERBESSERTER EMPFANG MIT FEHLERBEHANDLUNG
                try:
                    # Verwende kürzeres Timeout für Empfang
                    client_socket.settimeout(10.0)
                    response = recv_frame(client_socket, timeout=10)
                    
                    if response is not None:
                        # Erfolgreicher Empfang
                        consecutive_errors = 0
                        ping_timeout_count = 0
                        last_activity_time = current_time
                        
                        print(f"[CONNECTION] ✓ Received {len(response)} bytes from server")
                        
                        # Verarbeite Nachricht über Queue für Stabilität
                        self.handle_server_message(response)
                        
                    else:
                        # Timeout beim Empfang
                        print("[CONNECTION] Receive timeout (normal)")
                        if time_since_last_activity > 60:  # 1 Minute ohne Aktivität
                            ping_timeout_count += 1
                            print(f"[CONNECTION] Activity timeout #{ping_timeout_count}")
                            
                except socket.timeout:
                    # Timeout ist normal, keine Aktion benötigt
                    print("[CONNECTION] Socket timeout (normal)")
                    if time_since_last_activity > 60:
                        ping_timeout_count += 1
                        print(f"[CONNECTION] Activity timeout #{ping_timeout_count}")
                        
                except ConnectionResetError as e:
                    print(f"[CONNECTION] Connection reset by server: {e}")
                    consecutive_errors += 1
                    break
                    
                except BrokenPipeError as e:
                    print(f"[CONNECTION] Broken pipe: {e}")
                    consecutive_errors += 1
                    break
                    
                except OSError as e:
                    print(f"[CONNECTION] OS error: {e}")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                        
                except Exception as e:
                    print(f"[CONNECTION RECV ERROR] {e}")
                    consecutive_errors += 1
                
                # ✅ VERBINDUNGS-ÜBERWACHUNG
                if consecutive_errors >= max_consecutive_errors:
                    print(f"[CONNECTION] ✗ Too many consecutive errors ({consecutive_errors}), disconnecting...")
                    break
                    
                if ping_timeout_count >= max_ping_timeouts:
                    print(f"[CONNECTION] ✗ Too many ping timeouts ({ping_timeout_count}), disconnecting...")
                    break
                    
                # ✅ VERBINDUNGS-TIMEOUT
                if time_since_last_activity > 120:  # 2 Minuten ohne Aktivität
                    print("[CONNECTION] ✗ No activity for 2 minutes, disconnecting...")
                    break
                
                # ✅ AUSGEWOGENE PAUSE FÜR STABILITÄT
                time.sleep(0.5)  # Moderate Pause für Stabilität
                
                # ✅ STATUS-AUSGABE alle 30 Sekunden
                if int(current_time) % 30 == 0:
                    print(f"[CONNECTION STATUS] Active for {int(current_time - last_activity_time)}s, errors: {consecutive_errors}")
                        
        except Exception as e:
            print(f"[CONNECTION LOOP ERROR] {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            # ✅ SORGFÄLTIGES CLEANUP
            print("[CONNECTION] Connection loop ended - cleaning up...")
            connected = False
            
            try:
                # Setze Timeout zurück
                client_socket.settimeout(original_timeout)
            except:
                pass
                
            try:
                # Sende ggf. eine Disconnect-Nachricht
                if hasattr(self, '_send_message'):
                    disconnect_msg = self.build_sip_message("MESSAGE", server_ip, {
                        "MESSAGE_TYPE": "DISCONNECT",
                        "TIMESTAMP": int(time.time()),
                        "CLIENT_NAME": self._client_name
                    })
                    self._send_message(disconnect_msg)
            except:
                pass
                
            try:
                # Schließe Socket
                if client_socket.fileno() != -1:
                    client_socket.close()
                    print("[CONNECTION] Socket closed")
            except:
                pass
                
            # UI-Update
            try:
                if hasattr(self, 'update_connection_status'):
                    self.update_connection_status("disconnected")
            except:
                pass
                
            print("[CONNECTION] Cleanup completed")

    def _test_connection_simple(self, client_socket, server_ip, client_name):
        """Einfacher Verbindungstest ohne komplexe Logik"""
        try:
            print("[CONNECTION TEST] Simple connection test...")
            
            # Setze kürzeres Timeout für Test
            original_timeout = client_socket.gettimeout()
            client_socket.settimeout(5.0)
            
            # Sende einfachen Ping
            test_data = {
                "MESSAGE_TYPE": "PING",
                "TIMESTAMP": int(time.time()),
                "CLIENT_NAME": client_name,
                "TEST": "connection_test"
            }
            
            test_msg = self.build_sip_message("MESSAGE", server_ip, test_data)
            
            if send_frame(client_socket, test_msg.encode('utf-8')):
                # Versuche Antwort zu empfangen
                try:
                    response = recv_frame(client_socket, timeout=5)
                    if response:
                        print("[CONNECTION TEST] Success - received response")
                        client_socket.settimeout(original_timeout)
                        return True
                except:
                    pass  # Timeout ist okay für Test
            
            print("[CONNECTION TEST] Failed - no response")
            client_socket.settimeout(original_timeout)
            return False
            
        except Exception as e:
            print(f"[CONNECTION TEST ERROR] {str(e)}")
            try:
                client_socket.settimeout(original_timeout)
            except:
                pass
            return False
    def start_connection(self, server_ip, server_port, client_name, client_socket, message_handler=None):
        """STABILISIERTE REGISTRATION MIT VERBESSERTER FEHLERBEHANDLUNG UND KEY-MANAGEMENT"""
        try:
            print(f"[CONNECTION] Starting stabilized connection to {server_ip}:{server_port}")
            
            # ✅ VERIFY-GENERATOR INSTANZ ERSTELLEN (NEUE KLASSE)
            print("SEED+++")
            print(client_name)
            self.client_generator = init_verify_generator(client_name, client_name)  # ✅ GENERATOR INSTANZ SPEICHERN
            print(f"🔐 [CLIENT] Verify-Generator für Client-Name '{client_name}' initialisiert")
            
            # 1. Socket für Stabilität konfigurieren
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
            
            client_socket.settimeout(25.0)

            # 2. Load client public key MIT VERBESSERTER FEHLERBEHANDLUNG
            print("[CONNECTION] Loading client public key...")
            client_pubkey = load_publickey()
            if not client_pubkey:
                print("[CONNECTION ERROR] Failed to load client public key - generating new one...")
                client_pubkey = generate_new_keypair()
                if not client_pubkey:
                    raise ValueError("Cannot generate or load client public key")
            
            # ✅ VERBESSERTE KEY-VALIDIERUNG
            if not client_pubkey or not isinstance(client_pubkey, str):
                print("[CONNECTION ERROR] Invalid client public key type")
                raise ValueError("Invalid client public key type")
                
            # Bereinige den Key für zuverlässige Übertragung
            client_pubkey = client_pubkey.strip()
            client_pubkey = client_pubkey.replace('\r\n', '\n').replace('\r', '\n')
            
            # Stelle sicher, dass PEM-Format korrekt ist
            if not client_pubkey.startswith('-----BEGIN PUBLIC KEY-----'):
                # Versuche zu reparieren
                if 'BEGIN PUBLIC KEY' in client_pubkey:
                    # Extrahiere den Key-Inhalt
                    lines = client_pubkey.split('\n')
                    key_content = ''.join([line.strip() for line in lines if line.strip() and not line.startswith('---')])
                    client_pubkey = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
                else:
                    # Base64-Key, füge PEM-Header hinzu
                    key_content = client_pubkey.replace(' ', '').replace('\n', '')
                    client_pubkey = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
            
            print(f"[CONNECTION] Client public key prepared (length: {len(client_pubkey)})")
            print(f"[CONNECTION DEBUG] Key preview: {client_pubkey[:100]}...")

            # 3. VOLLSTÄNDIGE REGISTRATION NACHRICHT
            register_data = {
                "MESSAGE_TYPE": "REGISTER",
                "CLIENT_NAME": client_name,
                "PUBLIC_KEY": client_pubkey,  # ✅ IMMER MIT PUBLIC KEY
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0"
            }
            
            print(f"[CONNECTION DEBUG] Registration data keys: {list(register_data.keys())}")
            print(f"[CONNECTION DEBUG] Public key in data: {'PUBLIC_KEY' in register_data}")
            
            # ✅ build_sip_message WIRD AUTOMATISCH DEN VERIFY-CODE GENERIEREN (MIT GENERATOR INSTANZ)
            register_msg = self.build_sip_message(
                "REGISTER", 
                f"{server_ip}:{server_port}", 
                register_data, 
                from_server=False,
                client_name=client_name
            )
            
            print(f"[CONNECTION] Sending registration ({len(register_msg)} chars)...")
            if not send_frame(client_socket, register_msg.encode('utf-8')):
                raise ConnectionError("Failed to send registration frame")
            print("[CONNECTION] Registration sent successfully")

            # 4. Erste Response empfangen und parsen
            print("[CONNECTION] Waiting for server response...")
            response = recv_frame(client_socket, timeout=25)
            if not response:
                raise ConnectionError("Empty response from server - timeout or connection issue")

            if isinstance(response, bytes):
                response = response.decode('utf-8')

            print(f"[CONNECTION] Server response received ({len(response)} bytes)")
            print(f"[CONNECTION DEBUG] Response preview: {response[:200]}...")

            # 5. SIP-PARSING MIT VERBESSERTER FEHLERBEHANDLUNG
            sip_data = self.parse_sip_message(response)
            if not sip_data:
                print("[CONNECTION ERROR] Failed to parse SIP response")
                print(f"[CONNECTION DEBUG] Raw response: {response}")
                raise ValueError("Invalid SIP response format - cannot parse")
                
            print(f"[CONNECTION] SIP message type: {sip_data.get('type')}")
            print(f"[CONNECTION DEBUG] SIP headers: {list(sip_data.get('headers', {}).keys())}")

            # 6. BODY-EXTRAKTION MIT VALIDIERUNG
            body = sip_data.get('body', '')
            if not body:
                print("[CONNECTION ERROR] No body in SIP response")
                print(f"[CONNECTION DEBUG] Full SIP data: {sip_data}")
                raise ValueError("No body in SIP response")
                
            print(f"[CONNECTION] Body length: {len(body)}")
            print(f"[CONNECTION DEBUG] Body preview: {body[:200]}...")

            # 7. JSON PARSEN MIT DETAILLIERTEM FEHLERREPORTING
            try:
                response_data = json.loads(body)
                print(f"[CONNECTION] JSON parsed successfully: {list(response_data.keys())}")
            except json.JSONDecodeError as e:
                print(f"[CONNECTION ERROR] JSON decode error: {e}")
                print(f"[CONNECTION DEBUG] Problematic body: {body}")
                raise ValueError("Invalid JSON in response body")

            # 8. Server Public Key extrahieren MIT FALLBACKS
            server_public_key = response_data.get('SERVER_PUBLIC_KEY')
            if not server_public_key:
                # Alternative Schlüsselnamen prüfen
                possible_keys = ['public_key', 'server_public_key', 'server_key', 'SERVER_PUBLIC_KEY']
                for key in possible_keys:
                    if key in response_data:
                        server_public_key = response_data[key]
                        print(f"[CONNECTION] Found key in field: {key}")
                        break
            
            if not server_public_key:
                print(f"[CONNECTION ERROR] No server public key found in response")
                print(f"[CONNECTION DEBUG] Available fields: {list(response_data.keys())}")
                print(f"[CONNECTION DEBUG] Full response data: {response_data}")
                raise ValueError("No server public key found in response")

            # 9. Key formatieren und validieren
            server_public_key = server_public_key.replace('\\\\n', '\n').replace('\\n', '\n')
            
            if not is_valid_public_key(server_public_key):
                print("[CONNECTION ERROR] Server public key validation failed")
                print(f"[CONNECTION DEBUG] Key preview: {server_public_key[:200]}")
                raise ValueError("Invalid server public key format")

            # Save server public key
            with open("server_public_key.pem", "w") as f:
                f.write(server_public_key)
            print("[CONNECTION] Server public key saved")

            # 10. Client ID vom Server empfangen und speichern
            client_id = response_data.get('CLIENT_ID')
            if client_id:
                self.client_id = client_id
                print(f"[CONNECTION] Server hat Client-ID zugewiesen: {client_id}")
                save_client_id(client_id)
            else:
                print("⚠️ [CONNECTION] Keine CLIENT_ID in Server-Antwort")

            # 11. Zweite Response (Merkle Data) empfangen
            print("[CONNECTION] Waiting for Merkle data...")
            merkle_response = recv_frame(client_socket, timeout=25)
            if not merkle_response:
                raise ConnectionError("No Merkle data received - timeout")

            if isinstance(merkle_response, bytes):
                merkle_response = merkle_response.decode('utf-8')

            print(f"[CONNECTION] Merkle response received ({len(merkle_response)} bytes)")

            # Merkle Data parsen
            merkle_sip_data = self.parse_sip_message(merkle_response)
            if not merkle_sip_data:
                raise ValueError("Invalid Merkle SIP response")

            merkle_body = merkle_sip_data.get('body', '')
            if not merkle_body:
                raise ValueError("No body in Merkle response")
                
            try:
                merkle_data = json.loads(merkle_body)
                print(f"[CONNECTION] Merkle JSON parsed successfully")
            except json.JSONDecodeError as e:
                print(f"[CONNECTION ERROR] Merkle JSON error: {e}")
                print(f"[CONNECTION DEBUG] Merkle body: {merkle_body}")
                raise ValueError("Invalid JSON in Merkle response")

            # Merkle Daten extrahieren
            all_keys = merkle_data.get('ALL_KEYS', [])
            merkle_root = merkle_data.get('MERKLE_ROOT', '')

            if not merkle_root:
                print("[CONNECTION ERROR] No Merkle root in response")
                raise ValueError("No Merkle root in response")

            # Merkle Verification
            print("[CONNECTION] Starting Merkle verification...")
            print(f"[CONNECTION DEBUG] All keys count: {len(all_keys)}")
            print(f"[CONNECTION DEBUG] Merkle root: {merkle_root[:50]}...")
            
            if not verify_merkle_integrity(all_keys, merkle_root):
                print("[CONNECTION ERROR] Merkle verification failed - potential security issue")
                raise ValueError("Merkle verification failed - potential security issue")

            print("[CONNECTION] Merkle verification successful")

            # 12. Socket für Hauptloop neu konfigurieren
            client_socket.settimeout(10.0)  # Angemessenes Timeout für Hauptloop
            
            # 13. Hauptloop starten
            print("[CONNECTION] Starting stabilized communication loop...")
            self.connection_loop(client_socket, server_ip, message_handler)
            return True

        except socket.timeout:
            error_msg = "Connection timeout during registration"
            print(f"[CONNECTION ERROR] {error_msg}")
            return False
        except ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            print(f"[CONNECTION ERROR] {error_msg}")
            return False
        except Exception as e:
            error_msg = f"Connection failed: {str(e)}"
            print(f"[CONNECTION ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            return False

    def _send_message(self, message):
        """Sendet Nachricht an Server - Thread-sichere Version"""
        try:
            if hasattr(self, 'client_socket') and self.client_socket:
                # Füge Nachricht zur Queue hinzu für geordnete Verarbeitung
                if not hasattr(self, '_message_queue'):
                    self._message_queue = []
                    
                self._message_queue.append({
                    'type': 'send_message',
                    'message': message,
                    'timestamp': time.time()
                })
                
                # Starte Queue-Verarbeitung falls nicht bereits aktiv
                if not hasattr(self, '_processing_queue') or not self._processing_queue:
                    threading.Thread(target=self._process_queue_simple, daemon=True).start()
                    
                return True
            else:
                print("[SEND ERROR] Not connected to server")
                return False
                
        except Exception as e:
            print(f"[SEND ERROR] Failed to queue message: {str(e)}")
            return False
    def build_sip_message(self, method, recipient, custom_data=None, from_server=False, client_name=None, server_host=None):
            """VOLLSTÄNDIG EINHEITLICHE SIP-NACHRICHTENERSTELLUNG MIT VERIFY-CODE"""
            if custom_data is None:
                custom_data = {}
            
            if not isinstance(custom_data, dict):
                raise ValueError("custom_data must be a dictionary")
            
            # Basis-Datenstruktur
            message_data = {
                "MESSAGE_TYPE": custom_data.get("MESSAGE_TYPE", "UNKNOWN"),
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0"
            }
            
            # Benutzerdaten hinzufügen
            for key, value in custom_data.items():
                if key != "MESSAGE_TYPE":
                    message_data[key] = value
            
            # JSON-Body erstellen
            try:
                body = json.dumps(message_data, separators=(',', ':'))
            except Exception as e:
                raise ValueError(f"JSON encoding failed: {e}")
            
            # Absenderadresse bestimmen
            if from_server:
                from_header = f"<sip:server@{server_host}>" if server_host else "<sip:server>"
            else:
                # Client-Absender
                if not client_name or client_name == "unknown":
                    client_name = getattr(self, '_client_name', 'unknown')
                
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    client_ip = s.getsockname()[0]
                    s.close()
                except:
                    client_ip = "127.0.0.1"
                
                from_header = f"<sip:{client_name}@{client_ip}>"
            
            # ✅ VERIFY-CODE MIT KORREKTEM GENERATOR GENERIEREN
            verify_header = ""
            if not from_server:
                try:
                    # ✅ VERWENDE DEN KORREKTEN CLIENT-GENERATOR STATT "default"
                    if hasattr(self, 'client_generator'):
                        verify_code = self.client_generator.generate_verify_code()
                        print(f"🔐 [CLIENT] Verify-Code mit Generator '{self.client_generator.client_id}': {verify_code}")
                    else:
                        # ✅ KORREKTUR: DIREKTEN GENERATOR VERWENDEN STATT NICHT-EXISTIERENDER FUNKTION
                        if not client_name or client_name == "unknown":
                            client_name = getattr(self, '_client_name', 'unknown')
                        generator = init_verify_generator(client_name, client_name)
                        verify_code = generator.generate_verify_code()
                        print(f"🔐 [CLIENT] Verify-Code mit Generator '{client_name}': {verify_code}")
                    
                    verify_header = f"Verify-Code: {verify_code}\r\n"
                except Exception as e:
                    print(f"⚠️ [VERIFY] Failed to generate verify code: {e}")
                    # Fallback: Ohne Verify-Code senden (für erste Nachricht)
                    verify_header = ""
            
            # SIP-Nachricht erstellen
            sip_message = (
                f"{method} sip:{recipient} SIP/2.0\r\n"
                f"From: {from_header}\r\n"
                f"To: <sip:{recipient}>\r\n"
                f"{verify_header}"  # ✅ Verify-Code Header
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}"
            )
            
            return sip_message
    def parse_sip_message(self,message):
        """VOLLSTÄNDIG EINHEITLICHER SIP-PARSER - FÜR CLIENT UND SERVER IDENTISCH"""
        # 1. Input-Normalisierung
        if isinstance(message, dict):
            return message  # Bereits geparst
            
        if isinstance(message, bytes):
            try:
                message = message.decode('utf-8')
            except UnicodeDecodeError:
                print("[PARSE ERROR] Invalid UTF-8 encoding")
                return None
        
        message = message.strip()
        if not message:
            return None

        # 2. Header und Body trennen
        parts = message.split('\r\n\r\n', 1)
        if len(parts) < 2:
            print("[PARSE ERROR] No body separator found")
            return None
            
        headers_part, body_part = parts
        headers_lines = headers_part.split('\r\n')

        # 3. Ergebnis-Struktur
        result = {
            'headers': {},
            'body': body_part.strip(),
            'custom_data': {}
        }

        # 4. Erste Zeile (Request/Response Line)
        first_line = headers_lines[0]
        if first_line.startswith('SIP/2.0'):
            # Response
            parts = first_line.split(' ', 2)
            result['status_code'] = parts[1] if len(parts) > 1 else ''
            result['status_message'] = parts[2] if len(parts) > 2 else ''
            result['type'] = 'response'
        else:
            # Request
            parts = first_line.split(' ', 2)
            result['method'] = parts[0] if len(parts) > 0 else ''
            result['uri'] = parts[1] if len(parts) > 1 else ''
            result['protocol'] = parts[2] if len(parts) > 2 else ''
            result['type'] = 'request'

        # 5. Header parsen
        for line in headers_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                result['headers'][key.strip().upper()] = value.strip()
                
                # Content-Length speziell behandeln
                if key.strip().upper() == 'CONTENT-LENGTH':
                    try:
                        result['content_length'] = int(value.strip())
                    except ValueError:
                        pass

        # 6. Body als JSON parsen (falls vorhanden)
        body_content = body_part.strip()
        if body_content:
            try:
                result['custom_data'] = json.loads(body_content)
            except json.JSONDecodeError:
                # Body ist kein JSON, einfach als Text belassen
                result['custom_data'] = {'raw_body': body_content}

        return result


    def _process_received_frame(self, frame_data):
        """VOLLSTÄNDIG EINHEITLICHE FRAME-VERARBEITUNG - NUR JSON"""
        try:
            # 1. Decoding
            if isinstance(frame_data, bytes):
                try:
                    message = frame_data.decode('utf-8')
                except UnicodeDecodeError:
                    # Binärdaten für Audio/verschlüsselte Daten
                    if hasattr(self, 'call_manager') and self.call_manager.active_call:
                        print("[AUDIO] Received binary data during active call")
                    return
            else:
                message = frame_data

            # 2. ✅ AUSSCHLIESSLICH SIP-PARSER VERWENDEN
            msg = self.parse_sip_message(message)
            if not msg:
                print("[PROCESS ERROR] Invalid SIP message format")
                return

            # 3. ✅ AUSSCHLIESSLICH JSON custom_data VERWENDEN
            custom_data = msg.get('custom_data', {})
            message_type = custom_data.get('MESSAGE_TYPE', 'UNKNOWN')

            print(f"[PROCESS] Message type: {message_type}")

            # 4. NACHRICHTEN-ROUTING
            if message_type in ['INCOMING_CALL', 'SESSION_KEY', 'CALL_RESPONSE', 
                              'CALL_TIMEOUT', 'PUBLIC_KEY_RESPONSE', 'CALL_END']:
                if hasattr(self, 'call_manager'):
                    print(f"[CALL] Delegating {message_type} to call manager")
                    self.call_manager.handle_message(msg)
                return

            # 5. ANDERE NACHRICHTENTYPEN
            if message_type == 'IDENTITY_CHALLENGE':
                self._handle_identity_challenge(msg)
            elif message_type == 'IDENTITY_VERIFIED':
                self._handle_identity_verified(msg)
            elif message_type == 'PHONEBOOK_UPDATE':
                self._process_phonebook_update(msg)
            elif message_type == 'PING':
                self._handle_ping_message()
            elif message_type == 'PONG':
                print("[PONG] Received from server")
            else:
                print(f"[PROCESS WARNING] Unknown message type: {message_type}")
                
        except Exception as e:
            print(f"[FRAME PROCESS ERROR] {str(e)}")

    def _process_call_messages(self):
        """Verarbeitet Call-bezogene Nachrichten asynchron"""
        try:
            # Diese Methode kann für zukünftige Erweiterungen genutzt werden
            pass
        except Exception as e:
            print(f"[CALL PROCESS ERROR] {str(e)}")

    def end_current_call(self):
        """Beendet den aktuellen Anruf - Delegiert an CALL Manager"""
        try:
            if hasattr(self, 'call_manager'):
                self.call_manager.cleanup_call_resources()
            else:
                # Fallback Cleanup
                self.active_call = False
                if hasattr(self, 'audio_threads'):
                    for thread in self.audio_threads:
                        try:
                            if thread.is_alive():
                                thread.join(timeout=1.0)
                        except:
                            pass
                    self.audio_threads = []
        except Exception as e:
            print(f"[END CALL ERROR] {str(e)}")

    def cleanup_call_resources(self):
        """Bereinigt Call-Ressourcen - Delegiert an CALL Manager"""
        try:
            if hasattr(self, 'call_manager'):
                self.call_manager.cleanup_call_resources()
            self.update_call_ui(active=False)
        except Exception as e:
            print(f"[CLEANUP ERROR] {str(e)}")

    def show_error(self, message):
        """Zeigt Fehlermeldungen an - Thread-sichere Version"""
        try:
            if hasattr(self, 'after'):
                self.after(0, lambda: messagebox.showerror("Error", message))
            else:
                messagebox.showerror("Error", message)
        except Exception as e:
            print(f"[SHOW ERROR ERROR] {str(e)}")

    # Existierende Methoden beibehalten aber ggf. anpassen
    # IN CLIENT.PY - Korrigiere die Update-Nachricht

    def create_settings(self):
        # Unverändert beibehalten
        self.connection_window = ctk.CTkToplevel(self.phonebook_tab)
        self.connection_window.title("Connecting...")
        self.connection_window.geometry("400x400")  # Größer gemacht für neue Buttons
        self.connection_window.configure(fg_color='darkgrey')

        # Schriftarten definieren
        label_font = ("Helvetica", 14)
        button_font = ("Helvetica", 14, "bold")

        self.status_label = ctk.CTkLabel(self.connection_window, text="Connecting...", font=label_font)
        self.status_label.pack(pady=20)

        # ✅ NEU: Server-Auswahl Button
        self.server_selection_button = ctk.CTkButton(
            self.connection_window, 
            text="🔍 Server Auswahl", 
            command=self.show_server_selection_dialog,
            fg_color="#2b2b2b",
            hover_color="#3b3b3b"
        )
        self.server_selection_button.pack(pady=10)

        # Server-IP Frame
        self.server_frame = ctk.CTkFrame(self.connection_window, fg_color="red")
        self.server_frame.pack(pady=5)

        self.server_ip_label = ctk.CTkLabel(self.server_frame, text="Server-IP:")
        self.server_ip_label.pack(side='left', fill="x", expand=True, padx=10)

        self.server_ip_input = ctk.CTkEntry(self.server_frame)
        self.server_ip_input.insert(0, "sichereleitung.duckdns.org")
        self.server_ip_input.pack(side='left', fill="x", expand=True, padx=10)

        # Port Frame
        self.port_frame = ctk.CTkFrame(self.connection_window, fg_color="red")
        self.port_frame.pack(pady=5)

        self.server_port_label = ctk.CTkLabel(self.port_frame, text="Port:")
        self.server_port_label.pack(side='left', fill="x", expand=True, padx=10)

        self.server_port_input = ctk.CTkEntry(self.port_frame)
        self.server_port_input.insert(0, "5061")
        self.server_port_input.pack(side='left', fill="x", expand=True, padx=10)

        # Verbinden Button
        self.button_frame = ctk.CTkFrame(self.connection_window, fg_color="grey")
        self.button_frame.pack(pady=20)

        self.connect_button = ctk.CTkButton(self.button_frame, text="Verbinden", command=self.on_connect_click)
        self.connect_button.pack(side='left', fill="x", expand=True, padx=10)

    def on_connect_click(self):
        # Sicherstellen, dass update_relay_status verfügbar ist
        if not hasattr(self, 'update_relay_status'):
            # Fallback: Definiere eine einfache Version
            def update_relay_status(message, color="white"):
                print(f"[RELAY STATUS] {message}")
                try:
                    if hasattr(self, 'relay_status_label') and self.relay_status_label.winfo_exists():
                        self.relay_status_label.configure(text=message, text_color=color)
                except:
                    pass
            self.update_relay_status = update_relay_status

        if hasattr(self, 'client_socket') and self.client_socket:
            messagebox.showerror("Fehler", "Bereits verbunden")
            return

        # ✅ NEU: Server-Discovery vor manueller Eingabe
        discovered_server = None
        try:
            if hasattr(self, 'relay_manager'):
                self.update_relay_status("🔍 Suche beste Server...", "yellow")
                discovered_server = self.relay_manager.discover_servers()
                
                if discovered_server:
                    server_ip = discovered_server['ip']
                    server_port = discovered_server['port']
                    print(f"[RELAY] Gefundener Server: {server_ip}:{server_port}")
                    
                    # Auto-fill die Eingabefelder
                    if hasattr(self, 'server_ip_input') and self.server_ip_input.winfo_exists():
                        self.server_ip_input.delete(0, tk.END)
                        self.server_ip_input.insert(0, server_ip)
                    if hasattr(self, 'server_port_input') and self.server_port_input.winfo_exists():
                        self.server_port_input.delete(0, tk.END)  
                        self.server_port_input.insert(0, str(server_port))
                        
                    self.update_relay_status(f"✅ Server gefunden: {server_ip}:{server_port}", "green")
                else:
                    self.update_relay_status("⚠️ Keine Server gefunden - verwende manuelle Eingabe", "orange")
        except Exception as e:
            print(f"[RELAY DISCOVERY ERROR] {e}")
            self.update_relay_status("⚠️ Server-Suche fehlgeschlagen", "orange")

        # ✅ REST DER METHODE MIT getaddrinfo FIX
        server_ip = self.server_ip_input.get()
        server_port = self.server_port_input.get()

        print(f"\n{'='*60}")
        print("[DEBUG] === START CONNECTION ATTEMPT ===")
        print(f"{'='*60}")
        
        try:
            # Validate inputs
            print(f"[DEBUG 1] Input validation - Server: '{server_ip}', Port: '{server_port}'")
            if not server_ip or not server_port:
                raise ValueError("Server-IP und Port müssen angegeben werden")
            
            port = int(server_port)
            if not (0 < port <= 65535):
                raise ValueError("Ungültiger Port")
            print(f"[DEBUG 2] Port validation passed: {port}")

            # ✅ FIX: Ersetze gethostbyname durch getaddrinfo
            print(f"[DEBUG 3] Starting DNS resolution for: {server_ip}")
            try:
                # Get all address information - DIES IST DER FIX
                addr_info = socket.getaddrinfo(server_ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                print(f"[DEBUG 4] getaddrinfo results: {len(addr_info)} entries")
                
                for i, (family, socktype, proto, canonname, sockaddr) in enumerate(addr_info):
                    print(f"[DEBUG 4.{i}] Family: {family}, Type: {socktype}, Proto: {proto}")
                    print(f"[DEBUG 4.{i}] Canonname: {canonname}, Addr: {sockaddr}")
                
                # ✅ NEU: Verwende getaddrinfo statt gethostbyname
                # Extrahiere die erste IPv4-Adresse aus den getaddrinfo-Ergebnissen
                resolved_ip = None
                for family, socktype, proto, canonname, sockaddr in addr_info:
                    if family == socket.AF_INET:  # IPv4
                        resolved_ip = sockaddr[0]  # IP-Adresse aus (ip, port) Tupel
                        break
                
                if resolved_ip:
                    print(f"[DEBUG 5] Resolved IP via getaddrinfo: {resolved_ip}")
                else:
                    print("[DEBUG 5] No IPv4 address found")
                    # Fallback: Verwende die ursprüngliche Eingabe
                    resolved_ip = server_ip
                    
            except Exception as dns_error:
                print(f"[DEBUG 6] DNS resolution failed: {dns_error}")
                print(f"[DEBUG 6] DNS error type: {type(dns_error).__name__}")
                import traceback
                traceback.print_exc()
                # Fallback auf ursprüngliche IP
                resolved_ip = server_ip

            # Socket creation with extensive debugging
            print("[DEBUG 7] Creating socket...")
            try:
                # ✅ OPTIONAL: Verwende getaddrinfo auch für die Socket-Erstellung
                # Dies ist besser für IPv6/IPv4 Dual-Stack
                if addr_info:
                    # Verwende die erste Adresse aus getaddrinfo
                    family, socktype, proto, canonname, sockaddr = addr_info[0]
                    self.client_socket = socket.socket(family, socktype, proto)
                    print(f"[DEBUG 8] Socket created successfully using getaddrinfo: family={family}")
                else:
                    # Fallback auf traditionelle Methode
                    self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print("[DEBUG 8] Socket created successfully using AF_INET fallback")
                
                # Set various socket options for debugging
                self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print("[DEBUG 9] Socket options set")
                
                # Get socket details before connection
                sock_fd = self.client_socket.fileno()
                sock_family = self.client_socket.family
                sock_type = self.client_socket.type
                sock_proto = self.client_socket.proto
                print(f"[DEBUG 10] Socket details - FD: {sock_fd}, Family: {sock_family}, Type: {sock_type}, Proto: {sock_proto}")
                
            except Exception as sock_error:
                print(f"[DEBUG 11] Socket creation failed: {sock_error}")
                print(f"[DEBUG 11] Socket error type: {type(sock_error).__name__}")
                raise

            # Connection attempt with detailed timing
            print(f"[DEBUG 12] Setting socket timeout to 15 seconds")
            self.client_socket.settimeout(15)
            
            print(f"[DEBUG 13] Attempting connection to {server_ip}:{port}")
            connection_start_time = time.time()
            
            try:
                # ✅ VERBESSERT: Verwende getaddrinfo für bessere Adressauflösung
                if addr_info:
                    # Verbinde mit der ersten gefundenen Adresse
                    family, socktype, proto, canonname, sockaddr = addr_info[0]
                    print(f"[DEBUG 13.5] Connecting using getaddrinfo result: {sockaddr}")
                    self.client_socket.connect(sockaddr)
                else:
                    # Fallback
                    self.client_socket.connect((server_ip, port))
                    
                connection_time = time.time() - connection_start_time
                print(f"[DEBUG 14] Connection successful! Time: {connection_time:.3f} seconds")
                
                # Get connection details
                try:
                    local_addr = self.client_socket.getsockname()
                    peer_addr = self.client_socket.getpeername()
                    print(f"[DEBUG 15] Local address: {local_addr}")
                    print(f"[DEBUG 16] Peer address: {peer_addr}")
                except Exception as addr_error:
                    print(f"[DEBUG 17] Address info error: {addr_error}")

                # Test socket properties
                try:
                    sock_timeout = self.client_socket.gettimeout()
                    sock_blocking = self.client_socket.getblocking()
                    print(f"[DEBUG 18] Socket timeout: {sock_timeout}, Blocking: {sock_blocking}")
                except Exception as prop_error:
                    print(f"[DEBUG 19] Socket properties error: {prop_error}")

                # Store connection info
                self.server_ip = server_ip
                self.server_port = port
                
                # Start connection thread
                print("[DEBUG 20] Starting connection thread...")
                threading.Thread(
                    target=self.start_connection_wrapper,
                    daemon=True,
                    name=f"ConnectionThread-{server_ip}:{port}"
                ).start()
                
                print("[DEBUG 21] Closing connection window")
                if hasattr(self, 'connection_window') and self.connection_window:
                    self.connection_window.destroy()
                print("[DEBUG 22] Connection process completed successfully!")

            except socket.timeout:
                connection_time = time.time() - connection_start_time
                print(f"[DEBUG 23] Connection timeout after {connection_time:.3f} seconds")
                print("[DEBUG 24] Socket timeout exception details:")
                import traceback
                traceback.print_exc()
                
                messagebox.showerror("Fehler", "Verbindungstimeout - Server nicht erreichbar")
                self.cleanup_connection()
                
            except ConnectionRefusedError as cre:
                connection_time = time.time() - connection_start_time
                print(f"[DEBUG 25] Connection refused after {connection_time:.3f} seconds")
                print(f"[DEBUG 26] ConnectionRefusedError: {cre}")
                print(f"[DEBUG 27] Errno: {cre.errno}")
                print(f"[DEBUG 28] Strerror: {cre.strerror}")
                
                # Additional diagnostic information
                try:
                    # Try connecting to a known working service to verify network
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(5)
                    test_socket.connect(("8.8.8.8", 53))  # Google DNS
                    test_socket.close()
                    print("[DEBUG 29] Network connectivity test passed")
                except Exception as test_error:
                    print(f"[DEBUG 30] Network test failed: {test_error}")
                
                messagebox.showerror("Fehler", "Verbindung abgelehnt - Server nicht erreichbar oder Port falsch")
                self.cleanup_connection()
                
            except OSError as ose:
                connection_time = time.time() - connection_start_time
                print(f"[DEBUG 31] OSError after {connection_time:.3f} seconds")
                print(f"[DEBUG 32] OSError: {ose}")
                print(f"[DEBUG 33] Errno: {ose.errno}")
                print(f"[DEBUG 34] Strerror: {ose.strerror}")
                print("[DEBUG 35] Full traceback:")
                import traceback
                traceback.print_exc()
                
                # OS-specific debugging
                import platform
                print(f"[DEBUG 36] Platform: {platform.system()} {platform.release()}")
                print(f"[DEBUG 37] Python version: {sys.version}")
                
                messagebox.showerror("Fehler", f"Netzwerkfehler: {str(ose)}")
                self.cleanup_connection()
                
            except Exception as e:
                connection_time = time.time() - connection_start_time
                print(f"[DEBUG 38] Unexpected error after {connection_time:.3f} seconds")
                print(f"[DEBUG 39] Error type: {type(e).__name__}")
                print(f"[DEBUG 40] Error message: {e}")
                print("[DEBUG 41] Full traceback:")
                import traceback
                traceback.print_exc()
                
                messagebox.showerror("Fehler", f"Unerwarteter Fehler: {str(e)}")
                self.cleanup_connection()

        except ValueError as ve:
            print(f"[DEBUG 42] ValueError: {ve}")
            print(f"[DEBUG 43] ValueError type: {type(ve).__name__}")
            messagebox.showerror("Fehler", f"Ungültige Eingabe: {str(ve)}")
            self.cleanup_connection()
            
        except Exception as e:
            print(f"[DEBUG 44] General exception: {e}")
            print(f"[DEBUG 45] Exception type: {type(e).__name__}")
            print("[DEBUG 46] Full traceback:")
            import traceback
            traceback.print_exc()
            
            messagebox.showerror("Fehler", f"Unerwarteter Fehler: {str(e)}")
            self.cleanup_connection()
        
        finally:
            print(f"[DEBUG 47] === END CONNECTION ATTEMPT ===")
            print(f"{'='*60}\n")
    def on_update_click(self):
        """KORRIGIERT: Update ohne Debug-Methoden die nicht existieren"""
        global connected
        try:
            if not hasattr(self, 'client_socket') or not self.client_socket or not connected:
                messagebox.showerror("Fehler", "Nicht mit Server verbunden")
                print("[UPDATE] ❌ Nicht mit Server verbunden")
                return

            print("[UPDATE] 🟡 Update-Button geklickt")

            # Einfache Queue-Status-Ausgabe ohne separate Methode
            print(f"\n🔍 UPDATE QUEUE STATUS:")
            print(f"Queue size: {len(self._message_queue) if hasattr(self, '_message_queue') else 0}")
            print(f"Processing: {getattr(self, '_processing_queue', False)}")

            # Update Request
            update_data = {
                "MESSAGE_TYPE": "UPDATE_REQUEST", 
                "CLIENT_NAME": self._client_name,
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0",
                "REQUEST_TYPE": "PHONEBOOK_UPDATE"
            }
            
            update_msg = self.build_sip_message("MESSAGE", self.server_ip, update_data)
            print(f"[UPDATE] 📤 Sending update request: {len(update_msg)} chars")

            # Sende Update
            if send_frame(self.client_socket, update_msg.encode('utf-8')):
                print("[UPDATE] ✅ Update request sent to server")
                
                # Queue initialisieren falls nicht vorhanden
                if not hasattr(self, '_message_queue'):
                    self._message_queue = []
                    
                # Tracking zur Queue hinzufügen
                self._message_queue.append({
                    'type': 'update_request_sent',
                    'timestamp': time.time()
                })
                
                # Starte Queue-Verarbeitung falls nicht aktiv
                if not getattr(self, '_processing_queue', False):
                    print("[UPDATE] 🚀 Starting queue processor for response...")
                    self._processing_queue = True
                    threading.Thread(
                        target=self._process_queue_simple,
                        daemon=True,
                        name="UpdateResponseProcessor"
                    ).start()
                else:
                    print(f"[UPDATE] ⏳ Queue processor already running, {len(self._message_queue)} items waiting")
                    
            else:
                print("[UPDATE] ❌ Failed to send update request")
                messagebox.showerror("Fehler", "Update-Nachricht konnte nicht gesendet werden")

        except Exception as e:
            print(f"[UPDATE] 💥 Error: {str(e)}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Fehler", f"Update fehlgeschlagen: {str(e)}")
    def set_selected_entry(self, entry, frame):
        """Setzt den ausgewählten Eintrag und aktualisiert die UI"""
        self.selected_entry = entry
        self.update_phonebook_ui(self.phonebook_entries)  # Neuzeichnen mit Highlight        
    def update_phonebook_ui(self, entries):
        """Aktualisiert die CustomTkinter-Oberfläche mit den Telefonbucheinträgen"""
        try:
            # 1. Lösche vorhandene Einträge
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
            
            # Schriftdefinition
            entry_font = ("Helvetica", 16)
            
            # 2. Erstelle neue Einträge
            for entry in entries:
                frame = ctk.CTkFrame(
                    self.scrollable_frame,
                    fg_color="#002200"
                )
                frame.pack(fill="x", pady=3, padx=5)
                
                # Label erstellen
                text_label = ctk.CTkLabel(
                    frame,
                    text=f"{entry['id']}: {entry['name']}",
                    anchor="w",
                    font=entry_font,
                    text_color="white",
                    fg_color="#006400"
                )
                text_label.pack(side="left", fill="x", expand=True, padx=5)
                
                # Korrekte Lambda-Bindung
                text_label.bind("<Button-1>", 
                    lambda event, e=entry.copy(), f=frame: self.set_selected_entry(e, f))
                frame.bind("<Button-1>", 
                    lambda event, e=entry.copy(), f=frame: self.set_selected_entry(e, f))
                
                # Highlight für ausgewählten Eintrag
                if self.selected_entry and self.selected_entry.get('id') == entry.get('id'):
                    frame.configure(fg_color="gray")
                
            # 3. Aktualisiere Scrollbereich
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            
        except Exception as e:
            print(f"[UI ERROR] Failed to update phonebook UI: {str(e)}")
            traceback.print_exc()
    def update_phonebook(self, phonebook_data):        
        try:
            # 1. Input validieren und konvertieren
            if isinstance(phonebook_data, str):
                try:
                    phonebook_data = json.loads(phonebook_data)
                except json.JSONDecodeError as e:
                    print("[ERROR] Invalid JSON string:", str(e))
                    return
                    
            if not isinstance(phonebook_data, (list, dict)):
                print("[ERROR] Invalid phonebook format - expected list or dict")
                return

            # 2. Normalisiere die Datenstruktur
            if isinstance(phonebook_data, dict):
                # Falls als Dict mit 'clients'-Key geliefert
                entries = phonebook_data.get('clients', [])
            else:
                entries = phonebook_data
                
            # 3. Validierte Einträge erstellen
            valid_entries = []
            for entry in entries:
                try:
                    if not isinstance(entry, dict):
                        continue
                        
                    # Erforderliche Felder extrahieren
                    client_id = str(entry.get('id', '0')).strip()
                    client_name = str(entry.get('name', load_client_name() or 'Unnamed')).strip()
                    client_ip = str(entry.get('ip', ''))
                    client_port = str(entry.get('port', ''))
                    public_key = str(entry.get('public_key', ''))
                    
                    # Tkinter-kompatibles Dict erstellen
                    tk_entry = {
                        'id': client_id,
                        'name': client_name,
                        'ip': client_ip,
                        'port': client_port,
                        'public_key': public_key,
                        'callable': bool(client_ip and client_port)
                    }
                    
                    valid_entries.append(tk_entry)
                    
                    print(f"[DEBUG] Added entry: {client_id} - {client_name}")
                    
                except Exception as e:
                    print(f"[WARNING] Invalid entry skipped: {str(e)}")
                    traceback.print_exc()
                    continue

            # 4. Debug-Ausgabe
            print(f"[DEBUG] Processed {len(valid_entries)} valid entries")
            if valid_entries:
                print("[DEBUG] First entry sample:", valid_entries[0])

            # 5. ✅ MINIMAL-INVASIVE KORREKTUR: Thread-sichere UI-Aktualisierung
            def safe_ui_update():
                try:
                    self.update_phonebook_ui(valid_entries)
                    
                    # 6. Internen Zustand aktualisieren
                    if self.phonebook_entries != valid_entries:
                        self.phonebook_entries = valid_entries
                    
                    print("[SUCCESS] Phonebook updated")
                except Exception as e:
                    error_msg = f"UI update error: {str(e)}"
                    print(error_msg)
                    if hasattr(self, 'show_error'):
                        self.show_error(error_msg)

            # Im Hauptthread direkt ausführen, sonst schedulen
            if threading.current_thread() == threading.main_thread():
                safe_ui_update()
            else:
                self.after(0, safe_ui_update)

        except Exception as e:
            error_msg = f"Critical phonebook update error: {str(e)}"
            print(error_msg)
            traceback.print_exc()
            
            # Fehler anzeigen (Tkinter-spezifisch)
            if hasattr(self, 'show_error'):
                self.show_error(error_msg)
    
    def _clear_phonebook_entries(self):
        """Löscht alle Einträge im scrollable_frame"""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.entry_buttons = []
    def cleanup_connection(self):
        """Bereinigt die Verbindung und setzt den Zustand zurück"""
        try:
            print("[CLEANUP] Cleaning up connection...")
            
            # Socket schließen
            if hasattr(self, 'client_socket') and self.client_socket:
                try:
                    self.client_socket.close()
                    print("[CLEANUP] Socket closed")
                except Exception as e:
                    print(f"[CLEANUP WARNING] Socket close failed: {str(e)}")
                finally:
                    self.client_socket = None
            
            # Call-Ressourcen bereinigen
            if hasattr(self, 'call_manager'):
                try:
                    self.call_manager.cleanup_call_resources()
                    print("[CLEANUP] Call resources cleaned")
                except Exception as e:
                    print(f"[CLEANUP WARNING] Call cleanup failed: {str(e)}")
            
            # Queue zurücksetzen
            if hasattr(self, '_message_queue'):
                self._message_queue.clear()
            
            # Status zurücksetzen
            if hasattr(self, 'connected'):
                self.connected = False
            
            # UI zurücksetzen falls vorhanden
            if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                try:
                    self.status_label.configure(text="Verbindung getrennt")
                except:
                    pass
                    
            print("[CLEANUP] Connection cleanup completed")
            
        except Exception as e:
            print(f"[CLEANUP ERROR] Cleanup failed: {str(e)}")    
    def _add_phonebook_entry(self, entry):
        """Fügt einen einzelnen Eintrag hinzu"""
        btn = ctk.CTkButton(
            self.scrollable_frame,
            text=f"{entry['id']}: {entry['name']}",
            fg_color="#006400",
            text_color="white",
            font=("Helvetica", 14),
            height=50,
            corner_radius=10,
            command=lambda e=entry: self.on_entry_click(e)
        )
        btn.pack(fill="x", pady=5, padx=5)
        self.entry_buttons.append(btn)
    
    def _update_canvas_scrollregion(self):
        """Aktualisiert die Scrollregion des Canvas"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.canvas.yview_moveto(0)  # Zum Anfang scrollen


    def on_hangup_click(self):
        """Beendet den aktuellen Anruf und bereinigt alle Ressourcen"""
        try:
            if not self.active_call and not hasattr(self, 'pending_call'):
                print("[HANGUP] No active call to hang up")
                return
                
            print("[HANGUP] Ending call and cleaning up resources...")
            
            # 1. Sende Hangup-Nachricht an Server (falls verbunden)
            if hasattr(self, 'client_socket') and self.client_socket:
                try:
                    hangup_msg = self.build_sip_message("MESSAGE", "server", {
                        "MESSAGE_TYPE": "CALL_END",
                        "TIMESTAMP": int(time.time()),
                        "REASON": "user_hangup"
                    })
                    send_frame(self.client_socket, hangup_msg.encode('utf-8'))
                    print("[HANGUP] Hangup message sent to server")
                except Exception as e:
                    print(f"[HANGUP WARNING] Failed to send hangup message: {str(e)}")
            
            # 2. Beende aktiven Anruf
            self.end_current_call()
            
            # 3. Bereinige pending_call Daten
            if hasattr(self, 'pending_call'):
                del self.pending_call
                
            # 4. UI zurücksetzen
            self.update_call_ui(active=False)
            
            print("[HANGUP] Call successfully terminated")
            
        except Exception as e:
            print(f"[HANGUP ERROR] Failed to hang up: {str(e)}")
            # Versuche trotzdem zu bereinigen
            try:
                self.cleanup_call_resources()
                if hasattr(self, 'pending_call'):
                    del self.pending_call
                self.update_call_ui(active=False)
            except:
                pass

    def _handle_ping_message(self):
        """Handle PING messages by responding with PONG"""
        try:
            if hasattr(self, 'client_socket') and self.client_socket:
                # ✅ VERIFY-CODE FÜR PONG-NACHRICHT GENERIEREN
                if hasattr(self, 'client_generator'):
                    verify_code = self.client_generator.generate_verify_code()
                    print(f"🔐 [PING] PONG Verify-Code: {verify_code}")
                else:
                    client_name = getattr(self, '_client_name', 'ping_client')
                    generator = init_verify_generator(client_name, client_name)
                    verify_code = generator.generate_verify_code()
                    print(f"🔐 [PING] PONG Verify-Code (Fallback): {verify_code}")
                
                pong_msg = self.build_sip_message(
                    "MESSAGE",
                    "server",
                    {"PONG": "true"},
                    additional_headers=[f"Verify-Code: {verify_code}"]  # ✅ VERIFY-CODE HINZUFÜGEN
                )
                self.client_socket.sendall(pong_msg.encode('utf-8'))
                print("[DEBUG] Sent PONG response with verify-code")
                return True
            return False
        except Exception as e:
            print(f"[ERROR] Failed to send PONG: {str(e)}")
            return False
   


    def _process_queue_simple(self):
        """VOLLSTÄNDIG NEU: Robuste Queue-Verarbeitung die garantiert läuft"""
        print(f"[QUEUE] 🚀 START Queue Processor - {len(self._message_queue)} items waiting")
        
        # Setze Flag sofort
        self._processing_queue = True
        processed_count = 0
        max_items_per_run = 50  # Verhindere Endlosschleifen
        
        try:
            while (hasattr(self, '_message_queue') and 
                   self._message_queue and 
                   processed_count < max_items_per_run):
                
                item = self._message_queue.pop(0)
                processed_count += 1
                
                if not isinstance(item, dict):
                    print(f"[QUEUE] ❌ Invalid item type: {type(item)}")
                    continue
                    
                item_type = item.get('type', 'unknown')
                print(f"[QUEUE] 🔄 Processing item {processed_count}: {item_type}")
                
                try:
                    if item_type == 'frame_data':
                        data = item.get('data')
                        if data:
                            print(f"[QUEUE] 📨 Processing frame data: {len(data)} bytes")
                            success = self._process_received_frame(data)
                            print(f"[QUEUE] {'✅' if success else '❌'} Frame processing {'successful' if success else 'failed'}")
                        else:
                            print("[QUEUE] ⚠️ No data in frame_data item")
                            
                    elif item_type == 'send_message':
                        message = item.get('message')
                        if message:
                            print(f"[QUEUE] 📤 Sending message: {len(message)} chars")
                            success = self._send_direct_message(message)
                            print(f"[QUEUE] {'✅' if success else '❌'} Message send {'successful' if success else 'failed'}")
                        else:
                            print("[QUEUE] ⚠️ No message in send_message item")
                            
                    elif item_type == 'update_request_sent':
                        print("[QUEUE] 📋 Update request was sent - waiting for response")
                        # Keine weitere Aktion benötigt
                        
                    else:
                        print(f"[QUEUE] 🤔 Unknown item type: {item_type}")
                        print(f"[QUEUE] 📋 Item keys: {list(item.keys())}")
                        
                except Exception as e:
                    print(f"[QUEUE] 💥 ERROR processing item {item_type}: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    # Weiter mit nächstem Item
                    
                # Kurze Pause zwischen Items für Stabilität
                time.sleep(0.01)
                
            print(f"[QUEUE] ✅ COMPLETED - Processed {processed_count} items")
            
            # Wenn noch Items übrig sind, neu starten
            remaining = len(self._message_queue) if hasattr(self, '_message_queue') else 0
            if remaining > 0:
                print(f"[QUEUE] 🔄 Restarting for {remaining} remaining items")
                self._processing_queue = False
                threading.Thread(
                    target=self._process_queue_simple, 
                    daemon=True,
                    name="QueueProcessor-Restart"
                ).start()
                
        except Exception as e:
            print(f"[QUEUE] 💥 CRITICAL ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            # WICHTIG: Flag immer zurücksetzen
            self._processing_queue = False
            print(f"[QUEUE] 🏁 Processor stopped")

    def handle_server_message(self, raw_data):
        """KORRIGIERT: Garantiert dass Queue-Verarbeitung startet"""
        print(f"\n=== HANDLING SERVER MESSAGE ({len(raw_data)} bytes) ===")
        
        try:
            # Queue initialisieren falls nicht vorhanden
            if not hasattr(self, '_message_queue'):
                self._message_queue = []
            
            # Item zur Queue hinzufügen
            queue_item = {
                'type': 'frame_data',
                'data': raw_data,
                'timestamp': time.time(),
                'source': 'server',
                'size': len(raw_data)
            }
            
            self._message_queue.append(queue_item)
            current_queue_size = len(self._message_queue)
            print(f"[QUEUE] ➕ Added to queue. Size: {current_queue_size}")
            
            # Queue-Verarbeitung STARTEN - garantiert
            if not getattr(self, '_processing_queue', False):
                print("[QUEUE] 🚀 Starting queue processor...")
                self._processing_queue = True
                threading.Thread(
                    target=self._process_queue_simple, 
                    daemon=True,
                    name=f"QueueProcessor-{int(time.time())}"
                ).start()
            else:
                print(f"[QUEUE] ⏳ Processor already running, {current_queue_size} items waiting")
            
            return True
            
        except Exception as e:
            print(f"[HANDLER ERROR] ❌ {str(e)}")
            return False

    def _send_direct_message(self, message):
        """Vereinfachtes Senden von Nachrichten mit Fehlerbehandlung"""
        try:
            if not hasattr(self, 'client_socket') or not self.client_socket:
                print("[SEND ERROR] Keine Client-Socket-Verbindung")
                return False
                
            if self.client_socket.fileno() == -1:
                print("[SEND ERROR] Socket geschlossen")
                return False
                
            if isinstance(message, str):
                message = message.encode('utf-8')
                
            success = send_frame(self.client_socket, message)
            if success:
                print(f"[SEND] Nachricht gesendet ({len(message)} bytes)")
            else:
                print("[SEND ERROR] Frame konnte nicht gesendet werden")
                
            return success
            
        except Exception as e:
            print(f"[SEND ERROR] {e}")
            return False

    def _process_received_frame(self, frame_data):
        """KORRIGIERTE Frame-Verarbeitung mit besserer Fehlerbehandlung"""
        try:
            print(f"[FRAME] Verarbeite {len(frame_data)} bytes")
            
            # 1. Decoding versuchen
            if isinstance(frame_data, bytes):
                try:
                    message = frame_data.decode('utf-8')
                    print(f"[FRAME] Als UTF-8 decodiert: {len(message)} Zeichen")
                except UnicodeDecodeError:
                    # Binärdaten (Audio/verschlüsselte Daten)
                    print(f"[FRAME] Binärdaten empfangen: {len(frame_data)} bytes")
                    
                    # Versuche als verschlüsselte Phonebook-Daten
                    if len(frame_data) > 512:
                        print("[FRAME] Versuche als verschlüsselte Phonebook-Daten")
                        result = self._decrypt_phonebook_data(frame_data)
                        if result:
                            return True
                    
                    # Audio-Daten während aktiver Calls
                    if hasattr(self, 'call_manager') and self.call_manager.active_call:
                        print("[FRAME] Binärdaten während aktiven Calls - möglicherweise Audio")
                        # Hier könnte Audio-Weiterleitung implementiert werden
                    
                    return False
            else:
                message = str(frame_data)
            
            # 2. SIP-Nachricht parsen
            msg = self.parse_sip_message(message)
            if not msg:
                print("[FRAME ERROR] Konnte SIP-Nachricht nicht parsen")
                return False
            
            # 3. Nachrichtentyp ermitteln
            custom_data = msg.get('custom_data', {})
            message_type = custom_data.get('MESSAGE_TYPE', 'UNKNOWN')
            
            print(f"[FRAME] Nachrichtentyp: {message_type}")
            
            # 4. NACHRICHTEN-ROUTING
            if message_type in ['INCOMING_CALL', 'SESSION_KEY', 'CALL_RESPONSE', 
                              'CALL_TIMEOUT', 'PUBLIC_KEY_RESPONSE', 'CALL_END',
                              'CALL_CONFIRMED']:  # ✅ HIER FEHLTE CALL_CONFIRMED!
                if hasattr(self, 'call_manager'):
                    print(f"[CALL] Delegiere {message_type} an Call Manager")
                    self.call_manager.handle_message(msg)
                else:
                    print(f"[CALL ERROR] Kein Call Manager für {message_type}")
            
            elif message_type == 'IDENTITY_CHALLENGE':
                print("[IDENTITY] Challenge vom Server")
                self._handle_identity_challenge(msg)
            
            elif message_type == 'IDENTITY_VERIFIED':
                print("[IDENTITY] Verifizierung bestätigt")
                self._handle_identity_verified(msg)
            
            elif message_type == 'PHONEBOOK_UPDATE':
                print("[PHONEBOOK] Update empfangen")
                self._process_phonebook_update(msg)
            
            elif message_type == 'PING':
                print("[PING] Vom Server empfangen")
                self._handle_ping_message()
            
            elif message_type == 'PONG':
                print("[PONG] Vom Server empfangen")
                # Einfach bestätigen
            
            else:
                print(f"[FRAME WARN] Unbekannter Nachrichtentyp: {message_type}")
                print(f"[DEBUG] Custom Data Keys: {list(custom_data.keys())}")
                
            return True
            
        except Exception as e:
            print(f"[FRAME PROCESS ERROR] {e}")
            import traceback
            traceback.print_exc()
            return False
    def _handle_identity_challenge(self, msg):
        """VOLLSTÄNDIG EINHEITLICHE IDENTITY CHALLENGE VERARBEITUNG - KORRIGIERT FÜR SIP"""
        try:
            print("\n" + "="*60)
            print("[IDENTITY] START: Handling identity challenge from server")
            print("="*60)
            
            # 1. ✅ UNTERSCHEIDUNG: SIP-NACHRICHT vs. ROHES JSON
            if isinstance(msg, str) and 'SIP/2.0' in msg:
                print("[IDENTITY] Received SIP-formatted message, extracting JSON body...")
                # SIP-Nachricht parsen
                sip_data = self.parse_sip_message(msg)
                if not sip_data:
                    print("[IDENTITY ERROR] Failed to parse SIP message")
                    return False
                    
                # JSON-Body extrahieren
                body = sip_data.get('body', '')
                if not body:
                    print("[IDENTITY ERROR] No body in SIP message")
                    return False
                    
                try:
                    custom_data = json.loads(body)
                    print("[IDENTITY] Successfully extracted JSON from SIP body")
                except json.JSONDecodeError as e:
                    print(f"[IDENTITY ERROR] JSON decode failed: {e}")
                    return False
                    
            elif isinstance(msg, dict):
                print("[IDENTITY] Received direct JSON message")
                custom_data = msg.get('custom_data', {})
            else:
                print("[IDENTITY ERROR] Unsupported message format")
                return False
            
            # 2. ERFORDERLICHE FELDER EXTRAHIEREN
            encrypted_challenge_b64 = custom_data.get('ENCRYPTED_CHALLENGE')
            challenge_id = custom_data.get('CHALLENGE_ID')
            
            if not encrypted_challenge_b64 or not challenge_id:
                print("[IDENTITY ERROR] Missing required fields in challenge")
                print(f"[DEBUG] ENCRYPTED_CHALLENGE: {'present' if encrypted_challenge_b64 else 'missing'}")
                print(f"[DEBUG] CHALLENGE_ID: {'present' if challenge_id else 'missing'}")
                print(f"[DEBUG] Available keys: {list(custom_data.keys())}")
                return False
            
            print(f"[DEBUG] Challenge ID: {challenge_id}")
            print(f"[DEBUG] Encrypted challenge length: {len(encrypted_challenge_b64)}")
            
            # 3. Base64 decode
            try:
                encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
                print(f"[DEBUG] Decoded challenge length: {len(encrypted_challenge)} bytes")
            except Exception as e:
                print(f"[IDENTITY ERROR] Base64 decode failed: {str(e)}")
                return False
            
            # 4. Mit privatem Schlüssel entschlüsseln
            print("[DEBUG] Decrypting with client private key")
            try:
                private_key = load_privatekey()
                priv_key = RSA.load_key_string(private_key.encode())
                decrypted_challenge = priv_key.private_decrypt(
                    encrypted_challenge, 
                    RSA.pkcs1_padding
                )
                challenge = decrypted_challenge.decode('utf-8')
                print(f"[DEBUG] Decrypted challenge: {challenge}")
                
            except Exception as e:
                print(f"[IDENTITY ERROR] Decryption failed: {str(e)}")
                return False
            
            # 5. Response erstellen
            response_data = challenge + "VALIDATED"
            print(f"[DEBUG] Response data: {response_data}")
            
            # 6. Mit Server Public Key verschlüsseln
            print("[DEBUG] Encrypting with server public key")
            try:
                server_pubkey = load_server_publickey()
                # PEM-Format bereinigen
                if '\\n' in server_pubkey:
                    server_pubkey = server_pubkey.replace('\\n', '\n')
                
                server_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(server_pubkey.encode()))
                encrypted_response = server_key.public_encrypt(
                    response_data.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                encrypted_response_b64 = base64.b64encode(encrypted_response).decode('utf-8')
                
            except Exception as e:
                print(f"[IDENTITY ERROR] Encryption failed: {str(e)}")
                return False
            
            # 7. ✅ KORREKTE SIP-RESPONSE SENDEN (nicht nur JSON)
            print("[DEBUG] Sending SIP response to server")
            
            response_data = {
                "MESSAGE_TYPE": "IDENTITY_RESPONSE",
                "CHALLENGE_ID": challenge_id,
                "ENCRYPTED_RESPONSE": encrypted_response_b64,
                "TIMESTAMP": int(time.time())
            }
            
            # Verwende build_sip_message für korrektes SIP-Format
            response_msg = self.build_sip_message("MESSAGE", "server", response_data)
            
            if self._send_message(response_msg):
                print("[IDENTITY] SIP response sent to server successfully!")
                return True
            else:
                print("[IDENTITY ERROR] Failed to send response")
                return False
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Challenge handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


    def _handle_identity_verified(self, message):
        """Korrigierte Verarbeitung der Identity Verification Bestätigung"""
        try:
            print("\n" + "="*60)
            print("[IDENTITY] Processing verification confirmation")
            print("="*60)
            
            # 1. Nachricht parsen (kann String oder Dict sein)
            if isinstance(message, str):
                print("[IDENTITY] Received string message, parsing as SIP...")
                sip_data = self.parse_sip_message(message)
                if not sip_data:
                    print("[IDENTITY ERROR] Failed to parse SIP message")
                    return False
                    
                # Extrahiere JSON-Body
                body = sip_data.get('body', '')
                if not body:
                    print("[IDENTITY ERROR] No body in SIP message")
                    return False
                    
                try:
                    message_data = json.loads(body)
                    print("[IDENTITY] Successfully extracted JSON from SIP body")
                except json.JSONDecodeError as e:
                    print(f"[IDENTITY ERROR] JSON decode failed: {e}")
                    return False
            else:
                print("[IDENTITY] Received dict message")
                message_data = message
            
            # 2. Verschiedene mögliche Erfolgs-Indikatoren prüfen
            status_indicators = [
                message_data.get('STATUS'),
                message_data.get('MESSAGE_TYPE'), 
                message_data.get('RESULT'),
                '200' in str(message)  # Fallback für Status-Code
            ]
            
            print(f"[IDENTITY] Status indicators: {status_indicators}")
            
            # 3. Erfolg erkennen anhand verschiedener möglicher Muster
            is_verified = any([
                status == 'VERIFICATION_SUCCESSFUL' for status in status_indicators if status
            ]) or any([
                'VERIFIED' in str(indicator) for indicator in status_indicators if indicator
            ]) or any([
                'SUCCESS' in str(indicator) for indicator in status_indicators if indicator
            ]) or '200 OK' in str(message)
            
            if is_verified:
                print("✅ [IDENTITY] Successfully verified by server!")
                
                # 4. Phonebook anfordern
                print("[IDENTITY] Requesting phonebook update...")
                self.request_phonebook_update()
                return True
            else:
                reason = message_data.get('REASON', 'Unknown error')
                print(f"❌ [IDENTITY] Verification failed: {reason}")
                return False
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Verification handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def request_phonebook_update(self):
        """Fordert Phonebook-Update nach erfolgreicher Verifikation an"""
        try:
            print("[PHONEBOOK] Requesting update after identity verification...")
            
            update_data = {
                "MESSAGE_TYPE": "PHONEBOOK_REQUEST",
                "CLIENT_NAME": self._client_name,
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0"
            }
            
            update_msg = self.build_sip_message(
                "MESSAGE", 
                self.server_ip, 
                update_data
            )
            
            if self._send_message(update_msg):
                print("[PHONEBOOK] Update request sent successfully")
            else:
                print("[PHONEBOOK ERROR] Failed to send update request")
                
        except Exception as e:
            print(f"[PHONEBOOK ERROR] Update request failed: {str(e)}")
    def receive_messages(self):
        """Empfängt Nachrichten vom Server und schreibt sie korrekt in die Queue"""
        while self.connected:
            try:
                data = recv_frame(self.client_socket)
                if data:
                    print(f"[CLIENT] Empfangen vom Server: {len(data)} bytes")
                    
                    # ✅ KORREKT: Als Dictionary in die Queue schreiben
                    self._message_queue_simple.append({
                        'type': 'frame_data',
                        'data': data
                    })
                    
                    # Queue-Verarbeitung starten
                    if not self._processing_queue_simple:
                        self._process_queue_simple()
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.connected:
                    print(f"[CLIENT RECV ERROR] {str(e)}")
                break            

    def _find_my_client_id(self):
        """Ermittelt die eigene Client-ID zuverlässig"""
        try:
            # 1. Versuche aus den Phonebook-Einträgen zu finden
            if hasattr(self, 'phonebook_entries') and self.phonebook_entries:
                for entry in self.phonebook_entries:
                    if isinstance(entry, dict) and entry.get('name') == self._client_name:
                        client_id = entry.get('id')
                        if client_id:
                            print(f"[CLIENT ID] Found in phonebook: {client_id}")
                            return str(client_id)
            
            # 2. Versuche aus client_id.txt zu laden
            try:
                if os.path.exists("client_id.txt"):
                    with open("client_id.txt", "r") as f:
                        client_id = f.read().strip()
                        if client_id:
                            print(f"[CLIENT ID] Loaded from file: {client_id}")
                            return client_id
            except Exception as e:
                print(f"[CLIENT ID WARNING] File read failed: {str(e)}")
            
            # 3. Fallback: Generiere eine temporäre ID
            temp_id = str(hash(self._client_name) % 10000)  # Einfache Hash-basierte ID
            print(f"[CLIENT ID] Generated temporary ID: {temp_id}")
            return temp_id
            
        except Exception as e:
            print(f"[CLIENT ID ERROR] {str(e)}")
            return "unknown"

            return "127.0.0.1"

    def _process_sip_message(self, message):
        """Verarbeitet SIP-Nachrichten mit verschlüsselten Daten"""
        sip_data = self.parse_sip_message(message)
        if not sip_data:
            return False

        try:
            # Extrahiere verschlüsselte Teile aus custom_data
            custom_data = sip_data.get('custom_data', {})
            
            if 'ENCRYPTED_SECRET' in custom_data and 'ENCRYPTED_PHONEBOOK' in custom_data:
                print("[DEBUG] Found encrypted phonebook in SIP message")
                secret = base64.b64decode(custom_data['ENCRYPTED_SECRET'])
                phonebook = base64.b64decode(custom_data['ENCRYPTED_PHONEBOOK'])
                return self._decrypt_phonebook(secret + phonebook)
                
            return False
            
        except Exception as e:
            print(f"[ERROR] SIP message processing failed: {str(e)}")
            return False                    

    def _decrypt_phonebook(self, encrypted_data):
        """Robuste Entschlüsselung mit korrekter Bytes/String-Handling"""
        print("\n=== DECRYPT PHONEBOOK DEBUG ===")
        print(f"[DEBUG] Input type: {type(encrypted_data)}, length: {len(encrypted_data) if hasattr(encrypted_data, '__len__') else 'N/A'}")
        
        try:
            # 1. Handle raw binary data (direct encrypted format)
            if isinstance(encrypted_data, bytes) and len(encrypted_data) > 512:
                print("[DEBUG] Processing raw binary encrypted data")
                encrypted_secret = encrypted_data[:512]
                encrypted_phonebook = encrypted_data[512:]
                print(f"[DEBUG] Secret length: {len(encrypted_secret)} bytes")
                print(f"[DEBUG] Phonebook length: {len(encrypted_phonebook)} bytes")
                
            else:
                print(f"[ERROR] Unsupported input format: {type(encrypted_data)} or insufficient length")
                return None

            # 2. Validate secret length
            if len(encrypted_secret) != 512:
                raise ValueError(f"Invalid secret length: {len(encrypted_secret)} bytes (expected 512)")

            # 3. RSA decrypt
            print("[DEBUG] RSA decrypting secret...")
            private_key = load_privatekey()
            if not private_key or not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
                raise ValueError("Invalid private key format")
                
            priv_key = RSA.load_key_string(private_key.encode())
            decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            secure_del(priv_key)
            
            print(f"[DEBUG] RSA decrypted: {len(decrypted_secret)} bytes")
            print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(decrypted_secret[:32])}")
            print(f"[DEBUG] As string: {decrypted_secret[:50]!r}")

            # 4. Extract AES components with improved error handling
            prefix = b"+++secret+++"
            if not decrypted_secret.startswith(prefix):
                print("[ERROR] Secret prefix not found in decrypted data")
                print(f"[DEBUG] Actual prefix: {decrypted_secret[:11]!r}")
                raise ValueError("Secret prefix not found in decrypted data")
                
            secret_start = len(prefix)
            extracted_secret = decrypted_secret[secret_start:secret_start+48]
            secure_del(decrypted_secret)
            
            if len(extracted_secret) != 48:
                raise ValueError(f"Invalid secret length: {len(extracted_secret)} bytes (expected 48)")
                
            print(f"[DEBUG] Extracted secret length: {len(extracted_secret)}")
            print(f"[DEBUG] Secret full (hex): {binascii.hexlify(extracted_secret)}")
            
            iv = extracted_secret[:16]
            key = extracted_secret[16:48]
            
            print("[DEBUG] AES components:")
            print(f"IV (16 bytes): {binascii.hexlify(iv)}")
            print(f"Key (32 bytes): {binascii.hexlify(key)}")

            # 5. AES decrypt with extensive debugging
            print("[DEBUG] AES decrypting phonebook...")
            print(f"[DEBUG] Encrypted phonebook length: {len(encrypted_phonebook)} bytes")
            print(f"[DEBUG] Encrypted phonebook first 32 bytes (hex): {binascii.hexlify(encrypted_phonebook[:32])}")

            # Try different padding modes
            try:
                cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=1)
                decrypted = cipher.update(encrypted_phonebook) + cipher.final()
                print("[DEBUG] AES decryption successful with PKCS#7 padding")
            except EVP.EVPError as padding_error:
                print(f"[DEBUG] PKCS#7 padding failed: {padding_error}")
                # Fallback: Try without padding
                try:
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=0)
                    decrypted = cipher.update(encrypted_phonebook) + cipher.final()
                    print("[DEBUG] AES decryption successful without padding")
                except EVP.EVPError as no_padding_error:
                    print(f"[DEBUG] No padding also failed: {no_padding_error}")
                    raise ValueError("AES decryption failed with both padding modes")

            print(f"[DEBUG] Decrypted data length: {len(decrypted)} bytes")
            print(f"[DEBUG] Decrypted data (hex): {binascii.hexlify(decrypted[:64])}...")
            print(f"[DEBUG] As string: {decrypted[:100]!r}")

            # 6. Try to decode as UTF-8 JSON
            try:
                phonebook_data = json.loads(decrypted.decode('utf-8'))
                print("[DEBUG] Successfully parsed as JSON")
            except UnicodeDecodeError:
                print("[DEBUG] UTF-8 decode failed, trying other encodings")
                # Try alternative encodings
                for encoding in ['latin-1', 'ascii', 'utf-16']:
                    try:
                        decoded_str = decrypted.decode(encoding)
                        print(f"[DEBUG] Successfully decoded as {encoding}")
                        phonebook_data = json.loads(decoded_str)
                        break
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                else:
                    raise ValueError("Failed to decode decrypted data with any encoding")

            if not isinstance(phonebook_data, dict):
                raise ValueError("Decrypted data is not a valid JSON object")
                
            print(f"[DEBUG] Phonebook keys: {list(phonebook_data.keys())}")
            if 'clients' in phonebook_data:
                print(f"[DEBUG] Phonebook entries: {len(phonebook_data.get('clients', []))}")

            # 7. CRITICAL: UI Update - This is likely where it fails!
            print("[DEBUG] Attempting to call update_phonebook()...")
            if hasattr(self, 'update_phonebook') and callable(self.update_phonebook):
                print("[DEBUG] update_phonebook method found and callable")
                try:
                    # Thread-safe UI update
                    if threading.current_thread() != threading.main_thread():
                        print("[DEBUG] Not in main thread, scheduling UI update")
                        self.after(0, lambda: self.update_phonebook(phonebook_data))
                    else:
                        print("[DEBUG] In main thread, calling directly")
                        self.update_phonebook(phonebook_data)
                    print("[DEBUG] UI update call completed")
                except Exception as e:
                    print(f"[ERROR] Failed to call update_phonebook: {str(e)}")
                    traceback.print_exc()
            else:
                print("[ERROR] update_phonebook method not found or not callable")
                print(f"[DEBUG] hasattr update_phonebook: {hasattr(self, 'update_phonebook')}")
                if hasattr(self, 'update_phonebook'):
                    print(f"[DEBUG] update_phonebook callable: {callable(self.update_phonebook)}")
            
            print("[DEBUG] Phonebook decryption completed successfully!")
            return phonebook_data
            
        except Exception as e:
            print(f"[DECRYPT ERROR] {str(e)}")
            traceback.print_exc()
            return None

    def _decrypt_phonebook_data(self, encrypted_data):
        """VERBESSERTE Phonebook Entschlüsselung mit robuster Fehlerbehandlung"""
        print("\n=== DECRYPT PHONEBOOK DEBUG ===")
        
        try:
            # 1. Input Validation
            if not isinstance(encrypted_data, bytes) or len(encrypted_data) <= 512:
                print(f"[ERROR] Invalid encrypted data: type={type(encrypted_data)}, length={len(encrypted_data) if hasattr(encrypted_data, '__len__') else 'N/A'}")
                return None

            print(f"[DEBUG] Encrypted data length: {len(encrypted_data)} bytes")
            
            # 2. Split into secret and phonebook
            encrypted_secret = encrypted_data[:512]
            encrypted_phonebook = encrypted_data[512:]
            
            print(f"[DEBUG] Secret part: {len(encrypted_secret)} bytes")
            print(f"[DEBUG] Phonebook part: {len(encrypted_phonebook)} bytes")

            # 3. Load private key with better error handling
            print("[DEBUG] Loading private key...")
            private_key_pem = load_privatekey()
            if not private_key_pem:
                print("[ERROR] No private key loaded")
                return None
                
            print(f"[DEBUG] Private key loaded, length: {len(private_key_pem)}")
            
            try:
                # 4. RSA Decryption
                print("[DEBUG] Starting RSA decryption...")
                priv_key = RSA.load_key_string(private_key_pem.encode())
                if not priv_key:
                    print("[ERROR] Failed to load private key string")
                    return None
                    
                decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
                print(f"[DEBUG] RSA decryption successful: {len(decrypted_secret)} bytes")
                
            except Exception as rsa_error:
                print(f"[RSA ERROR] Decryption failed: {str(rsa_error)}")
                return None

            # 5. Extract AES components
            print("[DEBUG] Extracting AES components...")
            
            # Flexible Prefix-Handling
            prefix = b"+++secret+++"
            if decrypted_secret.startswith(prefix):
                secret_data = decrypted_secret[len(prefix):len(prefix)+48]
                print("[DEBUG] Found secret prefix")
            else:
                # Fallback: Use first 48 bytes
                secret_data = decrypted_secret[:48]
                print("[DEBUG] Using first 48 bytes without prefix")
                
            print(f"[DEBUG] Secret data length: {len(secret_data)} bytes")
            
            if len(secret_data) < 48:
                print(f"[WARNING] Short secret: {len(secret_data)} bytes, padding if needed")
                # Padding falls nötig
                secret_data = secret_data + b'\0' * (48 - len(secret_data))
            
            # Extract IV and Key
            iv = secret_data[:16]
            key = secret_data[16:48]
            
            print(f"[DEBUG] IV length: {len(iv)}")
            print(f"[DEBUG] Key length: {len(key)}")

            # 6. AES Decryption
            print("[DEBUG] Starting AES decryption...")
            try:
                cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=1)
                decrypted_phonebook = cipher.update(encrypted_phonebook) + cipher.final()
                print(f"[DEBUG] AES decryption successful: {len(decrypted_phonebook)} bytes")
                
            except Exception as aes_error:
                print(f"[AES ERROR] Decryption failed: {str(aes_error)}")
                # Fallback: Try without padding
                try:
                    print("[DEBUG] Trying AES without padding...")
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=0)
                    decrypted_phonebook = cipher.update(encrypted_phonebook) + cipher.final()
                    print(f"[DEBUG] AES without padding successful: {len(decrypted_phonebook)} bytes")
                except Exception as aes_error2:
                    print(f"[AES ERROR 2] Fallback also failed: {str(aes_error2)}")
                    return None

            # 7. Parse JSON
            print("[DEBUG] Parsing JSON...")
            try:
                # Versuche UTF-8 decoding
                json_str = decrypted_phonebook.decode('utf-8')
                phonebook_data = json.loads(json_str)
                print("[DEBUG] JSON parsed successfully with UTF-8")
                
            except UnicodeDecodeError:
                # Fallback für andere Encodings
                print("[DEBUG] UTF-8 failed, trying other encodings...")
                for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        json_str = decrypted_phonebook.decode(encoding)
                        phonebook_data = json.loads(json_str)
                        print(f"[DEBUG] JSON parsed successfully with {encoding}")
                        break
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                else:
                    print("[ERROR] Failed to decode with any encoding")
                    return None
                    
            except json.JSONDecodeError as e:
                print(f"[JSON ERROR] Failed to parse JSON: {str(e)}")
                print(f"[DEBUG] First 200 chars of decrypted data: {decrypted_phonebook[:200]}")
                return None

            # 8. Update UI
            print(f"[DEBUG] Phonebook data type: {type(phonebook_data)}")
            print(f"[DEBUG] Phonebook keys: {list(phonebook_data.keys()) if isinstance(phonebook_data, dict) else 'Not a dict'}")
            
            if hasattr(self, 'update_phonebook') and callable(self.update_phonebook):
                print("[DEBUG] Calling update_phonebook...")
                try:
                    # Thread-safe update
                    if threading.current_thread() != threading.main_thread():
                        self.after(0, lambda: self.update_phonebook(phonebook_data))
                    else:
                        self.update_phonebook(phonebook_data)
                    print("[DEBUG] UI update completed successfully")
                except Exception as ui_error:
                    print(f"[UI ERROR] Failed to update phonebook: {str(ui_error)}")
            else:
                print("[ERROR] update_phonebook not available")

            return phonebook_data
            
        except Exception as e:
            print(f"[DECRYPT ERROR] Critical error: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

            

    def _process_phonebook_update(self, message):
        """KORRIGIERT: Verarbeitet Phonebook-Updates mit korrektem SIP-Parsing"""
        print("\n=== CLIENT PHONEBOOK UPDATE PROCESSING ===")
        
        try:
            # 1. ✅ SIP-NACHRICHT PARSEN (egal ob String oder bereits geparst)
            if isinstance(message, str):
                print("[DEBUG] Parsing SIP message from string...")
                sip_data = self.parse_sip_message(message)
                if not sip_data:
                    print("[ERROR] Failed to parse SIP message")
                    return False
            elif isinstance(message, dict):
                print("[DEBUG] Using pre-parsed SIP message")
                sip_data = message
            else:
                print("[ERROR] Unsupported message format")
                return False

            # 2. ✅ KRITISCH: JSON AUS DEM BODY EXTRAHIEREN
            body = sip_data.get('body', '')
            print(f"[DEBUG] Body length: {len(body)}")
            
            if not body:
                print("[ERROR] No body in SIP message")
                return False

            # 3. ✅ BODY ALS JSON PARSEN
            try:
                message_data = json.loads(body)
                print(f"[DEBUG] JSON parsed successfully. Keys: {list(message_data.keys())}")
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON decode failed: {e}")
                print(f"[DEBUG] Body content: {body[:200]}...")
                return False

            # 4. ✅ VERSUCH 1: Direkt verschlüsselte Daten finden
            if 'ENCRYPTED_SECRET' in message_data and 'ENCRYPTED_PHONEBOOK' in message_data:
                print("[DEBUG] Found encrypted data in JSON")
                try:
                    encrypted_secret = base64.b64decode(message_data['ENCRYPTED_SECRET'])
                    encrypted_phonebook = base64.b64decode(message_data['ENCRYPTED_PHONEBOOK'])
                    encrypted_data = encrypted_secret + encrypted_phonebook
                    
                    print(f"[DEBUG] Encrypted data: {len(encrypted_data)} bytes")
                    return self._decrypt_phonebook_data(encrypted_data)
                    
                except Exception as e:
                    print(f"[ERROR] Failed to process encrypted data: {e}")
                    return False

            # 5. ✅ VERSUCH 2: Custom Data durchsuchen
            custom_data = sip_data.get('custom_data', {})
            if 'ENCRYPTED_SECRET' in custom_data and 'ENCRYPTED_PHONEBOOK' in custom_data:
                print("[DEBUG] Found encrypted data in custom_data")
                try:
                    encrypted_secret = base64.b64decode(custom_data['ENCRYPTED_SECRET'])
                    encrypted_phonebook = base64.b64decode(custom_data['ENCRYPTED_PHONEBOOK'])
                    encrypted_data = encrypted_secret + encrypted_phonebook
                    
                    print(f"[DEBUG] Encrypted data: {len(encrypted_data)} bytes")
                    return self._decrypt_phonebook_data(encrypted_data)
                    
                except Exception as e:
                    print(f"[ERROR] Failed to process custom_data: {e}")
                    return False

            # 6. ✅ VERSUCH 3: Rohdaten im Body
            if 'ENCRYPTED' in body:
                print("[DEBUG] Searching for encrypted data in raw body...")
                
                # Versuche Base64-Daten direkt aus dem Body zu extrahieren
                import re
                base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
                base64_matches = re.findall(base64_pattern, body)
                
                if len(base64_matches) >= 2:
                    print(f"[DEBUG] Found {len(base64_matches)} base64 blocks")
                    try:
                        # Nehme die zwei größten Base64-Blöcke
                        base64_matches.sort(key=len, reverse=True)
                        encrypted_secret = base64.b64decode(base64_matches[0])
                        encrypted_phonebook = base64.b64decode(base64_matches[1])
                        encrypted_data = encrypted_secret + encrypted_phonebook
                        
                        print(f"[DEBUG] Extracted encrypted data: {len(encrypted_data)} bytes")
                        return self._decrypt_phonebook_data(encrypted_data)
                        
                    except Exception as e:
                        print(f"[ERROR] Raw body extraction failed: {e}")
                        return False

            # 7. ✅ VERSUCH 4: Direkt als Bytes verarbeiten (falls message schon Bytes sind)
            if isinstance(message, bytes) and len(message) > 512:
                print("[DEBUG] Processing as raw bytes...")
                return self._decrypt_phonebook_data(message)

            # 8. ✅ KEINE DATEN GEFUNDEN
            print("[ERROR] No encrypted phonebook data found in any location")
            print(f"[DEBUG] Available keys in message_data: {list(message_data.keys())}")
            print(f"[DEBUG] Available keys in custom_data: {list(custom_data.keys())}")
            print(f"[DEBUG] Body preview: {body[:500]}...")
            
            return False
            
        except Exception as e:
            print(f"[CRITICAL ERROR] Phonebook processing failed: {str(e)}")
            traceback.print_exc()
            return False

    def start_connection_wrapper(self, status_label=None, server_ip=None, server_port=None, client_name=None):
        """Korrigierte Tkinter-Version mit sauberer Attribut-Handhabung"""
        def update_status(message):
            if status_label:
                status_label.config(text=message)
            print(f"[STATUS] {message}")

        try:
            update_status("Verbindung wird vorbereitet...")
            
            # Parameter-Validierung mit übergebenen Werten oder self-Attributen
            ip = server_ip if server_ip is not None else getattr(self, 'server_ip', None)
            port_str = server_port if server_port is not None else getattr(self, 'server_port', None)
            name = client_name if client_name is not None else getattr(self, '_client_name', None)

            if not ip or not port_str:
                update_status("Server-IP und Port benötigt")
                return

            try:
                port = int(port_str)
                if not (0 < port <= 65535):
                    update_status("Ungültiger Port (1-65535)")
                    return
            except ValueError:
                update_status("Port muss eine Zahl sein")
                return

            # Socket-Erstellung
            client_socket = getattr(self, 'client_socket', None)
            if not client_socket:
                try:
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.settimeout(10)
                    if hasattr(self, 'client_socket'):
                        self.client_socket = client_socket
                except Exception as e:
                    update_status(f"Socket-Fehler: {str(e)}")
                    return

            # Verbindungsaufbau
            update_status("Verbinde mit Server...")
            try:
                success = self.start_connection(
                    ip,
                    port,
                    self._client_name,
                    client_socket,
                    self  # Message-Handler
                )
                
                if success:
                    update_status(f"Verbunden mit {ip}:{port}")
                else:
                    update_status("Verbindung fehlgeschlagen")
                    
            except socket.timeout:
                update_status("Timeout - Server nicht erreichbar")
            except ConnectionRefusedError:
                update_status("Verbindung abgelehnt")
            except socket.gaierror:
                update_status("Ungültige Server-Adresse")
            except Exception as e:
                update_status(f"Fehler: {str(e)}")
                traceback.print_exc()

        except Exception as e:
            update_status(f"Kritischer Fehler: {str(e)}")
            traceback.print_exc()
        finally:
            client_socket = getattr(self, 'client_socket', None)
            if client_socket:
                try:
                    client_socket.close()
                    if hasattr(self, 'client_socket'):
                        self.client_socket = None
                except:
                    pass


    def send_sip_response(self, sip_data, status_code, reason_phrase):
        """Sendet eine SIP-Antwort für eingehende Anrufe"""
        try:
            response = (
                f"SIP/2.0 {status_code} {reason_phrase}\r\n"
                f"From: {sip_data.get('headers', {}).get('FROM', '')}\r\n"
                f"To: {sip_data.get('headers', {}).get('TO', '')}\r\n"
                f"Call-ID: {sip_data.get('headers', {}).get('CALL-ID', '')}\r\n"
                f"CSeq: {sip_data.get('headers', {}).get('CSEQ', '')}\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            
            if hasattr(self, 'client_socket') and self.client_socket:
                send_frame(self.client_socket, response.encode('utf-8'))
                print(f"[SIP RESPONSE] Sent {status_code} {reason_phrase}")
                
        except Exception as e:
            print(f"[SIP RESPONSE ERROR] Failed to send response: {str(e)}")            


    def _disable_other_buttons(self, disable):
        """Hilfsfunktion zum Deaktivieren/Reaktivieren anderer Buttons während Anrufen"""
        try:
            # VERBESSERT: Vereinfachte Implementierung ohne komplexe Logik
            buttons_to_disable = ['update_button', 'setup_button', 'call_button']
            
            for btn_name in buttons_to_disable:
                if hasattr(self.client, btn_name):
                    button = getattr(self.client, btn_name)
                    try:
                        if disable:
                            button.configure(state="disabled")
                        else:
                            button.configure(state="normal")
                    except Exception as e:
                        print(f"[UI WARNING] Could not update button {btn_name}: {str(e)}")
                        
            # Hangup-Button umgekehrt behandeln
            if hasattr(self.client, 'hangup_button'):
                try:
                    if disable:
                        self.client.hangup_button.configure(state="normal")
                    else:
                        self.client.hangup_button.configure(state="disabled")
                except Exception as e:
                    print(f"[UI WARNING] Could not update hangup button: {str(e)}")
                        
        except Exception as e:
            print(f"[BUTTON DISABLE ERROR] {str(e)}")   
    # === DELEGIERTE CALL-METHODEN ===
    def on_call_click(self):
        """Delegate call initiation to CALL class"""
        if hasattr(self, 'call_manager'):
            self.call_manager.on_call_click(self.selected_entry)
        else:
            messagebox.showerror("Error", "Call system not initialized")

    def on_hangup_click(self):
        """Delegate hangup to CALL class"""
        if hasattr(self, 'call_manager'):
            self.call_manager.hangup_call()
        else:
            print("[HANGUP] No call manager available")

    def update_call_ui(self, active, status=None, caller_name=None):
        """Update UI for call status changes - VERBESSERT: Keine Rekursion"""
        try:
            # VERBESSERT: Rekursionsschutz
            if hasattr(self, '_updating_ui') and self._updating_ui:
                return
            self._updating_ui = True
            
            if active:
                if status == "requesting":
                    status_text = f"Anfrage an {caller_name}..." if caller_name else "Anrufanfrage..."
                elif status == "connected":
                    status_text = f"Verbunden mit: {caller_name}" if caller_name else "Aktiver Anruf"
                else:
                    status_text = f"Aktiver Anruf mit: {caller_name}" if caller_name else "Aktiver Anruf"
            else:
                status_text = "Bereit für Anrufe"
            
            # VERBESSERT: Direkte UI-Änderungen ohne Wrapper
            try:
                if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                    self.status_label.configure(text=status_text)
            except Exception as e:
                print(f"[STATUS LABEL ERROR] {str(e)}")
                
        except Exception as e:
            print(f"[UI UPDATE ERROR] {str(e)}")
        finally:
            # Flag immer zurücksetzen
            if hasattr(self, '_updating_ui'):
                self._updating_ui = False
    def _perform_connection(self, server_ip=None, server_port=None):
        """Führt die eigentliche Verbindung durch"""
        try:
            # Wenn keine Parameter, verwende manuelle Eingabe
            if server_ip is None and hasattr(self, 'server_ip_input'):
                server_ip = self.server_ip_input.get()
            if server_port is None and hasattr(self, 'server_port_input'):
                server_port = self.server_port_input.get()
            
            # Rest der vorhandenen Verbindungslogik...
            if not server_ip or not server_port:
                messagebox.showerror("Fehler", "Server-IP und Port benötigt")
                return
            
            # Socket erstellen und verbinden (vorhandener Code)
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(15)
            self.client_socket.connect((server_ip, int(server_port)))
            
            # Verbindung erfolgreich
            self.relay_status_label.configure(
                text=f"✅ Verbunden mit {server_ip}:{server_port}", 
                text_color="green"
            )
            
            # Starte Verbindungsthread (vorhandener Code)
            threading.Thread(
                target=self.start_connection_wrapper,
                args=(self.status_label, server_ip, server_port, self._client_name),
                daemon=True
            ).start()
            
            if hasattr(self, 'connection_window'):
                self.connection_window.destroy()
                
        except Exception as e:
            print(f"[CONNECTION ERROR] {str(e)}")
            self.relay_status_label.configure(text="❌ Verbindung fehlgeschlagen", text_color="red")
            self.cleanup_connection()
            raise
    # Beispiel für die Verwendung in Ihrer PHONEBOOK Klasse:

    def show_server_selection_dialog(self):
        """Zeigt einen Dialog zur Server-Auswahl an"""
        try:
            # Hole detaillierte Server-Informationen
            server_info = self.relay_manager.get_detailed_server_info()
            
            if 'error' in server_info:
                messagebox.showerror("Server Info", server_info['error'])
                return
            
            # Erstelle Auswahl-Dialog
            dialog = tk.Toplevel(self)
            dialog.title("Server Auswahl")
            dialog.geometry("600x400")
            
            # Besten Server anzeigen
            if server_info['best_server']:
                best = server_info['best_server']
                tk.Label(dialog, text=f"Empfohlener Server: {best['name']}", 
                        font=("Arial", 12, "bold"), fg="green").pack(pady=10)
                tk.Label(dialog, text=f"IP: {best['ip']}:{best['port']} | Ping: {best['ping_ms']}ms | Last: {best['load_percent']}%").pack()
            
            # Alle Server in einer Liste anzeigen
            tk.Label(dialog, text="\nVerfügbare Server:", font=("Arial", 10, "bold")).pack(pady=10)
            
            for server in server_info['servers']:
                status_color = "green" if server['status'] == 'available' else "red"
                server_text = f"{server['name']} - {server['ip']}:{server['port']} | Ping: {server['ping_ms']}ms | Last: {server['load_percent']}%"
                
                frame = tk.Frame(dialog)
                frame.pack(fill="x", padx=20, pady=2)
                
                tk.Label(frame, text=server_text, fg=status_color).pack(side="left")
                
                if server['status'] == 'available':
                    tk.Button(frame, text="Auswählen", 
                             command=lambda s=server: self._select_server(s['ip'])).pack(side="right")
            
        except Exception as e:
            messagebox.showerror("Fehler", f"Server-Auswahl fehlgeschlagen: {str(e)}")

    def _select_server(self, server_ip):
        """Wählt einen spezifischen Server aus"""
        if self.relay_manager.select_specific_server(server_ip):
            messagebox.showinfo("Server Auswahl", f"Server {server_ip} wurde ausgewählt")
        else:
            messagebox.showerror("Fehler", f"Server {server_ip} ist nicht erreichbar")      
    def update_server_status(self, message, color="white"):
        """Aktualisiert den Server-Status (nicht in der Kontaktliste)"""
        try:
            def safe_update():
                if hasattr(self, 'server_status_label') and self.server_status_label.winfo_exists():
                    self.server_status_label.configure(text=message, text_color=color)
            
            if threading.current_thread() == threading.main_thread():
                safe_update()
            else:
                self.after(0, safe_update)
                
        except Exception as e:
            print(f"[SERVER STATUS ERROR] {str(e)}")              
def is_linux():
    return sys.platform.startswith("linux")
def main():
    print("[DEBUG] Starting application...")
    security_monitor = None
    
    # Nur unter Linux versuchen
    if is_linux():
        try:
            from access_monitor import SecurityMonitor
            security_monitor = SecurityMonitor(hardening_rules={
                'prevent_fd_leaks': False,
                'restrict_env': False,
                'disable_debugger': True,
                'strict_path_checking': True
            })
            print("[INFO] Security Monitor aktiviert (Linux-only)")
        except ImportError:
            print("[INFO] access_monitor.py nicht gefunden - Laufe ohne Sicherheitsmonitor")
        except Exception as e:
            print(f"[WARN] Security Monitor fehlgeschlagen: {str(e)}")
    else:
        print(f"[INFO] Kein Security Monitor auf {sys.platform} (nur Linux unterstützt)")

    # Rest der Initialisierung (wie gehabt)
    try:
        app = PHONEBOOK()
        app.mainloop()
    except Exception as e:
        print(f"[ERROR] Hauptanwendung fehlgeschlagen: {str(e)}")
        traceback.print_exc()
if __name__ == "__main__":
    main()
