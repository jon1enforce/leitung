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
import mmap
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
    """Lädt den privaten Schlüssel - konsistent mit generate_keys() - KORRIGIERT"""
    try:
        if not os.path.exists("client_private_key.pem"):
            print("[KEY] Generating new RSA key pair...")
            # Generiere neuen RSA-Schlüssel
            bits = 4096
            new_key = RSA.gen_key(bits, 65537)

            # Speichere den privaten Schlüssel im PKCS#8 Format
            from M2Crypto import EVP
            pkey = EVP.PKey()
            pkey.assign_rsa(new_key)
            
            priv_memory = BIO.MemoryBuffer()
            pkey.save_key_bio(priv_memory, cipher=None)
            
            with open("client_private_key.pem", "wb") as privHandle:
                privHandle.write(priv_memory.getvalue())
            
            # Speichere auch den öffentlichen Schlüssel
            pub_memory = BIO.MemoryBuffer()
            new_key.save_pub_key_bio(pub_memory)
            public_key_pem = pub_memory.getvalue().decode('utf-8')

            with open("client_public_key.pem", "w") as pubHandle:
                pubHandle.write(public_key_pem)
            
            print("[KEY] New key pair generated successfully")
            return public_key_pem  # Rückgabe als String
            
        else:
            # Lade den privaten Schlüssel - KORREKTUR: Immer private key zurückgeben
            print("[KEY] Loading existing private key...")
            with open("client_private_key.pem", "rb") as f:
                private_key_data = f.read()
            
            # Validiere dass es ein privater Schlüssel ist
            private_key_str = private_key_data.decode('utf-8')
            if not ('-----BEGIN PRIVATE KEY-----' in private_key_str or 
                   '-----BEGIN RSA PRIVATE KEY-----' in private_key_str):
                raise ValueError("Invalid private key format in file")
            
            print("[KEY] Private key loaded successfully")
            return private_key_str  # WICHTIG: Private key als String zurückgeben
            
    except Exception as e:
        print(f"[KEY ERROR] Failed to load private key: {str(e)}")
        # Fallback: Versuche Schlüssel neu zu generieren
        try:
            print("[KEY] Attempting to regenerate keys...")
            if os.path.exists("client_private_key.pem"):
                os.remove("client_private_key.pem")
            if os.path.exists("client_public_key.pem"):
                os.remove("client_public_key.pem")
            return load_privatekey()  # Rekursiver Aufruf
        except:
            print("[KEY CRITICAL] Key generation failed")
            return None
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




class CALL:
    def __init__(self, client_instance):
        self.client = client_instance
        self.active_call = False
        self.pending_call = None
        self.incoming_call = None
        self.current_secret = None
        self.audio_threads = []
        # Audio settings
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 16000
        self.CHUNK = 1024
        self.PORT = 51821  # Audio port
        self.connection_state = "disconnected"  # disconnected, connecting, connected
        self.connection_lock = threading.Lock()
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
            # VERBESSERT: Explizite Prüfung auf Rekursion vermeiden
            if hasattr(self, '_in_call_click') and self._in_call_click:
                return
            self._in_call_click = True
            
            # Verwende übergebenen Eintrag oder falls None, versuche self.client.selected_entry
            if selected_entry is None and hasattr(self.client, 'selected_entry'):
                selected_entry = self.client.selected_entry
                
            if not selected_entry:
                messagebox.showerror("Error", "Bitte Kontakt auswählen")
                self._in_call_click = False
                return

            print(f"[CALL] Starte Anruf zu {selected_entry.get('name', 'Unknown')}")

            # Prüfe ob bereits ein aktiver Call läuft
            if self.active_call or self.pending_call:
                messagebox.showwarning("Warning", "Bereits in einem Anruf aktiv")
                self._in_call_click = False
                return

            # Validiere dass required fields vorhanden sind
            if 'id' not in selected_entry:
                messagebox.showerror("Error", "Ungültiger Kontakt (fehlende ID)")
                self._in_call_click = False
                return

            # Schritt 1: Anruf initiieren
            self.initiate_call(selected_entry)
            
            # UI auf "Warten" setzen - VERBESSERT: Direkter Aufruf ohne Wrapper
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
            # Sicherstellen dass Flag zurückgesetzt wird
            if hasattr(self, '_in_call_click'):
                self._in_call_click = False
    def _generate_wireguard_keypair(self):
        """Generiert ein WireGuard Schlüsselpaar"""
        try:
            # Private Key generieren
            private_key = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
            private_key = private_key.stdout.strip()
            
            # Public Key aus Private Key ableiten
            public_key = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True, check=True)
            public_key = public_key.stdout.strip()
            
            return private_key, public_key
        except Exception as e:
            print(f"[WIREGUARD ERROR] Key generation failed: {str(e)}")
            raise

    def _setup_wireguard_tunnel(self, private_key, peer_public_key, endpoint, my_ip):
        """Richtet einen WireGuard Tunnel ein - KORRIGIERT FÜR OPENBSD/LINUX"""
        try:
            interface = "wg-phonebook"
            
            # ✅ Privilegien-Eskalations-Tool erkennen
            sudo_command = None
            for cmd in ['doas', 'sudo']:
                try:
                    subprocess.run([cmd, 'echo', 'test'], capture_output=True, check=True)
                    sudo_command = cmd
                    print(f"[WG] Using {sudo_command} for privileged commands")
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            if not sudo_command:
                print("[WG WARNING] No sudo/doas found, trying without privileges")
                sudo_command = ""  # Leerstring für direkte Ausführung
            
            def run_privileged(cmd, input_data=None):
                """Hilfsfunktion für privilegierte Befehle"""
                full_cmd = [sudo_command] + cmd if sudo_command else cmd
                try:
                    if input_data:
                        result = subprocess.run(full_cmd, input=input_data, capture_output=True, text=True, check=True)
                    else:
                        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"[WG ERROR] Command failed: {e.stderr}")
                    return False
                except Exception as e:
                    print(f"[WG ERROR] Command execution failed: {e}")
                    return False
            
            # Interface erstellen
            if not run_privileged(['ip', 'link', 'add', 'dev', interface, 'type', 'wireguard']):
                return False
            
            # Private Key setzen
            if not run_privileged(['wg', 'set', interface, 'private-key'], input_data=private_key):
                return False
            
            # Peer konfigurieren
            if not run_privileged(['wg', 'set', interface, 'peer', peer_public_key, 'endpoint', endpoint, 'allowed-ips', '0.0.0.0/0']):
                return False
            
            # IP Adresse setzen
            if not run_privileged(['ip', 'addr', 'add', f'{my_ip}/24', 'dev', interface]):
                return False
            
            # Interface aktivieren
            if not run_privileged(['ip', 'link', 'set', 'up', 'dev', interface]):
                return False
            
            print(f"[WG] WireGuard tunnel setup successful: {my_ip} -> {endpoint}")
            return True
            
        except Exception as e:
            print(f"[WIREGUARD ERROR] Tunnel setup failed: {str(e)}")
            return False
    def _update_ui_wrapper(self, active, status=None, caller_name=None):
        """Wrapper für UI-Updates mit Fallback - VERBESSERT: Vereinfacht"""
        try:
            # VERBESSERT: Direkter Aufruf ohne Rekursion
            self.update_call_ui(active, status, caller_name)
        except Exception as e:
            print(f"[UI WRAPPER WARNING] Failed to update UI: {str(e)}")
            # Fallback: Einfache Status-Änderung
            try:
                if hasattr(self.client, 'status_label') and self.client.status_label.winfo_exists():
                    if active:
                        self.client.status_label.configure(text="Aktiver Anruf")
                    else:
                        self.client.status_label.configure(text="Bereit")
            except:
                pass
    


    def _handle_session_key(self, msg):
        """Verarbeitet Session Key vom Server"""
        try:
            custom_data = msg.get('custom_data', {})
            encrypted_session = custom_data.get('ENCRYPTED_SESSION')
            
            if encrypted_session:
                # Entschlüssele Session Key mit privatem Schlüssel
                private_key = load_privatekey()
                priv_key = RSA.load_key_string(private_key.encode())
                
                encrypted_bytes = base64.b64decode(encrypted_session)
                decrypted = priv_key.private_decrypt(encrypted_bytes, RSA.pkcs1_padding)
                
                # Erwartetes Format: b"+++session_key+++" + 48 Bytes
                if decrypted.startswith(b"+++session_key+++"):
                    session_secret = decrypted[17:65]  # 48 Bytes
                    self.current_secret = session_secret
                    print("[CALL] Session key received and stored")
                    
                    # Starte Audio wenn Call pending
                    if hasattr(self, 'pending_call') and self.pending_call.get('status') == 'accepted':
                        self._start_audio_streams()
                        
        except Exception as e:
            print(f"[CALL ERROR] Session key handling failed: {str(e)}")
    def handle_message(self, raw_message):
        """Zentrale Message-Handling Methode - KORRIGIERT FÜR MESSAGE-TYPE ERKENNUNG"""
        try:
            print(f"[CALL] Handling raw message type: {type(raw_message)}")
            
            # ✅ Zuerst die Nachricht korrekt parsen
            if isinstance(raw_message, str):
                # Verwende den SIP-Parser des Clients
                if hasattr(self.client, 'parse_sip_message'):
                    msg = self.client.parse_sip_message(raw_message)
                else:
                    # Fallback: Versuche JSON zu parsen
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
                
            # ✅ Jetzt den Message-Type aus der geparsten Nachricht extrahieren
            message_type = self._extract_message_type(msg)
            print(f"[CALL] Handling message type: {message_type}")
            
            if message_type == 'INCOMING_CALL':
                self.handle_incoming_call(msg)
            elif message_type == 'SESSION_KEY':
                self._handle_session_key(msg)
            elif message_type == 'CALL_RESPONSE':
                self.handle_call_response(msg)
            elif message_type == 'PUBLIC_KEY_RESPONSE':
                print("[CALL] Received PUBLIC_KEY_RESPONSE, processing...")
                self.handle_public_key_response(msg)
            elif message_type == 'CALL_TIMEOUT':
                self.cleanup_call_resources()
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo("Call Failed", "Timeout - Keine Antwort vom Empfänger"))
            elif message_type == 'CALL_END':
                self.cleanup_call_resources()
            elif message_type == 'PONG':
                print("[CALL] Pong received")  # Ignorieren
            else:
                print(f"[CALL WARNING] Unknown message type: {message_type}")
                
        except Exception as e:
            print(f"[CALL MSG ERROR] Failed to handle message: {str(e)}")
            import traceback
            traceback.print_exc()

    def _extract_message_type(self, parsed_msg):
        """EINHEITLICHE MESSAGE-TYPE EXTRAKTION - KORRIGIERT FÜR GEPARSTE NACHRICHTEN"""
        try:
            if not parsed_msg:
                return "UNKNOWN"
            
            # ✅ PRIORITÄT 1: custom_data aus geparster SIP-Nachricht
            custom_data = parsed_msg.get('custom_data', {})
            message_type = custom_data.get('MESSAGE_TYPE')
            
            if message_type:
                return message_type
            
            # ✅ PRIORITÄT 2: Direkt aus dem Dictionary (falls bereits geparst)
            message_type = parsed_msg.get('MESSAGE_TYPE')
            if message_type:
                return message_type
                
            # ✅ PRIORITÄT 3: Body als JSON parsen
            body = parsed_msg.get('body', '')
            if body.strip().startswith('{'):
                try:
                    body_data = json.loads(body)
                    return body_data.get('MESSAGE_TYPE', 'UNKNOWN')
                except json.JSONDecodeError:
                    pass
            
            # ✅ PRIORITÄT 4: Headers durchsuchen
            headers = parsed_msg.get('headers', {})
            message_type = headers.get('MESSAGE_TYPE')
            if message_type:
                return message_type
                
            return "UNKNOWN"
            
        except Exception as e:
            print(f"[EXTRACT ERROR] {str(e)}")
            return "UNKNOWN"


    def initiate_call(self, recipient):
        """Initiiert Anruf mit EINHEITLICHEM Format - KORRIGIERT"""
        try:
            print(f"[CALL] Starting call to {recipient.get('name', 'Unknown')}")

            # 1. Validiere Eingabe
            if not recipient or 'id' not in recipient:
                raise ValueError("Ungültiger Empfänger (fehlende ID)")

            # 2. Prüfe aktive Calls
            if self.active_call or self.pending_call:
                raise RuntimeError("Bereits in einem Anruf aktiv")

            # 3. EINHEITLICHE GET_PUBLIC_KEY Nachricht
            key_request_data = {
                "MESSAGE_TYPE": "GET_PUBLIC_KEY",
                "TARGET_CLIENT_ID": recipient['id'],
                "CALLER_NAME": self.client._client_name,
                "CALLER_CLIENT_ID": self.client._find_my_client_id()
            }
            
            key_request_msg = self.client.build_sip_message(
                "MESSAGE", 
                "server", 
                key_request_data
            )

            # 4. EINHEITLICHES Framing verwenden
            if not self.client._send_message(key_request_msg):
                raise ConnectionError("Konnte Key-Request nicht senden")

            # 5. Call-Status setzen
            self.pending_call = {
                'recipient': recipient,
                'status': 'requesting_key',
                'start_time': time.time(),
                'timeout': 120
            }

            # 6. UI aktualisieren
            if hasattr(self.client, 'update_call_ui'):
                self.client.update_call_ui(True, "requesting", recipient.get('name', 'Unknown'))

            print(f"[CALL] Call initiated to {recipient.get('name', 'Unknown')}")

            # 7. Timeout-Überwachung starten
            threading.Thread(target=self._call_timeout_watchdog, daemon=True).start()

        except Exception as e:
            print(f"[CALL ERROR] Initiation failed: {str(e)}")
            self.cleanup_call_resources()
            if hasattr(self.client, 'show_error'):
                self.client.show_error(f"Anruf fehlgeschlagen: {str(e)}")
            raise

    def handle_public_key_response(self, msg):
        """Verarbeitet Public-Key-Antwort - KORRIGIERT FÜR PEM-FORMAT"""
        try:
            # ✅ VALIDIERE: Prüfe ob wir auf eine Key-Anfrage warten
            if not self.pending_call or self.pending_call.get('status') != 'requesting_key':
                print("[CALL WARNING] Unexpected public key response - no pending call or wrong status")
                return False
                
            print(f"[CALL] Processing public key response...")
            
            # ✅ SICHERSTELLEN: msg ist ein Dictionary
            if not isinstance(msg, dict):
                print(f"[CALL ERROR] Expected dict but got {type(msg)}")
                return False
                
            # ✅ KORREKT: Daten aus CUSTOM_DATA extrahieren
            custom_data = msg.get('custom_data', {})
            target_id = custom_data.get('TARGET_CLIENT_ID')
            public_key = custom_data.get('PUBLIC_KEY')
            caller_name = custom_data.get('CALLER_NAME')
            
            # ✅ FALLBACK: Direkte Felder prüfen
            if not public_key:
                public_key = msg.get('PUBLIC_KEY')
            if not target_id:
                target_id = msg.get('TARGET_CLIENT_ID')
            if not caller_name:
                caller_name = msg.get('CALLER_NAME')
                
            if not public_key:
                print("[CALL ERROR] No public key received in any field")
                raise Exception("No public key received from server")
                
            if not target_id:
                print("[CALL WARNING] No target ID in response")
                target_id = self.pending_call['recipient'].get('id', 'unknown')
                
            print(f"[CALL] Received public key for client {target_id} (length: {len(public_key)})")
            
            # ✅ KRITISCHE KORREKTUR: PEM-FORMAT SICHERSTELLEN
            print("[CALL] Formatting public key for PEM...")
            public_key = self._ensure_pem_format(public_key)
            if not public_key:
                raise Exception("Invalid public key format - cannot convert to PEM")
                
            print(f"[CALL] Formatted public key (PEM): {public_key[:100]}...")
            
            # ✅ WireGuard Schlüsselpaar generieren
            wg_private_key, wg_public_key = self._generate_wireguard_keypair()
            print(f"[CALL] Generated WireGuard keys (pub: {wg_public_key[:20]}...)")
            
            # ✅ Session Key generieren (48 Bytes: 16 IV + 32 AES Key)
            session_secret = os.urandom(48)
            iv = session_secret[:16]
            aes_key = session_secret[16:48]
            
            # ✅ Call-Daten vorbereiten
            call_data = {
                "caller_name": self.client._client_name,
                "caller_client_id": self.client._find_my_client_id(),
                "caller_wg_public_key": wg_public_key,
                "caller_wg_listen_port": 51820,
                "caller_public_ip": self._get_public_ip(),
                "caller_local_ip": self._get_local_ip(),
                "aes_iv": base64.b64encode(iv).decode('utf-8'),
                "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                "timestamp": time.time(),
                "call_type": "wireguard_audio"
            }
            
            print(f"[CALL] Prepared call data for encryption")
            
            # ✅ Mit Public Key des Empfängers verschlüsseln
            try:
                # Public Key laden mit PEM-Validierung
                print("[CALL] Loading recipient public key...")
                recipient_key = self._load_public_key(public_key)
                if not recipient_key:
                    raise Exception("Failed to load recipient public key")
                    
                # Daten serialisieren und verschlüsseln
                call_data_json = json.dumps(call_data).encode('utf-8')
                print(f"[CALL] Call data JSON length: {len(call_data_json)}")
                
                # Prüfe ob Daten zu lang für RSA sind
                max_length = 512 - 11  # RSA PKCS#1 Padding
                if len(call_data_json) > max_length:
                    raise Exception(f"Call data too large for RSA encryption: {len(call_data_json)} > {max_length}")
                    
                encrypted_data = recipient_key.public_encrypt(call_data_json, RSA.pkcs1_padding)
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
                print(f"[CALL] Call data encrypted successfully (size: {len(encrypted_b64)} chars)")
                
            except Exception as e:
                print(f"[CALL ERROR] Encryption failed: {str(e)}")
                raise Exception(f"Verschlüsselung fehlgeschlagen: {str(e)}")
            
            # ✅ CALL_REQUEST an Server senden
            call_request_data = {
                "MESSAGE_TYPE": "CALL_REQUEST",
                "TARGET_CLIENT_ID": target_id,
                "ENCRYPTED_CALL_DATA": encrypted_b64,
                "CALLER_NAME": self.client._client_name,
                "CALLER_CLIENT_ID": self.client._find_my_client_id(),
                "TIMESTAMP": int(time.time())
            }
            
            call_request_msg = self.client.build_sip_message("MESSAGE", "server", call_request_data)
            
            if not self.client._send_message(call_request_msg):
                raise Exception("Failed to send CALL_REQUEST to server")
                
            print("[CALL] CALL_REQUEST sent to server")
            
            # ✅ Call-Status aktualisieren
            self.pending_call.update({
                'status': 'request_sent',
                'wg_private_key': wg_private_key,
                'wg_public_key': wg_public_key,
                'session_secret': session_secret,
                'target_id': target_id
            })
            
            # ✅ WireGuard Server vorbereiten (als Caller)
            print("[CALL] Setting up WireGuard tunnel as caller...")
            success = self._setup_caller_wireguard(wg_private_key, wg_public_key)
            
            if not success:
                raise Exception("WireGuard tunnel setup failed")
                
            print("[CALL] WireGuard tunnel setup complete - waiting for callee...")
            
            # ✅ UI aktualisieren
            recipient_name = self.pending_call['recipient'].get('name', 'Unknown')
            if hasattr(self.client, 'update_call_ui'):
                self.client.update_call_ui(True, "ringing", recipient_name)
                
            return True
            
        except Exception as e:
            print(f"[CALL ERROR] Public key response handling failed: {str(e)}")
            
            # ✅ Fehler an UI melden
            if hasattr(self.client, 'after'):
                self.client.after(0, lambda: messagebox.showerror(
                    "Call Failed", 
                    f"Verbindungsaufbau fehlgeschlagen: {str(e)}"
                ))
            
            self.cleanup_call_resources()
            return False

    def _ensure_pem_format(self, key_data):
        """Stellt sicher dass der Schlüssel im korrekten PEM-Format vorliegt"""
        try:
            if not key_data:
                return None
                
            key_str = key_data.strip()
            
            # Falls bereits korrektes PEM, zurückgeben
            if key_str.startswith('-----BEGIN PUBLIC KEY-----') and key_str.endswith('-----END PUBLIC KEY-----'):
                print("[PEM] Key is already in valid PEM format")
                return key_str
            
            # Falls Base64 ohne PEM-Header, Header hinzufügen
            if 'BEGIN PUBLIC KEY' not in key_str and 'END PUBLIC KEY' not in key_str:
                print("[PEM] Adding PEM headers to base64 key")
                # Entferne alle Leerzeichen und Zeilenumbrüche
                key_content = re.sub(r'\s+', '', key_str)
                # Validiere Base64
                try:
                    base64.b64decode(key_content)
                    key_str = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
                    print("[PEM] Successfully converted to PEM format")
                except Exception as e:
                    print(f"[PEM ERROR] Invalid base64: {e}")
                    return None
            
            # Validiere den PEM-Key
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
                
            # Bereinige den Key
            pem_key = pem_key.strip()
            pem_key = pem_key.replace('\\\\n', '\n').replace('\\n', '\n')
            
            print(f"[KEY LOAD] Loading key: {pem_key[:100]}...")
            
            # Versuche den Key zu laden
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

    def _setup_caller_wireguard(self, private_key, public_key):
        """Richtet WireGuard als Caller (Server) ein - KORRIGIERT FÜR OPENBSD/LINUX"""
        try:
            interface = "wg-phonebook"
            
            # ✅ Privilegien-Eskalations-Tool erkennen
            sudo_command = None
            for cmd in ['doas', 'sudo']:
                try:
                    subprocess.run([cmd, 'echo', 'test'], capture_output=True, check=True)
                    sudo_command = cmd
                    print(f"[WG] Using {sudo_command} for privileged commands")
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            if not sudo_command:
                print("[WG WARNING] No sudo/doas found, trying without privileges")
                sudo_command = ""  # Leerstring für direkte Ausführung
            
            def run_privileged(cmd, input_data=None):
                """Hilfsfunktion für privilegierte Befehle"""
                full_cmd = [sudo_command] + cmd if sudo_command else cmd
                try:
                    if input_data:
                        result = subprocess.run(full_cmd, input=input_data, capture_output=True, text=True)
                    else:
                        result = subprocess.run(full_cmd, capture_output=True, text=True)
                    return result
                except Exception as e:
                    print(f"[WG ERROR] Command failed: {e}")
                    return type('Result', (), {'returncode': 1, 'stderr': str(e)})()
            
            # ✅ Altes Interface bereinigen
            run_privileged(['ip', 'link', 'del', 'dev', interface])
            time.sleep(0.5)
            
            # ✅ Neues Interface erstellen
            result = run_privileged(['ip', 'link', 'add', 'dev', interface, 'type', 'wireguard'])
            if result.returncode != 0:
                print(f"[WG ERROR] Interface creation failed: {result.stderr}")
                return False
            
            # ✅ Private Key setzen
            result = run_privileged(['wg', 'set', interface, 'private-key', '/dev/stdin'], input_data=private_key)
            if result.returncode != 0:
                print(f"[WG ERROR] Private key setup failed: {result.stderr}")
                return False
            
            # ✅ Listen Port setzen
            result = run_privileged(['wg', 'set', interface, 'listen-port', '51820'])
            if result.returncode != 0:
                print(f"[WG ERROR] Listen port setup failed: {result.stderr}")
                return False
            
            # ✅ IP Adresse setzen (Caller bekommt .1)
            result = run_privileged(['ip', 'addr', 'add', '10.8.0.1/24', 'dev', interface])
            if result.returncode != 0:
                print(f"[WG ERROR] IP assignment failed: {result.stderr}")
                return False
            
            # ✅ Interface aktivieren
            result = run_privileged(['ip', 'link', 'set', 'up', 'dev', interface])
            if result.returncode != 0:
                print(f"[WG ERROR] Interface activation failed: {result.stderr}")
                return False
            
            print("[WG] WireGuard tunnel setup successful as caller (10.8.0.1)")
            return True
            
        except Exception as e:
            print(f"[WG ERROR] Tunnel setup failed: {str(e)}")
            return False
    def handle_incoming_call(self, msg):
        """Verarbeitet eingehende Anrufe"""
        try:
            headers = msg.get('headers', {})
            custom_data = msg.get('custom_data', {})
            
            # Prüfe beide Quellen für Call-Informationen
            caller_name = headers.get('CALLER_NAME') or custom_data.get('CALLER_NAME')
            caller_id = headers.get('CALLER_CLIENT_ID') or custom_data.get('CALLER_CLIENT_ID')
            encrypted_data = headers.get('ENCRYPTED_CALL_DATA') or custom_data.get('ENCRYPTED_CALL_DATA')
            
            if not all([caller_name, caller_id, encrypted_data]):
                print("[CALL ERROR] Missing call information")
                self._send_call_response("rejected", caller_id)
                return
                
            print(f"[CALL] Incoming call from {caller_name}")
            
            # In UI thread abfragen
            if hasattr(self.client, 'after'):
                self.client.after(0, lambda: self._ask_call_acceptance(
                    caller_name, caller_id, encrypted_data))
            else:
                self._ask_call_acceptance(caller_name, caller_id, encrypted_data)
                
        except Exception as e:
            print(f"[CALL ERROR] Incoming call handling failed: {str(e)}")
            self._send_call_response("error", caller_id)

    def _ask_call_acceptance(self, caller_name, caller_id, encrypted_data):
        """Fragt Benutzer nach Annahme des Anrufs"""
        try:
            accept = messagebox.askyesno(
                "Eingehender Anruf",
                f"Eingehender Anruf von {caller_name}.\nAnnehmen?"
            )
            
            if accept:
                self._accept_incoming_call(caller_name, caller_id, encrypted_data)
            else:
                self._reject_incoming_call(caller_id)
                
        except Exception as e:
            print(f"[CALL ERROR] Acceptance dialog failed: {str(e)}")
            self._reject_incoming_call(caller_id)

    def _accept_incoming_call(self, caller_name, caller_id, encrypted_data):
        """Nimmt eingehenden Anruf an"""
        try:
            # Daten entschlüsseln
            private_key = load_privatekey()
            priv_key = RSA.load_key_string(private_key.encode())
            
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted_bytes = priv_key.private_decrypt(encrypted_bytes, RSA.pkcs1_padding)
            call_info = json.loads(decrypted_bytes.decode('utf-8'))
            
            # WireGuard Schlüsselpaar generieren (direkt in CALL-Klasse)
            wg_private_key, wg_public_key = self._generate_wireguard_keypair()
            
            # WireGuard konfigurieren
            caller_endpoint = f"{call_info.get('caller_public_ip', '')}:51820"
            my_wg_ip = "10.8.0.2"
            
            success = self._setup_wireguard_tunnel(wg_private_key, call_info['caller_wg_public_key'], caller_endpoint, my_wg_ip)
            
            if not success:
                raise Exception("WireGuard setup failed")
                
            # Call-Daten speichern
            self.pending_call = {
                'caller_name': caller_name,
                'caller_id': caller_id,
                'wg_private_key': wg_private_key,
                'wg_peer_key': call_info['caller_wg_public_key'],
                'aes_iv': base64.b64decode(call_info['aes_iv']),
                'aes_key': base64.b64decode(call_info['aes_key']),
                'status': 'accepted'
            }
            
            # Session Key speichern
            self.current_secret = self.pending_call['aes_iv'] + self.pending_call['aes_key']
            
            # Akzeptanz an Server senden
            self._send_call_response("accepted", caller_id, wg_public_key)
            
            # Audio starten
            self._start_audio_streams()
            
            # UI aktualisieren
            self._update_ui_wrapper(active=True, status="connected", caller_name=caller_name)
            
            print("[CALL] Call accepted and setup complete")
            
        except Exception as e:
            print(f"[CALL ERROR] Acceptance failed: {str(e)}")
            self._send_call_response("error", caller_id)
            self.cleanup_call_resources()

    def _reject_incoming_call(self, caller_id):
        """Lehnt eingehenden Anruf ab"""
        try:
            self._send_call_response("rejected", caller_id)
            print("[CALL] Call rejected")
        except Exception as e:
            print(f"[CALL ERROR] Rejection failed: {str(e)}")

    def _send_call_response(self, response, caller_id, wg_public_key=None):
        """Sendet Call-Antwort an Server"""
        try:
            response_data = {
                "MESSAGE_TYPE": "CALL_RESPONSE",
                "RESPONSE": response,
                "CALLER_CLIENT_ID": caller_id,
                "TIMESTAMP": int(time.time())
            }
            
            if wg_public_key:
                response_data["CALLEE_WG_PUBLIC_KEY"] = wg_public_key
                response_data["CALLEE_IP"] = self._get_public_ip()
            
            response_msg = self.client.build_sip_message("MESSAGE", "server", response_data)
            self.client._send_message(response_msg)
            
        except Exception as e:
            print(f"[CALL ERROR] Failed to send response: {str(e)}")

    # === CALL RESPONSE HANDLING ===
    def handle_call_response(self, msg):
        """Verarbeitet Antwort auf eigenen Anruf"""
        try:
            if not self.pending_call:
                print("[CALL WARNING] No pending call for response")
                return
                
            custom_data = msg.get('custom_data', {})
            response = custom_data.get('RESPONSE')
            callee_wg_key = custom_data.get('CALLEE_WG_PUBLIC_KEY')
            callee_ip = custom_data.get('CALLEE_IP')
            
            if response == "accepted" and callee_wg_key:
                print("[CALL] Call accepted by recipient")
                self._setup_outgoing_call(callee_wg_key, callee_ip)
            elif response == "rejected":
                print("[CALL] Call rejected by recipient")
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo("Call Rejected", "Der Empfänger hat den Anruf abgelehnt"))
                self.cleanup_call_resources()
            elif response == "timeout":
                print("[CALL] Call timeout")
                if hasattr(self.client, 'after'):
                    self.client.after(0, lambda: messagebox.showinfo("Call Failed", "Der Empfänger hat nicht geantwortet"))
                self.cleanup_call_resources()
            else:
                print(f"[CALL] Unknown response: {response}")
                self.cleanup_call_resources()
                
        except Exception as e:
            print(f"[CALL ERROR] Response handling failed: {str(e)}")
            self.cleanup_call_resources()

    def _setup_outgoing_call(self, callee_wg_key, callee_ip=None):
        """Richtet ausgehenden Anruf ein"""
        try:
            # WireGuard konfigurieren
            public_ip = callee_ip or self._get_public_ip()
            my_wg_ip = "10.8.0.1"  # Caller bekommt .1
            
            wg_config = self.client.wg_manager.create_interface_config(
                self.pending_call['wg_private_key'],
                callee_wg_key,
                f"{public_ip}:51820",
                my_wg_ip
            )
            
            success = self.client.wg_manager.setup_wireguard_tunnel(wg_config)
            
            if success:
                self.pending_call['status'] = 'connected'
                self.pending_call['wg_peer_key'] = callee_wg_key
                
                # Session Key aus pending_call verwenden
                if 'session_secret' in self.pending_call:
                    self.current_secret = self.pending_call['session_secret']
                    self._start_audio_streams()
                
                # UI aktualisieren
                recipient_name = self.pending_call['recipient'].get('name', 'Unknown')
                self._update_ui_wrapper(active=True, status="connected", caller_name=recipient_name)
                print("[CALL] Outgoing call setup complete")
            else:
                raise Exception("WireGuard setup failed")
                
        except Exception as e:
            print(f"[CALL ERROR] Outgoing call setup failed: {str(e)}")
            self.cleanup_call_resources()

    # === AUDIO STREAMS ===
    def _start_audio_streams(self):
        """Startet bidirektionale Audio-Streams"""
        if not self.current_secret:
            print("[AUDIO] No session key available")
            return
            
        try:
            # Extrahiere AES-Parameter
            iv = self.current_secret[:16]
            key = self.current_secret[16:48]
            
            # Ziel-IP im WireGuard-Netzwerk basierend auf der Rolle
            if self.pending_call and 'recipient' in self.pending_call:
                # Wir sind der Anrufer -> Ziel ist 10.8.0.2
                target_ip = "10.8.0.2"
            else:
                # Wir sind der Angerufene -> Ziel ist 10.8.0.1
                target_ip = "10.8.0.1"
            
            # Beende bestehende Audio-Threads
            self._stop_audio_streams()
            
            # Starte Sende-Thread
            send_thread = threading.Thread(
                target=self.audio_stream_out, 
                args=(target_ip, iv, key),
                daemon=True
            )
            
            # Starte Empfangs-Thread  
            recv_thread = threading.Thread(
                target=self.audio_stream_in,
                args=(iv, key),
                daemon=True
            )
            
            send_thread.start()
            recv_thread.start()
            
            self.audio_threads = [send_thread, recv_thread]
            self.active_call = True
            print(f"[AUDIO] Bidirectional audio streams started to {target_ip}")
            
        except Exception as e:
            print(f"[AUDIO ERROR] Failed to start streams: {e}")

    def _stop_audio_streams(self):
        """Stoppt alle Audio-Streams"""
        self.active_call = False
        time.sleep(0.1)  # Kurze Pause für Threads zum Beenden
        
        for thread in self.audio_threads:
            try:
                if thread.is_alive():
                    thread.join(timeout=1.0)
            except:
                pass
        self.audio_threads = []

    def audio_stream_out(self, target_ip, iv, key):
        """Sendet Audio an Ziel-IP"""
        audio = None
        stream = None
        audio_socket = None
        
        try:
            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=self.FORMAT,
                channels=self.CHANNELS,
                rate=self.RATE,
                input=True,
                frames_per_buffer=self.CHUNK
            )
            
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            audio_socket.settimeout(0.1)
            
            print(f"[AUDIO OUT] Streaming to {target_ip}:{self.PORT}")
            
            while self.active_call:
                try:
                    data = stream.read(self.CHUNK, exception_on_overflow=False)
                    
                    # Verschlüsseln
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 1)
                    encrypted_data = cipher.update(data) + cipher.final()
                    
                    audio_socket.sendto(encrypted_data, (target_ip, self.PORT))
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.active_call:
                        print(f"[AUDIO OUT ERROR] {str(e)}")
                    break
                    
        except Exception as e:
            print(f"[AUDIO OUT SETUP ERROR] {str(e)}")
        finally:
            try:
                if stream:
                    stream.stop_stream()
                    stream.close()
                if audio:
                    audio.terminate()
                if audio_socket:
                    audio_socket.close()
            except:
                pass

    def audio_stream_in(self, iv, key):
        """Empfängt Audio"""
        audio = None
        stream = None
        audio_socket = None
        
        try:
            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=self.FORMAT,
                channels=self.CHANNELS,
                rate=self.RATE,
                output=True,
                frames_per_buffer=self.CHUNK
            )
            
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            audio_socket.bind(('0.0.0.0', self.PORT))
            audio_socket.settimeout(0.1)
            
            print("[AUDIO IN] Listening for audio...")
            
            while self.active_call:
                try:
                    encrypted_data, addr = audio_socket.recvfrom(4096)
                    
                    # Entschlüsseln
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 0)
                    decrypted_data = cipher.update(encrypted_data) + cipher.final()
                    
                    stream.write(decrypted_data)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.active_call:
                        print(f"[AUDIO IN ERROR] {str(e)}")
                    break
                    
        except Exception as e:
            print(f"[AUDIO IN SETUP ERROR] {str(e)}")
        finally:
            try:
                if stream:
                    stream.stop_stream()
                    stream.close()
                if audio:
                    audio.terminate()
                if audio_socket:
                    audio_socket.close()
            except:
                pass

    # === TIMEOUT & CLEANUP ===
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
        """Bereinigt alle Call-Ressourcen"""
        print("[CALL] Cleaning up call resources...")
        self.active_call = False
        
        # Audio-Threads stoppen
        self._stop_audio_streams()
        
        # WireGuard herunterfahren
        try:
            if hasattr(self.client, 'wg_manager'):
                self.client.wg_manager.cleanup()
        except Exception as e:
            print(f"[CLEANUP WARNING] WireGuard cleanup failed: {str(e)}")
        
        # Variablen zurücksetzen
        self.pending_call = None
        self.incoming_call = None
        self.current_secret = None
        
        # UI zurücksetzen
        try:
            self._update_ui_wrapper(active=False)
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



    def _get_public_ip(self):
        """Ermittelt die öffentliche IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_local_ip(self):
        """Ermittelt die lokale IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def on_entry_click(self, entry):
        """Handler für Klicks auf Telefonbucheinträge"""
        try:
            self.client.selected_entry = entry
            print(f"[CALL] Selected entry: {entry.get('name', 'Unknown')}")
        except Exception as e:
            print(f"[CALL ERROR] Entry click failed: {str(e)}")
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
        self.active_call = False
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
        settings_menu.add_command(label="Tastatur", command=self.open_keyboard_settings)
        settings_menu.add_command(label="Sprache", command=self.open_language_settings)
        self.menu_bar.add_cascade(label="Einstellungen", menu=settings_menu)

        # Notebook für Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        # Telefonbuch-Tab
        self.phonebook_tab = ctk.CTkFrame(self.notebook, fg_color='black')
        self.notebook.add(self.phonebook_tab, text="Telefonbuch")
        self.create_phonebook_tab()

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
        """KORRIGIERTE Connection-Loop mit besserem Timeout-Management"""
        global connected
        connected = True
        print("[CONNECTION] Starting improved connection loop")
        
        # Lokale IP ermitteln
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            print(f"[CONNECTION] Local IP: {local_ip}")
        except Exception as ip_error:
            print(f"[WARNING] Could not determine local IP: {ip_error}")
            local_ip = "127.0.0.1"
        
        client_name = self._client_name
        ping_interval = 30  # Normales Ping-Intervall
        fast_ping_interval = 5  # Schnelles Intervall bei ausstehenden Requests
        last_ping_time = 0
        pending_requests = 0
        
        while connected:
            try:
                current_time = time.time()
                
                # Entscheide Ping-Intervall basierend auf ausstehenden Requests
                if pending_requests > 0:
                    interval = fast_ping_interval
                    print(f"[PING] Fast mode ({interval}s) - {pending_requests} pending requests")
                else:
                    interval = ping_interval
                
                # Ping senden wenn Intervall abgelaufen
                if current_time - last_ping_time >= interval:
                    # 1. Ping vorbereiten
                    ping_data = {
                        "MESSAGE_TYPE": "PING",
                        "TIMESTAMP": int(current_time),
                        "CLIENT_NAME": client_name,
                        "CLIENT_IP": local_ip,
                        "PENDING_REQUESTS": pending_requests
                    }
                    
                    ping_msg = self.build_sip_message("MESSAGE", server_ip, ping_data)
                    
                    # 2. Ping senden
                    print(f"[PING] Sending ping to {server_ip}")
                    if send_frame(client_socket, ping_msg.encode('utf-8')):
                        last_ping_time = current_time
                        pending_requests += 1  # Ping als ausstehenden Request zählen
                    else:
                        print("[PING ERROR] Failed to send ping")
                        connected = False
                        break
                
                # 3. Auf Antwort warten mit kürzerem Timeout
                client_socket.settimeout(3.0)  # Nur 3 Sekunden warten
                
                try:
                    response = recv_frame(client_socket, timeout=3)
                    
                    if response is None:
                        # Timeout ist normal - weiter im Loop
                        continue
                        
                    if isinstance(response, bytes):
                        response = response.decode('utf-8')
                    
                    # 4. Antwort verarbeiten
                    if response:
                        sip_data = self.parse_sip_message(response)
                        if sip_data:
                            custom_data = sip_data.get('custom_data', {})
                            message_type = custom_data.get('MESSAGE_TYPE')
                            
                            if message_type == 'PONG':
                                print("[PING] Pong received successfully")
                                pending_requests = max(0, pending_requests - 1)
                                
                            elif message_type == 'IDENTITY_CHALLENGE':
                                print("[IDENTITY] Challenge received in ping loop")
                                self._handle_identity_challenge(sip_data)
                                pending_requests = max(0, pending_requests - 1)
                                
                            elif message_type == 'PHONEBOOK_UPDATE':
                                print("[UPDATE] Phonebook received in ping loop")
                                self._process_phonebook_update(sip_data)
                                pending_requests = max(0, pending_requests - 1)
                                
                            else:
                                print(f"[PING] Other message: {message_type}")
                                # Zur normalen Verarbeitung weiterleiten
                                self.handle_server_message(response)
                        
                        else:
                            print("[PING] Could not parse server response")
                    
                except socket.timeout:
                    # Timeout ist normal bei schnellen Pings
                    continue
                    
                except ConnectionError as e:
                    print(f"[CONNECTION ERROR] Connection lost: {e}")
                    connected = False
                    break
                    
                except Exception as e:
                    print(f"[CONNECTION ERROR] Unexpected error: {e}")
                    # Kein Break - versuche Verbindung zu halten
                    continue
                
                # Kurze Pause zwischen Durchläufen
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[CONNECTION LOOP ERROR] {str(e)}")
                connected = False
                break
        
        # Verbindungsende
        print("[CONNECTION] Connection loop ended")
        connected = False
        self.cleanup_connection()
    def start_connection(self, server_ip, server_port, client_name, client_socket, message_handler=None):
        """VOLLSTÄNDIG KORRIGIERTE REGISTRATION MIT EINHEITLICHEM PARSING"""
        try:
            # 1. Configure socket
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client_socket.settimeout(15.0)

            # 2. Load client public key
            client_pubkey = load_publickey()
            if not is_valid_public_key(client_pubkey):
                raise ValueError("Invalid client public key format")

            # 3. REGISTRATION NACHRICHT
            register_data = {
                "MESSAGE_TYPE": "REGISTER",
                "CLIENT_NAME": client_name,
                "PUBLIC_KEY": client_pubkey,
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0"
            }
            
            register_msg = self.build_sip_message(
                "REGISTER", 
                f"{server_ip}:{server_port}", 
                register_data, 
                from_server=False,
                client_name=client_name
            )
            
            print("\n[Client] Sending registration...")
            send_frame(client_socket, register_msg.encode('utf-8'))

            # 4. Response empfangen und parsen
            response = recv_frame(client_socket)
            if not response:
                raise ConnectionError("Empty response from server")

            if isinstance(response, bytes):
                response = response.decode('utf-8')

            print(f"\n[Client] Server response received ({len(response)} bytes)")

            # 5. ✅ EINHEITLICHES SIP-PARSING
            sip_data = self.parse_sip_message(response)
            if not sip_data:
                raise ValueError("Invalid SIP response format")
                
            print(f"[DEBUG] SIP message type: {sip_data.get('type')}")
            print(f"[DEBUG] Status code: {sip_data.get('status_code')}")

            # 6. ✅ KORREKTE BODY-EXTRAKTION
            body = sip_data.get('body', '')
            if not body:
                raise ValueError("No body in SIP response")
                
            print(f"[DEBUG] Body length: {len(body)}")
            print(f"[DEBUG] Body content: {body[:200]}...")

            # 7. ✅ BODY ALS JSON PARSEN
            try:
                response_data = json.loads(body)
                print(f"[DEBUG] JSON parsed successfully: {list(response_data.keys())}")
            except json.JSONDecodeError as e:
                print(f"[DEBUG] JSON decode error: {e}")
                raise ValueError("Invalid JSON in response body")

            # 8. Server Public Key extrahieren
            server_public_key = response_data.get('SERVER_PUBLIC_KEY')
            if not server_public_key:
                # Alternative Schlüsselnamen prüfen
                possible_keys = ['public_key', 'server_public_key', 'server_key']
                for key in possible_keys:
                    if key in response_data:
                        server_public_key = response_data[key]
                        print(f"[DEBUG] Found key in field: {key}")
                        break
            
            if not server_public_key:
                print(f"[DEBUG] Available fields: {list(response_data.keys())}")
                raise ValueError("No server public key found in response")

            # 9. Key formatieren und validieren
            server_public_key = server_public_key.replace('\\\\n', '\n').replace('\\n', '\n')
            
            if not is_valid_public_key(server_public_key):
                print("[DEBUG] Key validation failed")
                raise ValueError("Invalid server public key format")

            # Save server public key
            with open("server_public_key.pem", "w") as f:
                f.write(server_public_key)
            print("[DEBUG] Server public key saved")

            # 10. Zweite Response (Merkle Data) empfangen
            merkle_response = recv_frame(client_socket)
            if not merkle_response:
                raise ConnectionError("No Merkle data received")

            if isinstance(merkle_response, bytes):
                merkle_response = merkle_response.decode('utf-8')

            # Merkle Data parsen
            merkle_sip_data = self.parse_sip_message(merkle_response)
            if not merkle_sip_data:
                raise ValueError("Invalid Merkle SIP response")

            merkle_body = merkle_sip_data.get('body', '')
            if not merkle_body:
                raise ValueError("No body in Merkle response")
                
            try:
                merkle_data = json.loads(merkle_body)
            except json.JSONDecodeError as e:
                print(f"[DEBUG] Merkle JSON error: {e}")
                raise ValueError("Invalid JSON in Merkle response")

            # Merkle Daten extrahieren
            all_keys = merkle_data.get('ALL_KEYS', [])
            merkle_root = merkle_data.get('MERKLE_ROOT', '')

            if not merkle_root:
                raise ValueError("No Merkle root in response")

            # Merkle Verification
            print("\n=== CLIENT VERIFICATION ===")
            if not verify_merkle_integrity(all_keys, merkle_root):
                raise ValueError("Merkle verification failed")

            print("[DEBUG] Merkle verification successful")

            # 11. Hauptloop starten
            print("\n[Client] Starting communication loop...")
            self.connection_loop(client_socket, server_ip, message_handler)
            return True

        except Exception as e:
            error_msg = f"Connection failed: {str(e)}"
            print(f"\n[Client ERROR] {error_msg}")
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
                    threading.Thread(target=self._process_queue, daemon=True).start()
                    
                return True
            else:
                print("[SEND ERROR] Not connected to server")
                return False
                
        except Exception as e:
            print(f"[SEND ERROR] Failed to queue message: {str(e)}")
            return False

    def build_sip_message(self,method, recipient, custom_data=None, from_server=False, client_name=None, server_host=None):
        """VOLLSTÄNDIG EINHEITLICHE SIP-NACHRICHTENERSTELLUNG - FÜR CLIENT UND SERVER"""
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
        
        # SIP-Nachricht erstellen
        sip_message = (
            f"{method} sip:{recipient} SIP/2.0\r\n"
            f"From: {from_header}\r\n"
            f"To: <sip:{recipient}>\r\n"
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



    def _process_queue(self):
        """KORRIGIERTE Queue-Verarbeitung ohne Deadlocks"""
        if getattr(self, '_processing_queue', False):
            return
            
        self._processing_queue = True
        
        try:
            while hasattr(self, '_message_queue') and self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                # Frame-Daten verarbeiten
                if isinstance(queue_item, dict) and queue_item.get('type') == 'frame_data':
                    frame_data = queue_item['data']
                    self._process_received_frame(frame_data)
                
                # Direkte Nachrichten senden
                elif isinstance(queue_item, dict) and queue_item.get('type') == 'send_message':
                    message = queue_item['message']
                    try:
                        if hasattr(self, 'client_socket') and self.client_socket:
                            # VERBESSERT: Timeout handling
                            self.client_socket.settimeout(30)
                            send_frame(self.client_socket, message.encode('utf-8'))
                            print("[CLIENT] Nachricht gesendet")
                    except socket.timeout:
                        print("[CLIENT] Send timeout")
                    except Exception as e:
                        print(f"[CLIENT ERROR] Send failed: {str(e)}")
                
                # Call-bezogene Nachrichten
                elif isinstance(queue_item, dict) and queue_item.get('type') == 'call_request':
                    if hasattr(self, 'call_manager'):
                        recipient = queue_item.get('recipient')
                        if recipient:
                            self.call_manager.initiate_call(recipient)
                            
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self._processing_queue = False

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
        self.connection_window.geometry("300x300")
        self.connection_window.configure(fg_color='darkgrey')

        # Schriftarten definieren
        label_font = ("Helvetica", 14)
        button_font = ("Helvetica", 14, "bold")

        self.status_label = ctk.CTkLabel(self.connection_window, text="Connecting...", font=label_font)
        self.status_label.pack(pady=20)

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
        self.button_frame.pack(pady=40)

        self.connect_button = ctk.CTkButton(self.button_frame, text="Verbinden", command=self.on_connect_click)
        self.connect_button.pack(side='left', fill="x", expand=True, padx=10)

    def on_connect_click(self):
        if hasattr(self, 'client_socket') and self.client_socket:
            messagebox.showerror("Fehler", "Bereits verbunden")
            return

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

            # Extensive DNS resolution debugging
            print(f"[DEBUG 3] Starting DNS resolution for: {server_ip}")
            try:
                # Get all address information
                addr_info = socket.getaddrinfo(server_ip, port, socket.AF_INET, socket.SOCK_STREAM)
                print(f"[DEBUG 4] getaddrinfo results: {len(addr_info)} entries")
                
                for i, (family, socktype, proto, canonname, sockaddr) in enumerate(addr_info):
                    print(f"[DEBUG 4.{i}] Family: {family}, Type: {socktype}, Proto: {proto}")
                    print(f"[DEBUG 4.{i}] Canonname: {canonname}, Addr: {sockaddr}")
                
                # Traditional gethostbyname
                resolved_ip = socket.gethostbyname(server_ip)
                print(f"[DEBUG 5] gethostbyname result: {resolved_ip}")
                
            except Exception as dns_error:
                print(f"[DEBUG 6] DNS resolution failed: {dns_error}")
                print(f"[DEBUG 6] DNS error type: {type(dns_error).__name__}")
                import traceback
                traceback.print_exc()

            # Socket creation with extensive debugging
            print("[DEBUG 7] Creating socket...")
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("[DEBUG 8] Socket created successfully")
                
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
        """KORRIGIERTE Update-Nachricht mit JSON-Format"""
        global connected
        try:
            if not hasattr(self, 'client_socket') or not self.client_socket or not connected:
                messagebox.showerror("Fehler", "Nicht mit Server verbunden")
                print("[UPDATE ERROR] Nicht mit Server verbunden")
                return

            print("[CLIENT] Update-Button geklickt - Sende JSON Update Request")

            # ✅ KORREKTUR: UPDATE im JSON-Format senden
            update_data = {
                "MESSAGE_TYPE": "UPDATE_REQUEST",
                "CLIENT_NAME": self._client_name,
                "TIMESTAMP": int(time.time()),
                "VERSION": "2.0"
            }
            
            update_msg = self.build_sip_message(
                "MESSAGE", 
                self.server_ip, 
                update_data
            )

            # Sende UPDATE Nachricht mit Framing
            try:
                if send_frame(self.client_socket, update_msg.encode('utf-8')):
                    print("[CLIENT] JSON Update Request an Server gesendet")
                    
                    # Zur Queue hinzufügen
                    if not hasattr(self, '_message_queue'):
                        self._message_queue = []
                        
                    self._message_queue.append({
                        'type': 'update_request_sent',
                        'message': update_msg,
                        'timestamp': time.time(),
                        'server_ip': self.server_ip
                    })

                    # Queue-Verarbeitung starten
                    if not hasattr(self, '_processing_queue') or not self._processing_queue:
                        threading.Thread(target=self._process_queue, daemon=True).start()

                else:
                    messagebox.showerror("Fehler", "Update-Nachricht konnte nicht gesendet werden")

            except Exception as e:
                print(f"[CLIENT ERROR] Senden der UPDATE Nachricht fehlgeschlagen: {str(e)}")
                messagebox.showerror("Fehler", f"Update-Nachricht konnte nicht gesendet werden: {str(e)}")

        except Exception as e:
            print(f"[CLIENT ERROR] Update click failed: {str(e)}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Fehler", f"Update konnte nicht gestartet werden: {str(e)}")
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

    def _get_local_ip(self):
        """Ermittelt die lokale IP-Adresse"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"


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

    def open_keyboard_settings(self):
        messagebox.showinfo("Tastatur", "Tastatureinstellungen (nicht implementiert)")

    def open_language_settings(self):
        messagebox.showinfo("Sprache", "Spracheinstellungen (nicht implementiert)")


    def _handle_ping_message(self):
        """Handle PING messages by responding with PONG"""
        try:
            if hasattr(self, 'client_socket') and self.client_socket:
                pong_msg = self.build_sip_message(
                    "MESSAGE",
                    "server",
                    {"PONG": "true"}
                )
                self.client_socket.sendall(pong_msg.encode('utf-8'))
                print("[DEBUG] Sent PONG response")
                return True
            return False
        except Exception as e:
            print(f"[ERROR] Failed to send PONG: {str(e)}")
            return False
   
    def handle_server_message(self, raw_data):
        """KORRIGIERT: Vereinfachte Message-Verarbeitung ohne Rekursionsgefahr"""
        print(f"\n=== HANDLING SERVER MESSAGE ({len(raw_data) if hasattr(raw_data, '__len__') else '?'} bytes) ===")
        
        try:
            # 1. ✅ QUEUE-INITIALISIERUNG (Thread-sicher)
            if not hasattr(self, '_message_queue'):
                self._message_queue = []
            if not hasattr(self, '_queue_processing'):
                self._queue_processing = False
            if not hasattr(self, '_queue_size_limit'):
                self._queue_size_limit = 120
            
            # 2. ✅ DOS-SCHUTZ (einfache Version)
            current_time = time.time()
            if not hasattr(self, '_last_minute_check'):
                self._last_minute_check = current_time
            if not hasattr(self, '_messages_this_minute'):
                self._messages_this_minute = 0
            
            if current_time - self._last_minute_check >= 60:
                self._last_minute_check = current_time
                self._messages_this_minute = 0
            
            if self._messages_this_minute >= self._queue_size_limit:
                print(f"[DOS] Limit erreicht - ignoriere Nachricht")
                return False
            
            self._messages_this_minute += 1
            
            # 3. ✅ NACHRICHT ZUR QUEUE HINZUFÜGEN
            self._message_queue.append({
                'timestamp': time.time(),
                'data': raw_data
            })
            
            print(f"[QUEUE] Nachricht hinzugefügt ({len(self._message_queue)} in Warteschlange)")
            
            # 4. ✅ VERARBEITUNG NUR STARTEN WENN NICHT BEREITS AKTIV
            if not self._queue_processing:
                self._queue_processing = True
                threading.Thread(
                    target=self._process_queue_simple, 
                    daemon=True
                ).start()
            
            return True
            
        except Exception as e:
            print(f"[HANDLER ERROR] {str(e)}")
            return False

    def _process_queue_simple(self):
        """Einfache Queue-Verarbeitung ohne komplexe Logik"""
        print("[QUEUE] Starte Verarbeitung...")
        
        try:
            while self._message_queue:
                # Kurze Pause für Batch-Verarbeitung
                time.sleep(0.05)
                
                # Nächste Nachricht aus Queue holen
                if not self._message_queue:
                    break
                    
                message_item = self._message_queue.pop(0)
                raw_data = message_item['data']
                
                try:
                    # Nachricht als String konvertieren
                    if isinstance(raw_data, bytes):
                        message_str = raw_data.decode('utf-8', errors='ignore')
                    else:
                        message_str = str(raw_data)
                    
                    print(f"[PROCESS] Verarbeite Nachricht: {message_str[:100]}...")
                    
                    # ✅ EINFACHE NACHRICHTEN-ROUTING-LOGIK
                    
                    # A) PHONEBOOK-UPDATE
                    if any(keyword in message_str for keyword in ['PHONEBOOK_UPDATE', 'ENCRYPTED_SECRET', 'ENCRYPTED_PHONEBOOK']):
                        print("[ROUTE] → Phonebook Update")
                        self._process_phonebook_update(message_str)
                    
                    # B) CALL-NACHRICHTEN
                    elif any(keyword in message_str for keyword in ['INCOMING_CALL', 'CALL_RESPONSE', 'SESSION_KEY', 'PUBLIC_KEY_RESPONSE']):
                        print("[ROUTE] → Call Manager")
                        if hasattr(self, 'call_manager'):
                            self.call_manager.handle_message(message_str)
                    
                    # C) IDENTITY-NACHRICHTEN
                    elif 'IDENTITY_CHALLENGE' in message_str:
                        print("[ROUTE] → Identity Challenge")
                        self._handle_identity_challenge(message_str)
                    
                    elif 'IDENTITY_VERIFIED' in message_str:
                        print("[ROUTE] → Identity Verified") 
                        self._handle_identity_verified(message_str)
                    
                    # D) PING/PONG
                    elif 'PING' in message_str:
                        print("[ROUTE] → Ping Handler")
                        self._handle_ping_message()
                    
                    # E) STANDARD-VERARBEITUNG
                    else:
                        print("[ROUTE] → Standard Processing")
                        self._process_received_frame(raw_data)
                        
                except Exception as e:
                    print(f"[PROCESS ERROR] Nachricht fehlgeschlagen: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
        finally:
            self._queue_processing = False
            print("[QUEUE] Verarbeitung beendet")
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
                    self._message_queue.append({
                        'type': 'frame_data',
                        'data': data
                    })
                    
                    # Queue-Verarbeitung starten
                    if not self._processing_queue:
                        self._process_queue()
                        
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

    def _get_public_ip(self):
        """Ermittelt die öffentliche IP-Adresse"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"


    def _process_queue(self):
        """Verarbeitet Nachrichten aus der Queue - kompatibel mit existing SIP methods"""
        self._processing_queue = True
        
        try:
            while self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                if isinstance(queue_item, dict) and queue_item.get('type') == 'frame_data':
                    frame_data = queue_item['data']
                    
                    try:
                        message = frame_data.decode('utf-8')
                        msg = self.parse_sip_message(message)
                        if not msg:
                            continue
                            
                        # Prüfe sowohl headers als auch custom_data für Nachrichtentypen
                        headers = msg.get('headers', {})
                        custom_data = msg.get('custom_data', {})
                        
                        # Extrahiere MESSAGE_TYPE aus Headers (höhere Priorität) oder custom_data
                        message_type = headers.get('MESSAGE_TYPE') or custom_data.get('MESSAGE_TYPE')
                        
                        # === CALL-RELATED MESSAGES AN CALL MANAGER DELEGIEREN ===
                        if message_type in ['INCOMING_CALL', 'SESSION_KEY', 'CALL_RESPONSE', 
                                          'CALL_TIMEOUT', 'PUBLIC_KEY_RESPONSE', 'CALL_END']:
                            if hasattr(self, 'call_manager'):
                                print(f"[CALL] Delegating {message_type} to call manager")
                                self.call_manager.handle_message(message_type, msg)
                                continue
                            else:
                                print(f"[CALL WARNING] No call manager for {message_type}")
                        
                        # INCOMING_CALL Handling (Fallback falls kein call_manager)
                        elif message_type == 'INCOMING_CALL':
                            print("[CALL] Incoming call received")
                            if hasattr(self, 'call_manager'):
                                self.call_manager.handle_incoming_call(msg)
                            else:
                                print("[CALL ERROR] No call manager available")
                            continue
                        
                        # SESSION_KEY Handling (Fallback)
                        elif message_type == 'SESSION_KEY':
                            print("[CALL] Received session key from server")
                            if hasattr(self, 'call_manager'):
                                self.call_manager.handle_message('SESSION_KEY', msg)
                            else:
                                print("[CALL ERROR] No call manager available")
                            continue
                        
                        # CALL_RESPONSE Handling (Fallback)
                        elif message_type == 'CALL_RESPONSE':
                            print("[CALL] Received call response")
                            if hasattr(self, 'call_manager'):
                                self.call_manager.handle_call_response(msg)
                            else:
                                print("[CALL ERROR] No call manager available")
                            continue
                        
                        # CALL_TIMEOUT Handling (Fallback)
                        elif message_type == 'CALL_TIMEOUT':
                            print("[CALL] Call timeout received from server")
                            if hasattr(self, 'call_manager'):
                                self.call_manager.cleanup_call_resources()
                                messagebox.showinfo("Call Failed", "Der Empfänger hat nicht innerhalb von 120 Sekunden geantwortet")
                            else:
                                print("[CALL ERROR] No call manager available")
                            continue
                        
                        # PUBLIC_KEY_RESPONSE Handling (Fallback)
                        elif message_type == 'PUBLIC_KEY_RESPONSE':
                            print("[CALL] Public key response received")
                            if hasattr(self, 'call_manager'):
                                self.call_manager.handle_public_key_response(msg)
                            else:
                                print("[CALL ERROR] No call manager available")
                            continue
                        
                        # IDENTITY_CHALLENGE aus Headers
                        elif message_type == 'IDENTITY_CHALLENGE':
                            print("[IDENTITY] Challenge vom Server empfangen")
                            self._handle_identity_challenge(msg)
                            continue
                            
                        # IDENTITY_VERIFIED aus Headers
                        elif message_type == 'IDENTITY_VERIFIED':
                            print("[IDENTITY] Verifizierung bestätigt")
                            self._handle_identity_verified(msg)
                            continue
                            
                        # PHONEBOOK_UPDATE
                        elif message_type == 'PHONEBOOK_UPDATE':
                            print("[UPDATE] Phonebook update received")
                            self._process_phonebook_update(msg)
                            continue
                        
                        # PING/PONG Handling
                        elif headers.get('PING') == 'true':
                            print("[PING] Ping received from server")
                            self._handle_ping_message()
                            continue
                            
                        elif headers.get('PONG') == 'true':
                            print("[PONG] Pong received from server")
                            continue
                            
                    except UnicodeDecodeError:
                        # Versuche es als binäre Daten zu verarbeiten
                        if len(frame_data) > 512:
                            print("[DEBUG] Trying to process as encrypted phonebook data")
                            result = self._process_encrypted_phonebook(frame_data)
                            if result:
                                continue
                        print("[DEBUG] Could not decode frame as UTF-8")
                        continue
                        
                elif isinstance(queue_item, str):
                    print(f"[CLIENT] Verarbeite String aus Queue: {queue_item[:100]}...")
                    
                    # Legacy-String-Verarbeitung (für Abwärtskompatibilität)
                    if 'IDENTITY_CHALLENGE' in queue_item:
                        print("[IDENTITY] Challenge vom Server (String-Format) empfangen")
                        self._handle_identity_challenge(queue_item)
                        continue
                        
                    elif 'IDENTITY_VERIFIED' in queue_item:
                        print("[IDENTITY] Verifizierung bestätigt (String-Format)")
                        self._handle_identity_verified(queue_item)
                        continue
                        
                    elif 'INCOMING_CALL' in queue_item:
                        print("[CALL] Incoming call (String-Format) empfangen")
                        if hasattr(self, 'call_manager'):
                            # Versuche die String-Nachricht zu parsen
                            try:
                                msg = self.parse_sip_message(queue_item)
                                if msg:
                                    self.call_manager.handle_incoming_call(msg)
                                else:
                                    print("[CALL ERROR] Could not parse string message")
                            except Exception as e:
                                print(f"[CALL ERROR] Failed to parse incoming call: {str(e)}")
                        else:
                            print("[CALL ERROR] No call manager available")
                        continue
                        
                    try:
                        sip_data = self.parse_sip_message(queue_item)
                        if sip_data:
                            print("[CLIENT] Verarbeite SIP Nachricht aus String-Queue")
                            # Prüfe auf Call-Nachrichten in String-Format
                            if 'INCOMING_CALL' in queue_item:
                                if hasattr(self, 'call_manager'):
                                    self.call_manager.handle_incoming_call(sip_data)
                            else:
                                self._process_sip_message(sip_data)
                        else:
                            print("[CLIENT ERROR] Could not parse string from queue")
                    except Exception as e:
                        print(f"[CLIENT ERROR] Failed to process string from queue: {str(e)}")
                
                elif isinstance(queue_item, dict):
                    if queue_item.get('type') == 'send_message':
                        message = queue_item['message']
                        try:
                            send_frame(self.client_socket, message.encode('utf-8'))
                            print("[CLIENT] Nachricht gesendet")
                        except Exception as e:
                            print(f"[CLIENT ERROR] Send failed: {str(e)}")
                    
                    elif queue_item.get('type') == 'update_request':
                        print("[UPDATE] Request wurde verarbeitet")
                    
                    elif queue_item.get('type') == 'call_request':
                        # Direkter Call-Request aus der Queue
                        if hasattr(self, 'call_manager'):
                            recipient = queue_item.get('recipient')
                            if recipient:
                                self.call_manager.initiate_call(recipient)
                        else:
                            print("[CALL ERROR] No call manager for direct call request")
                
                else:
                    print(f"[CLIENT WARN] Unbekanntes Queue-Format: {type(queue_item)}")
                        
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self._processing_queue = False


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
    def _process_encrypted_phonebook(self, encrypted_data):
        """Process encrypted phonebook data without recursion"""
        print("\n=== PROCESSING ENCRYPTED PHONEBOOK ===")
        
        try:
            # 1. Validate input
            if not encrypted_data:
                print("[ERROR] Empty encrypted data received")
                return False
                
            # 2. Handle bytes input
            if isinstance(encrypted_data, bytes):
                # Skip frame header if present (first 4 bytes)
                if len(encrypted_data) > 4 and encrypted_data[:4] == struct.pack('!I', len(encrypted_data)-4):
                    encrypted_data = encrypted_data[4:]
                
                # Try to find SIP message body
                body_start = encrypted_data.find(b'\r\n\r\n')
                if body_start != -1:
                    headers = encrypted_data[:body_start]
                    body = encrypted_data[body_start+4:]  # Skip \r\n\r\n
                    
                    print("[DEBUG] Found SIP message with body")
                    
                    # Try to parse as JSON
                    try:
                        message_data = json.loads(body.decode('utf-8'))
                        if "ENCRYPTED_SECRET" in message_data and "ENCRYPTED_PHONEBOOK" in message_data:
                            print("[DEBUG] Found encrypted phonebook in JSON body")
                            encrypted_secret = base64.b64decode(message_data["ENCRYPTED_SECRET"])
                            encrypted_phonebook = base64.b64decode(message_data["ENCRYPTED_PHONEBOOK"])
                            combined = encrypted_secret + encrypted_phonebook
                            return self._decrypt_phonebook_data(combined)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                        
                    # Try key-value format
                    if b"ENCRYPTED_SECRET:" in body and b"ENCRYPTED_PHONEBOOK:" in body:
                        print("[DEBUG] Found encrypted phonebook in key-value body")
                        secret_part = body.split(b"ENCRYPTED_SECRET:")[1].split(b"\n")[0].strip()
                        phonebook_part = body.split(b"ENCRYPTED_PHONEBOOK:")[1].split(b"\n")[0].strip()
                        
                        try:
                            encrypted_secret = base64.b64decode(secret_part)
                            encrypted_phonebook = base64.b64decode(phonebook_part)
                            combined = encrypted_secret + encrypted_phonebook
                            return self._decrypt_phonebook_data(combined)
                        except binascii.Error as e:
                            print(f"[ERROR] Base64 decode failed: {e}")
                
                # Direct processing if no headers found
                if len(encrypted_data) >= 512:
                    print("[DEBUG] Trying direct encrypted phonebook processing")
                    return self._decrypt_phonebook_data(encrypted_data)
                    
            # 3. Handle dict input
            elif isinstance(encrypted_data, dict):
                if 'ENCRYPTED_SECRET' in encrypted_data and 'ENCRYPTED_PHONEBOOK' in encrypted_data:
                    print("[DEBUG] Found encrypted phonebook in dict")
                    encrypted_secret = base64.b64decode(encrypted_data['ENCRYPTED_SECRET'])
                    encrypted_phonebook = base64.b64decode(encrypted_data['ENCRYPTED_PHONEBOOK'])
                    combined = encrypted_secret + encrypted_phonebook
                    return self._decrypt_phonebook_data(combined)
                    
            print("[ERROR] No valid encrypted data format detected")
            return False
                
        except Exception as e:
            print(f"[CRITICAL ERROR] {str(e)}")
            # Use simpler error logging to avoid recursion
            import sys
            sys.stderr.write(f"Error processing encrypted phonebook: {str(e)}\n")
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
        """Main method for decrypting phonebook data with enhanced error handling"""
        print("\n=== DECRYPT PHONEBOOK DEBUG ===")
        
        try:
            # Debug input
            print(f"[DEBUG] Initial input type: {type(encrypted_data)}")
            if isinstance(encrypted_data, bytes):
                print(f"[DEBUG] Input length: {len(encrypted_data)} bytes")
                print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(encrypted_data[:32])}")
            
            # Handle raw binary data (direct encrypted format)
            if isinstance(encrypted_data, bytes) and len(encrypted_data) > 512:
                print("[DEBUG] Processing raw binary encrypted data")
                secret = encrypted_data[:512]
                phonebook = encrypted_data[512:]
                print(f"[DEBUG] Secret length: {len(secret)} bytes")
                print(f"[DEBUG] Phonebook length: {len(phonebook)} bytes")
                
            # Handle dictionary format (from SIP custom_data)
            elif isinstance(encrypted_data, dict):
                print("[DEBUG] Processing encrypted dictionary")
                required_keys = ['encrypted_secret', 'encrypted_phonebook']
                if all(k in encrypted_data for k in required_keys):
                    try:
                        # Base64 decode with validation
                        secret = base64.b64decode(encrypted_data['encrypted_secret'])
                        phonebook = base64.b64decode(encrypted_data['encrypted_phonebook'])
                        print(f"[DEBUG] Decoded secret: {len(secret)} bytes")
                        print(f"[DEBUG] Decoded phonebook: {len(phonebook)} bytes")
                    except Exception as e:
                        print(f"[ERROR] Base64 decode failed: {str(e)}")
                        return None
                else:
                    print("[ERROR] Missing required encrypted fields")
                    return None
            else:
                print(f"[ERROR] Unsupported input format: {type(encrypted_data)}")
                return None

            # Validate secret length
            if len(secret) != 512:
                raise ValueError(f"Invalid secret length: {len(secret)} bytes (expected 512)")

            # RSA decrypt
            print("[DEBUG] RSA decrypting secret...")
            private_key = load_privatekey()
            if not private_key or not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
                raise ValueError("Invalid private key format")
                
            priv_key = RSA.load_key_string(private_key.encode())
            decrypted_secret = priv_key.private_decrypt(secret, RSA.pkcs1_padding)
            secure_del(priv_key)
            
            print(f"[DEBUG] RSA decrypted: {len(decrypted_secret)} bytes")
            print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(decrypted_secret[:32])}")
            print(f"[DEBUG] As string: {decrypted_secret[:50]!r}")

            # Extract AES components with improved error handling
            prefix = b"+++secret+++"
            if prefix not in decrypted_secret:
                print("[ERROR] Secret prefix not found in decrypted data")
                print(f"[DEBUG] Actual prefix: {decrypted_secret[:11]!r}")
                raise ValueError("Secret prefix not found in decrypted data")
                
            secret_start = decrypted_secret.find(prefix) + len(prefix)
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

            # AES decrypt with extensive debugging
            print("[DEBUG] AES decrypting phonebook...")
            print(f"[DEBUG] Encrypted phonebook length: {len(phonebook)} bytes")
            print(f"[DEBUG] Encrypted phonebook first 32 bytes (hex): {binascii.hexlify(phonebook[:32])}")

            # Try different padding modes
            try:
                cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=1)
                decrypted = cipher.update(phonebook) + cipher.final()
                print("[DEBUG] AES decryption successful with PKCS#7 padding")
            except EVP.EVPError as padding_error:
                print(f"[DEBUG] PKCS#7 padding failed: {padding_error}")
                # Fallback: Try without padding
                try:
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=0)
                    decrypted = cipher.update(phonebook) + cipher.final()
                    print("[DEBUG] AES decryption successful without padding")
                except EVP.EVPError as no_padding_error:
                    print(f"[DEBUG] No padding also failed: {no_padding_error}")
                    raise ValueError("AES decryption failed with both padding modes")

            print(f"[DEBUG] Decrypted data length: {len(decrypted)} bytes")
            print(f"[DEBUG] Decrypted data (hex): {binascii.hexlify(decrypted[:64])}...")
            print(f"[DEBUG] As string: {decrypted[:100]!r}")

            # Try to decode as UTF-8 JSON
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
                
            print(f"[DEBUG] Phonebook entries: {len(phonebook_data.get('clients', []))}")

            # UI Update
            if hasattr(self, 'update_phonebook'):
                self.update_phonebook(phonebook_data)
                print("[DEBUG] UI update scheduled")
            
            return phonebook_data
            
        except Exception as e:
            print(f"[DECRYPT ERROR] {str(e)}")
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
