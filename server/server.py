import socket
import threading
from M2Crypto import RSA, BIO, EVP
import hashlib
import json
import os
import random
import time
import uuid
import re
import struct
import base64
import ctypes
import platform
from typing import Optional, Dict, List
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import select
import binascii
BUFFER_SIZE = 4096
import os
import hmac
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
import requests
import ipaddress


# Globale Variablen für Verify-Code-Generator
import hashlib

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
    def debug_info(self):
        """Gibt Debug-Informationen aus"""
        next_code = self._calculate_expected_code(self.counter)
        return f"Client-ID: '{self.client_id}', Seed: '{self.seed}', Counter: {self.counter}, Next: '{next_code}'"
    def verify_code(self, received_code, sync_tolerance=25):
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

def generate_verify_code(client_id=None):
    """
    Generiert einen Verify-Code (Kompatibilitätsfunktion)
    
    Args:
        client_id: Client-ID
        
    Returns:
        str: Verify-Code
    """
    # ✅ KORREKTUR: CLIENT-ID ALS SEED VERWENDEN
    if client_id is None:
        client_id = "default"
    generator = init_verify_generator(client_name, client_name)  # ✅ SEED = CLIENT-ID
    return generator.generate_verify_code()

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
def log_invalid_message(client_info, message_content, error_type):
    """Protokolliert fehlerhafte Nachrichten in log.txt"""
    try:
        with open("log.txt", "a", encoding="utf-8") as log_file:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {error_type} from {client_info}\n"
            log_entry += f"Message preview: {message_content[:200]}...\n"
            log_entry += "-" * 50 + "\n"
            log_file.write(log_entry)
        print(f"📝 [LOG] Invalid message logged: {error_type}")
    except Exception as e:
        print(f"❌ [LOG] Failed to write to log file: {e}")
def recv_frame(sock, timeout=30):
    """EINHEITLICHER Frame-Empfänger für ALLE Nachrichten - IDENTISCH AUF CLIENT UND SERVER"""
    original_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    
    try:
        # Peer Info für Logging
        try:
            peer_info = f"{sock.getpeername()[0]}:{sock.getpeername()[1]}"
        except:
            peer_info = "unknown"
        
        print(f"📡 [FRAME] Waiting for frame from {peer_info}")
        
        # 1. Header lesen (4 Bytes Network Byte Order)
        header = b''
        start_time = time.time()
        
        while len(header) < 4:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                print(f"⏰ [FRAME] Header timeout from {peer_info}")
                raise TimeoutError("Header receive timeout")
                
            sock.settimeout(min(5, remaining_time))
            chunk = sock.recv(4 - len(header))
            if not chunk:
                print(f"🔌 [FRAME] Connection closed by {peer_info} during header")
                return None
            header += chunk
        
        # 2. Länge decodieren
        try:
            length = struct.unpack('!I', header)[0]
            print(f"📏 [FRAME] {peer_info} announced {length} bytes")
        except struct.error as e:
            print(f"❌ [FRAME] INVALID HEADER from {peer_info}: {header.hex()} - {e}")
            return None
        
        # 3. EINHEITLICHE SICHERHEITSCHECKS
        MAX_FRAME_SIZE = 10 * 1024 * 1024  # 10MB Maximum (KONSISTENT)
        
        if length > MAX_FRAME_SIZE:
            print(f"❌ [FRAME] OVERSIZE from {peer_info}: {length} bytes > {MAX_FRAME_SIZE} bytes")
            raise ValueError(f"Frame too large: {length} bytes (max: {MAX_FRAME_SIZE} bytes)")
        
        if length < 0:
            print(f"❌ [FRAME] NEGATIVE LENGTH from {peer_info}: {length}")
            raise ValueError(f"Invalid frame length: {length} bytes")
        
        if length == 0:
            print(f"📭 [FRAME] Empty frame from {peer_info}")
            return b''
        
        # 4. Body lesen
        received = b''
        bytes_received = 0
        
        while len(received) < length:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                print(f"⏰ [FRAME] Body timeout from {peer_info}, received {len(received)}/{length} bytes")
                raise TimeoutError(f"Body receive timeout after {timeout}s")
                
            sock.settimeout(min(10, remaining_time))
            chunk_size = min(8192, length - len(received))
            chunk = sock.recv(chunk_size)
            
            if not chunk:
                print(f"🔌 [FRAME] Connection closed by {peer_info} during body")
                raise ConnectionError(f"Incomplete frame: received {len(received)} of {length} bytes")
            
            received += chunk
            bytes_received += len(chunk)
        
        # 5. Erfolgslogging
        print(f"✅ [FRAME] Successfully received {length} bytes from {peer_info}")
        return received
        
    except socket.timeout:
        print(f"⏰ [FRAME] Overall timeout after {timeout}s from {peer_info}")
        raise TimeoutError(f"Frame receive timeout after {timeout}s")
    except ConnectionError as e:
        print(f"🔌 [FRAME] Connection error from {peer_info}: {e}")
        raise
    except ValueError as e:
        print(f"❌ [FRAME] Validation error from {peer_info}: {e}")
        raise
    except Exception as e:
        print(f"❌ [FRAME] Unexpected error from {peer_info}: {e}")
        return None
    finally:
        try:
            sock.settimeout(original_timeout)
        except:
            pass

def verify_code_with_detection(received_code, client_info, sync_tolerance=5, check_range=100):
    """
    Erweiterte Verify-Code Validierung die RNG-State-Angriffe erkennt
    
    Returns:
        "valid"   - Code ist gültig und neu
        "reused"  - Code wurde wiederverwendet (RNG State Angriff!)
        "invalid" - Code ist komplett falsch
    """
    # Hole den Generator für diesen Client
    generator = init_verify_generator(None, client_info)
    
    # ✅ KORREKTUR: Verwende NUR EINE Lock-Acquisition für alles
    with generator._lock:
        current_counter = generator.counter
        
        # 1. Prüfe zuerst mit der normalen verify_code Logik (mit Synchronisation)
        for offset in range(sync_tolerance):
            test_counter = current_counter + offset
            expected_base_string = f"{generator.seed}:{test_counter}"
            expected_hash = hashlib.sha256(expected_base_string.encode('utf-8'))
            expected_hash_hex = expected_hash.hexdigest()
            expected_code = expected_hash_hex[:4]
            
            if received_code == expected_code:
                # ✅ ERFOLG: COUNTER SYNCHRONISIEREN
                generator.counter = test_counter + 1
                
                if offset > 0:
                    print(f"✅ [VERIFY] Code #{test_counter} für '{client_info}' (sync +{offset}): {received_code}")
                else:
                    print(f"✅ [VERIFY] Code #{test_counter} für '{client_info}': {received_code}")
                
                print(f"📊 [STATS] Counter synchronisiert: {generator.counter}")
                return "valid"
        
        # 2. Code ist invalid - prüfe ob es ein RNG-State-Angriff sein könnte
        # Dazu prüfen wir einen erweiterten Bereich um den aktuellen Counter
        # Prüfe Codes in der Vergangenheit (wiederverwendete Codes)
        for offset in range(1, check_range + 1):  # Nur Vergangenheit prüfen
            test_counter = current_counter - offset
            if test_counter < 0:
                continue
                
            expected_base_string = f"{generator.seed}:{test_counter}"
            expected_hash = hashlib.sha256(expected_base_string.encode('utf-8'))
            expected_hash_hex = expected_hash.hexdigest()
            expected_code = expected_hash_hex[:4]
            
            if received_code == expected_code:
                # 🚨 RNG-STATE ANGRIFF ERKANNT! Code wurde wiederverwendet!
                print(f"🚨 [RNG_DETECTION] Code match at PAST counter {test_counter} (current: {current_counter})")
                return "reused"
    
    # 3. Code ist komplett falsch (nicht in der Nähe des aktuellen Counters)
    return "invalid"
def debug_print_key(key_type, key_data):
    """Print detailed key information"""
    print(f"\n=== {key_type.upper()} KEY DEBUG ===")
    print(f"Length: {len(key_data)} bytes")
    print(f"First 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[:32])}")
    print(f"First 32 bytes (ascii): {key_data[:32].decode('ascii', errors='replace')}")
    if len(key_data) > 32:
        print(f"Last 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[-32:])}")
    print("="*50)




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


def extract_public_key(raw_data):
    """
    Extrahiert den vollständigen Public Key aus SIP-Nachrichten
    - Verarbeitet mehrzeilige Keys in Headern
    - Behält PEM-Formatierung bei
    """
    try:
        data = raw_data.decode('utf-8') if isinstance(raw_data, bytes) else str(raw_data)
        
        # Variante 1: Key ist im Body nach \r\n\r\n
        if '\r\n\r\n' in data:
            body = data.split('\r\n\r\n')[1]
            if '-----BEGIN PUBLIC KEY-----' in body:
                start = body.index('-----BEGIN PUBLIC KEY-----')
                end = body.index('-----END PUBLIC KEY-----') + len('-----END PUBLIC KEY-----')
                return body[start:end]

        # Variante 2: Key ist über Header-Zeilen verteilt
        key_lines = []
        collecting = False
        
        for line in data.splitlines():
            if '-----BEGIN PUBLIC KEY-----' in line:
                collecting = True
                key_lines.append(line.strip())
            elif collecting:
                if '-----END PUBLIC KEY-----' in line:
                    key_lines.append(line.strip())
                    break
                key_lines.append(line.strip())
        
        if not key_lines:
            return None
            
        pubkey = '\n'.join(key_lines)
        
        if not pubkey.startswith('-----BEGIN PUBLIC KEY-----') or \
           not pubkey.endswith('-----END PUBLIC KEY-----'):
            return None
            
        return pubkey
        
    except Exception as e:
        print(f"Key Extraction Error: {str(e)}")
        return None


def generate_keys():
    """Generiert Server-Schlüsselpaar - KORRIGIERT FÜR EINHEITLICHES FORMAT"""
    if not os.path.exists("server_public_key.pem") or not os.path.exists("server_private_key.pem"):
        print("Generiere neue Server-Schlüssel...")
        
        try:
            from M2Crypto import RSA, BIO
            
            # Generiere RSA Key (4096 bits wie der Client)
            key = RSA.gen_key(4096, 65537)
            
            # ✅ KORREKTUR: Verwende direkte RSA-Methoden statt EVP.PKey
            # Speichere öffentlichen Schlüssel
            pub_bio = BIO.MemoryBuffer()
            key.save_pub_key_bio(pub_bio)
            public_key_data = pub_bio.getvalue()
            
            with open("server_public_key.pem", "wb") as f:
                f.write(public_key_data)
            
            # ✅ KORREKTUR: Speichere privaten Schlüssel direkt mit RSA (PKCS#1)
            priv_bio = BIO.MemoryBuffer()
            key.save_key_bio(priv_bio, cipher=None)  # cipher=None für unverschlüsselt
            private_key_data = priv_bio.getvalue()
            
            with open("server_private_key.pem", "wb") as f:
                f.write(private_key_data)
            
            print("Server-Schlüssel erfolgreich generiert!")
            
            # Validiere die Keys
            try:
                # Teste public key
                with open("server_public_key.pem", "rb") as f:
                    pub_data = f.read()
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(pub_data))
                print("✓ Public key ist valide")
                
                # Teste private key - WICHTIG: Mit RSA.load_key_string testen
                with open("server_private_key.pem", "rb") as f:
                    priv_data = f.read()
                priv_key = RSA.load_key_string(priv_data)
                print("✓ Private key ist valide")
                
                # Teste Verschlüsselung/Entschlüsselung
                test_msg = b"Test Message for Server Key Validation"
                encrypted = pub_key.public_encrypt(test_msg, RSA.pkcs1_padding)
                decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
                
                if decrypted == test_msg:
                    print("✓ Server Key Pair: Verschlüsselung/Entschlüsselung erfolgreich")
                else:
                    print("✗ Server Key Pair: Verschlüsselung/Entschlüsselung fehlgeschlagen")
                    
            except Exception as e:
                print(f"Server Key-Validierungsfehler: {e}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Fehler bei der Server-Schlüsselgenerierung: {e}")
            return False
    else:
        print("Server-Schlüssel existieren bereits")
        return True

def load_server_publickey():
    """Lädt den öffentlichen Server-Schlüssel"""
    generate_keys()  # Stellt sicher dass Schlüssel existieren
    with open("server_public_key.pem", "rb") as f:
        return f.read().decode('utf-8')

def normalize_key(key):
    """Normalisiert öffentliche Schlüssel für konsistenten Vergleich"""
    if not key or "-----BEGIN PUBLIC KEY-----" not in key:
        return None
    
    # Extrahiere nur den Base64-Inhalt zwischen den PEM-Markern
    try:
        key_content = "".join(
            key.split("-----BEGIN PUBLIC KEY-----")[1]
            .split("-----END PUBLIC KEY-----")[0]
            .strip().split()
        )
        return key_content if key_content else None
    except Exception:
        return None


def merge_public_keys(keys):
    """Identisch auf Client und Server"""
    return "|||".join(normalize_key(k) for k in keys if k)

def shorten_public_key(key):
    """Kürzt die Darstellung des öffentlichen Schlüssels."""
    shortened = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    return shortened



def quantum_safe_hash(data):
    return hashlib.sha3_256(data.encode('utf-8')).hexdigest()


def build_merkle_tree_from_keys(all_keys):
    """Konsistente Merkle Tree Berechnung mit Debugging"""
    print("\n[Server] Building Merkle Tree from keys:")
    
    # 1. Normalisierung und Deduplizierung
    normalized_keys = []
    seen_keys = set()
    
    for key in all_keys:
        if not key:
            continue
            
        normalized = normalize_key(key)
        if normalized and normalized not in seen_keys:
            seen_keys.add(normalized)
            normalized_keys.append(normalized)
            print(f" - Added key: {normalized[:30]}...")

    if not normalized_keys:
        raise ValueError("No valid keys for Merkle tree")

    # 2. Zusammenführung mit konsistentem Trennzeichen
    merged = "|||".join(sorted(normalized_keys))  # Sortiert für konsistente Reihenfolge
    print(f"Merged keys length: {len(merged)}")
    
    # 3. Merkle Root berechnen
    merkle_root = build_merkle_tree([merged])
    print(f"Calculated Merkle Root: {merkle_root}")
    
    return merkle_root

   
def load_client_name():
    """Lädt den Client-Namen - versucht active_clients.json, sonst Dialog"""
    # Fallback für Nicht-Hauptthread
    if threading.current_thread() is not threading.main_thread():
        return "default_client"
    
    # Zuerst versuchen, aus active_clients.json zu lesen
    name_from_file = None
    if os.path.exists("active_clients.json"):
        try:
            with open("active_clients.json", "r") as file:
                clients_data = json.load(file)
                # Nimm den ersten gefundenen Namen
                for client_id, client_info in clients_data.items():
                    if "name" in client_info:
                        name_from_file = client_info["name"]
                        break
        except:
            pass
    
    # Wenn Name gefunden wurde, zurückgeben
    if name_from_file:
        return name_from_file
    
    # Sonst Dialog anzeigen
    client_name = simpledialog.askstring("Name", "Gib deinen Namen ein:")
    if client_name:
        return client_name
    else:
        messagebox.showerror("Fehler", "Kein Name eingegeben. Abbruch.")
        return None



class AccurateRelayManager:
    def __init__(self, server_instance):
        self.server = server_instance
        self.is_seed_server = False
        
        # ✅ KORRIGIERT: RLock statt data_lock
        self.data_lock = threading.RLock()
        
        # Feste Seed-Server Liste - gleiche Ports wie SIP
        self.SEED_SERVERS = [
            ("sichereleitung.duckdns.org", 5060),  # Haupt-SIP Port
            ("sichereleitung.duckdns.org", 5061),  # Alternativ-Port
        ]
        
        # ✅ NEU: Echte Server-IP für Discovery
        self._real_server_ip = self._get_real_server_ip()
        self.session_routing = {}  # {session_bytes: target_addr}
        # Rest der Initialisierung...
        self.known_servers = {}  # {server_ip: server_data}
        self.server_load = 0  # Eigene Last in %
        self.max_traffic_mbps = 100  # Default Wert
        self.current_traffic = 0
        
        # Prüfe ob dieser Server ein Seed-Server ist
        self._check_if_im_seed()
        
        # Starte Dienste
        if self.is_seed_server:
            self._start_seed_server()
        else:
            self._start_regular_server()
    
    def _get_real_server_ip(self):
        """Ermittelt die echte Server-IP für Discovery-Antworten"""
        try:
            # Versuche die öffentliche IP zu ermitteln
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Wenn es eine private IP ist, verwende den Hostnamen
            if local_ip.startswith('192.168.') or local_ip.startswith('10.') or local_ip == '127.0.0.1':
                # Verwende den Hostnamen oder DuckDNS Name
                return "sichereleitung.duckdns.org"
            else:
                return local_ip
                
        except Exception as e:
            print(f"[RELAY] Could not determine real IP: {e}")
            return "sichereleitung.duckdns.org"  # Fallback
    
    def _check_if_im_seed(self):
        """Prüft ob dieser Server in der Seed-Liste ist - MIT FESTER SEED-LISTE"""
        try:
            if not hasattr(self.server, 'host') or not self.server.host:
                print("⚠️  Server host not yet initialized, assuming regular server")
                self.is_seed_server = False
                return
                
            my_host = self.server.host
            seed_hosts = [seed[0] for seed in self.SEED_SERVERS]
            
            # Prüfe auf Seed-Server (inklusive localhost/127.0.0.1 für lokale Tests)
            self.is_seed_server = (my_host in seed_hosts or 
                                  my_host == 'localhost' or 
                                  my_host == '127.0.0.1' or
                                  my_host == '0.0.0.0' or  # Auch 0.0.0.0 zählt als Seed
                                  any(seed[0] in my_host for seed in self.SEED_SERVERS))
            
            print(f"🔍 Seed-Check: {my_host} → {'SEED-SERVER' if self.is_seed_server else 'Regular Server'}")
            
            # ✅ WENN WIR SEED SIND: Automatisch in known_servers eintragen
            if self.is_seed_server:
                self._register_self_as_seed()
            
        except Exception as e:
            print(f"⚠️  Seed check failed: {e}, assuming regular server")
            self.is_seed_server = False

    def _register_self_as_seed(self):
        """Registriert diesen Server automatisch als Seed in der known_servers Liste"""
        try:
            with self.data_lock:
                server_data = {
                    'ip': self._real_server_ip,  # ✅ ECHTE IP statt 0.0.0.0
                    'port': self.server.port,
                    'name': f"Seed-Server-{self._real_server_ip}",
                    'max_traffic': self.max_traffic_mbps,
                    'current_load': self.server_load,
                    'last_seen': time.time(),
                    'is_seed': True  # Markiere als Seed-Server
                }
                
                self.known_servers[self._real_server_ip] = server_data
                print(f"✅ Seed-Server automatisch registriert: {self._real_server_ip}:{self.server.port}")
                
        except Exception as e:
            print(f"❌ Fehler bei Selbst-Registrierung als Seed: {e}")

    def _start_regular_server(self):
        """Startet den Regular-Server Modus - NUR für nicht-Seed Server"""
        print("🚀 Starte als Regular Server...")
        
        # ✅ NUR für Regular Server: Bei Seeds registrieren
        if not self.is_seed_server:
            self._register_with_seeds()
            self._discover_other_servers()
        else:
            print("✅ Seed-Server - keine externe Registration nötig")
        
        # Starte Monitoring
        threading.Thread(target=self._load_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._server_discovery_loop, daemon=True).start()
    
    def _start_seed_server(self):
        """Startet den Seed-Server Modus"""
        print("🌱 Starte als SEED-SERVER...")
        
        # Seed-Server läuft auf den gleichen Ports wie SIP
        # Kein separater Port nötig!
        
        # Starte Load-Monitoring
        threading.Thread(target=self._load_monitoring_loop, daemon=True).start()
        
        print("✅ Seed-Server bereit (verwendet SIP-Ports 5060/5061)")
    
    def _setup_traffic_limits(self):
        """Einfaches Traffic-Setup"""
        print("\n=== TRAFFIC SETUP ===")
        
        try:
            traffic_input = input("Max traffic load in mbit/s: ").strip()
            self.max_traffic_mbps = float(traffic_input)
            print(f"✅ Traffic-Limit: {self.max_traffic_mbps} Mbit/s")
        except:
            self.max_traffic_mbps = 100
            print(f"⚠️  Verwende Standard: {self.max_traffic_mbps} Mbit/s")
    
    def _register_with_seeds(self):
        """Registriert diesen Server bei Seed-Servern - VERBESSERT MIT FRAMED SIP"""
        print("📝 Registriere bei Seed-Servern...")
        
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((seed_host, seed_port))
                
                # Baue SIP-Nachricht für Registration
                registration_data = {
                    'type': 'register',
                    'port': self.server.port,
                    'name': f"Server-{self._real_server_ip}",
                    'max_traffic': self.max_traffic_mbps,
                    'current_load': self.server_load,
                    'timestamp': time.time()
                }
                
                # Sende als framed SIP
                sip_message = self.server.build_sip_message(
                    "REGISTER", 
                    seed_host,
                    registration_data
                )
                
                # ✅ KORREKTUR: Verwende send_frame
                if send_frame(sock, sip_message.encode('utf-8')):
                    # Empfange Response MIT FRAMED SIP
                    response_data = recv_frame(sock)
                    if response_data:
                        try:
                            response = json.loads(response_data.decode('utf-8'))
                            if response.get('status') == 'registered':
                                print(f"✅ Bei Seed {seed_host}:{seed_port} registriert")
                                break
                        except Exception as e:
                            print(f"❌ Response parsing failed: {e}")
                    
            except Exception as e:
                print(f"❌ Registrierung bei {seed_host}:{seed_port} fehlgeschlagen: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass

    def _discover_other_servers(self):
        """Holt Server-Liste von Seed-Servern - VERBESSERT MIT FRAMED SIP"""
        print("🔍 Hole Server-Liste...")
        
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((seed_host, seed_port))
                
                request_data = {
                    'type': 'get_servers',
                    'requester_ip': self._real_server_ip,
                    'timestamp': time.time()
                }
                
                # Sende als framed SIP
                sip_message = self.server.build_sip_message(
                    "MESSAGE",
                    seed_host, 
                    request_data
                )
                
                # ✅ KORREKTUR: Verwende send_frame
                if send_frame(sock, sip_message.encode('utf-8')):
                    response_data = recv_frame(sock)
                    if response_data:
                        try:
                            response = json.loads(response_data.decode('utf-8'))
                            if response.get('status') == 'success':
                                servers = response.get('servers', {})
                                
                                # ✅ BEREINIGE: Entferne 0.0.0.0 Einträge
                                clean_servers = {}
                                for server_ip, server_data in servers.items():
                                    if server_ip != '0.0.0.0':
                                        clean_servers[server_ip] = server_data
                                
                                with self.data_lock:
                                    self.known_servers = clean_servers
                                
                                print(f"✅ {len(clean_servers)} Server in Liste von {seed_host}")
                                break
                        except Exception as e:
                            print(f"❌ Response parsing failed: {e}")
                        
            except Exception as e:
                print(f"❌ Discovery von {seed_host}:{seed_port} fehlgeschlagen: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass

    def _update_load_on_seeds(self):
        """Aktualisiert eigene Last bei Seed-Servern - VERBESSERT MIT FRAMED SIP"""
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((seed_host, seed_port))
                
                update_data = {
                    'type': 'update_load',
                    'server_ip': self._real_server_ip,
                    'current_load': self.server_load,
                    'timestamp': time.time()
                }
                
                # Sende als framed SIP
                sip_message = self.server.build_sip_message(
                    "MESSAGE",
                    seed_host,
                    update_data
                )
                
                # ✅ KORREKTUR: Verwende send_frame
                if send_frame(sock, sip_message.encode('utf-8')):
                    print(f"📈 Load update an {seed_host}: {self.server_load}%")
                
                sock.close()
                break  # Nur einen Seed-Server benachrichtigen
                
            except Exception as e:
                print(f"❌ Load update an {seed_host} fehlgeschlagen: {e}")
                continue
    
    def handle_seed_request(self, sip_message, client_socket, client_address):
        """Verarbeitet Seed-Anfragen - KORRIGIERT FÜR DISCOVERY"""
        if not self.is_seed_server:
            return False
            
        try:
            message = self.server.parse_sip_message(sip_message)
            if not message:
                return False
                
            custom_data = message.get('custom_data', {})
            request_type = custom_data.get('type')
            message_type = custom_data.get('MESSAGE_TYPE')
            
            response_data = {}
            
            # ✅ DISCOVERY_REQUEST VON CLIENT ERKENNEN
            if message_type == 'DISCOVERY_REQUEST':
                print(f"[RELAY] Discovery request from {client_address[0]}")
                response_data = self._handle_seed_get_servers(custom_data)
                
            elif request_type == 'register':
                response_data = self._handle_seed_register(custom_data, client_address[0])
            elif request_type == 'get_servers':
                response_data = self._handle_seed_get_servers(custom_data)
            elif request_type == 'update_load':
                response_data = self._handle_load_update(custom_data)
            else:
                print(f"[RELAY WARNING] Unknown seed request: {request_type}")
                response_data = {
                    'status': 'error',
                    'error': f'Unknown request type: {request_type}'
                }
            
            # ✅ KORREKTUR: IMMER FRAMED SIP VERWENDEN
            response_msg = self.server.build_sip_message(
                "200 OK", 
                client_address[0],
                response_data
            )
            
            # ✅ SEND_FRAME VERWENDEN, NICHT sock.send()
            success = send_frame(client_socket, response_msg.encode('utf-8'))
            
            if success:
                print(f"[RELAY] ✅ Framed SIP response sent for {request_type or message_type} to {client_address[0]}")
            else:
                print(f"[RELAY] ❌ Failed to send framed SIP response to {client_address[0]}")
                
            return success
                
        except Exception as e:
            print(f"[RELAY ERROR] Seed Request failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _handle_seed_register(self, request_data, client_ip):
        """Verarbeitet Registrierungsanfragen"""
        with self.data_lock:
            server_data = {
                'ip': client_ip,
                'port': request_data['port'],
                'name': request_data.get('name', 'Unnamed'),
                'max_traffic': request_data.get('max_traffic', 100),
                'current_load': request_data.get('current_load', 0),
                'last_seen': time.time()
            }
            
            self.known_servers[client_ip] = server_data
            print(f"✅ Server registriert: {client_ip}:{request_data['port']}")
            
            return {
                'status': 'registered', 
                'server_count': len(self.known_servers),
                'message': f"Welcome! {len(self.known_servers)} servers total"
            }
    
    def _handle_seed_get_servers(self, request_data):
        """Gibt komplette Server-Liste zurück"""
        with self.data_lock:
            # Aktualisiere Load für alle Server
            current_time = time.time()
            for server_ip, server_data in self.known_servers.items():
                # Simuliere Load-Update falls älter als 2 Minuten
                if current_time - server_data.get('last_load_update', 0) > 120:
                    server_data['current_load'] = random.randint(0, 100)
                    server_data['last_load_update'] = current_time
            
            # ✅ ENTFERNE 0.0.0.0 Einträge falls vorhanden
            clean_servers = {}
            for server_ip, server_data in self.known_servers.items():
                if server_ip != '0.0.0.0':  # Filtere ungültige IPs
                    clean_servers[server_ip] = server_data
            
            return {
                'status': 'success',
                'servers': clean_servers,
                'total_servers': len(clean_servers),
                'timestamp': time.time()
            }
    
    def _handle_load_update(self, request_data):
        """Verarbeitet Load-Updates von Servern"""
        server_ip = request_data['server_ip']
        new_load = request_data['current_load']
        
        with self.data_lock:
            if server_ip in self.known_servers:
                self.known_servers[server_ip]['current_load'] = new_load
                self.known_servers[server_ip]['last_load_update'] = time.time()
                print(f"📊 Load Update: {server_ip} → {new_load}%")
        
        return {'status': 'load_updated'}
    
    def _load_monitoring_loop(self):
        """Überwacht und aktualisiert Server-Last"""
        while True:
            try:
                # Aktuelle Last berechnen (simuliert)
                traffic_ratio = self.current_traffic / self.max_traffic_mbps if self.max_traffic_mbps > 0 else 0
                self.server_load = min(100, int(traffic_ratio * 100))
                
                # Aktualisiere Last bei Seed-Servern (wenn nicht selbst Seed)
                if not self.is_seed_server:
                    self._update_load_on_seeds()
                
                time.sleep(30)  # Alle 30 Sekunden
                
            except Exception as e:
                print(f"Load Monitoring Error: {e}")
                time.sleep(60)

    
    def _server_discovery_loop(self):
        """Updated regelmäßig die Server-Liste"""
        while True:
            time.sleep(1800)  # Alle 30 Minuten
            print("🔄 Aktualisiere Server-Liste...")
            self._discover_other_servers()
    
    def get_server_list_for_client(self):
        """Gibt Server-Liste für Clients zurück - als framed SIP Message"""
        with self.data_lock:
            # Filtere Server mit Load < 100%
            available_servers = {}
            for server_ip, server_data in self.known_servers.items():
                if server_data.get('current_load', 100) < 100:
                    available_servers[server_ip] = server_data
            
            return {
                'servers': available_servers,
                'timestamp': time.time(),
                'total_available': len(available_servers),
                'total_servers': len(self.known_servers)
            }
    
    def get_server_status(self):
        """Gibt einfachen Status zurück"""
        with self.data_lock:
            available_count = sum(1 for s in self.known_servers.values() if s.get('current_load', 100) < 100)
            
            return {
                'is_seed_server': self.is_seed_server,
                'current_load': self.server_load,
                'known_servers': len(self.known_servers),
                'available_servers': available_count,
                'max_traffic': self.max_traffic_mbps,
                'current_traffic': self.current_traffic,
                'real_server_ip': self._real_server_ip  # ✅ NEU: Für Debugging
            }
class CONVEY:
    def __init__(self, server_instance):
        self.server = server_instance
        self.active_calls = {}
        self.call_lock = threading.RLock()
        
        # ✅ KRITISCH: SESSION_ID_LENGTH DEFINIEREN (muss mit CALL Klasse übereinstimmen)
        self.SESSION_ID_LENGTH = 8  # 8 Bytes für Session-ID
        
        # ✅ KONSISTENTE INITIALISIERUNG ALLER VARIABLEN
        self.udp_relay_port = 51820  # Einziger Server-Port
        self.audio_relays = {}  
        self.relay_lock = threading.Lock()
        self.udp_socket = None
        
        # ✅ SESSION-ROUTING HIER INITIALISIEREN
        self.session_routing = {}  # {session_bytes: target_addr}
        
        # ⚡ Legacy Connection Map (für Kompatibilität)
        self.connection_map = {}  
        self.client_names = {}    
        
        # Starte UDP Relay Server
        self._start_udp_relay()

    def _start_udp_relay(self):
        """🚀 KORRIGIERT: Konsistente Initialisierung"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.setblocking(False)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
            self.udp_socket.bind(('0.0.0.0', self.udp_relay_port))
            
            # ✅ SESSION-ROUTING SICHER INITIALISIEREN
            if not hasattr(self, 'session_routing'):
                self.session_routing = {}
            
            print(f"[TURBO RELAY] 🚀 Session-Based System gestartet:")
            print(f"  ⚡ Server Port: {self.udp_relay_port} (Session-Routing)")
            print(f"  📞 Client Port: 51821")
            print(f"  🔑 Session Routing entries: {len(self.session_routing)}")
            
            # Starte Turbo Loop
            threading.Thread(target=self._turbo_relay_loop, daemon=True, name="SessionTurboLoop").start()
            
        except Exception as e:
            print(f"[RELAY ERROR] Failed to start: {e}")
            import traceback
            traceback.print_exc()

    def _turbo_relay_loop(self):
        """⚡ KORRIGIERT: Session-basiertes UDP Relay mit KONSISTENTER Bytes-Verarbeitung"""
        import select
        packet_count = 0
        
        print(f"[TURBO RELAY FIXED] 🚀 Starting CONSISTENT bytes-based turbo loop...")
        
        while True:
            try:
                ready, _, _ = select.select([self.udp_socket], [], [], 0.05)
                
                if ready:
                    # ✅ GRÖSSENVALIDIERUNG
                    data, src_addr = self.udp_socket.recvfrom(1400)
                    packet_count += 1
                    
                    # ✅ VALIDIERUNG: Mindestens 8 Bytes für Session-ID
                    if len(data) < self.SESSION_ID_LENGTH:
                        continue
                        
                    if len(data) > 1400:
                        continue
                            
                    # ✅ KONSISTENT: Session-ID als Bytes extrahieren
                    session_bytes = data[:self.SESSION_ID_LENGTH]
                    
                    # ⚡ DEBUG: Zeige was tatsächlich ankommt
                    if packet_count % 100 == 0:
                        session_hex = session_bytes.hex()
                        print(f"🔍 [RELAY DEBUG] Packet #{packet_count} - Session: {session_hex} from {src_addr}")
                    
                    # ⚡ SCHNELLER SESSION-LOOKUP MIT BYTES
                    with self.relay_lock:
                        target_addr = self.session_routing.get(session_bytes)
                    
                    if target_addr:
                        try:
                            # ⚡ DIREKTES WEITERLEITEN
                            self.udp_socket.sendto(data, target_addr)
                            
                            # ✅ DEBUG: Zeige erfolgreiches Routing
                            if packet_count % 500 == 0:
                                session_hex = session_bytes.hex()
                                print(f"📤 [TURBO RELAY] Packet #{packet_count} routed via {session_hex} to {target_addr}")
                                    
                        except Exception as send_error:
                            print(f"[TURBO RELAY SEND ERROR] {send_error}")
                            # ✅ CLEANUP: Defekte Verbindungen
                            if "Connection refused" in str(send_error) or "Host is down" in str(send_error):
                                with self.relay_lock:
                                    # Finde und entferne alle Sessions die zu dieser Adresse führen
                                    sessions_to_remove = []
                                    for sess_bytes, addr in self.session_routing.items():
                                        if addr == target_addr:
                                            sessions_to_remove.append(sess_bytes)
                                    
                                    for sess_bytes in sessions_to_remove:
                                        del self.session_routing[sess_bytes]
                                        print(f"[TURBO RELAY] Removed broken session {sess_bytes.hex()}")
                    else:
                        # ❌ Keine Route für Session-ID
                        session_hex = session_bytes.hex()
                        print(f"❌ [TURBO RELAY WARNING] No route for session {session_hex} from {src_addr}")
                        
                        # 🔍 DEBUG: Zeige aktuelle Routing-Tabelle
                        if packet_count % 10 == 0:
                            with self.relay_lock:
                                print(f"🔍 [ROUTING TABLE DEBUG] {len(self.session_routing)} active sessions:")
                                for sess_bytes, addr in list(self.session_routing.items())[:3]:
                                    sess_hex = sess_bytes.hex()
                                    print(f"   {sess_hex} -> {addr}")
                                
            except BlockingIOError:
                continue
            except Exception as e:
                if "10054" not in str(e):
                    print(f"[TURBO RELAY ERROR] {e}")
                continue

    def _register_audio_relay(self, call_id, caller_name, callee_name):
        """🎯 KORRIGIERT: Generiert Session-IDs als BYTES für Konsistenz"""
        try:
            import secrets
            
            # ✅ KONSISTENT: Direkt 8 Bytes generieren (keine Strings!)
            caller_session_bytes = secrets.token_bytes(self.SESSION_ID_LENGTH)
            callee_session_bytes = secrets.token_bytes(self.SESSION_ID_LENGTH)
            
            print(f"[RELAY FIXED] {self.SESSION_ID_LENGTH}-Byte Session-IDs generiert:")
            print(f"  Caller → Callee: {caller_session_bytes.hex()}")
            print(f"  Callee → Caller: {callee_session_bytes.hex()}")

            # ✅ IP-Adressen ermitteln
            caller_ip = None
            callee_ip = None
            
            with self.server.clients_lock:
                for client_id, client_info in self.server.clients.items():
                    client_name = client_info.get('name', '')
                    if client_name == caller_name:
                        caller_ip = client_info.get('ip')
                    elif client_name == callee_name:
                        callee_ip = client_info.get('ip')
            
            if not caller_ip or not callee_ip:
                print(f"[RELAY ERROR] Could not find IP addresses for clients")
                return False

            # ✅ ROUTING EINRICHTEN MIT BYTES
            with self.relay_lock:
                # Alte Sessions bereinigen
                self._cleanup_existing_sessions(call_id)
                
                # Neues Routing mit BYTES als Keys
                self.session_routing[caller_session_bytes] = (callee_ip, 51821)
                self.session_routing[callee_session_bytes] = (caller_ip, 51821)
                
                print(f"[RELAY FIXED] Routing eingerichtet:")
                print(f"  {caller_session_bytes.hex()} -> {callee_ip}:51821")
                print(f"  {callee_session_bytes.hex()} -> {caller_ip}:51821")

            # ✅ Relay-Info speichern (NUR BYTES)
            self.audio_relays[call_id] = {
                'caller_name': caller_name,
                'callee_name': callee_name,
                'caller_addr': (caller_ip, 51821),
                'callee_addr': (callee_ip, 51821),
                # ✅ KONSISTENT: Nur Bytes speichern
                'caller_session_bytes': caller_session_bytes,
                'callee_session_bytes': callee_session_bytes,
                'timestamp': time.time(),
            }
            
            # ✅ An Clients als HEX-Strings senden (für einfache Übertragung)
            return {
                'caller_session_id': caller_session_bytes.hex(),  # Bytes zu Hex-String
                'callee_session_id': callee_session_bytes.hex()   # Bytes zu Hex-String
            }
            
        except Exception as e:
            print(f"[RELAY ERROR] Failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    def _cleanup_existing_sessions(self, call_id):
        """Bereinige alte Sessions für diesen Call"""
        if call_id in self.audio_relays:
            old_relay = self.audio_relays[call_id]
            if 'caller_session_bytes' in old_relay:
                self.session_routing.pop(old_relay['caller_session_bytes'], None)
            if 'callee_session_bytes' in old_relay:  
                self.session_routing.pop(old_relay['callee_session_bytes'], None)
        
    def _debug_session_routing(self):
        """🔍 ERWEITERT: Debug-Ausgabe mit Bytes/Hex-Konsistenz-Prüfung"""
        with self.relay_lock:
            print("\n" + "="*70)
            print("🔍 BYTES/HEX SESSION CONSISTENCY DEBUG")
            print("="*70)
            print(f"Total routing entries: {len(self.session_routing)}")
            print(f"Total active relays: {len(self.audio_relays)}")
            
            # 1. Routing-Tabelle (Bytes Keys)
            print(f"\n📋 ROUTING TABLE ({len(self.session_routing)} entries):")
            if not self.session_routing:
                print("  ❌ NO ROUTING ENTRIES")
            else:
                for session_bytes, target_addr in self.session_routing.items():
                    session_hex = session_bytes.hex()
                    print(f"  Bytes: {session_bytes.hex()} -> {target_addr}")
            
            # 2. Active Calls (Hex-Strings)
            print(f"\n📞 ACTIVE CALLS ({len(self.active_calls)}):")
            for call_id, call_data in self.active_calls.items():
                caller_hex = call_data.get('caller_session_id', 'MISSING')
                callee_hex = call_data.get('callee_session_id', 'MISSING')
                
                print(f"  Call {call_id}:")
                print(f"    Caller Session: {caller_hex}")
                print(f"    Callee Session: {callee_hex}")
                
                # ✅ KONSISTENZ-PRÜFUNG
                try:
                    caller_bytes = bytes.fromhex(caller_hex) if caller_hex != 'MISSING' else None
                    callee_bytes = bytes.fromhex(callee_hex) if callee_hex != 'MISSING' else None
                    
                    caller_in_routing = caller_bytes in self.session_routing if caller_bytes else False
                    callee_in_routing = callee_bytes in self.session_routing if callee_bytes else False
                    
                    status = "✅ CONSISTENT" if (caller_in_routing and callee_in_routing) else "❌ INCONSISTENT"
                    print(f"    Status: {status}")
                    
                except ValueError as e:
                    print(f"    Status: ❌ INVALID HEX: {e}")
            
            print("="*70)  
        
    def _is_server_in_same_nat(self, caller_nat_ip, callee_nat_ip):
        """Ermittelt ob der Server im gleichen NAT wie die Clients ist - VOLLSTÄNDIG KORRIGIERT"""
        try:
            # Server-IP ermitteln
            server_ip = self._get_server_public_ip()
            
            print(f"[RELAY DEBUG] Server IP: {server_ip}")
            print(f"[RELAY DEBUG] Caller NAT IP: {caller_nat_ip}")
            print(f"[RELAY DEBUG] Callee NAT IP: {callee_nat_ip}")
            
            # ✅ KRITISCHE KORREKTUR: Server ist IMMER im gleichen NAT wie sich selbst
            # Wenn einer der Clients die gleiche IP wie der Server hat → gleiches NAT
            
            # ✅ NEUE LOGIK: 
            # - Wenn Server lokale IP hat UND einer der Clients die gleiche lokale IP → gleiches NAT
            # - Wenn Server öffentliche IP hat UND einer der Clients die gleiche öffentliche IP → gleiches NAT
            
            caller_same_as_server = (caller_nat_ip == server_ip)
            callee_same_as_server = (callee_nat_ip == server_ip)
            
            # ✅ Server ist im gleichen NAT wenn mindestens ein Client die gleiche IP hat
            server_in_same_nat = caller_same_as_server or callee_same_as_server
            
            print(f"[RELAY DEBUG] Server in same NAT: {server_in_same_nat} (caller_same={caller_same_as_server}, callee_same={callee_same_as_server})")
            
            return server_in_same_nat
            
        except Exception as e:
            print(f"[RELAY WARNING] Could not determine server position: {e}")
            return False  # Im Zweifel: Server ist extern

    def _get_server_public_ip(self):
        """Ermittelt die ÖFFENTLICHE IP des Servers - KORRIGIERT"""
        try:
            try:
                # Methode 1: Über externen Service
                import urllib.request
                import json
                with urllib.request.urlopen('https://httpbin.org/ip', timeout=5) as response:
                    data = json.loads(response.read())
                    public_ip = data['origin']
                    print(f"[RELAY] Server public IP from external service: {public_ip}")
                    return public_ip
            except:
                # Methode 2: Socket Peer-IP (wenn Server hinter NAT)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]  # Lokale IP
                s.close()
                
                # ✅ KORREKTUR: Wenn Server lokale IP hat, können wir keine öffentliche IP ermitteln
                # In diesem Fall geben wir die lokale IP zurück und die Entscheidung wird anders getroffen
                if local_ip.startswith('192.168.') or local_ip.startswith('10.'):
                    print(f"[RELAY] Server has local IP {local_ip} - cannot determine public IP")
                    return local_ip  # ✅ KORREKTUR: Lokale IP zurückgeben
                
                print(f"[RELAY] Server has non-local IP {local_ip} - using as public IP")
                return local_ip
                
        except Exception as e:
            print(f"[RELAY WARNING] Could not get server public IP: {e}")
            return "UNKNOWN"

    def _get_local_audio_address(self, client_data, client_name):
        """Ermittelt lokale Audio-Adresse - KORRIGIERT"""
        local_ip = client_data.get('ip')  # Das ist die wichtige lokale IP
        if local_ip:
            audio_addr = (local_ip, 51821)
            print(f"[RELAY DEBUG] {client_name} local audio address: {audio_addr}")
            return audio_addr
        
        print(f"[RELAY ERROR] No local IP found for {client_name} in registration data")
        return None

    def _get_nat_audio_address(self, client_data, client_name):
        """Ermittelt NAT Audio-Adresse - KORRIGIERT"""
        nat_ip = client_data.get('nat_ip', client_data.get('ip'))  # Fallback auf lokale IP
        if nat_ip:
            audio_addr = (nat_ip, 51821)
            print(f"[RELAY DEBUG] {client_name} NAT audio address: {audio_addr}")
            return audio_addr
        
        print(f"[RELAY ERROR] No NAT IP found for {client_name}")
        return None
    def _get_nat_ip(self, client_data, client_name):
        """Ermittelt die NAT-IP eines Clients - Fallback Methode"""
        try:
            # Primär: Verwende das nat_ip Feld
            nat_ip = client_data.get('nat_ip')
            if nat_ip:
                return nat_ip
            
            # Fallback: Versuche Socket-Peer-IP
            client_socket = client_data.get('socket')
            if client_socket:
                try:
                    peer_ip, peer_port = client_socket.getpeername()
                    return peer_ip
                except Exception as e:
                    print(f"[RELAY WARNING] Could not get NAT IP from socket for {client_name}: {e}")
            
            # Letzter Fallback: Verwende lokale IP
            return client_data.get('ip')
            
        except Exception as e:
            print(f"[RELAY ERROR] Failed to get NAT IP for {client_name}: {e}")
            return None
    def _debug_connection_map(self):
        """Debug-Ausgabe der Connection Map"""
        with self.relay_lock:
            print("\n=== CONNECTION MAP DEBUG ===")
            print(f"Total connections: {len(self.connection_map)}")
            print(f"Active relays: {len(self.audio_relays)}")
            
            if not self.connection_map:
                print("  ❌ NO CONNECTIONS")
            else:
                for src, target in self.connection_map.items():
                    src_name = self.client_names.get(src, 'unknown')
                    target_name = self.client_names.get(target, 'unknown')
                    
                    # Erkenne ob lokale oder NAT-Verbindung
                    src_type = "LOCAL" if src[0].startswith('192.168.') or src[0].startswith('10.') else "NAT"
                    target_type = "LOCAL" if target[0].startswith('192.168.') or target[0].startswith('10.') else "NAT"
                    
                    print(f"  {src_name} {src} [{src_type}] <-> {target_name} {target} [{target_type}]")
            
            print("=== ACTIVE CALLS ===")
            for call_id, relay_data in self.audio_relays.items():
                same_nat = relay_data.get('same_nat', False)
                nat_status = "SAME_NAT" if same_nat else "DIFFERENT_NAT"
                print(f"  Call {call_id}: {relay_data['caller_name']} <-> {relay_data['callee_name']} [{nat_status}]")
            
            print("=" * 50)

    def _unregister_audio_relay(self, call_id):
        """🚀 Optimiertes Unregister für Hybrid-System"""
        with self.relay_lock:
            if call_id in self.audio_relays:
                relay_data = self.audio_relays[call_id]
                
                # ⚡ SCHNELLES CLEANUP der Turbo-Loop Connection Map
                caller_addr = relay_data.get('caller_addr')
                callee_addr = relay_data.get('callee_addr')
                
                if caller_addr and caller_addr in self.connection_map:
                    del self.connection_map[caller_addr]
                    print(f"[RELAY] Removed caller {caller_addr} from connection map")
                    
                if callee_addr and callee_addr in self.connection_map:  
                    del self.connection_map[callee_addr]
                    print(f"[RELAY] Removed callee {callee_addr} from connection map")
                
                # Cleanup client_names
                if caller_addr and caller_addr in self.client_names:
                    del self.client_names[caller_addr]
                if callee_addr and callee_addr in self.client_names:
                    del self.client_names[callee_addr]
                
                # Alte Struktur cleanup
                del self.audio_relays[call_id]
                print(f"[RELAY] ✅ Unregistered hybrid relay for call {call_id}")
                
                # Debug Info
                print(f"[RELAY DEBUG] Remaining connection map entries: {len(self.connection_map)}")
                print(f"[RELAY DEBUG] Remaining audio relays: {len(self.audio_relays)}")


    def handle_get_public_key(self, msg, client_socket, client_name):
        """VOLLSTÄNDIG KORRIGIERT: Public-Key-Antwort mit erweitertem Debugging"""
        try:
            print(f"\n=== CONVEY: GET_PUBLIC_KEY PROCESSING ===")
            print(f"[CONVEY] Processing GET_PUBLIC_KEY from {client_name}")
            
            custom_data = msg.get('custom_data', {})
            
            # EINHEITLICHE Daten-Extraktion
            target_id = custom_data.get('TARGET_CLIENT_ID')
            caller_name = custom_data.get('CALLER_NAME', client_name)
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            print(f"[CONVEY DEBUG] Target ID: {target_id}")
            print(f"[CONVEY DEBUG] Caller name: {caller_name}")
            print(f"[CONVEY DEBUG] Caller client ID: {caller_client_id}")
            print(f"[CONVEY DEBUG] Custom data keys: {list(custom_data.keys())}")

            if not target_id:
                print("[CONVEY ERROR] Missing target client ID")
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "MISSING_TARGET_CLIENT_ID",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False
                
            print(f"[CONVEY] Public key request from {caller_name} for client {target_id}")

            # Ziel-Client finden (thread-safe)
            target_client = None
            target_client_name = None
            target_client_id = None
            
            with self.server.clients_lock:
                print(f"[CONVEY DEBUG] Searching through {len(self.server.clients)} clients:")
                for client_id, client_info in self.server.clients.items():
                    client_name_debug = client_info.get('name', 'unknown')
                    has_pubkey = 'public_key' in client_info
                    print(f"[CONVEY DEBUG] Client {client_id}: {client_name_debug} (pubkey: {has_pubkey})")
                    
                    # ✅ VERBESSERTE SUCHE: Prüfe sowohl Client-ID als auch Name
                    if str(client_id) == str(target_id):
                        target_client = client_info
                        target_client_name = client_name_debug
                        target_client_id = client_id
                        print(f"[CONVEY DEBUG] ✓ Found target by ID: {client_name_debug}")
                        break
                    elif client_name_debug == target_id:
                        target_client = client_info  
                        target_client_name = client_name_debug
                        target_client_id = client_id
                        print(f"[CONVEY DEBUG] ✓ Found target by name: {client_name_debug}")
                        break

            if not target_client:
                print(f"[CONVEY ERROR] Target client {target_id} not found in clients")
                print(f"[CONVEY DEBUG] Available clients: {list(self.server.clients.keys())}")
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "TARGET_NOT_FOUND",
                    "TARGET_ID": target_id,
                    "DEBUG_INFO": f"Available clients: {list(self.server.clients.keys())}",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            if 'public_key' not in target_client:
                print(f"[CONVEY ERROR] Target client {target_client_name} has no public key")
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "TARGET_NO_PUBLIC_KEY",
                    "TARGET_ID": target_id,
                    "TARGET_NAME": target_client_name,
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            # Public Key des Ziels extrahieren
            target_public_key = target_client['public_key']
            print(f"[CONVEY] Found public key for target {target_client_name} (length: {len(target_public_key)})")

            # ✅ EINHEITLICHE Response-Erstellung
            response_data = {
                "MESSAGE_TYPE": "PUBLIC_KEY_RESPONSE",
                "TARGET_CLIENT_ID": target_client_id,
                "TARGET_CLIENT_NAME": target_client_name,
                "PUBLIC_KEY": target_public_key,
                "CALLER_NAME": caller_name,
                "CALLER_CLIENT_ID": caller_client_id,
                "TIMESTAMP": int(time.time()),
                "STATUS": "SUCCESS"
            }
            
            response_msg = self.server.build_sip_message(
                "MESSAGE", 
                caller_name, 
                response_data
            )
            
            print(f"[CONVEY] Sending PUBLIC_KEY_RESPONSE to {caller_name}")
            print(f"[CONVEY DEBUG] Response data: {response_data}")
            
            # EINHEITLICHES Framing
            success = send_frame(client_socket, response_msg.encode('utf-8'))
            
            if success:
                print(f"[CONVEY SUCCESS] Sent public key for client {target_client_name} to {caller_name}")
                return True
            else:
                print(f"[CONVEY ERROR] Failed to send public key response to {caller_name}")
                return False
                
        except Exception as e:
            print(f"[CONVEY ERROR] Public key handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            try:
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": f"PUBLIC_KEY_PROCESSING_FAILED: {str(e)}",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                pass
                
            return False
    def handle_call_request(self, msg, client_socket, client_name):
        """🚀 KORRIGIERT: Mit KONSISTENTER Session-ID Übergabe"""
        try:
            custom_data = msg.get('custom_data', {})
            target_id = custom_data.get('TARGET_CLIENT_ID')
            encrypted_data = custom_data.get('ENCRYPTED_CALL_DATA')
            caller_name = custom_data.get('CALLER_NAME')
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            print(f"[CONVEY] Framed SIP call request from {caller_name} to target {target_id}")

            # ✅ VALIDIERUNG
            if not all([target_id, encrypted_data, caller_name, caller_client_id]):
                print("[CONVEY ERROR] Missing required fields")
                return False

            # ✅ ZIELSUCHE
            target_client = None
            target_socket = None
            target_client_name = None
            target_client_id = None
            
            with self.server.clients_lock:
                for client_id, client_info in self.server.clients.items():
                    client_name_debug = client_info.get('name', 'unknown')
                    
                    if str(client_id) == str(target_id) or client_name_debug == target_id:
                        target_client = client_info
                        target_socket = client_info.get('socket')
                        target_client_name = client_name_debug
                        target_client_id = client_id
                        print(f"[CONVEY DEBUG] ✓ Found target: {client_name_debug}")
                        break

            if not target_client or not target_socket:
                print(f"[CONVEY ERROR] Target client {target_id} not found or offline")
                return False

            # ✅ Server IP für Relay
            def get_server_public_ip():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    return local_ip
                except:
                    return self.server.host
            
            server_ip = get_server_public_ip()

            # ✅ CALL REGISTRIERUNG
            call_id = f"{caller_client_id}_{target_client_id}_{int(time.time())}"
            
            # ✅ AUDIO RELAY SETUP MIT KONSISTENTEN BYTES
            relay_result = self._register_audio_relay(call_id, caller_name, target_client_name)
            if not relay_result:
                print("[CONVEY ERROR] Failed to setup audio relay")
                return False

            # ✅ KONSISTENT: Hex-Strings vom Relay erhalten
            caller_session_hex = relay_result.get('caller_session_id')  # Hex-String
            callee_session_hex = relay_result.get('callee_session_id')  # Hex-String
            
            if not caller_session_hex or not callee_session_hex:
                print("[CONVEY ERROR] Missing session IDs from relay setup")
                return False

            print(f"[CONVEY] ✅ Bidirectional Session IDs generated:")
            print(f"  Caller: {caller_session_hex}")
            print(f"  Callee: {callee_session_hex}")

            # ✅ INCOMING_CALL AN CALLEE mit HEX-STRINGS
            incoming_call_data = {
                "MESSAGE_TYPE": "INCOMING_CALL",
                "CALLER_NAME": caller_name,
                "CALLER_CLIENT_ID": caller_client_id,
                "ENCRYPTED_CALL_DATA": encrypted_data,
                "TIMESTAMP": int(time.time()),
                "TIMEOUT": 120,
                "USE_AUDIO_RELAY": True,
                "AUDIO_RELAY_IP": server_ip,
                "SERVER_RELAY_PORT": self.udp_relay_port,
                "CLIENT_PORT": 51821,
                # ✅ KONSISTENT: Hex-Strings senden
                "CALLER_SESSION_ID": caller_session_hex,  # Hex-String für Empfangen von Caller
                "CALLEE_SESSION_ID": callee_session_hex   # Hex-String für Senden an Caller
            }
            
            incoming_call_msg = self.server.build_sip_message("MESSAGE", target_client_name, incoming_call_data)
            
            print(f"[CONVEY DEBUG] Outgoing INCOMING_CALL with session IDs:")
            print(f"  Caller Session: {caller_session_hex}")
            print(f"  Callee Session: {callee_session_hex}")
            
            send_success = send_frame(target_socket, incoming_call_msg.encode('utf-8'))
            
            if not send_success:
                print("[CONVEY ERROR] Failed to send framed SIP INCOMING_CALL")
                return False

            print(f"[CONVEY] ✓ Framed SIP INCOMING_CALL successfully sent to target {target_client_name}")

            # ✅ ACTIVE CALLS REGISTRIERUNG
            self.active_calls[call_id] = {
                'caller_id': caller_client_id,
                'callee_id': target_client_id,
                'caller_name': caller_name,
                'callee_name': target_client_name,
                'caller_socket': client_socket,
                'callee_socket': target_socket,
                'start_time': time.time(),
                'status': 'pending',
                'timeout': 120,
                'server_ip': server_ip,
                # ✅ KONSISTENT: Hex-Strings speichern
                'caller_session_id': caller_session_hex,
                'callee_session_id': callee_session_hex
            }

            print(f"[CONVEY] Call {call_id} registered in active calls")

            # ✅ ACKNOWLEDGMENT AN CALLER mit HEX-STRINGS
            ack_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                "MESSAGE_TYPE": "CALL_REQUEST_ACK",
                "STATUS": "CALL_FORWARDED",
                "TARGET_ID": target_client_id,
                "TARGET_NAME": target_client_name,
                "CALL_ID": call_id,
                "TIMESTAMP": int(time.time()),
                "SERVER_RELAY_PORT": self.udp_relay_port,
                "CLIENT_PORT": 51821,
                # ✅ KONSISTENT: Hex-Strings senden
                "CALLER_SESSION_ID": caller_session_hex,  # Hex-String für Senden an Callee
                "CALLEE_SESSION_ID": callee_session_hex   # Hex-String für Empfangen von Callee
            })
            
            ack_success = send_frame(client_socket, ack_msg.encode('utf-8'))
            if ack_success:
                print(f"[CONVEY] ✓ Call request acknowledgment sent to caller {caller_name}")
            else:
                print(f"[CONVEY WARNING] Failed to send acknowledgment to caller")

            # Timeout-Überwachung
            threading.Thread(
                target=self._call_timeout_watchdog,
                args=(call_id,),
                daemon=True
            ).start()

            print(f"[CONVEY] ✅ Framed SIP call request completed for {call_id}")
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Framed SIP call request failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def handle_call_response(self, msg, client_socket, client_name):
        """🚀 KORRIGIERT: Mit bidirektionalen Session-IDs für Audio-Routing"""
        try:
            custom_data = msg.get('custom_data', {})
            response = custom_data.get('RESPONSE')
            caller_id = custom_data.get('CALLER_CLIENT_ID')
            
            print(f"[CONVEY] Framed SIP call response from {client_name}: {response}")
            print(f"[CONVEY DEBUG] Caller ID: {caller_id}")

            if not response or not caller_id:
                print("[CONVEY ERROR] Missing response or caller_id in framed SIP")
                return False
                
            # ✅ CALL-SUCHE
            call_id = None
            call_data = None
            
            print(f"[CONVEY DEBUG] Searching through {len(self.active_calls)} active calls")
            for cid, data in self.active_calls.items():
                print(f"[CONVEY DEBUG] Call {cid}: caller_id={data.get('caller_id')}, callee_id={data.get('callee_id')}, callee_name={data.get('callee_name')}")
                
                callee_matches = str(data['callee_id']) == str(client_name)  # ID-Vergleich
                caller_matches = str(data['caller_id']) == str(caller_id)    # ID-Vergleich
                
                # ✅ FALLBACK: Suche auch nach callee_name falls ID nicht matcht
                if not callee_matches:
                    callee_matches = str(data['callee_name']) == str(client_name)  # Name-Vergleich
                
                if callee_matches and caller_matches:
                    call_id = cid
                    call_data = data
                    print(f"[CONVEY DEBUG] ✓ Found matching call: {cid}")
                    break
            
            if not call_data:
                print(f"[CONVEY ERROR] No active call found for client {client_name} -> caller_id {caller_id}")
                return False
            
            print(f"[CONVEY] Processing call response for call {call_id}")
            
            # ✅ Server IP ermitteln
            def get_server_public_ip():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    return local_ip
                except:
                    return self.server.host
            
            server_ip = get_server_public_ip()
            
            # ✅ FRAME-SIP BEARBEITUNG
            if response == "accepted":
                print(f"[CONVEY] Call {call_id} accepted by {client_name}")
                
                # ✅ Session-IDs aus call_data holen
                caller_session_id = call_data.get('caller_session_id')
                callee_session_id = call_data.get('callee_session_id')
                
                if not caller_session_id or not callee_session_id:
                    print("[CONVEY ERROR] Missing session IDs in call data")
                    return False
                
                print(f"[CONVEY] ✅ Using Session-IDs - Caller: {caller_session_id}, Callee: {callee_session_id}")
                
                # ✅ CALL_RESPONSE AN CALLER mit BEIDEN Session-IDs
                response_data = {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "accepted",
                    "CALLER_CLIENT_ID": caller_id,
                    "TIMESTAMP": int(time.time()),
                    "USE_AUDIO_RELAY": True,
                    "AUDIO_RELAY_IP": server_ip,
                    # ✅ SINGLE-PORT SYSTEM INFORMATIONEN
                    "SERVER_RELAY_PORT": self.udp_relay_port,
                    "CLIENT_PORT": 51821,
                    # ✅ NEU: BIDIREKTIONALE SESSION-IDs
                    "CALLER_SESSION_ID": caller_session_id,  # Für Senden an Callee
                    "CALLEE_SESSION_ID": callee_session_id   # Für Empfangen von Callee
                }
                
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], response_data)
                send_success = send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                
                if send_success:
                    call_data['status'] = 'accepted'
                    print(f"[CONVEY] ✅ Call accepted response sent to {call_data['caller_name']} with both Session-IDs")
                    
                    # ✅ CALL_CONFIRMED an BEIDE CLIENTS mit jeweiligen Session-IDs
                    
                    # 1. CALL_CONFIRMED an CALLEE
                    callee_msg_data = {
                        "MESSAGE_TYPE": "CALL_CONFIRMED",
                        "TIMESTAMP": int(time.time()),
                        "USE_AUDIO_RELAY": True,
                        "AUDIO_RELAY_IP": server_ip,
                        "SERVER_RELAY_PORT": self.udp_relay_port,
                        "CLIENT_PORT": 51821,
                        # ✅ NEU: BIDIREKTIONALE SESSION-IDs
                        "CALLER_SESSION_ID": caller_session_id,  # Für Empfangen von Caller
                        "CALLEE_SESSION_ID": callee_session_id   # Für Senden an Caller
                    }
                    
                    callee_msg = self.server.build_sip_message("MESSAGE", client_name, callee_msg_data)
                    send_frame(client_socket, callee_msg.encode('utf-8'))
                    print(f"[CONVEY] ✅ CALL_CONFIRMED sent to callee {client_name} with Session-IDs")
                    
                    # 2. CALL_CONFIRMED an CALLER
                    caller_confirmed_data = {
                        "MESSAGE_TYPE": "CALL_CONFIRMED",
                        "TIMESTAMP": int(time.time()),
                        "USE_AUDIO_RELAY": True,
                        "AUDIO_RELAY_IP": server_ip,
                        "SERVER_RELAY_PORT": self.udp_relay_port,
                        "CLIENT_PORT": 51821,
                        # ✅ NEU: BIDIREKTIONALE SESSION-IDs
                        "CALLER_SESSION_ID": caller_session_id,  # Für Senden an Callee
                        "CALLEE_SESSION_ID": callee_session_id   # Für Empfangen von Callee
                    }
                    
                    caller_confirmed_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], caller_confirmed_data)
                    send_frame(call_data['caller_socket'], caller_confirmed_msg.encode('utf-8'))
                    print(f"[CONVEY] ✅ CALL_CONFIRMED sent to caller {call_data['caller_name']} with Session-IDs")
                    
                    print(f"[CONVEY] ✅ Framed SIP call {call_id} accepted with bidirectional Session-IDs")
                else:
                    print(f"[CONVEY ERROR] Failed to send accepted response to caller")
                    
            elif response == "rejected":
                print(f"[CONVEY] Call {call_id} rejected by {client_name}")
                
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "rejected",
                    "CALLER_CLIENT_ID": caller_id,
                    "TIMESTAMP": int(time.time())
                })
                send_success = send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                
                if send_success:
                    call_data['status'] = 'rejected'
                    print(f"[CONVEY] ✅ Call rejected response sent to {call_data['caller_name']}")
                else:
                    print(f"[CONVEY ERROR] Failed to send rejected response to caller")
                    
            elif response == "error":
                print(f"[CONVEY] Call {call_id} error from {client_name}")
                
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], {
                    "MESSAGE_TYPE": "CALL_RESPONSE", 
                    "RESPONSE": "error",
                    "ERROR": "CALLEE_ERROR",
                    "CALLER_CLIENT_ID": caller_id,
                    "TIMESTAMP": int(time.time())
                })
                send_success = send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                
                if send_success:
                    call_data['status'] = 'error'
                    print(f"[CONVEY] ✅ Call error response sent to {call_data['caller_name']}")
            
            # ✅ SAUBERES CLEANUP
            if response in ['accepted', 'rejected', 'error']:
                if call_id in self.active_calls:
                    if response in ['rejected', 'error']:
                        self._unregister_audio_relay(call_id)
                    del self.active_calls[call_id]
                    print(f"[CONVEY] ✅ Call {call_id} cleaned up")
            
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Framed SIP call response failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def handle_call_end(self, msg, client_socket, client_name):
        """Verarbeitet Call-Ende - OPTIMIERT"""
        try:
            custom_data = msg.get('custom_data', {})
            reason = custom_data.get('REASON', 'unknown')
            
            print(f"[CONVEY] Call end from {client_name}, reason: {reason}")
            
            # ✅ EFFIZIENTE CALL-SUCHE
            calls_to_remove = []
            
            for call_id, call_data in list(self.active_calls.items()):  # Thread-safe iteration
                if call_data['caller_id'] == client_name or call_data['callee_id'] == client_name:
                    calls_to_remove.append((call_id, call_data))
            
            # ✅ PARALLELE VERARBEITUNG für Performance
            for call_id, call_data in calls_to_remove:
                # UDP RELAY CLEANUP
                self._unregister_audio_relay(call_id)
                
                # ANDEREN CLIENT BENACHRICHTIGEN
                other_client = call_data['callee_id'] if call_data['caller_id'] == client_name else call_data['caller_id']
                
                end_msg = self.server.build_sip_message("MESSAGE", other_client, {
                    "MESSAGE_TYPE": "CALL_END",
                    "REASON": "remote_hangup", 
                    "TIMESTAMP": int(time.time())
                })
                
                try:
                    other_socket = call_data['callee_socket'] if call_data['caller_id'] == client_name else call_data['caller_socket']
                    if other_socket:
                        send_frame(other_socket, end_msg.encode('utf-8'))
                except:
                    pass
                
                # AUS ACTIVE_CALLS ENTFERNEN
                if call_id in self.active_calls:
                    del self.active_calls[call_id]
            
            # ✅ BESTÄTIGUNG SENDEN
            ack_msg = self.server.build_sip_message("MESSAGE", client_name, {
                "MESSAGE_TYPE": "CALL_END_ACK",
                "STATUS": "CALL_TERMINATED",
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(client_socket, ack_msg.encode('utf-8'))
            print(f"[CONVEY] Call ended for {client_name}")
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Call end handling failed: {str(e)}")
            return False

    def _call_timeout_watchdog(self, call_id):
        """Überwacht Call-Timeout - KORRIGIERT"""
        timeout = 120
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if call_id not in self.active_calls:
                return
                
            call_data = self.active_calls[call_id]
            if call_data['status'] != 'pending':
                return
                
            time.sleep(1)
        
        # Timeout erreicht
        if call_id in self.active_calls:
            call_data = self.active_calls[call_id]
            print(f"[CONVEY] Call {call_id} timeout")
            
            # ❌ KORREKTUR: Verwende 'caller_name' statt 'caller'
            timeout_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], {  # ✅ KORREKTUR
                "MESSAGE_TYPE": "CALL_RESPONSE",
                "RESPONSE": "timeout", 
                "TARGET_ID": call_data['callee_id'],
                "TIMESTAMP": int(time.time())
            })
            
            try:
                send_frame(call_data['caller_socket'], timeout_msg.encode('utf-8'))
            except:
                pass
            
            # UDP RELAY CLEANUP
            self._unregister_audio_relay(call_id)
            del self.active_calls[call_id]

    def cleanup_client_calls(self, client_name):
        """Bereinigt alle Calls eines Clients bei Disconnect - OPTIMIERT"""
        calls_to_remove = []
        
        # ✅ SCHNELLE SUCHE
        for call_id, call_data in list(self.active_calls.items()):
            if call_data['caller_id'] == client_name or call_data['callee_id'] == client_name:
                calls_to_remove.append((call_id, call_data))
        
        # ✅ PARALLELE VERARBEITUNG
        for call_id, call_data in calls_to_remove:
            self._unregister_audio_relay(call_id)
            
            # ANDEREN CLIENT BENACHRICHTIGEN
            other_client = call_data['callee_id'] if call_data['caller_id'] == client_name else call_data['caller_id']
            other_socket = call_data['callee_socket'] if call_data['caller_id'] == client_name else call_data['caller_socket']
            
            end_msg = self.server.build_sip_message("MESSAGE", other_client, {
                "MESSAGE_TYPE": "CALL_END",
                "REASON": "remote_disconnected",
                "TIMESTAMP": int(time.time())
            })
            
            try:
                if other_socket:
                    send_frame(other_socket, end_msg.encode('utf-8'))
            except:
                pass
            
            # AUS ACTIVE_CALLS ENTFERNEN
            if call_id in self.active_calls:
                del self.active_calls[call_id]
        
        if calls_to_remove:
            print(f"[CONVEY] Cleaned up {len(calls_to_remove)} calls for disconnected client {client_name}")


class Server:
    def __init__(self, host='0.0.0.0', port=5060):
        # ✅ ZUERST Basis-Attribute setzen
        self.host = host
        self.port = port
        
        # ✅ DANN Relay Manager initialisieren
        self.relay_manager = AccurateRelayManager(self)
        self.convey_manager = CONVEY(self)
        
        # Vorhandene Initialisierung...
        self.active_calls = {}  # Aktive Calls verwalten
        self.call_timeout = 30  # Timeout in Sekunden
        self._processing_client_queue = False
        # Lock für Thread-sicheren Zugriff auf active_calls
        self.call_lock = threading.RLock()
        self.all_public_keys = {}
        self.clients = {}
        self.client_secrets = {}
        self.server_public_key = load_server_publickey()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.all_public_keys = [self.server_public_key]
        self.client_send_lock = Lock()
        self.name_lock = Lock()
        self.key_lock = threading.Lock()
        self.pending_challenges = {}
        # Neue Attribute hinzufügen
        self.merkle_lock = threading.Lock()  # Für Merkle Tree Operationen
        self.last_merkle_root = None
        self.last_merkle_calculation = 0
        self.phonebook = []  # Für Phonebook-Daten
        self.clients_lock = threading.RLock()
        
        # ✅ FEHLENDE ATTRIBUTE HINZUFÜGEN
        self._message_queue = []  # Message Queue für Client-Nachrichten
        self._queue_lock = threading.Lock()  # Lock für Thread-safety
        
        print(f"Server configured with: {self.host}:{self.port}")
        print(f"🔧 Relay Manager: {'SEED-SERVER' if self.relay_manager.is_seed_server else 'Regular Server'}")
        
    def store_client_secret(self, client_id, encrypted_secret):
        """Speichert das entschlüsselte AES-Geheimnis für einen Client"""
        try:
            with open("server_private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
            
            decrypted = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            if not decrypted.startswith(b"+++secret+++"):
                raise ValueError("Invalid secret format")
                
            secret = decrypted[11:59]  # 48 Bytes (16 IV + 32 Key)
            self.client_secrets[client_id] = secret
            return True
            
        except Exception as e:
            print(f"Failed to store secret for {client_id}: {str(e)}")
            return False        



    def update_key_list(self):
        """Aktualisiert die Liste aller öffentlichen Schlüssel"""
        with self.key_lock:
            # ✅ ZUERST: Safe Kopie der Clients unter clients_lock erstellen
            with self.clients_lock:
                clients_copy = self.clients.copy()
            
            # ✅ JETZT: Safe mit der Kopie arbeiten
            client_keys = [
                c['public_key'] for c in clients_copy.values() 
                if 'public_key' in c
            ]
            self.all_public_keys = [self.server_public_key] + client_keys
            print(f"[DEBUG] Updated key list - Total keys: {len(self.all_public_keys)}")
    def debug_socket(self, sock):
        """Hilfsfunktion zur Socket-Diagnose"""
        if sock is None:
            print("Socket: None")
            return
        
        print("\n=== SOCKET DEBUG ===")
        print(f"Socket Fileno: {sock.fileno()}")
        print(f"Socket Type: {sock.type}")
        print(f"Socket Family: {sock.family}")
        print(f"Socket Proto: {sock.proto}")
        print(f"Socket Timeout: {sock.gettimeout()}")
        
        try:
            print(f"Local Address: {sock.getsockname()}")
        except Exception as e:
            print(f"Local Address Error: {e}")
        
        try:
            print(f"Peer Address: {sock.getpeername()}")
        except Exception as e:
            print(f"Peer Address Error: {e}")
        
        print("="*20)

# === EINHEITLICHER SIP STANDARD ===
    def build_sip_message(self, method, recipient, custom_data=None, from_server=True):
        """SERVER-VERSION - verwendet Server-spezifische Attribute"""
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
        
        # ✅ SERVER-SPEZIFISCHE ABSENDERADRESSE
        if from_server:
            from_header = f"<sip:server@{self.host}>" if hasattr(self, 'host') else "<sip:server>"
        else:
            # Server sollte nicht als Client senden - Fallback
            from_header = "<sip:server>"
        
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
        """VOLLSTÄNDIG EINHEITLICHER SIP-PARSER - NUR JSON"""
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
            'custom_data': {},
            'method': '',
            'status_code': ''
        }

        # 4. Erste Zeile (Request/Response Line)
        first_line = headers_lines[0]
        if first_line.startswith('SIP/2.0'):
            # Response
            parts = first_line.split(' ', 2)
            result['status_code'] = parts[1] if len(parts) > 1 else ''
            result['status_message'] = parts[2] if len(parts) > 2 else ''
        else:
            # Request
            parts = first_line.split(' ', 2)
            result['method'] = parts[0] if len(parts) > 0 else ''
            result['uri'] = parts[1] if len(parts) > 1 else ''
            result['protocol'] = parts[2] if len(parts) > 2 else ''

        # 5. Header parsen
        for line in headers_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                result['headers'][key.strip().upper()] = value.strip()

        # 6. ✅ NUR JSON-BODY - KEINE AUSNAHMEN
        body_content = body_part.strip()
        if body_content:
            try:
                result['custom_data'] = json.loads(body_content)
                print(f"[PARSE DEBUG] JSON body parsed: {list(result['custom_data'].keys())}")
            except json.JSONDecodeError as e:
                print(f"[PARSE ERROR] Invalid JSON format: {e}")
                print(f"[PARSE DEBUG] Body content: {body_content[:200]}...")
                return None  # ✅ KEIN FALLBACK - JSON IST PFLICHT

        return result



    def start(self):
        try:
            # Haupt-Socket für ersten Port
            main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            main_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            main_socket.bind((self.host, self.port))
            main_socket.listen(5)
            
            # Zweiter Socket für zusätzlichen Port
            alt_port = self.port + 1  # z.B. 5061 wenn main port 5060
            alt_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            alt_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            alt_socket.bind((self.host, alt_port))
            alt_socket.listen(5)
            
            print(f"Server lauscht auf {self.host}:{self.port} (Haupt) und {alt_port} (Alternativ)")
            print(f"🔧 Relay Manager: {'SEED-SERVER' if self.relay_manager.is_seed_server else 'Regular Server'}")
            
            # Zeige Relay-Status
            relay_status = self.relay_manager.get_server_status()
            print(f"📊 Relay Status: {relay_status}")
            
            with self.clients_lock:
                client_count = len(self.clients)
            print(f"Geladene Clients: {client_count}")

            sockets = [main_socket, alt_socket]
            
            while True:
                try:
                    # select() für gleichzeitige Überwachung beider Ports
                    readable, _, _ = select.select(sockets, [], [], 1)
                    
                    for sock in readable:
                        client_socket, addr = sock.accept()
                        print(f"Verbindung von {addr} angenommen (Port {sock.getsockname()[1]})")
                        self.debug_socket(client_socket)
                        
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, addr),  # ✅ addr hinzugefügt
                            daemon=True
                        )
                        client_thread.start()
                        
                except KeyboardInterrupt:
                    print("\nServer-Shutdown angefordert...")
                    break
                except Exception as e:
                    print(f"Fehler: {e}")
                    continue
                    
        except Exception as e:
            print(f"Kritischer Fehler: {e}")
            traceback.print_exc()
        finally:
            self._cleanup_server(main_socket, alt_socket)

    def _cleanup_server(self, main_socket=None, alt_socket=None):
        """Bereinigt Server-Ressourcen sicher"""
        print("\nSpeichere Client-Daten...")
        
        # Safe clients copy
        try:
            with self.clients_lock:
                clients_copy = self.clients.copy()
        except:
            clients_copy = {}

        active_clients = {
            cid: {k: v for k, v in data.items() if k != 'socket'} 
            for cid, data in clients_copy.items() 
            if data and data.get('socket') is not None
        }
        
        try:
            with open("active_clients.json", "w") as f:
                json.dump(active_clients, f, indent=2)
            print(f"{len(active_clients)} Clients gespeichert")
        except Exception as e:
            print(f"Fehler beim Speichern: {e}")
        
        print("Schließe Verbindungen...")
        
        # Safe client socket closing
        for client_id, client_data in clients_copy.items():
            if client_data and client_data.get('socket'):
                try:
                    client_data['socket'].close()
                except:
                    pass

        # Safe socket closing
        for sock in [main_socket, alt_socket]:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        print("Server beendet")

    def _handle_discovery_request(self, msg, client_socket, client_name):
        """Verarbeitet Discovery-Requests - VOLLSTÄNDIG FRAMED SIP"""
        try:
            print(f"[DISCOVERY] Request from {client_name}")
            
            # Hole Server-Liste vom Relay Manager
            server_list = self.relay_manager.get_server_list_for_client()
            
            # Baue Response mit framed SIP
            response_data = {
                "MESSAGE_TYPE": "DISCOVERY_RESPONSE",
                "SERVERS": server_list.get('servers', {}),
                "TOTAL_SERVERS": server_list.get('total_servers', 0),
                "AVAILABLE_SERVERS": server_list.get('available_servers', 0),
                "TIMESTAMP": int(time.time())
            }
            
            response_msg = self.build_sip_message("200 OK", client_name, response_data)
            
            # ✅ IMMER FRAMED SIP VERWENDEN
            success = send_frame(client_socket, response_msg.encode('utf-8'))
            
            if success:
                print(f"[DISCOVERY] ✅ Framed SIP response sent to {client_name}")
            else:
                print(f"[DISCOVERY] ❌ Failed to send framed SIP response to {client_name}")
                
            return success
            
        except Exception as e:
            print(f"[DISCOVERY ERROR] Handling failed: {str(e)}")
            
            # Sende auch Fehler mit framed SIP
            error_msg = self.build_sip_message("500 Error", client_name, {
                "MESSAGE_TYPE": "ERROR",
                "ERROR": f"DISCOVERY_FAILED: {str(e)}",
                "TIMESTAMP": int(time.time())
            })
            
            try:
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                pass
                
            return False

    def validate_client_name(self, name):
        """Überprüft ob der Client-Name eindeutig ist"""
        if not name or len(name) < 2:
            return False
            
        with self.name_lock:
            return not any(
                c['name'].lower() == name.lower() 
                for c in self.clients.values()
            )
    def _process_client_queue(self, client_queue, client_socket, client_name):
        """VOLLSTÄNDIG KORRIGIERT: Queue-Verarbeitung für alle Message-Types"""
        if getattr(self, '_processing_client_queue', False):
            return
            
        self._processing_client_queue = True
        
        try:
            while client_queue:
                queue_item = client_queue.pop(0)
                
                try:
                    # ✅ VALIDIERE ITEM
                    if not isinstance(queue_item, dict):
                        print(f"[QUEUE WARN] Ungültiges Item: {type(queue_item)}")
                        continue
                    
                    item_type = queue_item.get('type')
                    
                    if not item_type:
                        print(f"[QUEUE WARN] Kein Type gefunden: {list(queue_item.keys())}")
                        continue
                    
                    print(f"[QUEUE] Verarbeite: {item_type} für {client_name}")
                    
                    # === FRAME_DATA VERARBEITUNG ===
                    if item_type == 'frame_data':
                        frame_data = queue_item.get('data')
                        if not frame_data:
                            continue
                        
                        print(f"[SERVER] Empfangen von {client_name}: {len(frame_data)} bytes")
                        
                        # 1. Decoding versuchen
                        if isinstance(frame_data, bytes):
                            try:
                                message = frame_data.decode('utf-8')
                                print(f"[SERVER] Textnachricht von {client_name}: {len(message)} chars")
                            except UnicodeDecodeError:
                                # Binärdaten (verschlüsselte Daten, Audio, etc.)
                                print(f"[SERVER] Binary data from {client_name} ({len(frame_data)} bytes)")
                                
                                # Versuche als verschlüsselte Phonebook-Daten zu verarbeiten
                                if len(frame_data) > 512:
                                    result = self._process_encrypted_phonebook(frame_data)
                                    if result:
                                        continue
                                
                                # Audio-Daten während aktiven Calls
                                if hasattr(self, 'convey_manager') and self.convey_manager.active_calls:
                                    for call_id, call_data in self.convey_manager.active_calls.items():
                                        if call_data.get('caller_id') == client_name or call_data.get('callee_id') == client_name:
                                            print(f"[AUDIO] Binary data during active call {call_id}")
                                            # Audio-Daten weiterleiten
                                            self._forward_audio_data(frame_data, call_data, client_name)
                                            break
                                continue
                        else:
                            message = str(frame_data)
                        
                        # 2. SIP-Nachricht parsen
                        msg = self.parse_sip_message(message)
                        if not msg:
                            print(f"[SERVER ERROR] Invalid SIP format from {client_name}")
                            # Sende Fehlerantwort
                            error_msg = self.build_sip_message("400 Bad Request", client_name, {
                                "MESSAGE_TYPE": "ERROR",
                                "ERROR": "INVALID_SIP_FORMAT",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, error_msg.encode('utf-8'))
                            continue
                        
                        # 3. Debug-Ausgabe
                        debug_msg = message[:500] + "..." if len(message) > 500 else message
                        print(f"[SERVER DEBUG] SIP message from {client_name}:\n{debug_msg}")
                        
                        # 4. Daten extrahieren
                        headers = msg.get('headers', {})
                        custom_data = msg.get('custom_data', {})
                        body = msg.get('body', '')
                        
                        # 5. MESSAGE_TYPE ermitteln (mehrere Fallbacks)
                        message_type = None
                        message_type_sources = [
                            custom_data.get('MESSAGE_TYPE'),
                            headers.get('MESSAGE_TYPE'),
                            headers.get('MESSAGE-TYPE'),
                            custom_data.get('TYPE'),
                            headers.get('TYPE')
                        ]
                        
                        for source in message_type_sources:
                            if source:
                                message_type = source
                                break
                        
                        # Fallback: Body durchsuchen
                        if not message_type and body:
                            # JSON Body
                            if body.strip().startswith('{'):
                                try:
                                    body_data = json.loads(body)
                                    message_type = body_data.get('MESSAGE_TYPE')
                                except:
                                    pass
                            # Key-Value Body
                            else:
                                for line in body.split('\n'):
                                    line = line.strip()
                                    if line.startswith('MESSAGE_TYPE:'):
                                        message_type = line.split('MESSAGE_TYPE:', 1)[1].strip()
                                        break
                                    elif line.startswith('TYPE:'):
                                        message_type = line.split('TYPE:', 1)[1].strip()
                                        break
                        
                        if not message_type:
                            print(f"[SERVER WARNING] No message type from {client_name}")
                            message_type = "UNKNOWN"
                        
                        print(f"[SERVER] Message type: {message_type} from {client_name}")
                        
                        # === NACHRICHTENTYP-ROUTING ===
                        
                        # === CALL-RELATED MESSAGES ===
                        if message_type in ['GET_PUBLIC_KEY', 'CALL_REQUEST', 'CALL_RESPONSE', 
                                          'CALL_END', 'INCOMING_CALL', 'SESSION_KEY']:
                            if hasattr(self, 'convey_manager'):
                                print(f"[CALL] Delegating {message_type} to convey manager")
                                
                                try:
                                    if message_type == 'GET_PUBLIC_KEY':
                                        success = self.convey_manager.handle_get_public_key(msg, client_socket, client_name)
                                        if success:
                                            print(f"[CALL] GET_PUBLIC_KEY successfully processed for {client_name}")
                                        else:
                                            print(f"[CALL ERROR] GET_PUBLIC_KEY failed for {client_name}")
                                    elif message_type == 'CALL_REQUEST':
                                        self.convey_manager.handle_call_request(msg, client_socket, client_name)
                                    elif message_type == 'CALL_RESPONSE':
                                        self.convey_manager.handle_call_response(msg, client_socket, client_name)
                                    elif message_type == 'CALL_END':
                                        self.convey_manager.handle_call_end(msg, client_socket, client_name)
                                    elif message_type == 'INCOMING_CALL':
                                        # INCOMING_CALL wird vom Server initiiert, nicht empfangen
                                        print(f"[CALL WARNING] INCOMING_CALL should not be received from client")
                                    elif message_type == 'SESSION_KEY':
                                        self._handle_session_key(msg, client_socket, client_name)
                                except Exception as e:
                                    print(f"[CALL ERROR] Handling failed for {message_type}: {str(e)}")
                                    # Fehler an Client senden
                                    error_msg = self.build_sip_message("500 Error", client_name, {
                                        "MESSAGE_TYPE": "ERROR",
                                        "ERROR": f"CALL_PROCESSING_FAILED: {str(e)}",
                                        "ORIGINAL_TYPE": message_type,
                                        "TIMESTAMP": int(time.time())
                                    })
                                    send_frame(client_socket, error_msg.encode('utf-8'))
                            else:
                                print(f"[CALL ERROR] No convey manager for {message_type}")
                                error_msg = self.build_sip_message("503 Service Unavailable", client_name, {
                                    "MESSAGE_TYPE": "ERROR",
                                    "ERROR": "CALL_SERVICE_UNAVAILABLE",
                                    "TIMESTAMP": int(time.time())
                                })
                                send_frame(client_socket, error_msg.encode('utf-8'))
                            continue
                        
                        if message_type == 'PING':
                            print(f"[PING] Received from {client_name}")
                            
                            # ✅ KORREKTE PONG-NACHRICHT BAuen
                            pong_data = {
                                "MESSAGE_TYPE": "PONG",
                                "TIMESTAMP": int(time.time()),
                                "STATUS": "SUCCESS",
                                "CLIENT_NAME": client_name
                            }
                            
                            # ✅ VERWENDE "MESSAGE" STATT "200 OK" für PONG
                            pong_response = self.build_sip_message(
                                method="MESSAGE", 
                                recipient=client_name,
                                custom_data=pong_data
                            )
                            
                            print(f"[PING DEBUG] PONG response preview: {pong_response[:100]}...")
                            
                            if not send_frame(client_socket, pong_response.encode('utf-8')):
                                print(f"[PING ERROR] Failed to send pong to {client_name}")
                            else:
                                print(f"[PING] ✅ PONG sent to {client_name}")
                            continue
                        
                        
                        # === UPDATE & IDENTITY HANDLING ===
                        if (message_type == 'UPDATE_REQUEST' or 
                              headers.get('UPDATE') == 'true' or 
                              custom_data.get('UPDATE') == 'true'):
                            print(f"[UPDATE] Request from {client_name}")
                            self._handle_update_request(client_socket, client_name, msg)
                            continue
                        
                        if message_type == 'IDENTITY_RESPONSE':
                            print(f"[IDENTITY] Response from {client_name}")
                            self._handle_identity_response(client_socket, client_name, msg)
                            continue
                        
                        if message_type == 'IDENTITY_CHALLENGE':
                            print(f"[IDENTITY] Challenge from {client_name} - should be server-initiated")
                            # Client sollte keine Challenges senden
                            error_msg = self.build_sip_message("400 Bad Request", client_name, {
                                "MESSAGE_TYPE": "ERROR",
                                "ERROR": "UNEXPECTED_IDENTITY_CHALLENGE",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, error_msg.encode('utf-8'))
                            continue
                        
                        # === SECRET & ENCRYPTION HANDLING ===
                        if (message_type == 'ENCRYPTED_SECRET' or 
                              'ENCRYPTED_SECRET' in custom_data or 
                              'CLIENT_SECRET' in custom_data):
                            print(f"[SECRET] Received from {client_name}")
                            self._handle_encrypted_secret(msg, client_socket, client_name)
                            continue
                        
                        # === PHONEBOOK HANDLING ===
                        if (message_type == 'PHONEBOOK_REQUEST' or 
                              'PHONEBOOK_REQUEST' in custom_data):
                            print(f"[PHONEBOOK] Request from {client_name}")
                            self._handle_phonebook_request(msg, client_socket, client_name)
                            continue
                        
                        if message_type == 'PHONEBOOK_UPDATE':
                            print(f"[PHONEBOOK] Update from {client_name}")
                            # Client sollte keine Phonebook-Updates senden
                            error_msg = self.build_sip_message("400 Bad Request", client_name, {
                                "MESSAGE_TYPE": "ERROR", 
                                "ERROR": "CLIENT_CANNOT_SEND_PHONEBOOK_UPDATE",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, error_msg.encode('utf-8'))
                            continue
                        
                        # === LEGACY CALL SETUP ===
                        if ('CALL_SETUP' in custom_data or 
                              message_type == 'CALL_SETUP'):
                            print(f"[LEGACY CALL] Setup from {client_name}")
                            self._handle_legacy_call_setup(msg, client_socket, client_name)
                            continue
                        
                        # === REGISTRATION & DISCOVERY ===
                        if message_type == 'REGISTER':
                            print(f"[REGISTER] Received from {client_name}")
                            # Client ist bereits registriert, bestätigen
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "MESSAGE_TYPE": "REGISTRATION_CONFIRMED",
                                "STATUS": "ALREADY_REGISTERED",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        if message_type == 'DISCOVER':
                            print(f"[DISCOVER] Request from {client_name}")
                            self._handle_discovery_request(msg, client_socket, client_name)
                            continue
                        
                        # === ERROR HANDLING ===
                        if message_type == 'ERROR':
                            print(f"[ERROR] Received from {client_name}: {custom_data.get('ERROR', 'Unknown error')}")
                            # Error bestätigen
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "MESSAGE_TYPE": "ERROR_ACK",
                                "RECEIVED_ERROR": custom_data.get('ERROR', 'UNKNOWN'),
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        # === UNBEKANNTE NACHRICHT ===
                        else:
                            print(f"[UNKNOWN] Unknown message type from {client_name}: {message_type}")
                            print(f"[DEBUG] Headers: {list(headers.keys())}")
                            print(f"[DEBUG] Custom data: {list(custom_data.keys())}")
                            
                            # Versuche die Nachricht als Status-Update zu behandeln
                            if any(key in custom_data for key in ['STATUS', 'STATE', 'INFO']):
                                print(f"[STATUS] Status update from {client_name}")
                                ack_msg = self.build_sip_message("200 OK", client_name, {
                                    "MESSAGE_TYPE": "STATUS_ACK",
                                    "RECEIVED_STATUS": message_type,
                                    "TIMESTAMP": int(time.time())
                                })
                            else:
                                # Generische Bestätigung für unbekannte Nachrichten
                                ack_msg = self.build_sip_message("200 OK", client_name, {
                                    "MESSAGE_TYPE": "UNKNOWN_MESSAGE_ACK",
                                    "RECEIVED_TYPE": message_type,
                                    "SUGGESTION": "Use valid MESSAGE_TYPE",
                                    "TIMESTAMP": int(time.time())
                                })
                            
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                            
                except UnicodeDecodeError as ude:
                    print(f"[SERVER ERROR] UTF-8 decoding failed from {client_name}: {ude}")
                    error_msg = self.build_sip_message("400 Bad Request", client_name, {
                        "MESSAGE_TYPE": "ERROR",
                        "ERROR": "INVALID_ENCODING",
                        "DETAILS": "Message must be valid UTF-8",
                        "TIMESTAMP": int(time.time())
                    })
                    send_frame(client_socket, error_msg.encode('utf-8'))
                    continue
                    
                except Exception as e:
                    print(f"[SERVER ERROR] Processing failed for {client_name}: {str(e)}")
                    error_msg = self.build_sip_message("500 Internal Error", client_name, {
                        "MESSAGE_TYPE": "ERROR", 
                        "ERROR": "PROCESSING_FAILED",
                        "DETAILS": str(e)[:100],
                        "TIMESTAMP": int(time.time())
                    })
                    send_frame(client_socket, error_msg.encode('utf-8'))
                    continue

                        
        except Exception as e:
            print(f"[CLIENT QUEUE CRITICAL ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Versuche Fehler an Client zu senden
            try:
                error_msg = self.build_sip_message("500 Internal Error", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "QUEUE_PROCESSING_FAILED",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                print("[CRITICAL] Could not send error message to client")
                
        finally:
            self._processing_client_queue = False
            print(f"[QUEUE] Finished processing queue for {client_name}")
    def _verify_identity_response(self, client_socket, client_name, challenge_id, encrypted_response_b64):
        """Verifiziert die Identity Response des Clients - KORRIGIERT"""
        try:
            print(f"[IDENTITY VERIFY] Verifying response for {client_name}, challenge: {challenge_id}")
            
            # Prüfe ob Challenge existiert
            if not hasattr(self, 'pending_challenges') or challenge_id not in self.pending_challenges:
                print(f"[IDENTITY ERROR] Unknown challenge ID: {challenge_id}")
                return False
            
            challenge_data = self.pending_challenges[challenge_id]
            original_challenge = challenge_data.get('challenge')
            priv_key = challenge_data.get('private_key')
            
            if not original_challenge or not priv_key:
                print("[IDENTITY ERROR] Missing challenge data")
                return False
            
            # Entschlüssele die Response
            try:
                encrypted_response = base64.b64decode(encrypted_response_b64)
                decrypted_response = priv_key.private_decrypt(encrypted_response, RSA.pkcs1_padding)
                decrypted_text = decrypted_response.decode('utf-8')
                
                print(f"[IDENTITY DEBUG] Decrypted response: {decrypted_text}")
                print(f"[IDENTITY DEBUG] Expected: {original_challenge}")
                
                # ✅ KORRIGIERT: Erwarte sowohl die reine Challenge als auch Challenge+VALIDATED
                expected_responses = [
                    original_challenge,  # Nur die Challenge
                    original_challenge + "VALIDATED"  # Challenge + VALIDATED
                ]
                
                # Validiere die Response gegen beide möglichen Formate
                if decrypted_text in expected_responses:
                    print(f"[IDENTITY SUCCESS] {client_name} identity verified")
                    # Challenge aus pending entfernen
                    del self.pending_challenges[challenge_id]
                    return True
                else:
                    print(f"[IDENTITY FAIL] Response mismatch for {client_name}")
                    print(f"Expected one of: {expected_responses}")
                    print(f"Received: {decrypted_text}")
                    return False
                    
            except Exception as e:
                print(f"[IDENTITY DECRYPT ERROR] {str(e)}")
                return False
                
        except Exception as e:
            print(f"[IDENTITY VERIFY ERROR] {str(e)}")
            return False
    def _handle_encrypted_secret(self, msg, client_socket, client_name):
        """Verarbeitet verschlüsselte Secrets"""
        try:
            custom_data = msg.get('custom_data', {})
            encrypted_secret = (custom_data.get('ENCRYPTED_SECRET') or 
                               custom_data.get('CLIENT_SECRET'))
            
            if not encrypted_secret:
                raise ValueError("No encrypted secret found")
            
            # Client-ID finden
            client_id = None
            with self.clients_lock:
                for cid, data in self.clients.items():
                    if data.get('name') == client_name:
                        client_id = cid
                        break
            
            if not client_id:
                raise ValueError(f"Client {client_name} not found")
            
            # Secret verarbeiten
            encrypted_bytes = base64.b64decode(encrypted_secret)
            if self.store_client_secret(client_id, encrypted_bytes):
                response_msg = self.build_sip_message("200 OK", client_name, {
                    "MESSAGE_TYPE": "SECRET_STORED",
                    "CLIENT_ID": client_id,
                    "TIMESTAMP": int(time.time())
                })
                print(f"[SECRET] Stored for {client_name}")
            else:
                response_msg = self.build_sip_message("500 Error", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "SECRET_STORAGE_FAILED",
                    "CLIENT_ID": client_id,
                    "TIMESTAMP": int(time.time())
                })
                print(f"[SECRET ERROR] Storage failed for {client_name}")
            
            send_frame(client_socket, response_msg.encode('utf-8'))
            
        except Exception as e:
            print(f"[SECRET ERROR] Handling failed: {str(e)}")
            error_msg = self.build_sip_message("500 Error", client_name, {
                "MESSAGE_TYPE": "ERROR",
                "ERROR": f"SECRET_PROCESSING_FAILED: {str(e)}",
                "TIMESTAMP": int(time.time())
            })
            send_frame(client_socket, error_msg.encode('utf-8'))

    def _handle_phonebook_request(self, msg, client_socket, client_name):
        """Verarbeitet Phonebook-Requests"""
        try:
            # Client-ID finden
            client_id = None
            with self.clients_lock:
                for cid, data in self.clients.items():
                    if data.get('name') == client_name:
                        client_id = cid
                        break
            
            if not client_id:
                raise ValueError(f"Client {client_name} not found")
            
            # Phonebook senden
            if self.send_phonebook(client_id):
                response_msg = self.build_sip_message("200 OK", client_name, {
                    "MESSAGE_TYPE": "PHONEBOOK_SENT",
                    "CLIENT_ID": client_id,
                    "TIMESTAMP": int(time.time())
                })
                print(f"[PHONEBOOK] Sent to {client_name}")
            else:
                response_msg = self.build_sip_message("500 Error", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "PHONEBOOK_SEND_FAILED",
                    "CLIENT_ID": client_id,
                    "TIMESTAMP": int(time.time())
                })
                print(f"[PHONEBOOK ERROR] Send failed for {client_name}")
            
            send_frame(client_socket, response_msg.encode('utf-8'))
            
        except Exception as e:
            print(f"[PHONEBOOK ERROR] Handling failed: {str(e)}")
            error_msg = self.build_sip_message("500 Error", client_name, {
                "MESSAGE_TYPE": "ERROR",
                "ERROR": f"PHONEBOOK_PROCESSING_FAILED: {str(e)}",
                "TIMESTAMP": int(time.time())
            })
            send_frame(client_socket, error_msg.encode('utf-8'))

    def _handle_legacy_call_setup(self, msg, client_socket, client_name):
        """Verarbeitet Legacy Call-Setup"""
        try:
            custom_data = msg.get('custom_data', {})
            call_data = custom_data.get('CALL_SETUP')
            
            if call_data == 'request':
                caller_id = custom_data.get('CALLER_ID')
                callee_id = custom_data.get('CALLEE_ID')
                
                if caller_id and callee_id:
                    if self.initiate_call_between_clients(caller_id, callee_id):
                        response_msg = self.build_sip_message("200 OK", client_name, {
                            "MESSAGE_TYPE": "CALL_INITIATED",
                            "CALLER_ID": caller_id,
                            "CALLEE_ID": callee_id,
                            "TIMESTAMP": int(time.time())
                        })
                        print(f"[LEGACY CALL] Initiated between {caller_id} and {callee_id}")
                    else:
                        response_msg = self.build_sip_message("500 Error", client_name, {
                            "MESSAGE_TYPE": "ERROR",
                            "ERROR": "CALL_INITIATION_FAILED",
                            "CALLER_ID": caller_id,
                            "CALLEE_ID": callee_id,
                            "TIMESTAMP": int(time.time())
                        })
                        print(f"[LEGACY CALL ERROR] Initiation failed")
                else:
                    response_msg = self.build_sip_message("400 Bad Request", client_name, {
                        "MESSAGE_TYPE": "ERROR",
                        "ERROR": "MISSING_CALLER_OR_CALLEE_ID",
                        "TIMESTAMP": int(time.time())
                    })
            else:
                response_msg = self.build_sip_message("400 Bad Request", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "INVALID_CALL_SETUP_FORMAT",
                    "TIMESTAMP": int(time.time())
                })
            
            send_frame(client_socket, response_msg.encode('utf-8'))
            
        except Exception as e:
            print(f"[LEGACY CALL ERROR] Handling failed: {str(e)}")
            error_msg = self.build_sip_message("500 Error", client_name, {
                "MESSAGE_TYPE": "ERROR",
                "ERROR": f"LEGACY_CALL_PROCESSING_FAILED: {str(e)}",
                "TIMESTAMP": int(time.time())
            })
            send_frame(client_socket, error_msg.encode('utf-8'))
    def _handle_session_key(self, msg, client_socket, client_name):
        """Verarbeitet Session Key Nachrichten"""
        try:
            custom_data = msg.get('custom_data', {})
            encrypted_session = custom_data.get('ENCRYPTED_SESSION')
            target_client_id = custom_data.get('TARGET_CLIENT_ID')
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            if not encrypted_session:
                print("[SESSION KEY ERROR] Missing encrypted session data")
                return
                
            print(f"[SESSION KEY] Processing session key for {client_name}")
            
            # Session Key kann hier weiterverarbeitet werden
            # Für jetzt einfach Bestätigung senden
            ack_msg = self.build_sip_message("200 OK", client_name, {
                "STATUS": "SESSION_KEY_RECEIVED",
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(client_socket, ack_msg.encode('utf-8'))
            print(f"[SESSION KEY] Acknowledgment sent to {client_name}")
            
        except Exception as e:
            print(f"[SESSION KEY ERROR] Processing failed: {str(e)}")            
    def _generate_client_id_locked(self):
        """Private method - muss innerhalb von clients_lock aufgerufen werden!"""
        if not self.clients:
            return "0"
        
        numeric_ids = []
        for key in self.clients.keys():
            if key.isdigit():
                try:
                    numeric_ids.append(int(key))
                except ValueError:
                    continue
        
        if not numeric_ids:
            return "0"
        
        numeric_ids.sort()
        expected_id = 0
        for existing_id in numeric_ids:
            if expected_id < existing_id:
                return str(expected_id)
            expected_id = existing_id + 1
        
        return str(numeric_ids[-1] + 1)


    def handle_client(self, client_socket, client_address):
        """Vollständige Client-Behandlung - Jede Session isoliert"""
        print(f"\n[Server] Neue Verbindung von {client_address}")
        client_id = None
        client_name = None
        client_generator = None  # ✅ NEU: Verify-Generator für diesen Client
        client_local_ip = None   # ✅ NEU: Lokale IP aus Registration

        try:
            # 1. Registration empfangen (mit Timeout)
            client_socket.settimeout(30.0)
            print(f"[SERVER] Warte auf Registration von {client_address}")
            
            register_data = recv_frame(client_socket)
            if not register_data:
                print("[SERVER] Keine Registrierungsdaten empfangen")
                return

            print(f"[SERVER] Empfangene Daten: {len(register_data)} bytes")
            
            # 2. Prüfe ob es eine Relay-Manager Anfrage ist
            if self._handle_relay_manager_request(register_data, client_socket, client_address):
                print("[RELAY] Relay-Manager Anfrage verarbeitet - Verbindung geschlossen")
                return
            
            # 3. Normale Client-Registration verarbeiten
            if isinstance(register_data, bytes):
                try:
                    register_data = register_data.decode('utf-8')
                    print("[SERVER] Daten als UTF-8 decodiert")
                except UnicodeDecodeError:
                    print("[SERVER] Konnte Daten nicht als UTF-8 decodieren")
                    return

            # 4. SIP-Nachricht parsen
            sip_msg = self.parse_sip_message(register_data)
            if not sip_msg:
                print("[SERVER] Ungültige SIP-Nachricht")
                return

            # 5. Client-Identifikation
            from_header = sip_msg['headers'].get('From', sip_msg['headers'].get('FROM', ''))
            client_name_match = re.search(r'<sip:(.*?)@', from_header)
            if not client_name_match:
                print(f"[SERVER] Kein Client-Name in FROM-Header: {from_header}")
                return
                
            client_name = client_name_match.group(1)
            print(f"[SERVER] Client-Name: {client_name}")

            # ✅ LOKALE IP AUS REGISTRATION EXTRAHIEREN (MINIMALINVASIVE KORREKTUR)
            custom_data = sip_msg.get('custom_data', {})
            client_local_ip = custom_data.get('CLIENT_IP')
            print("++++++++++++")
            print(client_local_ip)
            print("++++++++++++")
            if client_local_ip:
                print(f"[SERVER] Client lokale IP aus Registration: {client_local_ip}")
            else:
                print(f"[SERVER WARNING] Keine CLIENT_IP in Registration von {client_name}")
                # Fallback: Verwende NAT-IP vom Socket
                client_local_ip = client_address[0]
                print(f"[SERVER] Verwende NAT-IP als Fallback: {client_local_ip}")

            # ✅ VERIFY-GENERATOR INSTANZ ERSTELLEN (MIT DEBUG-AUSGABE)
            print("SEED+++")
            print(client_name)
            
            # ✅ DEBUG: Vor der Generator-Initialisierung
            print(f"🔐 [DEBUG] Vor init_verify_generator: client_name='{client_name}'")
            
            client_generator = init_verify_generator(client_name, client_name)
            
            # ✅ DEBUG: Nach der Generator-Initialisierung
            print(f"🔐 [DEBUG] Nach init_verify_generator:")
            print(f"🔐 [DEBUG] - Generator Client-ID: '{client_generator.client_id}'")
            print(f"🔐 [DEBUG] - Generator Seed: '{client_generator.seed}'")
            print(f"🔐 [DEBUG] - Generator Counter: {client_generator.counter}")
            
            # ✅ DEBUG: Berechne mehrere mögliche Codes (wegen möglicher Desynchronisation)
            print(f"🔐 [DEBUG] Mögliche erwartete Codes:")
            for i in range(10):  # Prüfe die ersten 10 Counter
                expected_code = client_generator._calculate_expected_code(i)
                print(f"🔐 [DEBUG] - Counter {i}: {expected_code}")
            
            print(f"🔐 [SERVER] Verify-Generator für Client-Name '{client_name}' initialisiert")

            # ✅ VERIFY-CODE DER REGISTER-NACHRICHT VALIDIEREN MIT GENERATOR INSTANZ
            if "Verify-Code:" in register_data:
                lines = register_data.split('\r\n')
                verify_code_value = None
                for line in lines:
                    if line.startswith("Verify-Code:"):
                        verify_code_value = line.split(":")[1].strip()
                        break
                
                if verify_code_value:
                    # ✅ DEBUG: Vor der Verify-Validierung
                    print(f"🔐 [DEBUG] Vor verify_code: received_code='{verify_code_value}'")
                    print(f"🔐 [DEBUG] Generator Status vor Verify: {client_generator.debug_info()}")
                    
                    # ✅ REGISTER-CODE MIT GENERATOR INSTANZ VALIDIEREN - HÖHERE TOLERANZ
                    if client_generator.verify_code(verify_code_value, sync_tolerance=10):  # ✅ Erhöht von 5 auf 10
                        print(f"✅ [VERIFY] Register-Nachricht verifiziert, Counter synchronisiert")
                        # ✅ DEBUG: Nach erfolgreicher Verify
                        print(f"🔐 [DEBUG] Nach verify_code: Counter={client_generator.counter}")
                    else:
                        print(f"❌ [VERIFY] Ungültiger Register-Code von {client_name}")
                        print(f"🔐 [DEBUG] Generator Status nach fehlgeschlagenem Verify: {client_generator.debug_info()}")
                        
                        # ✅ ZUSÄTZLICHES DEBUGGING: Manuelle Code-Überprüfung
                        print(f"🔐 [DEBUG] Manuelle Code-Überprüfung für '{verify_code_value}':")
                        found_match = False
                        for test_counter in range(20):  # Prüfe breiteren Bereich
                            expected_code = client_generator._calculate_expected_code(test_counter)
                            if verify_code_value == expected_code:
                                print(f"🔐 [DEBUG] ✅ Code match at counter {test_counter}!")
                                found_match = True
                                break
                            if test_counter < 5:  # Zeige nur die ersten 5
                                print(f"🔐 [DEBUG]   Counter {test_counter}: {expected_code}")
                        
                        if not found_match:
                            print(f"🔐 [DEBUG] ❌ No match found in first 20 counters")
                        
                        return
                else:
                    print(f"❌ [VERIFY] Kein Verify-Code in Register-Nachricht von {client_name}")
                    return
            else:
                print(f"❌ [VERIFY] Kein Verify-Header in Register-Nachricht von {client_name}")
                return

            # 6. VERBESSERTE Public Key Extraktion
            client_pubkey = None
            
            # Methode 1: Aus custom_data (JSON Body)
            custom_data = sip_msg.get('custom_data', {})
            if 'PUBLIC_KEY' in custom_data:
                client_pubkey = custom_data['PUBLIC_KEY']
                print("[SERVER] Public Key aus custom_data extrahiert")
            
            # Methode 2: Aus Body (falls direkt im Body)
            elif sip_msg.get('body') and '-----BEGIN PUBLIC KEY-----' in sip_msg['body']:
                client_pubkey = sip_msg['body'].strip()
                print("[SERVER] Public Key aus Body extrahiert")
            
            # Methode 3: Durchsuche gesamte Nachricht
            elif '-----BEGIN PUBLIC KEY-----' in register_data:
                key_match = re.search(
                    r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', 
                    register_data, 
                    re.DOTALL
                )
                if key_match:
                    client_pubkey = key_match.group(0).strip()
                    print("[SERVER] Public Key mit Regex aus gesamter Nachricht extrahiert")
            
            # Methode 4: Prüfe spezielle Header
            else:
                for header_name, header_value in sip_msg['headers'].items():
                    if 'PUBLIC_KEY' in header_name and '-----BEGIN PUBLIC KEY-----' in header_value:
                        client_pubkey = header_value.strip()
                        print(f"[SERVER] Public Key aus Header {header_name} extrahiert")
                        break

            # Debug-Ausgabe des gefundenen Keys
            if client_pubkey:
                print(f"[SERVER] Public Key gefunden: {len(client_pubkey)} Zeichen")
                print(f"[SERVER] Key beginnt mit: {client_pubkey[:50]}...")
                print(f"[SERVER] Key endet mit: ...{client_pubkey[-50:]}")
            else:
                print("[SERVER] KEIN Public Key gefunden in:")
                print(f"[SERVER] Headers: {list(sip_msg['headers'].keys())}")
                print(f"[SERVER] Custom data keys: {list(custom_data.keys())}")
                print(f"[SERVER] Body length: {len(sip_msg.get('body', ''))}")
                return

            # 7. ✅ Client ATOMIC registrieren MIT LOKALER IP (MINIMALINVASIVE KORREKTUR)
            client_data = {
                'name': client_name,
                'public_key': client_pubkey,
                'socket': client_socket,
                'ip': client_local_ip,  # ✅ KORREKTUR: Lokale IP aus Registration verwenden!
                'nat_ip': client_address[0],  # ✅ NEU: NAT-IP auch speichern für Debugging
                'port': client_address[1],
                'login_time': time.time(),
                'last_update': time.time(),
                'verify_generator': client_generator  # ✅ GENERATOR IN CLIENT-DATA SPEICHERN
            }
            
            
            # ✅ ATOMIC Registration unter clients_lock
            with self.clients_lock:
                client_id = self._generate_client_id_locked()
                self.clients[client_id] = client_data
                print(f"[SERVER] Client {client_name} registriert mit ID: {client_id}")
                print(f"[SERVER DEBUG] Lokale IP: {client_local_ip}, NAT-IP: {client_address[0]}")
            
            # ✅ Gespeicherte Clients aktualisieren (mit Error Handling)
            try:
                self.save_active_clients()
            except Exception as e:
                print(f"⚠️ [SERVER] save_active_clients failed: {e}")
            
            # ✅ ALLE Public Keys sammeln (THREAD-SAFE)
            with self.clients_lock:
                clients_copy = self.clients.copy()
            
            all_public_keys = [self.server_public_key]  # Server Key zuerst
            for cid, client_info in clients_copy.items():
                if 'public_key' in client_info:
                    all_public_keys.append(client_info['public_key'])
            
            # ✅ Keys unter key_lock speichern
            with self.key_lock:
                self.all_public_keys = all_public_keys
            
            clients_count = len(clients_copy)
            print(f"[SERVER] Gesamte Keys: {len(all_public_keys)} (Server + {clients_count} Clients)")

            # 8. Merkle Root berechnen
            merkle_root = build_merkle_tree_from_keys(all_public_keys)
            print(f"[SERVER] Merkle Root: {merkle_root[:20]}...")

            # 9. ERSTE ANTWORT: Server Public Key und Client ID
            first_response_data = {
                    "SERVER_PUBLIC_KEY": self.server_public_key,
                    "CLIENT_ID": client_id
                }
                
            first_response_msg = self.build_sip_message("200 OK", client_name, first_response_data)
            print(f"[SERVER] Sende erste Antwort: {len(first_response_msg)} bytes")
            
            send_frame(client_socket, first_response_msg.encode('utf-8'))
            print("[SERVER] Erste Antwort erfolgreich gesendet")

            # Kurze Pause für Client-Verarbeitung
            time.sleep(0.1)

            # 10. ZWEITE ANTWORT: Merkle Root und alle Keys
            second_response_data = {
                    "MERKLE_ROOT": merkle_root,
                    "ALL_KEYS": all_public_keys  # ✅ Lokale Variable verwenden
                }            
                
            second_response_msg = self.build_sip_message("200 OK", client_name, second_response_data)
            print(f"[SERVER] Sende zweite Antwort: {len(second_response_msg)} bytes")
            
            send_frame(client_socket, second_response_msg.encode('utf-8'))
            print("[SERVER] Zweite Antwort erfolgreich gesendet")
            
            # 11. KORRIGIERTE Hauptkommunikationsschleife
            print(f"[SERVER] Starte Hauptloop für {client_name}")
            client_socket.settimeout(30.0)  # ✅ Höherer Timeout für normale Kommunikation
            
            # ✅ KORREKTUR: Thread-sichere pro-Client Queue
            client_queue = []  # Lokale Queue nur für diesen Client
            
            while True:
                try:
                    # ✅ VERWENDE recv_frame() FÜR ALLE NACHRICHTEN
                    frame_data = recv_frame(client_socket, timeout=30)
                    
                    if frame_data is None:
                        print(f"[SERVER] {client_name} hat Verbindung getrennt")
                        break
                    
                    if len(frame_data) == 0:
                        print(f"[SERVER] Leere Nachricht von {client_name}, ignoriere")
                        continue
                    
                    print(f"[SERVER] Nachricht von {client_name} empfangen: {len(frame_data)} bytes")
                    
                    # ✅ Prüfe auf Relay-Manager Anfragen auch während der Session
                    if self._handle_relay_message_during_session(frame_data, client_socket, client_address, client_name):
                        continue
                    
                    # ✅ VERIFY-CODE VALIDIERUNG FÜR EINGEHENDE NACHRICHTEN MIT GENERATOR INSTANZ
                    if len(frame_data) > 0:
                        try:
                            message_str = frame_data.decode('utf-8', errors='ignore')
                            
                            # Prüfe ob es eine SIP-Nachricht vom Client ist
                            sip_methods = ['REGISTER', 'INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'MESSAGE']
                            is_sip_message = any(method in message_str for method in sip_methods)
                            
                            if is_sip_message and not message_str.startswith("SIP/2.0"):
                                # ✅ VERIFY-CODE PRÜFUNG (nur für Client→Server Nachrichten)
                                if "Verify-Code:" in message_str:
                                    # Extrahiere Verify-Code
                                    lines = message_str.split('\r\n')
                                    verify_code_value = None
                                    for line in lines:
                                        if line.startswith("Verify-Code:"):
                                            verify_code_value = line.split(":")[1].strip()
                                            break
                                    
                                    if verify_code_value:
                                        # ✅ VALIDIERE VERIFY-CODE MIT GENERATOR INSTANZ
                                        if client_generator.verify_code(verify_code_value, sync_tolerance=5):
                                            print(f"✅ [VERIFY] Nachricht #{client_generator.get_message_count()} von {client_name} verifiziert")
                                        else:
                                            print(f"❌ [VERIFY] INVALID verify-code von {client_name}: {verify_code_value}")
                                            log_invalid_message(f"{client_address[0]}:{client_address[1]}", message_str, "INVALID_VERIFY_CODE")
                                            continue  # Nachricht verwerfen, aber Verbindung aufrechterhalten
                                    else:
                                        print(f"❌ [VERIFY] MALFORMED verify-code von {client_name}")
                                        log_invalid_message(f"{client_address[0]}:{client_address[1]}", message_str, "MALFORMED_VERIFY_CODE")
                                        continue
                                else:
                                    print(f"❌ [VERIFY] MISSING verify-code von {client_name}")
                                    log_invalid_message(f"{client_address[0]}:{client_address[1]}", message_str, "MISSING_VERIFY_CODE")
                                    continue
                                    
                        except Exception as e:
                            print(f"⚠️ [VERIFY] Error during verify-code validation: {e}")
                    
                    # ✅ Nachricht zur Verarbeitung in die LOKALE Client-Queue stellen
                    client_queue.append({
                        'type': 'frame_data',
                        'data': frame_data,
                        'client_socket': client_socket,
                        'client_name': client_name
                    })
                    
                    # ✅ LOKALE Queue verarbeiten (thread-sicher)
                    self._process_client_queue(client_queue, client_socket, client_name)
                    
                except socket.timeout:
                    # Timeout ist normal, prüfe auf Verbindung
                    print(f"[SERVER] Timeout bei {client_name}, aber Verbindung aktiv")
                    continue
                    
                except ConnectionError as e:
                    print(f"[SERVER] Verbindungsfehler bei {client_name}: {str(e)}")
                    break
                    
                except Exception as e:
                    print(f"[SERVER] Fehler bei {client_name}: {str(e)}")
                    break

        except socket.timeout:
            print(f"[SERVER] Timeout bei Registrierung von {client_address}")
            
        except Exception as e:
            print(f"[SERVER] Kritischer Fehler: {str(e)}")
            import traceback
            traceback.print_exc()
            
        finally:
            # ✅ Cleanup (THREAD-SAFE)
            print(f"[SERVER] Cleanup für {client_name if client_name else 'unknown'}")
            
            if client_id:
                self._safe_remove_client(client_id)
            
            # ✅ Call cleanup für diesen Client
            if hasattr(self, 'convey_manager') and client_name:
                self.convey_manager.cleanup_client_calls(client_name)
            
            try:
                client_socket.close()
            except:
                pass         
    def _handle_relay_manager_request(self, register_data, client_socket, client_address):
        """KORRIGIERT: Sendet IMMER framed SIP"""
        try:
            if isinstance(register_data, bytes):
                try:
                    register_data = register_data.decode('utf-8')
                except UnicodeDecodeError:
                    return False
            
            message = self.parse_sip_message(register_data)
            if not message:
                return False
            
            custom_data = message.get('custom_data', {})
            headers = message.get('headers', {})
            
            print(f"[RELAY DEBUG] Received message from {client_address}")
            print(f"[RELAY DEBUG] Message type: {custom_data.get('MESSAGE_TYPE')}")
            
            # ✅ WICHTIG: DISCOVERY_REQUEST ERKENNEN UND BEHANDELN
            message_type = custom_data.get('MESSAGE_TYPE')
            
            # 1. DISCOVERY REQUEST (vom Client)
            if message_type == 'DISCOVERY_REQUEST':
                print(f"[DISCOVERY] Handling discovery request from {client_address}")
                
                # Hole Server-Liste vom Relay Manager
                servers_data = self.relay_manager.get_server_list_for_client()
                
                # ✅ KORREKTUR: Framed SIP Response bauen
                response_data = {
                    "MESSAGE_TYPE": "DISCOVERY_RESPONSE",
                    "servers": servers_data.get('servers', {}),
                    "total_servers": servers_data.get('total_servers', 0),
                    "available_servers": servers_data.get('available_servers', 0),
                    "timestamp": int(time.time()),
                    "status": "success"
                }
                
                # ✅ KORREKTUR: Framed SIP Nachricht bauen
                response_msg = self.build_sip_message("200 OK", client_address[0], response_data)
                
                print(f"[DISCOVERY DEBUG] Sending framed SIP response to {client_address}")
                print(f"[DISCOVERY DEBUG] Response size: {len(response_msg)} bytes")
                print(f"[DISCOVERY DEBUG] Response preview: {response_msg[:100]}...")
                
                # ✅ KORREKTUR: MIT FRAMED SIP SENDEN
                success = send_frame(client_socket, response_msg.encode('utf-8'))
                
                if success:
                    print(f"[DISCOVERY] ✅ Sent FRAMED SIP discovery response to {client_address}")
                else:
                    print(f"[DISCOVERY] ❌ Failed to send framed SIP response to {client_address}")
                
                return success
                
            # 2. REGISTRATION REQUEST - NICHT an Relay Manager weiterleiten!
            elif (message_type == 'REGISTER' or 
                  'PUBLIC_KEY' in custom_data or
                  'CLIENT_NAME' in custom_data):
                print(f"[REGISTER] Detected registration request - NOT forwarding to relay")
                return False  # WICHTIG: False zurückgeben = normale Registration
            
            # 3. PING REQUEST
            elif message_type == 'PING':
                print(f"[PING] Handling ping from {client_address}")
                
                response_data = {
                    "MESSAGE_TYPE": "PONG",
                    "timestamp": int(time.time()),
                    "status": "success"
                }
                
                # ✅ KORREKTUR: Framed SIP
                response_msg = self.build_sip_message("200 OK", client_address[0], response_data)
                success = send_frame(client_socket, response_msg.encode('utf-8'))
                
                if success:
                    print(f"[PING] ✅ Sent FRAMED SIP PONG to {client_address}")
                return success
            
            # 4. RELAY INTERNE REQUESTS (nur von anderen Servern)
            request_type = custom_data.get('type')
            if request_type in ['get_servers', 'register', 'update_load']:
                print(f"[RELAY] Handling internal relay request: {request_type}")
                
                # ✅ KORREKTUR: Auch hier framed SIP verwenden
                return self.relay_manager.handle_seed_request(register_data, client_socket, client_address)
            
            # 5. UNBEKANNTE REQUESTS
            else:
                print(f"[RELAY WARNING] Unknown request type from {client_address}")
                
                # ✅ KORREKTUR: Framed SIP Error
                response_data = {
                    "MESSAGE_TYPE": "ERROR",
                    "error": "UNKNOWN_REQUEST_TYPE",
                    "received_type": message_type,
                    "received_request": request_type,
                    "timestamp": int(time.time())
                }
                
                response_msg = self.build_sip_message("400 Bad Request", client_address[0], response_data)
                success = send_frame(client_socket, response_msg.encode('utf-8'))
                
                if success:
                    print(f"[RELAY] ✅ Sent FRAMED SIP error response to {client_address}")
                return success
                    
        except Exception as e:
            print(f"[RELAY ERROR] Request handling failed: {e}")
            import traceback
            traceback.print_exc()
            
            # ✅ KORREKTUR: Auch Fehler als framed SIP senden
            try:
                error_data = {
                    "MESSAGE_TYPE": "ERROR", 
                    "error": f"INTERNAL_SERVER_ERROR: {str(e)}",
                    "timestamp": int(time.time())
                }
                error_msg = self.build_sip_message("500 Error", client_address[0], error_data)
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                pass
                
            return False

    def _handle_relay_message_during_session(self, frame_data, client_socket, client_address, client_name):
        """Verarbeitet Relay-Nachrichten während einer aktiven Session"""
        try:
            if isinstance(frame_data, bytes):
                try:
                    message_text = frame_data.decode('utf-8')
                except UnicodeDecodeError:
                    return False
            else:
                message_text = str(frame_data)
                
            message = self.parse_sip_message(message_text)
            if not message:
                return False
                
            custom_data = message.get('custom_data', {})
            request_type = custom_data.get('type')
            
            # Prüfe auf Relay-Nachrichten
            if request_type in ['register', 'get_servers', 'update_load']:
                print(f"[RELAY] Relay-Nachricht während Session von {client_address}: {request_type}")
                return self.relay_manager.handle_seed_request(message_text, client_socket, client_address)
            
            return False
            
        except Exception as e:
            print(f"[RELAY ERROR] Fehler bei Relay-Nachricht: {e}")
            return False
    def get_relay_status(self):
        """Gibt den Status des Relay-Managers zurück"""
        if hasattr(self, 'relay_manager'):
            return self.relay_manager.get_server_status()
        return {'error': 'Relay manager not available'}

    def get_available_servers(self):
        """Gibt verfügbare Server für Clients zurück"""
        if hasattr(self, 'relay_manager'):
            return self.relay_manager.get_server_list_for_client()
        return {'servers': {}, 'error': 'Relay manager not available'}

    def update_traffic_stats(self, traffic_mbps):
        """Aktualisiert Traffic-Statistiken"""
        if hasattr(self, 'relay_manager'):
            self.relay_manager.current_traffic = traffic_mbps
            return True
        return False
    def _safe_remove_client(self, client_id):
        """Thread-safe client removal - ENTFERNT CLIENT KOMPLETT"""
        with self.clients_lock:
            if client_id in self.clients:
                # ✅ VERIFY-GENERATOR ENTFERNEN
                client_name = self.clients[client_id].get('name')
                if client_name:
                    remove_generator(client_name)
                    print(f"🔐 [VERIFY] Generator für '{client_name}' entfernt")
                
                # ✅ CLIENT KOMPLETT ENTFERNEN
                del self.clients[client_id]
                print(f"[SERVER] Client {client_id} komplett entfernt")
        
        # ✅ KEY-LISTE AKTUALISIEREN
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        all_public_keys = [self.server_public_key]
        for cid, client_info in clients_copy.items():
            if 'public_key' in client_info:
                all_public_keys.append(client_info['public_key'])
        
        with self.key_lock:
            self.all_public_keys = all_public_keys
        
        # ✅ AKTIVE CLIENTS DATEI AKTUALISIEREN (Client entfernen)
        try:
            if os.path.exists("active_clients.json"):
                with open("active_clients.json", "r") as f:
                    active_clients = json.load(f)
                
                if client_id in active_clients:
                    del active_clients[client_id]
                    with open("active_clients.json", "w") as f:
                        json.dump(active_clients, f, indent=2)
                    print(f"[SERVER] Client {client_id} aus active_clients.json entfernt")
        except Exception as e:
            print(f"⚠️ [SERVER] Fehler beim Aktualisieren active_clients.json: {e}")

    def _generate_client_id_locked(self):
        """Private method - muss innerhalb von clients_lock aufgerufen werden!"""
        if not self.clients:
            return "0"
        
        numeric_ids = []
        for key in self.clients.keys():
            if key.isdigit():
                try:
                    numeric_ids.append(int(key))
                except ValueError:
                    continue
        
        if not numeric_ids:
            return "0"
        
        numeric_ids.sort()
        expected_id = 0
        for existing_id in numeric_ids:
            if expected_id < existing_id:
                return str(expected_id)
            expected_id = existing_id + 1
        
        return str(numeric_ids[-1] + 1)            

    def _find_my_client_id(self):
        """Hilfsmethode für Client-ID Suche (Kompatibilität)"""
        # Diese Methode wird vom Client erwartet, kann aber einfach sein
        return "server"


    def _extract_client_name(self, sip_data):
        """Extrahiert Client-Namen aus SIP Daten"""
        headers = sip_data.get('headers', {})
        from_header = headers.get('FROM', '')
        
        # Versuche Name aus From-Header zu extrahieren
        client_name_match = re.search(r'<sip:([^@]+)@', from_header)
        if client_name_match:
            return client_name_match.group(1)
        
        # Fallback: Aus Body oder generieren
        body = sip_data.get('body', '')
        if body and len(body) < 50:  # Kurzer Body könnte Name sein
            return body.strip()
        
        return f"client_{random.randint(1000, 9999)}"

    def _extract_public_key(self, sip_data):
        """Extrahiert Public Key aus SIP Daten"""
        body = sip_data.get('body', '')
        headers = sip_data.get('headers', {})
        
        # Primär: Suche im Body
        if body and '-----BEGIN PUBLIC KEY-----' in body:
            return body.strip()
        
        # Sekundär: Suche in Headern
        for key, value in headers.items():
            if '-----BEGIN PUBLIC KEY-----' in value:
                return value.strip()
        
        # Tertiär: Durchsuche alle Header nach Key-Informationen
        for key, value in headers.items():
            if 'PUBLIC' in key or 'KEY' in key:
                if 'BEGIN' in value and 'KEY' in value:
                    return value.strip()
        
        return None
    def _get_client_public_key(self, client_name):
        """Ermittelt den Public Key eines Clients"""
        with self.clients_lock:
            for client_data in self.clients.values():
                if client_data.get('name') == client_name and 'public_key' in client_data:
                    return client_data['public_key']
        return None


    def _send_to_client_safe(self, client_name, message):
        """Sicherer Versand an Client"""
        try:
            with self.clients_lock:
                for client_data in self.clients.values():
                    if client_data.get('name') == client_name and client_data.get('socket'):
                        send_frame(client_data['socket'], message.encode('utf-8'))
                        return True
            return False
        except Exception as e:
            print(f"[SEND ERROR] Failed to send to {client_name}: {str(e)}")
            return False            
    def _find_client_id_by_name(self, client_name):
        """Findet Client-ID anhand des Namens"""
        with self.clients_lock:
            for client_id, client_data in self.clients.items():
                if client_data.get('name') == client_name:
                    return client_id
        return None        
    def normalize_client_public_key(self, key):
        """
        Verbesserte Normalisierung von Client Public Keys für M2Crypto
        """
        if not key or not isinstance(key, str):
            print("[KEY NORMALIZE] Key is None or not a string")
            return None
        
        key = key.strip()
        print(f"[KEY NORMALIZE] Original key length: {len(key)}")
        print(f"[KEY NORMALIZE] First 100 chars: {key[:100]}")
        
        # ZUERST: Alle Varianten von escaped newlines ersetzen
        key = key.replace('\\\\n', '\n').replace('\\n', '\n')
        
        # Fall 1: Bereits korrektes PEM Format
        if key.startswith('-----BEGIN PUBLIC KEY-----') and key.endswith('-----END PUBLIC KEY-----'):
            print("[KEY NORMALIZE] Key is in valid PEM format after newline replacement")
            
            # Validiere, dass der Key tatsächlich korrekt ist
            try:
                # Teste ob der Key geladen werden kann
                test_bio = BIO.MemoryBuffer(key.encode())
                test_key = RSA.load_pub_key_bio(test_bio)
                print("[KEY NORMALIZE] Key validation successful")
                return key
            except Exception as e:
                print(f"[KEY NORMALIZE] Key validation failed: {e}")
                # Versuche Reparatur
        
        # Fall 2: Key enthält PEM Marker aber möglicherweise falsche Formatierung
        if '-----BEGIN PUBLIC KEY-----' in key and '-----END PUBLIC KEY-----' in key:
            try:
                # Extrahiere den Key-Inhalt zwischen den Markern
                start = key.find('-----BEGIN PUBLIC KEY-----') + len('-----BEGIN PUBLIC KEY-----')
                end = key.find('-----END PUBLIC KEY-----')
                key_content = key[start:end].strip()
                
                # Entferne alle Whitespace-Zeichen und baue korrekten PEM
                key_content = ''.join(key_content.split())
                
                # Baue korrektes PEM Format mit korrekten Zeilenumbrüchen
                normalized_key = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
                
                # Validiere den reparierten Key
                test_bio = BIO.MemoryBuffer(normalized_key.encode())
                test_key = RSA.load_pub_key_bio(test_bio)
                print("[KEY NORMALIZE] Successfully reconstructed and validated PEM format")
                return normalized_key
                
            except Exception as e:
                print(f"[KEY NORMALIZE] Reconstruction failed: {e}")
        
        # Fall 3: Nur Base64 content
        try:
            # Entferne eventuelle Prefixe
            clean_key = key
            if ':' in key:
                clean_key = key.split(':', 1)[1].strip()
            
            # Entferne alle Whitespace-Zeichen
            clean_key = ''.join(clean_key.split())
            
            # Validiere Base64
            base64.b64decode(clean_key)
            
            # Wrap in PEM headers mit korrekten Zeilenumbrüchen
            # Base64 in 64-Zeilen-Blöcke aufteilen für korrektes PEM
            chunks = [clean_key[i:i+64] for i in range(0, len(clean_key), 64)]
            pem_key = f"-----BEGIN PUBLIC KEY-----\n" + "\n".join(chunks) + f"\n-----END PUBLIC KEY-----"
            
            # Validiere
            test_bio = BIO.MemoryBuffer(pem_key.encode())
            test_key = RSA.load_pub_key_bio(test_bio)
            print("[KEY NORMALIZE] Successfully converted Base64 to PEM format")
            return pem_key
            
        except Exception as e:
            print(f"[KEY NORMALIZE] Base64 conversion failed: {e}")
        
        print("[KEY NORMALIZE] Key format could not be normalized")
        return None


    def _process_frame_data(self, queue_item):
        """Thread-safe frame data processing"""
        frame_data = queue_item['data']
        client_socket = queue_item['client_socket']
        client_name = queue_item['client_name']

        try:
            message = frame_data.decode('utf-8')
            print(f"[SERVER] Empfangen von {client_name}: {len(message)} bytes")
            
            msg = self.parse_sip_message(message)
            if not msg:
                print(f"[SERVER ERROR] Ungültiges SIP Format von {client_name}")
                return
                
            debug_msg = message[:200] + "..." if len(message) > 200 else message
            print(f"[SERVER DEBUG] SIP Nachricht:\n{debug_msg}")
            
            headers = msg.get('headers', {})
            custom_data = msg.get('custom_data', {})

            update_detected = False
            if headers.get('UPDATE') == 'true':
                update_detected = True
            elif custom_data.get('UPDATE') == 'true':
                update_detected = True
                
            if update_detected:
                print(f"[UPDATE] Empfangen von {client_name}")
                self._handle_update_request(client_socket, client_name, msg)
                return
                
            # Identity Response Handling - NOW THREAD-SAFE!
            if custom_data.get('MESSAGE_TYPE') == 'IDENTITY_RESPONSE':
                print(f"[IDENTITY] Response empfangen von {client_name}")
                self._handle_identity_response(client_socket, client_name, msg)
                return
                
            # ENCRYPTED_SECRET Handling
            if 'ENCRYPTED_SECRET' in custom_data:
                print(f"[ENCRYPTED] Empfangen von {client_name}")
                self._message_queue.append({
                    'type': 'process_encrypted',
                    'sip_data': msg,
                    'client_socket': client_socket,
                    'client_name': client_name
                })
                return
                
            # Normale SIP Nachrichten
            self._message_queue.append({
                'type': 'process_sip',
                'message': message,
                'sip_data': msg,
                'client_socket': client_socket,
                'client_name': client_name
            })
            
        except UnicodeDecodeError:
            print(f"[SERVER ERROR] Kein UTF-8 SIP von {client_name} - Verwerfe {len(frame_data)} bytes")
    def _handle_update_request(self, client_socket, client_name, msg):
        """KORRIGIERT mit besserem Debugging"""
        try:
            print(f"[UPDATE] Handling update request from {client_name}")
            
            # 1. Client-ID und Public Key finden MIT DEBUGGING
            client_id = None
            client_pubkey = None
            with self.clients_lock:
                print(f"[UPDATE DEBUG] Searching through {len(self.clients)} clients:")
                for cid, data in self.clients.items():
                    client_name_debug = data.get('name', 'unknown')
                    has_pubkey = 'public_key' in data
                    print(f"[UPDATE DEBUG] Client {cid}: {client_name_debug} (pubkey: {has_pubkey})")
                    
                    if data.get('name') == client_name:
                        client_id = cid
                        client_pubkey = data.get('public_key')
                        print(f"[UPDATE DEBUG] ✓ Found client: {client_name} -> ID: {client_id}")
                        break
            
            if not client_id:
                print(f"[UPDATE ERROR] Client {client_name} not found in clients list")
                print(f"[UPDATE DEBUG] Available clients: {list(self.clients.keys())}")
                error_msg = self.build_sip_message("404 Not Found", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "CLIENT_NOT_FOUND",
                    "DEBUG_INFO": f"Client {client_name} not found. Available: {list(self.clients.keys())}",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return
            
            if not client_pubkey:
                print(f"[UPDATE ERROR] Client {client_name} has no public key")
                error_msg = self.build_sip_message("400 Bad Request", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "NO_PUBLIC_KEY",
                    "DEBUG_INFO": f"Client {client_name} missing public key",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return
            
            print(f"[UPDATE] Starting identity challenge for {client_name} (ID: {client_id})")
            
            # Identity Challenge durchführen
            identity_verified = self._direct_identity_challenge(client_socket, client_pubkey, client_name)
            
            if identity_verified:
                print(f"[IDENTITY] {client_name} successfully verified")
                
                # Phonebook senden
                phonebook_sent = self.send_phonebook(client_id)
                
                if phonebook_sent:
                    print(f"[UPDATE] Phonebook sent to {client_name}")
                else:
                    print(f"[UPDATE ERROR] Failed to send phonebook to {client_name}")
                    error_msg = self.build_sip_message("500 Error", client_name, {
                        "MESSAGE_TYPE": "ERROR",
                        "ERROR": "PHONEBOOK_SEND_FAILED",
                        "TIMESTAMP": int(time.time())
                    })
                    send_frame(client_socket, error_msg.encode('utf-8'))
            else:
                print(f"[IDENTITY] {client_name} verification failed")
                error_msg = self.build_sip_message("401 Unauthorized", client_name, {
                    "MESSAGE_TYPE": "ERROR",
                    "ERROR": "IDENTITY_VERIFICATION_FAILED",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                    
        except Exception as e:
            print(f"[UPDATE ERROR] Handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            error_msg = self.build_sip_message("500 Error", client_name, {
                "MESSAGE_TYPE": "ERROR",
                "ERROR": f"UPDATE_PROCESSING_FAILED: {str(e)}",
                "TIMESTAMP": int(time.time())
            })
            send_frame(client_socket, error_msg.encode('utf-8'))

    def _direct_identity_challenge(self, client_socket, client_pubkey, client_name):
        """DIREKTE Identity Challenge OHNE Blockierung - KORRIGIERT"""
        try:
            print(f"[IDENTITY] Starting direct challenge for {client_name}")
            
            # 1. Zuerst den Public Key normalisieren
            normalized_pubkey = self.normalize_client_public_key(client_pubkey)
            if not normalized_pubkey:
                print(f"[IDENTITY ERROR] Invalid public key format for {client_name}")
                return False
            
            # 2. Server Private Key laden
            with open("server_private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
            
            # 3. Challenge generieren
            challenge = base64.b64encode(os.urandom(16)).decode('ascii')
            challenge_id = str(uuid.uuid4())
            
            print(f"[IDENTITY] Generated challenge (ID: {challenge_id}) for {client_name}")
            
            # 4. Challenge mit Client-Public-Key verschlüsseln
            try:
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(normalized_pubkey.encode()))
                encrypted_challenge = pub_key.public_encrypt(
                    challenge.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                print(f"[IDENTITY] Challenge encrypted successfully")
            except Exception as e:
                print(f"[IDENTITY ERROR] Encryption failed: {e}")
                return False
            
            # 5. Challenge senden
            challenge_msg = self.build_sip_message("MESSAGE", client_name, {
                "MESSAGE_TYPE": "IDENTITY_CHALLENGE",
                "CHALLENGE_ID": challenge_id,
                "ENCRYPTED_CHALLENGE": base64.b64encode(encrypted_challenge).decode('ascii'),
                "TIMESTAMP": int(time.time())
            })
            
            if not send_frame(client_socket, challenge_msg.encode('utf-8')):
                print("[IDENTITY ERROR] Failed to send challenge")
                return False
            
            print("[IDENTITY] Challenge sent successfully")
            
            # 6. Challenge-ID für asynchrone Verarbeitung speichern
            if not hasattr(self, 'pending_challenges'):
                self.pending_challenges = {}
                
            self.pending_challenges[challenge_id] = {
                'challenge': challenge,
                'client_name': client_name,
                'client_socket': client_socket,
                'private_key': priv_key,
                'timestamp': time.time(),
                'status': 'pending'
            }
            
            print(f"[IDENTITY] Challenge {challenge_id} für {client_name} gespeichert")
            
            # 7. KEINE BLOCKIERENDE SCHLEIFE - Rückkehr sofort
            # Die Antwort wird asynchron in _process_client_queue verarbeitet
            print(f"[IDENTITY] Challenge initiated, waiting for async response from {client_name}")
            return True  # Challenge wurde initiiert, Ergebnis kommt später
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Direct challenge failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _handle_fallback_identity_response(self, response_text, challenge, challenge_id, priv_key):
        """Fallback für Identity Response Parsing bei nicht-standard Format"""
        try:
            # Versuche verschiedene Response-Formate zu parsen
            lines = response_text.split('\n')
            encrypted_response_b64 = None
            found_challenge_id = None
            
            for line in lines:
                line = line.strip()
                if 'ENCRYPTED_RESPONSE:' in line:
                    encrypted_response_b64 = line.split('ENCRYPTED_RESPONSE:', 1)[1].strip()
                elif 'CHALLENGE_ID:' in line:
                    found_challenge_id = line.split('CHALLENGE_ID:', 1)[1].strip()
            
            if encrypted_response_b64 and found_challenge_id == challenge_id:
                encrypted_response = base64.b64decode(encrypted_response_b64)
                decrypted_response = priv_key.private_decrypt(encrypted_response, RSA.pkcs1_padding)
                decrypted_text = decrypted_response.decode('utf-8')
                
                return decrypted_text == challenge + "VALIDATED"
            
            return False
            
        except Exception as e:
            print(f"[IDENTITY FALLBACK ERROR] {e}")
            return False

    def _handle_identity_response(self, client_socket, client_name, msg):
        """Korrigiertes Identity Response Handling"""
        try:
            custom_data = msg.get('custom_data', {})
            
            encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
            response_challenge_id = custom_data.get('CHALLENGE_ID')
            
            print(f"[IDENTITY] Processing response from {client_name}, challenge: {response_challenge_id}")
            
            if not encrypted_response_b64 or not response_challenge_id:
                print("[IDENTITY ERROR] Missing encrypted response or challenge ID")
                return
            
            # Client-ID finden
            client_id = None
            with self.clients_lock:
                for cid, data in self.clients.items():
                    if data.get('name') == client_name:
                        client_id = cid
                        break
            
            if not client_id:
                print(f"[IDENTITY ERROR] Client {client_name} not found")
                return
            
            # Zur Queue-Verarbeitung hinzufügen
            self._message_queue.append({
                'type': 'process_identity_response',
                'sip_data': msg,
                'client_socket': client_socket,
                'client_name': client_name,
                'client_id': client_id,
                'encrypted_response_b64': encrypted_response_b64,
                'response_challenge_id': response_challenge_id
            })
            
            print(f"[IDENTITY] Identity response queued for {client_name}")
            
        except Exception as e:
            print(f"[IDENTITY RESPONSE ERROR] {str(e)}")

    def _process_send_response(self, queue_item):
        """Thread-safe response sending"""
        response = queue_item['response']
        client_socket = queue_item['client_socket']
        client_name = queue_item.get('client_name', 'unknown')
        
        try:
            send_frame(client_socket, response.encode('utf-8'))
            print(f"[SEND] Antwort an {client_name} gesendet")
        except Exception as e:
            print(f"[QUEUE ERROR] Send failed for {client_name}: {str(e)}")

    def _process_start_identity_challenge(self, queue_item):
        """Thread-safe identity challenge start"""
        client_socket = queue_item['client_socket']
        client_name = queue_item['client_name']
        client_id = queue_item['client_id']
        client_pubkey = queue_item['client_pubkey']
        
        try:
            print(f"[IDENTITY] Starte Challenge für {client_name}")
            identity_verified, challenge_id = self._direct_identity_challenge(client_socket, client_pubkey, client_name)
            
            # Speichere Challenge-ID für spätere Verifikation
            if challenge_id:
                if not hasattr(self, 'pending_challenges'):
                    self.pending_challenges = {}
                self.pending_challenges[challenge_id] = {
                    'client': client_name,
                    'client_id': client_id,
                    'timestamp': time.time()
                }
                print(f"[DEBUG] Challenge {challenge_id} für {client_name} gespeichert")
            
            if identity_verified:
                print(f"[IDENTITY] {client_name} erfolgreich verifiziert")
                if self.send_phonebook(client_id):
                    print(f"[UPDATE] Phonebook gesendet an {client_name}")
                else:
                    print(f"[UPDATE ERROR] Phonebook konnte nicht gesendet werden an {client_name}")
            else:
                print(f"[IDENTITY] {client_name} Verifizierung fehlgeschlagen")
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Challenge failed: {str(e)}")
            import traceback
            traceback.print_exc()
    def _process_identity_response(self, sip_data, raw_data):
        """Verarbeitet Identity Response - VOLLSTÄNDIG KORRIGIERT"""
        try:
            print("[DEBUG] ✓ FOUND MATCHING IDENTITY_RESPONSE!")
            
            # Extrahiere Body und parse als Key-Value
            body = sip_data.get('body', '')
            custom_data = {}
            for line in body.split('\n'):
                line = line.strip()
                if line and ': ' in line:
                    key, value = line.split(': ', 1)
                    custom_data[key] = value
            
            print(f"[DEBUG] Extracted custom data: {custom_data}")
            
            challenge_id = custom_data.get('CHALLENGE_ID')
            encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
            
            if not challenge_id:
                print("[ERROR] Missing CHALLENGE_ID in identity response")
                return False
                
            if not encrypted_response_b64:
                print("[ERROR] Missing ENCRYPTED_RESPONSE in identity response")
                return False
            
            # Überprüfe ob Challenge ID existiert
            if challenge_id not in self.active_challenges:
                print(f"[ERROR] Unknown challenge ID: {challenge_id}")
                print(f"[DEBUG] Active challenges: {list(self.active_challenges.keys())}")
                return False
            
            original_challenge = self.active_challenges[challenge_id]
            print(f"[DEBUG] Original challenge for ID {challenge_id}: {original_challenge}")
            
            # Entschlüssele die Response
            try:
                print(f"[DEBUG] Encrypted response (b64): {encrypted_response_b64[:100]}...")
                encrypted_response = base64.b64decode(encrypted_response_b64)
                print(f"[DEBUG] Decoded encrypted response length: {len(encrypted_response)} bytes")
                
                # DEBUG: Überprüfe ob die Verschlüsselung die richtige Länge hat
                if len(encrypted_response) != 512:
                    print(f"[ERROR] Invalid encrypted response length: {len(encrypted_response)} (expected 512)")
                    return False
                    
                # Versuche mit dem privaten Server-Schlüssel zu entschlüsseln
                decrypted_response = self.private_key.private_decrypt(
                    encrypted_response, 
                    RSA.pkcs1_padding
                )
                print(f"[DEBUG] Decrypted response raw: {decrypted_response[:100]}...")
                
                # Versuche als UTF-8 zu decodieren
                try:
                    decrypted_text = decrypted_response.decode('utf-8')
                    print(f"[DEBUG] Decrypted response text: {decrypted_text}")
                except UnicodeDecodeError:
                    print("[ERROR] Failed to decode decrypted response as UTF-8")
                    # Versuche alternative Encodings
                    try:
                        decrypted_text = decrypted_response.decode('latin-1')
                        print(f"[DEBUG] Decrypted response (latin-1): {decrypted_text}")
                    except:
                        print("[ERROR] Failed to decode with any encoding")
                        return False
                
                # Validiere die Response
                expected_response = original_challenge + "VALIDATED"
                print(f"[DEBUG] Expected response: {expected_response}")
                print(f"[DEBUG] Actual response: {decrypted_text}")
                
                if decrypted_text == expected_response:
                    print(f"[IDENTITY] {sip_data['from_user']} erfolgreich verifiziert")
                    # Lösche die Challenge aus dem aktiven Pool
                    del self.active_challenges[challenge_id]
                    return True
                else:
                    print("[IDENTITY] Verification failed - response mismatch")
                    print(f"Expected: '{expected_response}'")
                    print(f"Received: '{decrypted_text}'")
                    return False
                    
            except Exception as e:
                print(f"[IDENTITY ERROR] Decryption failed: {str(e)}")
                import traceback
                traceback.print_exc()
                return False
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Processing failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def encrypt_phonebook_data(self, phonebook_json, client_public_key_pem):
        """Encrypts phonebook data with extensive debugging"""
        print("\n=== ENCRYPT PHONEBOOK DEBUG ===")
        
        if not client_public_key_pem or "-----BEGIN PUBLIC KEY-----" not in client_public_key_pem:
            error_msg = "Invalid client public key format"
            print(f"[ENCRYPT VALIDATION] {error_msg}")
            return {'error': error_msg, 'plain_data': phonebook_json}

        try:
            # 1. Generate secret
            print("[DEBUG] Generating secret...")
            secret = self.generate_secret()
            print(f"[DEBUG] Secret length: {len(secret)}")
            print(f"[DEBUG] Secret (hex): {binascii.hexlify(secret)}")
            
            # 2. Prepare padded secret
            padded_secret = b"+++secret+++" + secret
            print(f"[DEBUG] Padded secret length: {len(padded_secret)}")
            
            # 3. Load public key
            print("[DEBUG] Loading client public key...")
            pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_public_key_pem.encode()))
            
            # 4. RSA encrypt
            print("[DEBUG] RSA encrypting...")
            encrypted_secret = pub_key.public_encrypt(padded_secret, RSA.pkcs1_padding)
            print(f"[DEBUG] Encrypted secret length: {len(encrypted_secret)}")
            print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(encrypted_secret[:32])}")
            
            # 5. Prepare AES components
            iv = secret[:16]
            aes_key = secret[16:48]
            print(f"[DEBUG] IV length: {len(iv)}")
            print(f"[DEBUG] AES key length: {len(aes_key)}")
            
            # 6. AES encrypt
            print("[DEBUG] AES encrypting phonebook...")
            phonebook_str = json.dumps(phonebook_json, separators=(',', ':'))
            print(f"[DEBUG] Phonebook JSON length: {len(phonebook_str)}")
            
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
            encrypted_phonebook = cipher.update(phonebook_str.encode()) + cipher.final()
            print(f"[DEBUG] Encrypted phonebook length: {len(encrypted_phonebook)}")
            
            return {
                'encrypted_secret': base64.b64encode(encrypted_secret).decode(),
                'encrypted_phonebook': base64.b64encode(encrypted_phonebook).decode(),
                'version': '2.0'
            }
            
        except Exception as e:
            error_msg = str(e)
            print(f"[ENCRYPT ERROR] {error_msg}")
            traceback.print_exc()
            return {'error': error_msg, 'plain_data': phonebook_json}
    def get_disk_entropy(self,size):
        """
        Lese zufällige Daten von der Festplatte (z. B. /dev/urandom).
        :param size: Anzahl der zu lesenden Bytes.
        :return: Zufällige Daten als Bytes.
        """
        try:
            with open("/dev/urandom", "rb") as f:
                return f.read(size)
        except Exception as e:
            print("Fehler beim Lesen der Festplatten-Entropie:", e)
            return None
    def generate_secret(self):
        """Erzeuge ein 48-Byte-Geheimnis (16 IV + 32 AES Key)"""
        # Erzeuge den IV (16 Bytes)
        iv_part1 = secure_random(8)
        iv_part2 = self.get_disk_entropy(8)
        if not iv_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        iv = iv_part1 + iv_part2
        
        # Erzeuge den AES-Schlüssel (32 Bytes)
        key_part1 = secure_random(16)
        key_part2 = self.get_disk_entropy(16)
        if not key_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        aes_key = key_part1 + key_part2
        
        # Kombiniere IV und Schlüssel (48 Bytes total)
        return iv + aes_key

    def generate_client_id(self):
        """Generiert sequentielle Client-IDs thread-safe"""
        with self.clients_lock:
            print(f"[DEBUG] generate_client_id - Current clients: {list(self.clients.keys())}")
            
            if not self.clients:
                print("[DEBUG] No clients yet, returning '0'")
                return "0"
            
            # ✅ Finde alle numerischen IDs
            numeric_ids = []
            for key in self.clients.keys():
                if key.isdigit():
                    try:
                        numeric_ids.append(int(key))
                    except ValueError:
                        continue
            
            print(f"[DEBUG] Found numeric IDs: {numeric_ids}")
            
            if not numeric_ids:
                print("[DEBUG] No numeric IDs found, returning '0'")
                return "0"
            
            # ✅ Finde die höchste ID
            max_id = max(numeric_ids)
            next_id = max_id + 1
            print(f"[DEBUG] Highest ID: {max_id}, Next ID: {next_id}")
            
            return str(next_id)
    def save_active_clients(self):
        """Speichert NUR aktuell verbundene Clients thread-safe"""
        try:
            # ✅ SICHER: Zuerst Kopie unter Lock erstellen
            with self.clients_lock:
                clients_copy = self.clients.copy()
            
            # ✅ SICHER: Mit der Kopie arbeiten
            active_clients = {
                client_id: {
                    'name': data['name'],
                    'public_key': data['public_key'],
                    'ip': data['ip'],
                    'port': data['port']
                }
                for client_id, data in clients_copy.items()
                if data.get('socket') is not None  # Nur mit aktiver Verbindung
            }
            
            with open("active_clients.json", "w") as f:
                json.dump(active_clients, f, indent=2)
                
            print(f"[DEBUG] Saved {len(active_clients)} active clients")
            return True
            
        except Exception as e:
            print(f"Fehler beim Speichern aktiver Clients: {e}")
            return False
    
    def load_active_clients(self):
        """Lädt nur die zuletzt aktiven Clients"""
        try:
            if os.path.exists("active_clients.json"):
                with open("active_clients.json", "r") as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Fehler beim Laden aktiver Clients: {e}")
            return {}

    def remove_client(self, client_id):
        """Entfernt Client thread-safe"""
        if not client_id:
            return False
            
        try:
            with self.clients_lock:
                if client_id not in self.clients:
                    return False
                    
                # ✅ SICHER: Client entfernen
                del self.clients[client_id]
                
                # ✅ SICHER: Nachrücklogik
                sorted_ids = sorted(
                    int(k) for k in self.clients.keys() 
                    if k.isdigit() and k in self.clients  # Double-check
                )
                
                # ✅ SICHER: Neues Dictionary erstellen
                new_clients = {}
                for new_id, old_id in enumerate(sorted_ids):
                    old_id_str = str(old_id)
                    if old_id_str in self.clients:
                        new_clients[str(new_id)] = self.clients[old_id_str]
                
                self.clients = new_clients
                
            # ✅ SICHER: Speichern außerhalb des Locks
            self.save_active_clients()
            return True
            
        except Exception as e:
            print(f"[ERROR] remove_client failed: {str(e)}")
            return False




    def get_ordered_keys(self):
        """Gibt Server-Key + geordnete Client-Keys thread-safe zurück"""
        # ✅ SICHER: Zuerst Kopie unter Lock erstellen
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        # ✅ SICHER: Mit der Kopie arbeiten
        client_keys = []
        for client_id in sorted(clients_copy.keys(), key=lambda x: int(x) if x.isdigit() else 0):
            client_data = clients_copy[client_id]
            if 'public_key' in client_data:
                client_keys.append(client_data['public_key'])
        
        return [self.server_public_key] + client_keys
    def process_merkle_tree(self, client_name, client_socket):
        """Berechnet den Merkle Tree mit ALLEN aktuellen Schlüsseln"""
        try:
            with self.key_lock:
                current_keys = self.all_public_keys.copy()
            
            print(f"\n[Server] Calculating Merkle Tree with {len(current_keys)} keys:")
            for i, key in enumerate(current_keys):
                print(f"Key {i}: {shorten_public_key(key)[:30]}...")

            # Berechne Merkle Root mit allen aktuellen Keys
            merkle_root = build_merkle_tree_from_keys(current_keys)
            
            # Sende aktualisierte Key-Liste an Client
            response = self.build_sip_message("MESSAGE", client_name, {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": json.dumps(current_keys),
                "TOTAL_KEYS": len(current_keys),
                "TIMESTAMP": int(time.time())
            })
            send_frame(client_socket, response)
            
        except Exception as e:
            print(f"[ERROR] Merkle Tree calculation failed: {str(e)}")
            traceback.print_exc()
    
    def handle_communication_loop(self, client_name, client_socket):
        last_pong_time = 0
        pong_delay = 20
        
        while True:
            try:
                client_socket.settimeout(0.1)
                data = client_socket.recv(4096)
                
                if not data:
                    break
                    
                msg = self.parse_sip_message(data)
                if not msg:
                    continue
                    
                if msg.get('method') == "MESSAGE" and msg.get('headers', {}).get("PING") == "true":
                    if time.time() - last_pong_time >= pong_delay:
                        pong_msg = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                        client_socket.sendall(pong_msg.encode('utf-8'))
                        last_pong_time = time.time()

                elif 'CLIENT_SECRET' in sip_msg.get('custom_data', {}):
                    encrypted_secret = base64.b64decode(sip_msg['custom_data']['CLIENT_SECRET'])
                    self.store_client_secret(client_id, encrypted_secret)
                        
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Kommunikationsfehler: {str(e)}")
                break
    def initiate_call_between_clients(self, caller_id, callee_id):
        """Vermittelt einen Call zwischen zwei Clients"""
        try:
            with self.key_lock:
                caller = self.clients.get(caller_id)
                callee = self.clients.get(callee_id)
                
                if not caller or not callee:
                    return False
                    
                # Generiere neues Call-Geheimnis
                call_secret = generate_secret()
                iv = call_secret[:16]
                aes_key = call_secret[16:]
                
                # Verschlüssele mit beiden Client-Keys
                caller_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(caller['public_key'].encode()))
                callee_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(callee['public_key'].encode()))
                
                # Mit Overhead für Integritätsprüfung
                secret_with_overhead = b"+++call_secret+++" + call_secret
                encrypted_for_caller = caller_pubkey.public_encrypt(secret_with_overhead, RSA.pkcs1_padding)
                encrypted_for_callee = callee_pubkey.public_encrypt(secret_with_overhead, RSA.pkcs1_padding)
                
                # Sende an beide Clients
                caller_msg = self.build_sip_message("MESSAGE", caller['name'], {
                    "CALL_SETUP": "initiator",
                    "TARGET_CLIENT": callee_id,
                    "ENCRYPTED_SECRET": base64.b64encode(encrypted_for_caller).decode(),
                    "TARGET_IP": callee.get('ip'),
                    "TARGET_PORT": callee.get('port')
                })
                
                callee_msg = self.build_sip_message("MESSAGE", callee['name'], {
                    "CALL_SETUP": "receiver",
                    "CALLER_ID": caller_id,
                    "ENCRYPTED_SECRET": base64.b64encode(encrypted_for_callee).decode(),
                    "CALLER_IP": caller.get('ip'),
                    "CALLER_PORT": caller.get('port')
                })
                
                # Sende Nachrichten
                with self.client_send_lock:
                    send_frame(caller['socket'], caller_msg)
                    send_frame(callee['socket'], callee_msg)
                    
                return True
                
        except Exception as e:
            print(f"[CALL ERROR] {str(e)}")
            return False                
    def get_all_clients(self):
        """
        Thread-safe access to ALL clients with deep copy protection.
        Returns a deep copy of all client data.
        """
        try:
            with self.clients_lock:
                clients_copy = self.clients.copy()
            
            # ✅ Safe Kopie aller Clients erstellen
            all_clients = {}
            for client_id, client_data in clients_copy.items():
                if client_data is not None:
                    all_clients[client_id] = {
                        'name': client_data.get('name', ''),
                        'public_key': client_data.get('public_key', ''),
                        'socket': client_data.get('socket'),
                        'ip': client_data.get('ip', ''),
                        'port': client_data.get('port', 0),
                        'login_time': client_data.get('login_time', 0),
                        'last_update': client_data.get('last_update', 0)
                    }
            
            return all_clients
            
        except Exception as e:
            print(f"[ERROR] get_all_clients failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}        
    def get_client(self, client_id):
        """
        Thread-safe client access with deep copy protection.
        Returns a deep copy of client data to prevent race conditions.
        """
        if not client_id:
            print("[DEBUG] get_client called with None/empty client_id")
            return None
            
        try:
            # Use RLock for read operations
            with self.clients_lock:
                if client_id not in self.clients:
                    print(f"[DEBUG] Client {client_id} not found in clients dictionary")
                    print(f"[DEBUG] Available clients: {list(self.clients.keys())}")
                    return None
                    
                client_data = self.clients[client_id]
                
                # ✅ SICHER: Prüfe ob client_data nicht None ist
                if client_data is None:
                    print(f"[DEBUG] Client {client_id} data is None")
                    return None
                
                # ✅ SICHER: Erstelle Kopie mit Default-Werten
                client_copy = {
                    'name': client_data.get('name', ''),  # Default value
                    'public_key': client_data.get('public_key', ''),
                    'socket': client_data.get('socket'),  # Kann None sein
                    'ip': client_data.get('ip', ''),
                    'port': client_data.get('port', 0),
                    'login_time': client_data.get('login_time', 0),
                    'last_update': client_data.get('last_update', 0)
                }
                
                return client_copy
                
        except Exception as e:
            print(f"[ERROR] get_client failed for {client_id}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    def update_phonebook(self):
        """Aktualisiert das Telefonbuch thread-safe"""
        try:
            # 1. Gespeicherte Clients laden (ist schon safe)
            saved_clients = self.load_active_clients()
            
            # 2. Verbundene Clients sammeln (MIT LOCK!)
            connected_clients = {}
            with self.clients_lock:
                for client_id, client_data in self.clients.items():
                    if client_data.get('socket') is not None:
                        connected_clients[client_id] = client_data.copy()  # Safe Kopie!
            
            # 3. Haupt-Dictionary aktualisieren (MIT LOCK!)
            with self.clients_lock:
                self.clients.update(saved_clients)
                self.clients.update(connected_clients)
            
            # 4. Phonebook erstellen (mit safe Kopie)
            phonebook_entries = []
            for cid, data in connected_clients.items():
                if cid.isdigit():
                    try:
                        phonebook_entries.append((int(cid), data))
                    except ValueError:
                        continue
            
            self.phonebook = sorted(phonebook_entries, key=lambda x: x[0])
            
            # 5. Safe debug output
            with self.clients_lock:
                phonebook_count = len(self.phonebook)
            
            print(f"Telefonbuch aktualisiert ({phonebook_count} Einträge):")
            for cid, data in self.phonebook:
                print(f"  {cid}: {data.get('name', 'unknown')}")
                
        except Exception as e:
            print(f"[ERROR] update_phonebook failed: {str(e)}")
    
    def build_phonebook_message(self, client_data, encrypted_secret, encrypted_phonebook, client_id):
        """Builds properly formatted SIP message with JSON body containing encrypted phonebook data.
        
        Args:
            client_data: Dictionary containing client information (name, ip)
            encrypted_secret: RSA-encrypted secret (bytes)
            encrypted_phonebook: AES-encrypted phonebook data (bytes)
            client_id: Client identifier string
            
        Returns:
            Properly formatted SIP message string
        
        Raises:
            ValueError: If input validation fails
        """
        # Input validation
        if not all(key in client_data for key in ['name', 'ip']):
            raise ValueError("Invalid client_data - missing required fields")
        if not isinstance(encrypted_secret, bytes) or len(encrypted_secret) != 512:
            raise ValueError("encrypted_secret must be 512 bytes")
        if not isinstance(encrypted_phonebook, bytes) or len(encrypted_phonebook) == 0:
            raise ValueError("encrypted_phonebook must be non-empty bytes")
        if not isinstance(client_id, str):
            raise ValueError("client_id must be string")
    
        # Prepare message data with compact JSON formatting
        message_data = {
            "MESSAGE_TYPE": "PHONEBOOK_UPDATE",
            "TIMESTAMP": int(time.time()),  # Integer timestamp
            "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode('ascii'),
            "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode('ascii'),
            "CLIENT_ID": client_id
        }
    
        # Generate compact JSON without extra whitespace
        try:
            json_body = json.dumps(message_data, separators=(',', ':'))
        except (TypeError, ValueError) as e:
            raise ValueError(f"JSON serialization failed: {str(e)}")
    
        # Build SIP message with proper line endings
        sip_message = (
            f"MESSAGE sip:{client_data['name']} SIP/2.0\r\n"
            f"From: <sip:server@{self.host}>\r\n"
            f"To: <sip:{client_data['name']}@{client_data['ip']}>\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_body)}\r\n\r\n"  # Double CRLF marks end of headers
            f"{json_body}"
        )
    
        # Debug output
        if __debug__:
            print("\n=== SERVER PHONEBOOK MESSAGE ===")
            header_part = sip_message.split('\r\n\r\n')[0]
            print(f"[Headers]\n{header_part}")
            print(f"[Body Length] {len(json_body)} bytes")
            print(f"[ENCRYPTED_SECRET] {message_data['ENCRYPTED_SECRET'][:64]}...")
            print(f"[ENCRYPTED_PHONEBOOK] {message_data['ENCRYPTED_PHONEBOOK'][:64]}...")
    
        return sip_message


    def handle_phonebook_message(self, encrypted_data):
        """Entschlüsselt das empfangene Telefonbuch"""
        try:
            # 1. Extrahiere verschlüsselte Teile
            encrypted_secret = base64.b64decode(encrypted_data['ENCRYPTED_SECRET'])
            encrypted_phonebook = base64.b64decode(encrypted_data['ENCRYPTED_PHONEBOOK'])
            
            # 2. Lade privaten Schlüssel
            with open("server_private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
            
            # 3. Entschlüssele das Geheimnis
            decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            # 4. Überprüfe Overhead
            if not decrypted_secret.startswith(b"+++secret+++"):
                print("Integritätsfehler: Falscher Overhead im entschlüsselten Geheimnis")
                return
                
            secret = decrypted_secret[11:59]  # 48 Bytes nach dem Overhead
            iv = secret[:16]
            aes_key = secret[16:]
            
            # 5. Speichere Geheimnis sicher
            self.secret_vault.store(secret)
            
            # 6. Entschlüssele Telefonbuch
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
            decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
            phonebook_data = json.loads(decrypted_data.decode('utf-8'))
            
            # 7. Aktualisiere Anzeige
            self.update_phonebook(phonebook_data)
            
        except Exception as e:
            print(f"Fehler beim Entschlüsseln des Telefonbuchs: {e}")

    def encrypt_phonebook(self, secret):
        """Verschlüsselt das Telefonbuch mit dem öffentlichen Schlüssel des Clients."""
        try:
            phonebook_str = json.dumps(self.phonebook)
            cipher = EVP.Cipher("aes_256_cbc", secret[16:], secret[:16], 1)
            encrypted_phonebook = cipher.update(phonebook_str.encode('utf-8')) + cipher.final()
            return encrypted_phonebook.hex()
        except Exception as e:
            print(f"Fehler bei der Verschlüsselung des Telefonbuchs: {e}")
            return ""
    def send_phonebook(self, client_id):
        """
        Sendet das verschlüsselte Phonebook an einen Client - VOLLSTÄNDIG KORRIGIERT
        """
        try:
            print(f"\n=== SEND PHONEBOOK DEBUG START (Client {client_id}) ===")
            
            # 1. Ziel Client-Daten validieren
            target_client_data = self.get_client(client_id)
            if not target_client_data:
                print(f"[ERROR] Client {client_id} nicht gefunden")
                return False
                
            if not target_client_data.get('socket'):
                print(f"[ERROR] Client {client_id} hat keinen Socket")
                return False

            client_name = target_client_data.get('name', 'unknown')
            print(f"[DEBUG] Sending phonebook to client: {client_name}")

            # 2. Public Key des Clients validieren und normalisieren
            client_pubkey = target_client_data.get('public_key', '')
            if not client_pubkey:
                print(f"[ERROR] Client {client_name} hat keinen public key")
                return False

            # 3. Public Key normalisieren
            normalized_pubkey = self.normalize_client_public_key(client_pubkey)
            if not normalized_pubkey:
                print(f"[ERROR] Client public key konnte nicht normalisiert werden")
                return False

            print(f"[DEBUG] Normalized public key length: {len(normalized_pubkey)}")

            # 4. Alle Clients fürs Phonebook holen
            all_clients_data = self.get_all_clients()
            print(f"[DEBUG] Total clients for phonebook: {len(all_clients_data)}")

            # 5. Phonebook-Liste erstellen (NUR ONLINE CLIENTS)
            phonebook_clients = []
            for cid, data in all_clients_data.items():
                # Nur Clients mit gültigen Daten und Public Key
                if (data.get('name') and data.get('public_key') and 
                    data.get('socket') is not None):  # Nur online Clients
                    client_entry = {
                        'id': cid,
                        'name': data['name'],
                        'public_key': data['public_key'],
                        'ip': data.get('ip', ''),
                        'port': data.get('port', 0),
                        'online': True
                    }
                    phonebook_clients.append(client_entry)

            # 6. Phonebook-Daten vorbereiten
            phonebook_data = {
                'version': '2.0',
                'timestamp': int(time.time()),
                'total_clients': len(phonebook_clients),
                'clients': phonebook_clients
            }

            print(f"[DEBUG] Phonebook entries: {len(phonebook_clients)}")

            # 7. Secret generieren
            secret = self.generate_secret()
            if not secret or len(secret) != 48:
                print(f"[ERROR] Invalid secret generated: {len(secret) if secret else 0} bytes")
                return False

            # 8. Secret mit Client Public Key verschlüsseln
            try:
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(normalized_pubkey.encode()))
                
                # Secret mit Overhead für Validierung
                secret_with_overhead = b"+++secret+++" + secret
                encrypted_secret = pub_key.public_encrypt(secret_with_overhead, RSA.pkcs1_padding)
                
                if len(encrypted_secret) != 512:
                    print(f"[ERROR] Encrypted secret has wrong length: {len(encrypted_secret)}")
                    return False
                    
                print(f"[DEBUG] Secret encrypted successfully: {len(encrypted_secret)} bytes")
                
            except Exception as e:
                print(f"[ERROR] Public key encryption failed: {e}")
                return False

            # 9. Phonebook mit AES verschlüsseln
            try:
                iv = secret[:16]  # Erste 16 Bytes als IV
                aes_key = secret[16:48]  # Nächste 32 Bytes als AES Key
                
                # Phonebook zu JSON serialisieren
                phonebook_json = json.dumps(phonebook_data, separators=(',', ':'))
                print(f"[DEBUG] Phonebook JSON length: {len(phonebook_json)}")
                
                # AES Verschlüsselung
                cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)  # 1 = encrypt
                encrypted_phonebook = cipher.update(phonebook_json.encode('utf-8')) + cipher.final()
                
                print(f"[DEBUG] Phonebook encrypted: {len(encrypted_phonebook)} bytes")
                
            except Exception as e:
                print(f"[ERROR] AES encryption failed: {e}")
                return False

            # 10. Phonebook-Nachricht erstellen
            message_data = {
                "MESSAGE_TYPE": "PHONEBOOK_UPDATE",
                "TIMESTAMP": phonebook_data['timestamp'],
                "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode('ascii'),
                "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode('ascii'),
                "CLIENT_ID": client_id,
                "TOTAL_CLIENTS": len(phonebook_clients)
            }

            # 11. SIP-Nachricht bauen
            phonebook_msg = self.build_sip_message("MESSAGE", client_name, message_data)
            
            print(f"[DEBUG] Phonebook message length: {len(phonebook_msg)}")
            print(f"[DEBUG] Message contains ENCRYPTED_SECRET: {'ENCRYPTED_SECRET' in phonebook_msg}")
            print(f"[DEBUG] Message contains ENCRYPTED_PHONEBOOK: {'ENCRYPTED_PHONEBOOK' in phonebook_msg}")

            # 12. Nachricht senden
            with self.client_send_lock:
                if target_client_data['socket'].fileno() == -1:
                    print(f"[ERROR] Socket closed for {client_name}")
                    return False
                    
                success = send_frame(target_client_data['socket'], phonebook_msg.encode('utf-8'))
                if success:
                    print(f"[SUCCESS] Phonebook sent to {client_name} with {len(phonebook_clients)} entries")
                    return True
                else:
                    print(f"[ERROR] Failed to send phonebook to {client_name}")
                    return False

        except Exception as e:
            print(f"[CRITICAL] Error in send_phonebook: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


    def _send_raw_data(self, sock, data, client_id):
        """Hilfsfunktion zum sicheren Senden von Rohdaten"""
        try:
            with self.client_send_lock:
                if sock.fileno() == -1:
                    print(f"[WARN] Socket closed for {client_id}")
                    return False
                    
                sock.settimeout(10.0)
                send_frame(sock, data)
                return True
        except Exception as e:
            print(f"[ERROR] Send failed for {client_id}: {str(e)}")
            return False



class SecureVault:
    def __init__(self):
        self.lib = None
        self.vault = None
        self._load_libraries()
        if not self.lib:
            raise RuntimeError("Failed to load vault library")
        self.vault = self.lib.vault_create()
        if not self.vault:
            raise RuntimeError("Failed to create vault")

    def _load_libraries(self):
        """Lädt die benötigten Bibliotheken"""
        try:
            self.lib = ctypes.CDLL("./libauslagern_x86_64.so")
            # Initialisiere benötigte Funktionen
            self.lib.vault_create.restype = ctypes.c_void_p
            self.lib.vault_retrieve.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        except Exception as e:
            print(f"Failed to load library: {str(e)}")
            raise

    def generate_and_store_secret(self):
        """Generiert und speichert ein neues Geheimnis"""
        try:
            # Allokiere Buffer
            secret_buf = (ctypes.c_ubyte * 48)()
            
            # Generiere Geheimnis
            if hasattr(self.lib, 'generate_secret'):
                self.lib.generate_secret(secret_buf)
            else:
                # Fallback: Nutze System-Entropie
                secret_buf[:] = secure_random(48)
            
            # Speichere im Vault
            self.lib.vault_load(ctypes.c_void_p(self.vault), secret_buf)
            
            # Rückgabe als bytes
            return bytes(secret_buf)
        except Exception as e:
            print(f"Secret generation failed: {str(e)}")
            return None
        finally:
            secure_del(secret_buf)   

    def retrieve_secret(self):
        """Holt das Geheimnis aus dem Vault"""
        try:
            buf = (ctypes.c_ubyte * 48)()
            self.lib.vault_retrieve(ctypes.c_void_p(self.vault), buf)
            return bytes(buf)
        except:
            return None
        finally:
            secure_del(buf)

    def wipe(self):
        """Löscht den Vault sicher"""
        if self.vault:
            self.lib.vault_wipe(ctypes.c_void_p(self.vault))
            self.vault = None
    
    def create(self) -> bool:
        """Erstellt einen neuen Vault"""
        if not self.lib:
            return False
        self.vault = self.lib.vault_create()
        return bool(self.vault)
    
    def generate_secret(self) -> Optional[int]:
        try:
            """Generiert ein 48-Byte Geheimnis und gibt nur die Speicheradresse zurück"""
            if not self.gen_lib:
                return None
            buf = (ctypes.c_ubyte * 48)()
            self.gen_lib.generate_secret(buf)
            return ctypes.addressof(buf)
        finally:
            secure_del(buf)
    def store(self, secret_ptr: int) -> bool:
        """Speichert ein Geheimnis (nur über Speicheradresse)"""
        if not self.vault or not secret_ptr:
            return False
        
        # Konvertiere void pointer zu c_ubyte pointer
        buf = (ctypes.c_ubyte * 48).from_address(secret_ptr)
        self.lib.vault_load(ctypes.c_void_p(self.vault), buf)
        return True
    
    def retrieve(self) -> Optional[bytes]:
        """Holt das Geheimnis zurück als Bytes"""
        if not self.vault:
            return None
        
        buf = (ctypes.c_ubyte * 48)()
        self.lib.vault_retrieve(ctypes.c_void_p(self.vault), buf)
        return bytes(buf)
    
    def wipe(self):
        """Löscht den Vault sicher"""
        if self.vault:
            self.lib.vault_wipe(ctypes.c_void_p(self.vault))
            self.vault = None
    
    def __del__(self):
        """Destruktor für sichere Bereinigung"""
        self.wipe()

if __name__ == "__main__":
    try:
        # Entropy check
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read().strip())
            if entropy < 2000:
                print("LOW ENTROPY DETECTED!")
            print(f"Entropy level: {entropy}")
        
        # Traffic limit abfragen
        try:
            traffic_input = input("Type MAX-TRAFFIC from this server in mbit/s: ").strip()
            max_traffic = float(traffic_input)
        except:
            max_traffic = 100
            print(f"Using default: {max_traffic} Mbit/s")
        
        print("Starting server...")
        
        # ✅ KORRIGIERT: Verwende 0.0.0.0 für Binding, aber behalte Hostname für Identification
        server = Server(host='0.0.0.0', port=5060)  # Bind auf alle Interfaces
        
        # Traffic Limit setzen
        if hasattr(server, 'relay_manager'):
            server.relay_manager.max_traffic_mbps = max_traffic
            print(f"✅ Traffic-Limit gesetzt: {max_traffic} Mbit/s")
        
        server.start()
        
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
