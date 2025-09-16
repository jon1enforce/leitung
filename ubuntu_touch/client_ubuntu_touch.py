import socket
from access_monitor import SecurityMonitor
import threading
from M2Crypto import RSA, BIO, EVP, Rand
import json
import os
import time
import sys
import pyaudio
import uuid
import random
import binascii
from datetime import datetime
from typing import Optional, NoReturn, Tuple
import base64
import re
import stun
import struct
import ctypes
from ctypes import CDLL, c_void_p, c_int, c_ubyte, byref, cast, POINTER, create_string_buffer, c_size_t, c_char_p
import platform
import traceback
import importlib
import wave
import numpy as np
from typing import Optional
import hmac
import hashlib
try:
    from PyQt5.QtCore import QObject, pyqtSignal as Signal, pyqtSlot as Slot, pyqtProperty as Property, QUrl
    from PyQt5.QtGui import QGuiApplication
    from PyQt5.QtQml import QQmlApplicationEngine
    from PyQt5.QtQuick import QQuickView
    from PyQt5.QtWidgets import QApplication, QMessageBox
    QT_BINDING = 'PyQt5'
    print("Using PyQt5 bindings")
except ImportError as e:
    print(f"PyQt5 import failed: {e}")
    try:
        from PySide6.QtCore import QObject, Signal, Slot, Property, QUrl
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtQml import QQmlApplicationEngine
        from PySide6.QtQuick import QQuickView
        from PySide6.QtWidgets import QApplication, QMessageBox
        QT_BINDING = 'PySide6'
        print("Using PySide6 bindings")
    except ImportError as e:
        print(f"PySide6 import failed: {e}")
        try:
            from PySide2.QtCore import QObject, Signal, Slot, Property, QUrl
            from PySide2.QtGui import QGuiApplication
            from PySide2.QtQml import QQmlApplicationEngine
            from PySide2.QtQuick import QQuickView
            from PySide2.QtWidgets import QApplication, QMessageBox
            QT_BINDING = 'PySide2'
            print("Using PySide2 bindings")
        except ImportError as e:
            print(f"PySide2 import failed: {e}")
            raise ImportError("No Qt bindings found. Please install PyQt5, PySide6 or PySide2")

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
WAV_INPUT = "test_input.wav"  # Vorbereitete Testdatei
WAV_OUTPUT = "received_audio.wav"
RATE = 44100  # Abtastrate (44.1 kHz)
CHUNK = 1024  # Grösse der Audioblöcke in Frames

# AES-Einstellungen
ENC_METHOD = "aes_256_cbc"

# Netzwerk-Einstellungen peer to peer:
HOST = "0.0.0.0"  # IP des Empfängers
PORT = 5060  # Port für die Übertragung

def load_client_name():
    """Lädt Client-Namen mit Fallback"""
    try:
        if os.path.exists("client_name.txt"):
            with open("client_name.txt", "r") as file:
                return file.read().strip()
        return ""
    except Exception as e:
        print("Fehler beim Namen laden: {}".format(e))
        return ""

def send_frame(sock, data):
    """Verschickt Daten mit Längenprefix"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

def recv_frame(sock, timeout=30):
    """Improved frame receiver with binary support"""
    sock.settimeout(timeout)
    try:
        # Read header
        header = sock.recv(4)
        if len(header) != 4:
            return None
            
        length = struct.unpack('!I', header)[0]
        if length > 10 * 1024 * 1024:  # 10MB max
            raise ValueError("Frame too large")
        
        # Read body
        received = bytearray()
        while len(received) < length:
            chunk = sock.recv(min(length - len(received), 4096))
            if not chunk:
                raise ConnectionError("Connection closed prematurely")
            received.extend(chunk)
        
        print(f"\n[FRAME DEBUG] Received {length} bytes")
        print(f"First 32 bytes (hex): {' '.join(f'{b:02x}' for b in received[:32])}")
        
        # Try UTF-8 decode for SIP messages
        try:
            return received.decode('utf-8')
        except UnicodeDecodeError:
            return bytes(received)  # Return binary data if not UTF-8
            
    except socket.timeout:
        raise TimeoutError("Timeout waiting for frame")
def get_public_ip():
    nat_type, public_ip, public_port = stun.get_ip_info()
    return public_ip, public_port  # Für SIP-Contact-Header


def shorten_public_key(key):
    """Kürzt die Darstellung des öffentlichen Schlüssels."""
    shortened = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("END_OF_KEYS","").replace("\n", "")
    return shortened


def merge_public_keys(keys):
    """Identisch auf Client und Server"""
    return "|||".join(normalize_key(k) for k in keys if k)

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
def is_valid_public_key(key):
    """Strict validation for PEM format public keys"""
    if not isinstance(key, str):
        return False
    key = key.strip()
    return (
        key.startswith('-----BEGIN PUBLIC KEY-----') and 
        key.endswith('-----END PUBLIC KEY-----') and
        "MII" in key and  # ASN.1 header
        len(key) > 100    # Minimum reasonable length
    )

def extract_keys_from_response(response):
    """Final fixed version for SIP message key extraction"""
    print(f"[DEBUG] Raw response type: {type(response)}")
    
    # Convert to string if bytes
    if isinstance(response, bytes):
        try:
            response = response.decode('utf-8')
        except UnicodeDecodeError:
            return []

    # Case 1: Response is a list (from SIP parser)
    if isinstance(response, list):
        print("[DEBUG] Processing as list")
        # Reconstruct the complete message properly
        response = ''.join([str(item) for item in response if item])
        print(f"[DEBUG] Reconstructed message: {response[:200]}...")

    # Case 2: Raw SIP message as string
    if isinstance(response, str):
        print("[DEBUG] Processing as SIP message")
        try:
            # Normalize line endings
            normalized = response.replace('\r\n', '\n').replace('\r', '\n')
            
            # Find header-body separator (double newline)
            header_end = normalized.find('\n\n')
            if header_end == -1:
                print("[ERROR] No header-body separator found")
                return []
                
            body = normalized[header_end+2:]  # Skip the double newline
            print(f"[DEBUG] Message body: {body[:200]}...")

            # Find the ALL_KEYS JSON array
            keys_start = body.find('ALL_KEYS: [')
            if keys_start == -1:
                print("[ERROR] ALL_KEYS marker not found")
                return []
                
            # Extract the complete JSON array
            keys_start += len('ALL_KEYS: [')
            bracket_count = 1
            keys_end = keys_start
            
            # Find matching closing bracket
            while bracket_count > 0 and keys_end < len(body):
                if body[keys_end] == '[':
                    bracket_count += 1
                elif body[keys_end] == ']':
                    bracket_count -= 1
                keys_end += 1
                
            if bracket_count != 0:
                print("[ERROR] Unbalanced brackets in JSON array")
                return []
                
            keys_json = '[' + body[keys_start:keys_end-1]  # Reconstruct array
            print(f"[DEBUG] JSON to parse: {keys_json[:200]}...")

            # Parse JSON and validate keys
            try:
                keys = json.loads(keys_json)
                valid_keys = [k.strip() for k in keys if is_valid_public_key(k.strip())]
                print(f"[DEBUG] Found {len(valid_keys)} valid keys")
                return valid_keys
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON decode failed: {str(e)}")
                return []
                
        except Exception as e:
            print(f"[CRITICAL] Processing failed: {str(e)}")
            traceback.print_exc()
            return []

    print("[WARNING] Unsupported response format")
    return []

def validate_key_pair(private_key, public_key):
    """Validate RSA key pair matches"""
    try:
        # Create test message
        test_msg = b"TEST_MESSAGE_" + os.urandom(16)
        
        # Ensure public_key is bytes
        if isinstance(public_key, str):
            public_key = public_key.encode('utf-8')
            
        # Encrypt with public key
        pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(public_key))
        encrypted = pub_key.public_encrypt(test_msg, RSA.pkcs1_padding)
        
        # Decrypt with private key
        priv_key = RSA.load_key_string(private_key)
        decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
        
        if decrypted == test_msg:
            print("[KEY VALIDATION] Key pair is valid and matches")
            return True
        else:
            print("[KEY VALIDATION] Key pair does not match!")
            return False
    except Exception as e:
        print(f"[KEY VALIDATION ERROR] {str(e)}")
        return False

def get_disk_entropy(size):
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

# Funktion zur Generierung von dynamischem Padding mit SHA-3, quantesicher:
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
def generate_dynamic_padding(data, key):
    """
    Generiert dynamisches Padding mit SHA3-256:
    - Konsistente Ergebnisse über Python-Versionen
    - Automatische String/Byte-Handhabung
    - 1-16 Byte Padding-Länge
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # SHA3-256 Hash berechnen
    if USE_PYSHA3:
        hash_obj = sha3.sha3_256(key)
    else:
        hash_obj = hashlib.sha3_256(key)
    
    padding_length = (hash_obj.digest()[0] % 16) + 1
    return bytes([padding_length] * padding_length)

# Funktion zum Hinzufügen von dynamischem Padding
def add_dynamic_padding(data, key):
    # Dynamisches Padding generieren
    padding = generate_dynamic_padding(data, key)
    # Daten mit Padding kombinieren
    padded_data = data + padding
    return padded_data

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
    
    return secret


def decrypt_audio_chunk(encrypted_chunk, key, iv):
    """Robust audio decryption with padding handling"""
    try:
        cipher = EVP.Cipher(
            alg='aes_256_cbc',
            key=key,
            iv=iv,
            op=0,
            padding=1
        )
        decrypted = cipher.update(encrypted_chunk) + cipher.final()
        
        # Remove dynamic padding
        if len(decrypted) > 0:
            pad_length = decrypted[-1]
            if 1 <= pad_length <= 16:  # Valid padding range
                return decrypted[:-pad_length]
        return decrypted
        
    except EVP.EVPError:
        # Fallback to no padding
        cipher = EVP.Cipher('aes_256_cbc', key, iv, 0, padding=0)
        return cipher.update(encrypted_chunk) + cipher.final()

def encrypt_audio_chunk(chunk, key, iv):
    """Robust audio chunk encryption"""
    try:
        # Add dynamic padding
        pad_length = (hashlib.sha256(key).digest()[0] % 16 + 1)
        padding = bytes([pad_length] * pad_length)
        padded_chunk = chunk + padding
        
        cipher = EVP.Cipher(
            alg='aes_256_cbc',
            key=key,
            iv=iv,
            op=1,  # encrypt
            padding=1
        )
        return cipher.update(padded_chunk) + cipher.final()
    except Exception as e:
        print(f"[AUDIO ENCRYPT ERROR] {str(e)}")
        return b''


def load_server_publickey():
    """Lädt den öffentlichen Server-Schlüssel aus der Datei"""
    if not os.path.exists("server_public_key.pem"):
        raise FileNotFoundError("Server public key file not found")
    
    with open("server_public_key.pem", "rb") as f:
        return f.read().decode('utf-8')




@staticmethod
def build_sip_request(method, recipient, client_name, server_ip, server_port):
    """Generiert standardkonforme SIP-Nachrichten mit korrekten Port-Handlings"""
    local_ip = socket.gethostbyname(socket.gethostname())
    
    # Wichtige Änderungen:
    local_port = random.randint(32768, 60999)  # IANA empfohlener ephemeral port range
    call_id = "{}@{}".format(uuid.uuid4(), server_ip)
    branch_id = "z9hG4bK{}".format(random.randint(1000, 9999))
    tag = random.randint(1000,9999)

    return (
        "{method} sip:{recipient}@{server_ip}:{server_port} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP {local_ip}:{local_port};rport;branch={branch_id}\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:{client_name}@{server_ip}>;tag={tag}\r\n"
        "To: <sip:{recipient}@{server_ip}>\r\n"
        "Call-ID: {call_id}\r\n"
        "CSeq: 1 {method}\r\n"
        "Contact: <sip:{client_name}@{local_ip}:{local_port}>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).format(
        method=method,
        recipient=recipient,
        server_ip=server_ip,
        server_port=server_port,
        local_ip=local_ip,
        local_port=local_port,
        branch_id=branch_id,
        client_name=client_name,
        tag=tag,
        call_id=call_id
    )

def build_sip_message(method, recipient, custom_data={}, from_server=False, host=None):
    """Erweitere SIP-Nachrichtenerstellung mit JSON-Unterstützung (standalone Version)
    
    Args:
        method: SIP Method (z.B. "MESSAGE", "REGISTER")
        recipient: Empfänger-URI
        custom_data: Dictionary mit Nachrichtendaten
        from_server: True für Server-Nachrichten, False für Client
        host: Server-Host-IP (nur bei from_server=True benötigt)
    """
    # Entscheide ob Body JSON oder Key-Value sein soll
    if any(isinstance(v, (dict, list)) for v in custom_data.values()):
        body = json.dumps(custom_data, separators=(',', ':'))
        content_type = "application/json"
    else:
        body = "\r\n".join("{}: {}".format(k, v) for k, v in custom_data.items())
        content_type = "text/plain"
    
    # Absenderadresse bestimmen
    if from_server:
        from_header = "<sip:server@{}>".format(host) if host else "<sip:server>"
    else:
        client_name = load_client_name()
        client_ip = socket.gethostbyname(socket.gethostname())
        from_header = "<sip:{}@{}>".format(client_name, client_ip)

    
    return (
        "{method} sip:{recipient} SIP/2.0\r\n"
        "From: {from_header}\r\n"
        "To: <sip:{recipient}>\r\n"
        "Content-Type: {content_type}\r\n"
        "Content-Length: {content_length}\r\n\r\n"
        "{body}"
    ).format(
        method=method,
        recipient=recipient,
        from_header=from_header,
        content_type=content_type,
        content_length=len(body),
        body=body
    )
def parse_sip_message(message):
    """Robust SIP message parser that handles both raw and parsed messages"""
    # If message is already parsed, return it directly
    if isinstance(message, dict):
        return message
        
    # Handle bytes input
    if isinstance(message, bytes):
        try:
            message = message.decode('utf-8')
        except UnicodeDecodeError:
            return None

    # Handle string input
    if isinstance(message, str):
        message = message.strip()
        if not message:
            return None

        # Rest of your existing parsing logic...
        parts = message.split('\r\n\r\n', 1)
        headers = parts[0].split('\r\n')
        body = parts[1] if len(parts) > 1 else ''

        result = {'headers': {}, 'body': body, 'custom_data': {}}

        # Parse first line
        first_line = headers[0]
        if first_line.startswith('SIP/2.0'):
            parts = first_line.split(' ', 2)
            result['status_code'] = parts[1] if len(parts) > 1 else ''
            result['status_message'] = parts[2] if len(parts) > 2 else ''
        else:
            parts = first_line.split(' ', 2)
            result['method'] = parts[0] if len(parts) > 0 else ''
            result['uri'] = parts[1] if len(parts) > 1 else ''
            result['protocol'] = parts[2] if len(parts) > 2 else ''

        # Parse headers
        for header in headers[1:]:
            if ': ' in header:
                key, val = header.split(': ', 1)
                result['headers'][key.strip().upper()] = val.strip()

        # Parse body
        if body:
            try:
                # Try JSON first
                result['custom_data'] = json.loads(body)
            except json.JSONDecodeError:
                # Fallback to key-value
                result['custom_data'] = dict(
                    line.split(': ', 1)
                    for line in body.splitlines()
                    if ': ' in line
                )

        return result
        
    return None
def connection_loop(client_socket, server_ip, message_handler=None):
    """Improved connection loop with proper SIP ping/pong and FRAMING support"""
    # FRAMING IS REQUIRED - no fallback!
    
    while True:
        try:
            # Build ping message
            ping_msg = (
                f"MESSAGE sip:{server_ip} SIP/2.0\r\n"
                f"From: <sip:{load_client_name()}@{socket.gethostbyname(socket.gethostname())}>\r\n"
                f"To: <sip:{server_ip}>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: 10\r\n\r\n"
                f"PING: true"
            )
            
            # Send ping MIT FRAMING (KEIN FALLBACK!)
            send_frame(client_socket,ping_msg)
            
            print("DEBUG:ping gesendet+++")

            # Wait for pong MIT FRAMING (KEIN FALLBACK!)
            response = recv_frame(client_socket)
            if response and isinstance(response, bytes):
                response = response.decode('utf-8')
            
            if not response:
                print("Server disconnected")
                break
                
            if message_handler:
                message_handler(response)
            else:
                # Default pong handling
                sip_data = parse_sip_message(response)
                if sip_data and sip_data.get('custom_data', {}).get('PONG') == 'true':
                    print("Pong received")
                else:
                    print(f"Unexpected response: {response[:100]}...")

            time.sleep(30)  # Ping interval
            
        except socket.timeout:
            print("Connection timeout")
            break
        except Exception as e:
            print(f"Connection error: {str(e)}")
            break
def extract_server_public_key(sip_data, raw_response=None):
    """
    Extrahiert den Server-Public-Key aus SIP-Daten mit mehreren Fallbacks
    Gibt den vollständigen PEM-formatierten Key oder None zurück
    """
    # Variante 1: Aus custom_data
    if isinstance(sip_data, dict) and sip_data.get('custom_data'):
        if 'SERVER_PUBLIC_KEY' in sip_data['custom_data']:
            key = sip_data['custom_data']['SERVER_PUBLIC_KEY']
            if '-----BEGIN PUBLIC KEY-----' in key:
                return key
    
    # Variante 2: Aus dem Body der rohen Response
    if raw_response:
        # Suche nach dem Key mit flexibler Position
        key_start = raw_response.find('-----BEGIN PUBLIC KEY-----')
        if key_start != -1:
            key_end = raw_response.find('-----END PUBLIC KEY-----', key_start)
            if key_end != -1:
                key_end += len('-----END PUBLIC KEY-----')
                return raw_response[key_start:key_end]
    
    # Variante 3: Aus Header-Zeilen
    if isinstance(sip_data, dict) and sip_data.get('headers'):
        for header in sip_data['headers'].values():
            if '-----BEGIN PUBLIC KEY-----' in header:
                key_start = header.find('-----BEGIN PUBLIC KEY-----')
                key_end = header.find('-----END PUBLIC KEY-----', key_start)
                if key_end != -1:
                    key_end += len('-----END PUBLIC KEY-----')
                    return header[key_start:key_end]
    
    return None           
    
def start_connection(server_ip, server_port, client_name, client_socket, message_handler=None):
    """
    Final corrected version with complete error handling
    """
    try:
        # 1. Configure socket
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client_socket.settimeout(15.0)

        # 2. Load and validate client key
        client_pubkey = load_publickey()
        if not is_valid_public_key(client_pubkey):
            raise ValueError("Invalid client public key format")

        # 3. Build and send registration
        local_ip = socket.gethostbyname(socket.gethostname())
        register_msg = (
            f"REGISTER sip:{server_ip}:{server_port} SIP/2.0\r\n"
            f"From: <sip:{client_name}@{local_ip}>\r\n"
            f"To: <sip:{server_ip}:{server_port}>\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(client_pubkey)}\r\n\r\n"
            f"{client_pubkey}"
        )
        
        print("\n[Client] Sending registration...")
        send_frame(client_socket, register_msg.encode('utf-8'))

        # 4. Receive and parse response
        response = recv_frame(client_socket)
        if not response:
            raise ConnectionError("Empty response from server")

        if isinstance(response, bytes):
            response = response.decode('utf-8')

        print(f"\n[Client] Server response:\n{response[:500]}...")

        # 5. Extract and validate server key
        server_public_key = None
        if '-----BEGIN PUBLIC KEY-----' in response:
            key_start = response.index('-----BEGIN PUBLIC KEY-----')
            key_end = response.index('-----END PUBLIC KEY-----') + len('-----END PUBLIC KEY-----')
            server_public_key = response[key_start:key_end]

        if not is_valid_public_key(server_public_key):
            raise ValueError("Invalid server public key")

        with open("server_public_key.pem", "w") as f:
            f.write(server_public_key)

        # 6. Receive and verify Merkle data
        merkle_response = recv_frame(client_socket)
        if not merkle_response:
            raise ConnectionError("No Merkle data received")

        if isinstance(merkle_response, bytes):
            merkle_response = merkle_response.decode('utf-8')

        merkle_data = parse_sip_message(merkle_response)
        if not merkle_data:
            raise ValueError("Invalid Merkle response format")

        # Extract keys and root hash
        all_keys = []
        if 'custom_data' in merkle_data and 'ALL_KEYS' in merkle_data['custom_data']:
            keys_data = merkle_data['custom_data']['ALL_KEYS']
            if isinstance(keys_data, str):
                try:
                    all_keys = json.loads(keys_data)
                except json.JSONDecodeError:
                    all_keys = [k.strip() for k in keys_data.split('|||') if k.strip()]
            elif isinstance(keys_data, list):
                all_keys = keys_data

        merkle_root = merkle_data.get('custom_data', {}).get('MERKLE_ROOT', '')
        if not merkle_root:
            raise ValueError("No Merkle root in response")

        print("\n=== CLIENT VERIFICATION ===")
        if not verify_merkle_integrity(all_keys, merkle_root):
            raise ValueError("Merkle verification failed")

        # 7. Start main loop with proper handler
        print("\n[Client] Starting communication loop...")
        if message_handler:
            # Wrap the handler if it's a QObject
            if hasattr(message_handler, 'handle_server_message'):
                handler = message_handler.handle_server_message
            else:
                handler = message_handler
        else:
            handler = None
            
        connection_loop(client_socket, server_ip, handler)
        return True

    except Exception as e:
        error_msg = f"Connection failed: {str(e)}"
        print(f"\n[Client ERROR] {error_msg}")
        traceback.print_exc()
        
        if message_handler and hasattr(message_handler, 'show_error'):
            try:
                message_handler.show_error(error_msg)
            except:
                print("Could not display error message")
        
        return False
    finally:
        if 'client_socket' in locals():
            try:
                client_socket.close()
            except:
                pass
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
    if not os.path.exists("public_key.pem"):
        # Generiere neuen RSA-Schlüssel
        bits = 4096
        new_key = RSA.gen_key(bits, 65537)

        # Speichere den öffentlichen Schlüssel im PEM-Format
        pub_memory = BIO.MemoryBuffer()
        new_key.save_pub_key_bio(pub_memory)
        public_key_pem = pub_memory.getvalue().decode('utf-8')  # Als String

        with open("public_key.pem", "w") as pubHandle:
            pubHandle.write(public_key_pem)

        # Speichere den privaten Schlüssel
        priv_memory = BIO.MemoryBuffer()
        new_key.save_key_bio(priv_memory, cipher=None)
        with open("private_key.pem", "wb") as privHandle:
            privHandle.write(priv_memory.getvalue())
        
        return public_key_pem
    else:
        # Lade den öffentlichen Schlüssel als kompletten PEM-String
        with open("public_key.pem", "r") as f:
            public_key = f.read().strip()
        
        # Validierung des Keys
        if not public_key.startswith('-----BEGIN PUBLIC KEY-----') or \
           not public_key.endswith('-----END PUBLIC KEY-----'):
            raise ValueError("Invalid public key format in file")
        
        return public_key


def load_privatekey():
    with open("private_key.pem", "rb") as privHandle:
        private_key = privHandle.read()
    return private_key.decode('utf-8')






# Nur für die bidirektionale Audioübertragungs - session, client - client(peer-peer):
# Nur für die bidirektionale Audioübertragungs - session, client - client(peer-peer):
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
# Füge diese Hilfsklassen hinzu
class CustomEvent:
    """Einfaches Event für thread-sichere Operationen"""
    def __init__(self, callback):
        self.callback = callback

    # Füge diese Methoden zur PHONEBOOK Klasse hinzu
    @Slot(result=list)
    def getPhonebookEntries(self):
        """QML-zugängliche Methode zum Abrufen der Einträge"""
        return self.phonebook_entries

    @Slot(result=str)
    def getPhonebookStatus(self):
        """Gibt den aktuellen Status zurück"""
        return self._connection_status

    @Slot()
    def refreshPhonebook(self):
        """Manuelles Refresh der Telefonbuch-UI"""
        print("[MANUAL REFRESH] Triggering phonebook refresh")
        if self.phonebook_entries:
            self.phonebookUpdated.emit(self.phonebook_entries)        
class PHONEBOOK(QObject):
    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.server_public_key = None
        self.encrypted_secret = None
        self.aes_iv = None
        self.aes_key = None
        self.secret_vault = SecureVault()
        self.current_secret = None
        self.phonebook_entries = []
        self._connection_status = "Nicht verbunden"
        self._call_status = ""
        self._client_name = ""  # Korrektes privates Attribut
        self.client_name = ""   # Öffentliche Property
                # Audio-Konstanten definieren
        self.AUDIO_HOST = "0.0.0.0"
        self.AUDIO_FORMAT = pyaudio.paInt16
        self.AUDIO_CHANNELS = 1
        self.AUDIO_RATE = 44100
        self.AUDIO_CHUNK = 1024
        self.AUDIO_IV_LEN = 16
        
        # Audio-Ports definieren (unterschiedlich für Senden/Empfangen)
        self.audio_port_out = 50001  # Für ausgehende Verbindungen
        self.audio_port_in = 50002   # Für eingehende Verbindungen
        
        # Thread-Management
        self.audio_threads = []
        self.active_call = False
        self.selected_entry = None
        self.load_client_name()
        self.clientNameRequested.connect(self.handle_name_request)
        self.phonebook_update_signal.connect(self.update_phonebook)
        # QML Engine Setup
        self.engine = QQmlApplicationEngine()
        self.engine.rootContext().setContextProperty("phonebook", self)
        self.engine.load('Phonebook.qml')
        
        if not self.engine.rootObjects():
            raise RuntimeError("QML konnte nicht geladen werden")

    # Properties für QML
    
    phonebookUpdateRequested = Signal()
    identityChallengeStarted = Signal()
    identityChallengeCompleted = Signal(bool, str)
    phonebook_update_signal = Signal(list)
    serverSettingsChanged = Signal(str, str) 
    clientNameRequested = Signal()
    clientNameChanged = Signal(str)
    connectionStatusChanged = Signal(str)
    callStatusChanged = Signal(str)
    phonebookUpdated = Signal(list)
    # Als Property für QML verfügbar machen
    @Property(str, notify=clientNameChanged)
    def clientName(self):
        return self._client_name

    @Slot(str, result=bool)
    def save_client_name(self, name):
        """Speichert den Client-Namen"""
        try:
            with open("client_config.json", "w") as f:
                json.dump({"name": name.strip()}, f)
            self._client_name = name.strip()
            self.client_name = self._client_name  # Konsistenz beibehalten
            self.clientNameChanged.emit(self._client_name)
            return True
        except Exception as e:
            print(f"Fehler beim Speichern: {str(e)}")
            return False
    def load_client_name(self):
        """Läd den gespeicherten Client-Namen"""
        try:
            if os.path.exists("client_config.json"):
                with open("client_config.json", "r") as f:
                    config = json.load(f)
                    self.client_name = config.get("name", "")
                    self._client_name = self.client_name
                    return True
        except Exception as e:
            print(f"Fehler beim Laden des Client-Namens: {str(e)}")
        return False
    

    @Slot()
    def handle_name_request(self):
        """Wird aufgerufen wenn ein Name benötigt wird"""
        if not os.path.exists("client_name.txt"):
            self._client_name = ""
            self.clientNameChanged.emit(self._client_name)

    @Slot(str)
    def set_client_name(self, name):
        """Wird von QML aufgerufen um Namen zu setzen"""
        if name and name.strip():
            self._client_name = name.strip()
            with open("client_name.txt", "w") as file:
                file.write(self._client_name)
            self.clientNameChanged.emit(self._client_name)
            return True
        return False

    @Property(str, notify=connectionStatusChanged)
    def connectionStatus(self):
        return self._connection_status

    @Property(str, notify=callStatusChanged)
    def callStatus(self):
        return self._call_status

    @Property('QVariant', notify=phonebookUpdated)
    def phonebookEntries(self):
        return self.phonebook_entries if hasattr(self, 'phonebook_entries') else []




    @Slot(str, str)
    def on_connect_click(self, server_ip, server_port):
        """Handle connection attempt with proper name validation and error handling"""
        # Check if already connected
        if self.client_socket:
            self._connection_status = "Bereits verbunden"
            self.connectionStatusChanged.emit(self._connection_status)
            return

        # Validate server parameters first
        try:
            if not server_ip or not server_port:
                raise ValueError("Server-IP und Port müssen angegeben werden")
            
            port = int(server_port)
            if not (0 < port <= 65535):
                raise ValueError("Ungültiger Port")
                
        except ValueError as e:
            self._connection_status = f"Ungültige Eingabe: {str(e)}"
            self.connectionStatusChanged.emit(self._connection_status)
            return

        # Handle client name requirement
        if not self._client_name:
            if not hasattr(self, '_name_requested'):
                self._name_requested = True
                self.clientNameRequested.emit()
            else:
                self._connection_status = "Verbindung abgebrochen - Kein Name angegeben"
                self.connectionStatusChanged.emit(self._connection_status)
            return

        # Attempt connection
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            
            # Async connection attempt
            def connection_attempt():
                try:
                    self.client_socket.connect((server_ip, port))
                    self.server_ip = server_ip
                    self.server_port = port
                    
                    self._connection_status = f"Verbunden mit {server_ip}:{port}"
                    self.connectionStatusChanged.emit(self._connection_status)
                    
                    # Start message handling thread
                    threading.Thread(
                        target=self.start_connection_wrapper,
                        daemon=True
                    ).start()
                    
                except socket.timeout:
                    self._connection_status = "Verbindungstimeout - Server nicht erreichbar"
                    self.cleanup_connection()
                except ConnectionRefusedError:
                    self._connection_status = "Verbindung abgelehnt - Server nicht erreichbar oder Port falsch"
                    self.cleanup_connection()
                except OSError as e:
                    self._connection_status = f"Netzwerkfehler: {str(e)}"
                    self.cleanup_connection()
                finally:
                    self.connectionStatusChanged.emit(self._connection_status)

            # Run connection in separate thread to avoid UI freeze
            threading.Thread(target=connection_attempt, daemon=True).start()

        except Exception as e:
            self._connection_status = f"Unerwarteter Fehler: {str(e)}"
            self.connectionStatusChanged.emit(self._connection_status)
            self.cleanup_connection()
    @Slot()
    def on_update_click(self):
        """Qt-compatible update click handler with Identity Challenge"""
        print("[CLIENT] Update-Button geklickt - Starte Identity Challenge Prozess")
        
        try:
            if not hasattr(self, 'client_socket') or not self.client_socket:
                self._connection_status = "Nicht mit Server verbunden"
                self.connectionStatusChanged.emit(self._connection_status)
                print("[UPDATE ERROR] Nicht mit Server verbunden")
                return

            # Baue UPDATE SIP Nachricht (framed)
            update_msg = (
                f"MESSAGE sip:{self.server_ip} SIP/2.0\r\n"
                f"From: <sip:{self._client_name}@client>\r\n"
                f"To: <sip:{self.server_ip}>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: 12\r\n"
                f"UPDATE: true\r\n\r\n"  # Header-Format
                f"UPDATE: true"  # Body-Format als Fallback
            )

            # Sende UPDATE Nachricht mit Framing
            try:
                send_frame(self.client_socket, update_msg.encode('utf-8'))
                print("[CLIENT] UPDATE Nachricht an Server gesendet")
                self._connection_status = "Update-Anfrage gesendet"
                self.connectionStatusChanged.emit(self._connection_status)
                
            except Exception as e:
                error_msg = f"Update-Nachricht konnte nicht gesendet werden: {str(e)}"
                print(f"[CLIENT ERROR] {error_msg}")
                self._connection_status = error_msg
                self.connectionStatusChanged.emit(self._connection_status)

        except Exception as e:
            error_msg = f"Update konnte nicht gestartet werden: {str(e)}"
            print(f"[CLIENT ERROR] {error_msg}")
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)
            import traceback
            traceback.print_exc()
    @Slot()
    def load_phonebook(self):
        if not self.client_socket:
            self._connection_status = "Keine Verbindung zum Server!"
            self.connectionStatusChanged.emit(self._connection_status)
            return
        
        try:
            request = build_sip_message(
                "GET",
                "server",
                {"REQUEST": "PHONEBOOK"}
            )
            self.client_socket.sendall(request.encode('utf-8'))
            
            response = recv_frame(self.client_socket)
            if response:
                phonebook_data = json.loads(response)
                self.update_phonebook(phonebook_data)
        except Exception as e:
            self._connection_status = "Fehler beim Laden des Telefonbuchs: {}".format(e)
            self.connectionStatusChanged.emit(self._connection_status)



    @Slot(int)
    def on_entry_click(self, index):
        print(f"🚀 DEBUG: on_entry_click called with index: {index}")
        print(f"📊 DEBUG: phonebook_entries length: {len(self.phonebook_entries)}")
        
        # Debug-Ausgabe aller Einträge
        for i, entry in enumerate(self.phonebook_entries):
            print(f"   [{i}] {entry.get('id', 'N/A')}: {entry.get('name', 'Unknown')}")
        
        if not self.phonebook_entries:
            print("❌ ERROR: phonebook_entries is EMPTY!")
            return
            
        if 0 <= index < len(self.phonebook_entries):
            self.selected_entry = self.phonebook_entries[index]
            print(f"✅ DEBUG: Selected entry: {self.selected_entry.get('id', 'N/A')}: {self.selected_entry.get('name', 'Unknown')}")
        else:
            print(f"❌ ERROR: Invalid index {index} (valid range: 0-{len(self.phonebook_entries)-1})")

    @Slot()
    def on_call_click(self):
        """Handler für den Call-Button - Ruft initiate_call auf"""
        if not self.selected_entry:
            self._call_status = "Bitte zuerst einen Kontakt auswählen"
            self.callStatusChanged.emit(self._call_status)
            print("DEBUG: selected_entry is None")
            return
            
        try:
            # Rufe initiate_call mit dem ausgewählten Eintrag auf
            self.initiate_call(self.selected_entry)
            self._call_status = "Anruf gestartet"
            self.callStatusChanged.emit(self._call_status)
            
        except Exception as e:
            error_msg = f"Anruf fehlgeschlagen: {str(e)}"
            print(f"[CALL ERROR] {error_msg}")
            self._call_status = error_msg
            self.callStatusChanged.emit(self._call_status)
            import traceback
            traceback.print_exc()

    @Slot()
    def on_hangup_click(self):
        self._call_status = "Anruf beendet"
        self.callStatusChanged.emit(self._call_status)

    @Slot()
    def open_keyboard_settings(self):
        self._call_status = "Tastatureinstellungen (nicht implementiert)"
        self.callStatusChanged.emit(self._call_status)

    @Slot()
    def open_language_settings(self):
        self._call_status = "Spracheinstellungen (nicht implementiert)"
        self.callStatusChanged.emit(self._call_status)

    def _process_json_body(self, body):
        try:
            data = json.loads(body)
            if 'MESSAGE_TYPE' in data and data['MESSAGE_TYPE'] == "PHONEBOOK_UPDATE":
                return self._process_phonebook_update(data)
            return False
        except json.JSONDecodeError:
            print("[CLIENT] Invalid JSON in message body")
            return False
    
    def _handle_sip_message(self, message):
        """Verarbeitet SIP-Nachrichten mit verschlüsselten Daten im Body"""
        sip_data = parse_sip_message(message)
        if not sip_data:
            return False

        try:
            # Extrahiere verschlüsselte Teile aus custom_data
            if 'custom_data' in sip_data:
                enc_secret = sip_data['custom_data'].get('ENCRYPTED_SECRET')
                enc_phonebook = sip_data['custom_data'].get('ENCRYPTED_PHONEBOOK')
                
                if enc_secret and enc_phonebook:
                    secret_bytes = base64.b64decode(enc_secret)
                    phonebook_bytes = base64.b64decode(enc_phonebook)
                    return self._process_raw_encrypted_data(secret_bytes + phonebook_bytes)
        
        except Exception as e:
            print(f"[ERROR] SIP message processing failed: {str(e)}")
        
        return False

    def _handle_sip_response(self, sip_data):
        """Handles SIP responses (like 200 OK)"""
        try:
            status_code = sip_data.get('status_code')
            print(f"[DEBUG] Received SIP response: {status_code}")
            
            if status_code == '200':
                # Handle successful responses
                return True
            else:
                print(f"[WARNING] Server returned error: {status_code}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Failed to handle SIP response: {str(e)}")
            return False

    def handle_server_message(self, raw_data):
        """Improved message handler that properly routes different message types"""
        print("\n=== HANDLING SERVER MESSAGE ===")
        print(f"[DEBUG] Raw data: {raw_data[:100]}...")  # Print first 100 bytes for debugging
        
        # Queue-Initialisierung mit DoS-Schutz
        if not hasattr(self, '_message_queue'):
            self._message_queue = []
            self._processing_queue = False
            self._queue_size_limit = 120  # Max 120 Nachrichten
            self._last_minute_check = time.time()
            self._messages_this_minute = 0
        
        # DoS-Schutz: Nachrichten pro Minute limitieren
        current_time = time.time()
        if current_time - self._last_minute_check >= 60:
            # Minute abgelaufen, Counter zurücksetzen
            self._last_minute_check = current_time
            self._messages_this_minute = 0
        
        if self._messages_this_minute >= self._queue_size_limit:
            print(f"[DOS PROTECTION] Message limit reached ({self._queue_size_limit}/min) - dropping message")
            return False  # Nachricht verwerfen
        
        self._messages_this_minute += 1
        
        # Nachricht zur Queue hinzufügen
        self._message_queue.append(raw_data)
        
        # Verarbeitung starten falls nicht bereits aktiv
        if not self._processing_queue:
            return self._process_queue()
        return True
    def _process_queue(self):
        """Verarbeitet Nachrichten aus der Queue - kompatibel mit existing SIP methods"""
        self._processing_queue = True
        
        try:
            while self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                # ✅ PRÜFE OB queue_item EIN DICTIONARY IST
                if isinstance(queue_item, dict) and queue_item.get('type') == 'frame_data':
                    frame_data = queue_item['data']
                    
                    try:
                        # NUR UTF-8 SIP Nachrichten
                        try:
                            message = frame_data.decode('utf-8')
                            print(f"[CLIENT] Empfangen: {len(message)} bytes")
                            
                            # Parse mit EXISTIERENDER Methode
                            sip_data = parse_sip_message(message)
                            if not sip_data:
                                print("[CLIENT ERROR] Ungültiges SIP Format")
                                continue
                                
                            # Debug-Ausgabe
                            debug_msg = message[:200] + "..." if len(message) > 200 else message
                            print(f"[CLIENT DEBUG] SIP Nachricht:\n{debug_msg}")
                            
                            # ✅ KORREKTE Header-Prüfung (UPPERCASE)
                            headers = sip_data.get('headers', {})
                            custom_data = sip_data.get('custom_data', {})
                            
                            # PONG Handling
                            if headers.get('PONG') == 'true':
                                print("[PONG] Vom Server empfangen")
                                continue
                                
                            # Identity Challenge Handling - KORRIGIERT
                            if (custom_data.get('MESSAGE_TYPE') == 'IDENTITY_CHALLENGE' or 
                                'IDENTITY_CHALLENGE' in message):
                                print("[IDENTITY] Challenge vom Server empfangen")
                                self._handle_identity_challenge(message)
                                continue
                                
                            # Identity Verification Handling
                            if (custom_data.get('STATUS') == 'IDENTITY_VERIFIED' or 
                                'IDENTITY_VERIFIED' in message):
                                print("[IDENTITY] Verifizierung bestätigt vom Server")
                                self._handle_identity_verified(message)
                                continue
                                
                            # Encrypted Phonebook Handling
                            if 'ENCRYPTED_SECRET' in custom_data and 'ENCRYPTED_PHONEBOOK' in custom_data:
                                print("\n=== PHONEBOOK UPDATE EMPFANGEN ===")
                                self._process_encrypted_phonebook(sip_data)
                                continue
                            # Normale SIP Nachrichten
                            print("[CLIENT] Verarbeite normale SIP Nachricht")
                            self._process_sip_message(sip_data)
                                
                        except UnicodeDecodeError:
                            print(f"[CLIENT ERROR] Kein UTF-8 SIP")
                            continue
                            
                    except Exception as e:
                        print(f"[CLIENT ERROR] Frame processing failed: {str(e)}")
                        import traceback
                        traceback.print_exc()
                
                # ✅ FALLBACK FÜR STRINGS (Identity Challenge erkennen!)
                elif isinstance(queue_item, str):
                    print(f"[CLIENT] Verarbeite String aus Queue: {queue_item[:100]}...")
                    
                    # Identity Challenge erkennen
                    if 'IDENTITY_CHALLENGE' in queue_item:
                        print("[IDENTITY] Challenge vom Server (String-Format) empfangen")
                        self._handle_identity_challenge(queue_item)
                        continue
                        
                    # Identity Verification erkennen
                    elif 'IDENTITY_VERIFIED' in queue_item:
                        print("[IDENTITY] Verifizierung bestätigt (String-Format)")
                        self._handle_identity_verified(queue_item)
                        continue
                        
                    # Versuche es als normale SIP Nachricht zu verarbeiten
                    try:
                        sip_data = parse_sip_message(queue_item)
                        if sip_data:
                            print("[CLIENT] Verarbeite SIP Nachricht aus String-Queue")
                            self._process_sip_message(sip_data)
                        else:
                            print("[CLIENT ERROR] Could not parse string from queue")
                    except Exception as e:
                        print(f"[CLIENT ERROR] Failed to process string from queue: {str(e)}")
                
                # ✅ Andere Dictionary-Typen
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
                            # ✅ INCOMING CALL HANDLING - NEU HINZUGEFÜGT
                elif isinstance(queue_item, (str, bytes, dict)):
                    # Konvertiere zu String für die Analyse
                    if isinstance(queue_item, bytes):
                        try:
                            message_str = queue_item.decode('utf-8')
                        except UnicodeDecodeError:
                            continue
                    elif isinstance(queue_item, dict):
                        # Falls bereits geparst
                        message_str = str(queue_item)
                    else:
                        message_str = queue_item
                    
                    # Prüfe auf eingehende Anrufe (INVITE Nachrichten)
                    if 'INVITE' in message_str and 'ENCRYPTED_SECRET' in message_str:
                        print("[INCOMING CALL] INVITE Nachricht erkannt")
                        
                        try:
                            # Parse die SIP Nachricht
                            sip_data = parse_sip_message(message_str)
                            if sip_data and sip_data.get('method') == 'INVITE':
                                print("[INCOMING CALL] Gültige INVITE Nachricht")
                                self.handle_incoming_call(sip_data)
                                continue
                        except Exception as e:
                            print(f"[INCOMING CALL ERROR] {str(e)}")
                            continue
                # ✅ Unbekanntes Format
                else:
                    print(f"[CLIENT WARN] Unbekanntes Queue-Format: {type(queue_item)}")
                        
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self._processing_queue = False
    def _process_framed_data(self, framed_data):
        """Verarbeitet gerahmte Rohdaten ohne SIP-Header"""
        print("[DEBUG] Processing framed encrypted data")
        
        try:
            # Frame-Header entfernen (falls vorhanden)
            if len(framed_data) > 4 and framed_data[:4] == struct.pack('!I', len(framed_data)-4):
                framed_data = framed_data[4:]
            
            # Mindestlänge überprüfen
            if len(framed_data) < 512:
                print("[ERROR] Framed data too short for encrypted payload")
                return False
                
            return self._decrypt_phonebook(framed_data)
            
        except Exception as e:
            print(f"[ERROR] Frame processing failed: {str(e)}")
            return False
    def _handle_ping_message(self):
        """Handle PING messages by responding with PONG using framing"""
        try:
            if hasattr(self, 'client_socket') and self.client_socket:
                pong_msg = build_sip_message(
                    "MESSAGE",
                    "server",
                    {"PONG": "true"}
                )
                # MIT FRAMING senden
                send_frame(self.client_socket, pong_msg.encode('utf-8'))
                print("[DEBUG] Sent PONG response with framing")
                return True
            return False
        except Exception as e:
            print(f"[ERROR] Failed to send PONG: {str(e)}")
            return False    





                        
    def _decrypt_phonebook(self, encrypted_data):
        """Einheitliche Entschlüsselungsmethode für alle Formate - THREAD SAFE mit extremem Debugging"""
        print("\n" + "="*80)
        print("=== UNIFIED DECRYPT PHONEBOOK DEBUG ===")
        print("="*80)
        
        try:
            # 1. EXTREME INPUT DEBUGGING
            print(f"[DEBUG] Input type: {type(encrypted_data)}")
            print(f"[DEBUG] Input length: {len(encrypted_data) if hasattr(encrypted_data, '__len__') else 'N/A'}")
            
            # 2. HANDLE DIFFERENT INPUT FORMATS
            encrypted_secret = None
            encrypted_phonebook = None
            
            # Format 1: Rohdaten-Bytes (secret + phonebook concatenated)
            if isinstance(encrypted_data, bytes) and len(encrypted_data) > 512:
                print("[DEBUG] Processing raw binary encrypted data")
                encrypted_secret = encrypted_data[:512]
                encrypted_phonebook = encrypted_data[512:]
                
            # Format 2: Dictionary mit separaten Feldern
            elif isinstance(encrypted_data, dict):
                print("[DEBUG] Processing dictionary format")
                required_keys = ['encrypted_secret', 'encrypted_phonebook']
                if all(k in encrypted_data for k in required_keys):
                    try:
                        encrypted_secret = base64.b64decode(encrypted_data['encrypted_secret'])
                        encrypted_phonebook = base64.b64decode(encrypted_data['encrypted_phonebook'])
                    except Exception as e:
                        print(f"[ERROR] Base64 decode failed: {e}")
                        return None
                else:
                    print(f"[ERROR] Missing required keys in dictionary: {list(encrypted_data.keys())}")
                    return None
            
            # Format 3: SIP Message (als Bytes)
            elif isinstance(encrypted_data, bytes):
                print("[DEBUG] Processing SIP message bytes")
                try:
                    sip_msg = parse_sip_message(encrypted_data.decode('utf-8'))
                    if sip_msg and 'custom_data' in sip_msg:
                        custom_data = sip_msg['custom_data']
                        if 'encrypted_secret' in custom_data and 'encrypted_phonebook' in custom_data:
                            encrypted_secret = base64.b64decode(custom_data['encrypted_secret'])
                            encrypted_phonebook = base64.b64decode(custom_data['encrypted_phonebook'])
                except Exception as e:
                    print(f"[DEBUG] SIP parse error: {str(e)}")
                    return None
            
            else:
                print(f"[ERROR] Unsupported input format: {type(encrypted_data)}")
                return None

            # 3. VALIDATION
            print(f"[DEBUG] Secret length: {len(encrypted_secret) if encrypted_secret else 'N/A'} bytes")
            print(f"[DEBUG] Phonebook length: {len(encrypted_phonebook) if encrypted_phonebook else 'N/A'} bytes")
            
            if not encrypted_secret or not encrypted_phonebook:
                print("[ERROR] Missing encrypted data parts")
                return None
                
            if len(encrypted_secret) != 512:
                raise ValueError(f"Invalid secret length: {len(encrypted_secret)} bytes (expected 512)")

            # 4. RSA DECRYPTION
            print("[DEBUG] RSA decrypting secret...")
            private_key = load_privatekey()
            if not private_key or not private_key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
                raise ValueError("Invalid private key format")
                
            priv_key = RSA.load_key_string(private_key.encode())
            decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            secure_del(priv_key)
            
            print(f"[DEBUG] RSA decrypted: {len(decrypted_secret)} bytes")
            print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(decrypted_secret[:32])}")

            # 5. EXTRACT AES COMPONENTS
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
            
            iv = extracted_secret[:16]
            key = extracted_secret[16:48]
            
            print("[DEBUG] AES components:")
            print(f"IV (16 bytes): {binascii.hexlify(iv)}")
            print(f"Key (32 bytes): {binascii.hexlify(key[:8])}...")

            # 6. AES DECRYPTION
            print("[DEBUG] AES decrypting phonebook...")
            print(f"[DEBUG] Encrypted phonebook length: {len(encrypted_phonebook)} bytes")
            
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
            print(f"[DEBUG] First 100 bytes: {decrypted[:100].decode('ascii', errors='replace')}")

            # 7. JSON PARSING
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

            # 8. UI UPDATE - DIREKT UND EINFACH!
            print("[DEBUG] Attempting UI update...")
            
            if hasattr(self, 'update_phonebook') and callable(self.update_phonebook):
                print("[DEBUG] Calling update_phonebook directly")
                try:
                    self.update_phonebook(phonebook_data)
                    print("[DEBUG] update_phonebook called successfully!")
                except Exception as e:
                    print(f"[UI UPDATE ERROR] {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print("[ERROR] update_phonebook method not available")

            print("="*80)
            print("=== DECRYPTION COMPLETED SUCCESSFULLY ===")
            print("="*80)
            
            return phonebook_data
                
        except Exception as e:
            error_msg = f"Entschlüsselung fehlgeschlagen: {str(e)}"
            print(f"[CRITICAL ERROR] {error_msg}")
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)
            import traceback
            traceback.print_exc()
            return None
             
    def _process_sip_message(self, message):
        """Verarbeitet SIP-Nachrichten mit verschlüsselten Daten"""
        sip_data = parse_sip_message(message)
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
    def _process_raw_encrypted_data(self, encrypted_data):
        """Verarbeitet reine verschlüsselte Daten ohne SIP-Header"""
        print("[DEBUG] Processing raw encrypted data")
        
        try:
            # Validierung der Eingangsdaten
            if len(encrypted_data) < 512:
                print("[ERROR] Data too short for encrypted payload")
                return False

            encrypted_secret = encrypted_data[:512]
            encrypted_phonebook = encrypted_data[512:]
            
            print(f"[DECRYPT] Secret part: {len(encrypted_secret)} bytes")
            print(f"[DECRYPT] Phonebook part: {len(encrypted_phonebook)} bytes")

            # Entschlüssele mit privatem Schlüssel
            private_key = load_privatekey()
            priv_key = RSA.load_key_string(private_key.encode())
            decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            if not decrypted_secret:
                raise ValueError("RSA decryption returned empty result")

            # Extrahiere das eigentliche Geheimnis (48 Bytes)
            if not decrypted_secret.startswith(b"+++secret+++"):
                raise ValueError("Invalid secret format - missing overhead")
                
            secret = decrypted_secret[11:59]  # 48 Bytes nach Prefix
            iv = secret[:16]
            aes_key = secret[16:48]
            
            # AES Entschlüsselung
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
            decrypted = cipher.update(encrypted_phonebook) + cipher.final()
            phonebook_data = json.loads(decrypted.decode('utf-8'))
            
            # Aktualisiere UI
            self.update_phonebook(phonebook_data)
            return True
            
        except Exception as e:
            print(f"[DECRYPT ERROR] {str(e)}")
            traceback.print_exc()
            return False
    def start_connection_wrapper(self):
        """Wrapper für Qt-compatible error handling mit erweitertem Debugging"""
        try:
            print(f"\n[CONNECTION] Starting connection to {self.server_ip}:{self.server_port}")
            print(f"[CONNECTION] Client name: {self._client_name}")
            
            # Validate parameters before attempting connection
            if not self.server_ip or not self.server_port:
                error_msg = "Server-IP und Port müssen angegeben werden"
                self.connectionStatusChanged.emit(error_msg)
                return
                
            try:
                port = int(self.server_port)
                if not (0 < port <= 65535):
                    error_msg = "Ungültiger Port (muss zwischen 1-65535 sein)"
                    self.connectionStatusChanged.emit(error_msg)
                    return
            except ValueError:
                error_msg = "Ungültiger Port (muss eine Zahl sein)"
                self.connectionStatusChanged.emit(error_msg)
                return

            # Create new socket if none exists
            if not self.client_socket:
                try:
                    self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.client_socket.settimeout(10)  # 10 second timeout for connection
                except Exception as e:
                    error_msg = f"Socket-Erstellung fehlgeschlagen: {str(e)}"
                    self.connectionStatusChanged.emit(error_msg)
                    return

            # Attempt connection with detailed status reporting
            try:
                print("[CONNECTION] Attempting to connect...")
                self.connectionStatusChanged.emit("Verbinde mit Server...")
                
                success = start_connection(
                    self.server_ip,
                    port,
                    self._client_name,
                    self.client_socket,
                    self  # Pass self as message handler
                )
                
                if success:
                    print("[CONNECTION] Connection established successfully")
                    self.connectionStatusChanged.emit(f"Verbunden mit {self.server_ip}:{port}")
                else:
                    error_msg = "Verbindung fehlgeschlagen (unbekannter Fehler)"
                    print(f"[CONNECTION] {error_msg}")
                    self.connectionStatusChanged.emit(error_msg)
                    
            except socket.timeout:
                error_msg = "Verbindungstimeout - Server nicht erreichbar"
                print(f"[CONNECTION] {error_msg}")
                self.connectionStatusChanged.emit(error_msg)
            except ConnectionRefusedError:
                error_msg = "Verbindung abgelehnt - Server nicht erreichbar oder Port falsch"
                print(f"[CONNECTION] {error_msg}")
                self.connectionStatusChanged.emit(error_msg)
            except socket.gaierror:
                error_msg = "Ungültige Server-Adresse"
                print(f"[CONNECTION] {error_msg}")
                self.connectionStatusChanged.emit(error_msg)
            except Exception as e:
                error_msg = f"Unbekannter Verbindungsfehler: {str(e)}"
                print(f"[CONNECTION] {error_msg}")
                traceback.print_exc()
                self.connectionStatusChanged.emit(error_msg)
                
        except Exception as e:
            error_msg = f"Kritischer Fehler: {str(e)}"
            print(f"[CONNECTION CRITICAL] {error_msg}")
            traceback.print_exc()
            self.connectionStatusChanged.emit(error_msg)
        finally:
            # Cleanup if connection failed
            if not hasattr(self, 'client_socket') or not self.client_socket:
                try:
                    if self.client_socket:
                        self.client_socket.close()
                        self.client_socket = None
                except:
                    pass
    def validate_private_key(private_key_pem):
        try:
            priv_key = RSA.load_key_string(private_key_pem.encode())
            # Test encryption/decryption
            test_msg = b"TEST_MESSAGE"
            encrypted = priv_key.public_encrypt(test_msg, RSA.pkcs1_padding)
            decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
            return decrypted == test_msg
        except Exception as e:
            print(f"Key validation failed: {e}")
            return False
    def check_key_pair(self):
        pubkey = load_publickey()
        privkey = load_privatekey()
        return validate_key_pair(privkey, pubkey)

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
                            return self._decrypt_phonebook(combined)
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
                            return self._decrypt_phonebook(combined)
                        except binascii.Error as e:
                            print(f"[ERROR] Base64 decode failed: {e}")
                
                # Direct processing if no headers found
                if len(encrypted_data) >= 512:
                    print("[DEBUG] Trying direct encrypted phonebook processing")
                    return self._decrypt_phonebook(encrypted_data)
                    
            # 3. Handle dict input
            elif isinstance(encrypted_data, dict):
                if 'ENCRYPTED_SECRET' in encrypted_data and 'ENCRYPTED_PHONEBOOK' in encrypted_data:
                    print("[DEBUG] Found encrypted phonebook in dict")
                    encrypted_secret = base64.b64decode(encrypted_data['ENCRYPTED_SECRET'])
                    encrypted_phonebook = base64.b64decode(encrypted_data['ENCRYPTED_PHONEBOOK'])
                    combined = encrypted_secret + encrypted_phonebook
                    return self._decrypt_phonebook(combined)
                    
            print("[ERROR] No valid encrypted data format detected")
            return False
                
        except Exception as e:
            print(f"[CRITICAL ERROR] {str(e)}")
            # Use simpler error logging to avoid recursion
            import sys
            sys.stderr.write(f"Error processing encrypted phonebook: {str(e)}\n")
            return False

    def update_phonebook(self, phonebook_data):
        """Aktualisiert das Telefonbuch für QML - sendet immer eine Liste"""
        print("\n" + "="*80)
        print("=== UPDATE_PHONEBOOK DEBUG START ===")
        print("="*80)
        
        try:
            # 1. EXTREME INPUT DEBUGGING
            print(f"[DEBUG] Input type: {type(phonebook_data)}")
            print(f"[DEBUG] Input repr: {repr(phonebook_data)[:200]}...")
            
            if hasattr(phonebook_data, '__len__'):
                print(f"[DEBUG] Input length: {len(phonebook_data)}")
            else:
                print("[DEBUG] Input has no length attribute")
            
            # 2. NORMALIZE TO LIST FORMAT FOR QML
            clients_list = []
            
            if isinstance(phonebook_data, dict) and 'clients' in phonebook_data:
                print("[DEBUG] Extracting clients from dictionary")
                clients_list = phonebook_data['clients']
                
            elif isinstance(phonebook_data, list):
                print("[DEBUG] Using data directly as list")
                clients_list = phonebook_data
                
            elif isinstance(phonebook_data, dict):
                print("[DEBUG] Converting dictionary to single-item list")
                clients_list = [phonebook_data]
                
            else:
                error_msg = f"Ungültiges Telefonbuchformat: {type(phonebook_data)}"
                print(f"[ERROR] {error_msg}")
                self._connection_status = error_msg
                self.connectionStatusChanged.emit(self._connection_status)
                return
            
            self.phonebook_entries = clients_list  # oder clients_list.copy() für Sicherheit
            print(f"[DEBUG] Updated self.phonebook_entries: {len(self.phonebook_entries)} entries")
            # 3. VALIDATE CLIENTS LIST
            print(f"[DEBUG] Final clients list type: {type(clients_list)}")
            print(f"[DEBUG] Final clients list length: {len(clients_list)}")
            
            if clients_list:
                print(f"[DEBUG] First client: {clients_list[0]}")
                print(f"[DEBUG] First client type: {type(clients_list[0])}")
                if isinstance(clients_list[0], dict):
                    print(f"[DEBUG] First client keys: {list(clients_list[0].keys())}")

            # 4. DIREKTER UI UPDATE - KEIN TIMER MEHR!
            try:
                print("[UI UPDATE] Emitting clients list to QML DIRECTLY")
                print(f"[UI UPDATE] List length: {len(clients_list)}")
                
                # Send ONLY the clients list to QML
                self.phonebookUpdated.emit(clients_list)
                
                # Status update
                status_msg = f"Telefonbuch aktualisiert ({len(clients_list)} Einträge)"
                print(f"[STATUS] {status_msg}")
                
                self._connection_status = status_msg
                self.connectionStatusChanged.emit(self._connection_status)
                
                print("[UI UPDATE] Signal emitted successfully!")
                
            except Exception as e:
                error_msg = f"UI Update failed: {str(e)}"
                print(f"[ERROR] {error_msg}")
                import traceback
                traceback.print_exc()
                self._connection_status = error_msg
                self.connectionStatusChanged.emit(self._connection_status)

            print("="*80)
            print("=== UPDATE_PHONEBOOK COMPLETED ===")
            print("="*80)

        except Exception as e:
            error_msg = f"KRITISCHER FEHLER in update_phonebook: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)

    def _handle_identity_challenge(self, message):
        """Qt-compatible identity challenge handler"""
        try:
            print("\n" + "="*60)
            print("[IDENTITY] START: Handling identity challenge from server")
            print("="*60)
            
            # 1. Parse SIP message
            print("[DEBUG] Step 1: Parsing SIP message")
            sip_data = parse_sip_message(message)
            if not sip_data:
                print("[IDENTITY ERROR] Invalid SIP message format")
                self._connection_status = "Ungültige Identity Challenge vom Server"
                self.connectionStatusChanged.emit(self._connection_status)
                return False
            
            print(f"[DEBUG] SIP data keys: {list(sip_data.keys())}")
            if 'headers' in sip_data:
                print(f"[DEBUG] Headers: {list(sip_data['headers'].keys())}")
            if 'custom_data' in sip_data:
                print(f"[DEBUG] Custom data keys: {list(sip_data['custom_data'].keys())}")
            
            # 2. Extract challenge data
            print("[DEBUG] Step 2: Extracting challenge data")
            custom_data = sip_data.get('custom_data', {})
            encrypted_challenge_b64 = custom_data.get('ENCRYPTED_CHALLENGE')
            challenge_id = custom_data.get('CHALLENGE_ID')
            
            print(f"[DEBUG] Encrypted challenge present: {encrypted_challenge_b64 is not None}")
            print(f"[DEBUG] Challenge ID present: {challenge_id is not None}")
            print(f"[DEBUG] Challenge ID: {challenge_id}")
            print(f"[DEBUG] Encrypted challenge length: {len(encrypted_challenge_b64) if encrypted_challenge_b64 else 0}")
            
            if not encrypted_challenge_b64 or not challenge_id:
                print("[IDENTITY ERROR] Missing challenge data")
                print(f"[DEBUG] Available custom_data: {custom_data}")
                self._connection_status = "Unvollständige Identity Challenge vom Server"
                self.connectionStatusChanged.emit(self._connection_status)
                return False
            
            # 3. Base64 decode
            print("[DEBUG] Step 3: Base64 decoding challenge")
            try:
                encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
                print(f"[DEBUG] Decoded challenge length: {len(encrypted_challenge)} bytes")
                print(f"[DEBUG] First 16 bytes (hex): {encrypted_challenge[:16].hex()}")
            except Exception as e:
                print(f"[IDENTITY ERROR] Base64 decode failed: {str(e)}")
                self._connection_status = "Fehler beim Decodieren der Challenge"
                self.connectionStatusChanged.emit(self._connection_status)
                return False
            
            # 4. Decrypt with client private key
            print("[DEBUG] Step 4: Decrypting with client private key")
            try:
                private_key = load_privatekey()
                print(f"[DEBUG] Client private key loaded: {len(private_key)} chars")
                print(f"[DEBUG] Private key starts with: {private_key[:50]}...")
                
                priv_key = RSA.load_key_string(private_key.encode())
                decrypted_challenge = priv_key.private_decrypt(
                    encrypted_challenge, 
                    RSA.pkcs1_padding
                )
                challenge = decrypted_challenge.decode('utf-8')
                print(f"[DEBUG] Decrypted challenge: {challenge}")
                print(f"[DEBUG] Decrypted challenge length: {len(challenge)} chars")
                
            except Exception as e:
                print(f"[IDENTITY ERROR] Decryption failed: {str(e)}")
                self._connection_status = "Fehler beim Entschlüsseln der Challenge"
                self.connectionStatusChanged.emit(self._connection_status)
                import traceback
                traceback.print_exc()
                return False
            
            # 5. Create response
            print("[DEBUG] Step 5: Creating response")
            response_data = challenge + "VALIDATED"
            print(f"[DEBUG] Response data: {response_data}")
            print(f"[DEBUG] Response length: {len(response_data)} chars")
            
            # 6. Encrypt response with server public key
            print("[DEBUG] Step 6: Encrypting with server public key")
            try:
                server_pubkey = load_server_publickey()
                print(f"[DEBUG] Server pubkey loaded: {len(server_pubkey)} chars")
                print(f"[DEBUG] Server pubkey starts with: {repr(server_pubkey[:50])}")
                print(f"[DEBUG] Server pubkey ends with: {repr(server_pubkey[-50:])}")
                
                # Ersetze literal \n durch echte Newlines
                if '\\n' in server_pubkey:
                    print("[DEBUG] Found literal \\n in key - replacing with actual newlines")
                    original_pubkey = server_pubkey
                    server_pubkey = server_pubkey.replace('\\n', '\n')
                    print(f"[DEBUG] Fixed key starts with: {repr(server_pubkey[:50])}")
                    print(f"[DEBUG] Fixed key ends with: {repr(server_pubkey[-50:])}")
                
                # Versuche den Key zu laden
                print("[DEBUG] Attempting to load key with BIO...")
                server_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(server_pubkey.encode()))
                print("[DEBUG] Key loaded successfully with BIO")
                
                encrypted_response = server_key.public_encrypt(
                    response_data.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                print(f"[DEBUG] Encrypted response length: {len(encrypted_response)} bytes")
                print(f"[DEBUG] First 16 bytes (hex): {encrypted_response[:16].hex()}")
                
            except Exception as e:
                print(f"[IDENTITY ERROR] Encryption failed: {str(e)}")
                print("[DEBUG] Trying alternative loading method...")
                
                try:
                    # Alternative: Speichere Key temporär und lade von Datei
                    with open("temp_server_key.pem", "w") as f:
                        f.write(server_pubkey)
                    server_key = RSA.load_pub_key("temp_server_key.pem")
                    encrypted_response = server_key.public_encrypt(
                        response_data.encode('utf-8'), 
                        RSA.pkcs1_padding
                    )
                    print("[DEBUG] Encryption successful with file method")
                    os.remove("temp_server_key.pem")
                except Exception as e2:
                    print(f"[IDENTITY ERROR] File method also failed: {str(e2)}")
                    self._connection_status = "Fehler beim Verschlüsseln der Response"
                    self.connectionStatusChanged.emit(self._connection_status)
                    import traceback
                    traceback.print_exc()
                    return False
            
            # 7. Send response back to server
            print("[DEBUG] Step 7: Sending response to server")
            
            # Verwende Dictionary für JSON-Format
            response_payload = {
                "MESSAGE_TYPE": "IDENTITY_RESPONSE",
                "CHALLENGE_ID": challenge_id,
                "ENCRYPTED_RESPONSE": base64.b64encode(encrypted_response).decode('utf-8')
            }
            
            # ERWEITERTES DEBUGGING
            print(f"[DEBUG] Response payload: {response_payload}")
            print(f"[DEBUG] ENCRYPTED_RESPONSE length: {len(response_payload['ENCRYPTED_RESPONSE'])}")
            print(f"[DEBUG] ENCRYPTED_RESPONSE preview: {response_payload['ENCRYPTED_RESPONSE'][:50]}...")
            
            response_msg = build_sip_message(
                "MESSAGE", 
                "server", 
                response_payload  # Als Dictionary für JSON-Format
            )
            
            print(f"[DEBUG] Response message length: {len(response_msg)} chars")
            print(f"[DEBUG] Response message preview: {repr(response_msg[:300])}")
            print(f"[DEBUG] Contains MESSAGE_TYPE: {'MESSAGE_TYPE' in response_msg}")
            print(f"[DEBUG] Contains CHALLENGE_ID: {'CHALLENGE_ID' in response_msg}")
            print(f"[DEBUG] Contains ENCRYPTED_RESPONSE: {'ENCRYPTED_RESPONSE' in response_msg}")
            print(f"[DEBUG] Response payload keys: {list(response_payload.keys())}")
            
            send_frame(self.client_socket, response_msg.encode('utf-8'))
            print("[IDENTITY] Response sent to server successfully!")
            
            self._connection_status = "Identity Challenge erfolgreich beantwortet"
            self.connectionStatusChanged.emit(self._connection_status)
            
            print("="*60)
            print("[IDENTITY] END: Challenge handling completed successfully")
            print("="*60)
            
            return True
            
        except Exception as e:
            error_msg = f"Identity Challenge fehlgeschlagen: {str(e)}"
            print(f"[IDENTITY ERROR] {error_msg}")
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)
            import traceback
            traceback.print_exc()
            
            print("="*60)
            print("[IDENTITY] END: Challenge handling failed")
            print("="*60)
            
            return False

    def _handle_identity_verified(self, message):
        """Verarbeitet Identity Verification Bestätigung vom Server"""
        try:
            print("[IDENTITY] Received verification confirmation from server")
            
            sip_data = parse_sip_message(message)
            if not sip_data:
                print("[IDENTITY ERROR] Invalid SIP message format")
                self._connection_status = "Ungültige Verifizierungsbestätigung"
                self.connectionStatusChanged.emit(self._connection_status)
                return False
            
            custom_data = sip_data.get('custom_data', {})
            status = custom_data.get('STATUS')
            
            if status == 'IDENTITY_VERIFIED':
                print("[IDENTITY] Successfully verified by server!")
                self._connection_status = "Identity erfolgreich verifiziert"
                self.connectionStatusChanged.emit(self._connection_status)
                return True
            else:
                error_msg = f"Verifizierung fehlgeschlagen: {custom_data.get('REASON', 'Unknown error')}"
                print(f"[IDENTITY] {error_msg}")
                self._connection_status = error_msg
                self.connectionStatusChanged.emit(self._connection_status)
                return False
                
        except Exception as e:
            error_msg = f"Verifizierungsverarbeitung fehlgeschlagen: {str(e)}"
            print(f"[IDENTITY ERROR] {error_msg}")
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)
            return False

    def _process_encrypted_phonebook(self, encrypted_data):
        """Process encrypted phonebook data without recursion - Qt compatible"""
        print("\n=== PROCESSING ENCRYPTED PHONEBOOK ===")
        
        try:
            # 1. Validate input
            if not encrypted_data:
                print("[ERROR] Empty encrypted data received")
                self._connection_status = "Keine verschlüsselten Daten empfangen"
                self.connectionStatusChanged.emit(self._connection_status)
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
                            return self._decrypt_phonebook(combined)
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
                            return self._decrypt_phonebook(combined)
                        except binascii.Error as e:
                            print(f"[ERROR] Base64 decode failed: {e}")
                
                # Direct processing if no headers found
                if len(encrypted_data) >= 512:
                    print("[DEBUG] Trying direct encrypted phonebook processing")
                    return self._decrypt_phonebook(encrypted_data)
                    
            # 3. Handle dict input
            elif isinstance(encrypted_data, dict):
                if 'ENCRYPTED_SECRET' in encrypted_data and 'ENCRYPTED_PHONEBOOK' in encrypted_data:
                    print("[DEBUG] Found encrypted phonebook in dict")
                    encrypted_secret = base64.b64decode(encrypted_data['ENCRYPTED_SECRET'])
                    encrypted_phonebook = base64.b64decode(encrypted_data['ENCRYPTED_PHONEBOOK'])
                    combined = encrypted_secret + encrypted_phonebook
                    return self._decrypt_phonebook(combined)
                    
            print("[ERROR] No valid encrypted data format detected")
            self._connection_status = "Ungültiges verschlüsseltes Datenformat"
            self.connectionStatusChanged.emit(self._connection_status)
            return False
                
        except Exception as e:
            error_msg = f"Verarbeitung verschlüsselter Daten fehlgeschlagen: {str(e)}"
            print(f"[CRITICAL ERROR] {error_msg}")
            self._connection_status = error_msg
            self.connectionStatusChanged.emit(self._connection_status)
            # Use simpler error logging to avoid recursion
            import sys
            sys.stderr.write(f"Error processing encrypted phonebook: {str(e)}\n")
            return False


    def _process_sip_framed_phonebook(self, sip_data):
        """Process SIP-framed encrypted phonebook message with multiple format support"""
        print("\n=== PROCESSING SIP FRAMED PHONEBOOK ===")
        
        try:
            # 1. Parse SIP message with improved robustness
            sip_msg = parse_sip_message(sip_data)
            if not sip_msg:
                print("[ERROR] Failed to parse SIP message")
                return False

            # 2. Extract message body with content-length awareness
            body = sip_msg.get('body', '')
            content_length = int(sip_msg.get('headers', {}).get('CONTENT-LENGTH', '0'))
            
            if isinstance(sip_data, bytes):
                # Handle binary SIP messages properly
                header_end = sip_data.find(b'\r\n\r\n')
                if header_end != -1:
                    body = sip_data[header_end+4:header_end+4+content_length]
                else:
                    print("[ERROR] No header-body separator found")
                    return False
            elif not body and content_length > 0:
                print("[ERROR] Content-Length indicates body but none found")
                return False

            # 3. Handle different body formats
            if isinstance(body, bytes):
                try:
                    # Try UTF-8 decode first
                    body_str = body.decode('utf-8')
                    print("[DEBUG] Decoded SIP message body as UTF-8")
                    
                    # Try JSON format
                    try:
                        json_data = json.loads(body_str)
                        if 'ENCRYPTED_SECRET' in json_data and 'ENCRYPTED_PHONEBOOK' in json_data:
                            print("[DEBUG] Found JSON formatted encrypted data")
                            encrypted_secret = base64.b64decode(json_data['ENCRYPTED_SECRET'])
                            encrypted_phonebook = base64.b64decode(json_data['ENCRYPTED_PHONEBOOK'])
                            combined = encrypted_secret + encrypted_phonebook
                            return self._process_encrypted_phonebook(combined)
                    except json.JSONDecodeError:
                        # Fall back to key-value format
                        if b'ENCRYPTED_SECRET:' in body and b'ENCRYPTED_PHONEBOOK:' in body:
                            print("[DEBUG] Found key-value formatted encrypted data")
                            try:
                                body_str = body.decode('utf-8')
                                secret_part = body_str.split('ENCRYPTED_SECRET:')[1].split('\n')[0].strip()
                                phonebook_part = body_str.split('ENCRYPTED_PHONEBOOK:')[1].split('\n')[0].strip()
                                encrypted_secret = base64.b64decode(secret_part)
                                encrypted_phonebook = base64.b64decode(phonebook_part)
                                combined = encrypted_secret + encrypted_phonebook
                                return self._process_encrypted_phonebook(combined)
                            except Exception as e:
                                print("[ERROR] Failed to parse key-value body:", str(e))
                                return False
                except UnicodeDecodeError:
                    # Handle as pure binary data
                    print("[DEBUG] Treating body as binary encrypted data")
                    return self._process_encrypted_phonebook(body)
            
            print("[ERROR] Unsupported SIP message format")
            return False
            
        except Exception as e:
            print("[ERROR] SIP framed processing failed:", str(e))
            traceback.print_exc()
            return False
    
    def _process_binary_phonebook(self, framed_data):
        """Process framed SIP messages with encrypted payload"""
        print("\n=== PROCESSING FRAMED SIP MESSAGE ===")
        print("[FRAME] Length: {} bytes".format(len(framed_data)))
        
        try:
            # Skip frame header if present (first 4 bytes)
            if len(framed_data) > 4 and framed_data[:4] == struct.pack('!I', len(framed_data)-4):
                framed_data = framed_data[4:]
            
            # Try to find SIP message body
            body_start = framed_data.find(b'\r\n\r\n')
            if body_start != -1:
                headers = framed_data[:body_start]
                body = framed_data[body_start+4:]  # Skip \r\n\r\n
                
                print("[DEBUG] Found SIP message with body")
                
                # Try to parse as JSON
                try:
                    message_data = json.loads(body.decode('utf-8'))
                    if "ENCRYPTED_SECRET" in message_data and "ENCRYPTED_PHONEBOOK" in message_data:
                        print("[DEBUG] Found encrypted phonebook in JSON body")
                        encrypted_secret = base64.b64decode(message_data["ENCRYPTED_SECRET"])
                        encrypted_phonebook = base64.b64decode(message_data["ENCRYPTED_PHONEBOOK"])
                        return self._process_encrypted_phonebook(encrypted_secret + encrypted_phonebook)
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
                        return self._process_encrypted_phonebook(encrypted_secret + encrypted_phonebook)
                    except binascii.Error as e:
                        print("[ERROR] Base64 decode failed: {}".format(e))

            
            # Fallback to direct processing if no SIP headers found
            if len(framed_data) >= 512:
                print("[DEBUG] Trying direct encrypted phonebook processing")
                return self._process_encrypted_phonebook(framed_data)
                
            print("[ERROR] No valid message format detected")
            return False
            
        except Exception as e:
            print("[CRITICAL ERROR] {}".format(str(e)))
            traceback.print_exc()
            return False
    

    
    def store_secret_safely(self, secret):
        """Sichert das Geheimnis mit SecureVault"""
        try:
            if not hasattr(self, 'secret_vault') or not self.secret_vault.vault:
                self.secret_vault = SecureVault()
                self.secret_vault.create()
            
            # Konvertiere zu ctypes Buffer
            buf = (ctypes.c_ubyte * 48)(*secret)
            self.secret_vault.store(ctypes.addressof(buf))
        except Exception as e:
            print("Warnung: Geheimnis konnte nicht sicher gespeichert werden: {0}".format(e))
            # Fallback: Temporär in Memory behalten
            self.temp_secret = secret
    def receive_audio_stream(self, key, seed):
        """
        Empfängt verschlüsselte Audiodaten, entschlüsselt sie und gibt sie über die Lautsprecher aus.
        Kompatibel für beide Clients.
        """
        audio = pyaudio.PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS, 
                           rate=RATE, output=True, frames_per_buffer=CHUNK)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Socket für eingehende Verbindungen
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, self.audio_port_in))
            s.listen(1)
            
            print(f"Warte auf Audio-Verbindung auf Port {self.audio_port_in}...")
            conn, addr = s.accept()
            print(f"Audio verbunden mit {addr}")

            try:
                # Empfange IV/Seed (16 Bytes)
                received_seed = conn.recv(16)
                if len(received_seed) != 16:
                    raise ValueError("Ungültiger IV empfangen")

                while self.active_call:
                    # Empfange verschlüsselten Chunk
                    encrypted_chunk = conn.recv(CHUNK + 16)  # Chunk + Padding
                    if not encrypted_chunk:
                        break

                    # Entschlüssele und spiele ab
                    decrypted_chunk = decrypt_audio_chunk(encrypted_chunk, key, received_seed)
                    stream.write(decrypted_chunk)
                    
            except Exception as e:
                print(f"Audio-Empfangsfehler: {e}")
            finally:
                stream.stop_stream()
                stream.close()
                audio.terminate()
                conn.close()            

    def initiate_call(self, recipient):
        """
        Startet einen verschlüsselten Anruf zu einem anderen Client.
        Kompatibel für beide Clients.
        """
        try:
            # 1. Generiere neues 48-Byte Geheimnis
            secret = generate_secret()
            self.current_secret = secret
            
            # 2. Verschlüssele mit Public Key des Empfängers
            recipient_pubkey = RSA.load_pub_key_bio(
                BIO.MemoryBuffer(recipient['public_key'].encode()))
            
            # Mit Overhead verschlüsseln
            secret_with_overhead = b"+++secret+++" + secret
            encrypted_secret = recipient_pubkey.public_encrypt(
                secret_with_overhead, 
                RSA.pkcs1_padding
            )
            
            # 3. Sichere das Geheimnis lokal
            self.secret_vault.store_secret_safely(secret, "call_session")
            
            # 4. Sende INVITE Nachricht
            request = build_sip_message(
                "INVITE",
                recipient['name'],
                {
                    "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode('utf-8'),
                    "CALLER_NAME": self._client_name,
                    "CALLER_IP": socket.gethostbyname(socket.gethostname()),
                    "CALLER_PORT": str(self.audio_port_out)
                }
            )
            self.client_socket.sendall(request.encode('utf-8'))
            
            # 5. Starte Audio-Streams
            iv = secret[:16]
            aes_key = secret[16:]
            
            # Starte Audio-Empfang im Hintergrund
            audio_receive_thread = threading.Thread(
                target=self.receive_audio_stream,
                args=(aes_key, iv),
                daemon=True
            )
            audio_receive_thread.start()
            
            # Kurze Verzögerung, dann Audio senden
            time.sleep(0.5)
            audio_send_thread = threading.Thread(
                target=self.send_audio_stream,
                args=(aes_key, iv, recipient['ip'], int(recipient['port'])),
                daemon=True
            )
            audio_send_thread.start()
            
            # UI aktualisieren
            self.active_call = True
            self.update_call_ui(active=True, caller_name=recipient['name'])
            
            print(f"Anruf an {recipient['name']} initiiert")
            
        except Exception as e:
            print(f"Anruf fehlgeschlagen: {str(e)}")
            self.cleanup_call_resources()
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
    def handle_incoming_call(self, sip_data):
        """
        Verarbeitet eingehende Anrufe.
        Kompatibel für beide Clients.
        """
        if self.active_call:
            # Bereits in einem Anruf - busy senden
            self.send_sip_response(sip_data, "486", "Busy Here")
            return
        
        try:
            custom_data = sip_data.get('custom_data', {})
            
            # 1. Extrahiere und entschlüssele das Geheimnis
            encrypted_secret = base64.b64decode(custom_data['ENCRYPTED_SECRET'])
            
            with open("client_private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
                decrypted = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            # 2. Überprüfe Overhead
            if not decrypted.startswith(b"+++secret+++"):
                raise ValueError("Ungültiges Geheimnisformat")
                
            secret = decrypted[11:59]  # 48 Bytes
            self.current_secret = secret
            self.secret_vault.store_secret_safely(secret, "incoming_call")
            
            # 3. Extrahiere Anrufer-Daten
            caller_ip = custom_data['CALLER_IP']
            caller_port = int(custom_data['CALLER_PORT'])
            caller_name = custom_data['CALLER_NAME']
            
            # 4. Bestätige den Anruf
            self.send_sip_response(sip_data, "200", "OK")
            
            # 5. Starte Audio-Streams
            iv = secret[:16]
            aes_key = secret[16:]
            
            # Audio zum Anrufer senden
            audio_send_thread = threading.Thread(
                target=self.send_audio_stream,
                args=(aes_key, iv, caller_ip, caller_port),
                daemon=True
            )
            audio_send_thread.start()
            
            # Audio vom Anrufer empfangen
            audio_receive_thread = threading.Thread(
                target=self.receive_audio_stream,
                args=(aes_key, iv),
                daemon=True
            )
            audio_receive_thread.start()
            
            # 6. UI aktualisieren
            self.active_call = True
            self.update_call_ui(active=True, caller_name=caller_name)
            
            print(f"Eingehender Anruf von {caller_name} angenommen")
            
        except Exception as e:
            print(f"Anrufannahme fehlgeschlagen: {str(e)}")
            self.send_sip_response(sip_data, "500", "Internal Error")
            self.cleanup_call_resources() 
    def cleanup_call_resources(self):
        """Bereinigt Anruf-Ressourcen"""
        self.active_call = False
        self.current_secret = None
        
        # Secure Vault bereinigen
        if hasattr(self, 'secret_vault'):
            try:
                self.secret_vault.wipe()
            except Exception as e:
                print(f"[CLEANUP WARNING] Vault cleanup failed: {str(e)}")
        
        # UI zurücksetzen
        self.update_call_ui(active=False)
        print("[CLEANUP] Call resources cleaned up")

    def update_call_ui(self, active, caller_name=None):
        """Aktualisiert die UI für den Anrufstatus"""
        self.active_call = active
        
        if active:
            status_text = f"Aktiver Anruf mit: {caller_name}" if caller_name else "Aktiver Anruf"
            print(f"[CALL UI] {status_text}")
        else:
            status_text = "Bereit für Anrufe"
            print("[CALL UI] Anruf beendet")
        
        # Qt Signal emit für UI Update
        self._call_status = status_text
        self.callStatusChanged.emit(self._call_status)
        
        # Optional: Weitere UI Updates hier
        if hasattr(self, 'callStatusChanged'):
            self.callStatusChanged.emit(status_text)                  
    def send_audio_stream(self, key, seed, target_ip, target_port):
        """
        Sendet verschlüsselte Audiodaten an einen Ziel-Client.
        Kompatibel für beide Clients.
        """
        audio = pyaudio.PyAudio()
        stream = audio.open(format=FORMAT, channels=CHANNELS,
                           rate=RATE, input=True, frames_per_buffer=CHUNK)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # Verbinde zum Ziel-Client
                s.connect((target_ip, target_port))
                
                # Sende den IV/Seed zuerst (16 Bytes)
                s.sendall(seed)
                
                print(f"Sende Audio an {target_ip}:{target_port}...")
                
                # Sende Audio-Daten
                while self.active_call:
                    chunk = stream.read(CHUNK)
                    encrypted_chunk = encrypt_audio_chunk(chunk, key, seed)
                    s.sendall(encrypted_chunk)
                    
            except Exception as e:
                print(f"Audio-Sendefehler: {str(e)}")
            finally:
                stream.stop_stream()
                stream.close()
                audio.terminate()
                s.close()           
    def cleanup_connection(self):
        """Cleanup connection resources"""
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
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
    # App muss zuerst erstellt werden
    app = QApplication(sys.argv) if 'QApplication' in globals() else QGuiApplication(sys.argv)
    
    try:
        phonebook = PHONEBOOK()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
