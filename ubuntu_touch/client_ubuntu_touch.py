import socket
import threading
from M2Crypto import RSA, BIO, EVP, Rand
import hashlib
import json
import os
import time
import sys
import pyaudio
import uuid
import random
import binascii
from datetime import datetime
import base64
import re
import stun
import struct
import ctypes
import platform
import traceback
import importlib
import wave
import numpy as np
from typing import Optional

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
PORT = 5061  # Port für die Übertragung

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
    """Überprüft die Integrität aller Schlüssel mittels Merkle Tree"""
    print("\n=== CLIENT VERIFICATION ===")
    
    try:
        # Validate inputs
        if not all_keys or not received_root_hash:
            print("[ERROR] Missing keys or Merkle root")
            return False
            
        if not isinstance(all_keys, (list, tuple)):
            print("[ERROR] Keys must be in a list")
            return False
            
        if not isinstance(received_root_hash, str):
            print("[ERROR] Merkle root must be a string")
            return False

        # 1. Deduplizierung und Normalisierung der Schlüssel
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
                print(f"[Client] Added key: {normalized[:30]}...")
        
        if not normalized_keys:
            print("Error: No valid keys after normalization")
            return False

        # 2. Zusammenführung mit Trennzeichen (matches server)
        merged = "|||".join(sorted(normalized_keys))  # Consistent sorting
        print(f"[Client] Merged keys (len={len(merged)}): {merged[:100]}...")

        # 3. Merkle Root berechnen (matches server's method)
        calculated_hash = build_merkle_tree([merged])
        print(f"[Client] Calculated hash: {calculated_hash}")
        print(f"Received hash:   {received_root_hash}")
        
        # 4. Comparison with tolerance for whitespace
        return calculated_hash.strip() == received_root_hash.strip()

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

def generate_secret():
    """
    Erzeuge ein 48-Byte-Geheimnis:
    - Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie.
    - Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festplatten-Entropi e.
    :return: 48-Byte-Geheimnis als Bytes.
    """
    # Erzeuge den Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie
    seed_part1 = os.urandom(8)  # 8 Bytes aus os.urandom
    seed_part2 = get_disk_entropy(8)  # 8 Bytes aus der Festplatten-Entropie
    if not seed_part2:
        raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
    seed = seed_part1 + seed_part2  # 16 Bytes Seed

    # Erzeuge den Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festpla tten-Entropie
    key_part1 = os.urandom(16)  # 16 Bytes aus os.urandom
    key_part2 = get_disk_entropy(16)  # 16 Bytes aus der Festplatten-Entropie
    if not key_part2:
        raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
    key = key_part1 + key_part2  # 32 Bytes Schlüssel

    # Kombiniere Seed und Schlüssel zu einem 48-Byte-Geheimnis
    secret = seed + key  # 16 + 32 = 48 Bytes
    return secret

# Funktion zur Generierung von dynamischem Padding mit SHA-3, quantesicher:

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
def decrypt_phonebook_data(encrypted_data, private_key_pem):
    try:
        # Split into RSA and AES encrypted parts
        encrypted_secret = encrypted_data[:512]
        encrypted_phonebook = encrypted_data[512:]
        
        # RSA Decrypt
        priv_key = RSA.load_key_string(private_key_pem.encode())
        decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
        
        # Extract 48-byte secret
        secret = extract_secret(decrypted_secret)
        iv = secret[:16]
        aes_key = secret[16:48]
        
        # AES Decrypt with explicit padding
        cipher = EVP.Cipher(
            alg="aes_256_cbc",
            key=aes_key,
            iv=iv,
            op=0,  # decrypt
            padding=1  # PKCS#7 padding
        )
        
        # Handle potential padding errors
        try:
            decrypted = cipher.update(encrypted_phonebook) + cipher.final()
            return json.loads(decrypted.decode('utf-8', errors='replace'))
        except EVP.EVPError as e:
            print(f"AES Decrypt Error: {str(e)}")
            # Try without padding as fallback
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0, padding=0)
            decrypted = cipher.update(encrypted_phonebook) + cipher.final()
            return json.loads(decrypted.decode('utf-8', errors='replace'))
            
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        raise

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
def send_audio_stream(key, seed):
    # Audio aus WAV-Datei lesen und senden
    with wave.open(WAV_INPUT, 'rb') as wf:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(seed)  # IV senden
            
            print("Sende WAV-Audio...")
            while True:
                chunk = wf.readframes(CHUNK)
                if not chunk:
                    break  # Ende der Datei
                
                encrypted = encrypt_audio_chunk(chunk, key, seed)
                s.sendall(encrypted)

def receive_audio_stream(key, seed):
    # Empfangene Daten in WAV-Datei schreiben
    with wave.open(WAV_OUTPUT, 'wb') as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(2)  # 16-bit = 2 bytes
        wf.setframerate(RATE)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            iv = conn.recv(IV_LEN)
            
            print("Empfange Audio...")
            while True:
                encrypted = conn.recv(CHUNK + 32)  # Mit Padding
                if not encrypted:
                    break
                
                decrypted = decrypt_audio_chunk(encrypted, key, iv)
                wf.writeframes(decrypted)

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
    """Improved connection loop with proper SIP ping/pong"""
    while True:
        try:
            # Send ping
            ping_msg = (
                f"MESSAGE sip:{server_ip} SIP/2.0\r\n"
                f"From: <sip:{load_client_name()}@{socket.gethostbyname(socket.gethostname())}>\r\n"
                f"To: <sip:{server_ip}>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: 10\r\n\r\n"
                f"PING: true"
            )
            client_socket.sendall(ping_msg.encode('utf-8'))

            # Wait for pong
            client_socket.settimeout(60)
            response = client_socket.recv(4096)
            
            if message_handler:
                message_handler(response)
            else:
                # Default pong handling
                sip_data = parse_sip_message(response)
                if sip_data and sip_data.get('custom_data', {}).get('PONG') == 'true':
                    print("Pong received")

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


#bidirektionale kommunikation
def start_audio_streams(called_client_ip, called_client_port, key, seed):
    # Thread für das Senden von Audio
    send_thread = threading.Thread(target=send_audio_stream, args=(key, seed, called_client_ip, called_client_port))
    send_thread.daemon = True
    send_thread.start()

    # Thread für das Empfangen von Audio
    receive_thread = threading.Thread(target=receive_audio_stream, args=(key, seed))
    receive_thread.daemon = True
    receive_thread.start()

def send_audio_stream(key, seed, target_ip, target_port):
    audio = pyaudio.PyAudio()
    stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((target_ip, target_port))
        s.sendall(seed)  # Sende den IV

        try:
            while True:
                chunk = stream.read(CHUNK)
                encrypted_chunk = encrypt_audio_chunk(chunk, key, seed)
                s.sendall(encrypted_chunk)
        except Exception as e:
            print("Fehler beim Senden von Audio: {}".format(e))
        finally:
            stream.stop_stream()
            stream.close()
            audio.terminate()

def receive_audio_stream(key, seed):
    audio = pyaudio.PyAudio()
    stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        iv = conn.recv(IV_LEN)

        try:
            while True:
                encrypted_chunk = conn.recv(CHUNK + IV_LEN)
                if not encrypted_chunk:
                    break
                decrypted_chunk = decrypt_audio_chunk(encrypted_chunk, key, iv)
                stream.write(decrypted_chunk)
        except Exception as e:
            print("Fehler beim Empfangen von Audio: {}".format(e))
        finally:
            stream.stop_stream()
            stream.close()
            audio.terminate()

class SecureVault:
    def __init__(self):
        self.lib = None
        self.vault = None
        self.gen_lib = None
        self._load_libraries()
        
    def _load_libraries(self):
        """Lädt alle benötigten Bibliotheken für die aktuelle Architektur mit erweiterter ARM64-Erkennung"""
        arch = platform.machine().lower()
        print("[DEBUG] Detected architecture: {}".format(arch))
  # Debug-Ausgabe
    
        # Erweitertes Mapping für ARM-Architekturen
        ARCH_ALIASES = {
            'aarch64': 'arm64',
            'armv8l': 'arm64',
            'armv8b': 'arm64',
            'arm64': 'arm64',
            'armv7l': 'armv7',
            'armv7': 'armv7'
        }
        
        # Normalisiere die Architekturbezeichnung
        normalized_arch = ARCH_ALIASES.get(arch, arch)
        print("[DEBUG] Normalized architecture: {}".format(normalized_arch))
    
        # Bibliotheks-Mapping mit Prioritäten
        LIBRARY_MAP = {
            'arm64': {
                'vault': 'libauslagern_arm64.so',
                'generator': 'libsecuregen_arm64.so',
                'fallback': 'libauslagern_armv7.so'  # Fallback für ARMv7-Kompatibilität
            },
            'armv7': {
                'vault': 'libauslagern_armv7.so',
                'generator': 'libsecuregen_armv7.so'
            },
            'x86_64': {
                'vault': 'libauslagern_x86_64.so',
                'generator': 'libsecuregen_x86_64.so'
            }
        }
    
    def create(self) -> bool:
        """Erstellt einen neuen Vault"""
        if not self.lib:
            return False
        self.vault = self.lib.vault_create()
        return bool(self.vault)
    
    def generate_secret(self):
        """Generiert ein 48-Byte Geheimnis und gibt nur die Speicheradresse zurück"""
        if not self.gen_lib:
            return None
        buf = (ctypes.c_ubyte * 48)()
        self.gen_lib.generate_secret(buf)
        return ctypes.addressof(buf)
    
    def store(self, secret_ptr):
        """Speichert ein Geheimnis (nur über Speicheradresse)"""
        if not self.vault or not secret_ptr:
            return False
        self.lib.vault_load(ctypes.c_void_p(self.vault), ctypes.c_void_p(secret_ptr))
        return True
    
    def retrieve(self):
        """Holt das Geheimnis zurück (gibt nur Speicheradresse zurück)"""
        if not self.vault:
            return None
        buf = (ctypes.c_ubyte * 48)()
        self.lib.vault_retrieve(ctypes.c_void_p(self.vault), ctypes.cast(ctypes.byref(buf), ctypes.POINTER(ctypes.c_ubyte)))
        return ctypes.addressof(buf)
    
    def wipe(self):
        """Löscht den Vault sicher"""
        if self.vault:
            self.lib.vault_wipe(ctypes.c_void_p(self.vault))
            self.vault = None
    
    def __del__(self):
        """Destruktor für sichere Bereinigung"""
        self.wipe()
class PHONEBOOK(QObject):
    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.server_public_key = None
        self.encrypted_secret = None
        self.aes_iv = None
        self.aes_key = None
        self.secret_vault = SecureVault()
        self.secret_vault.create()
        self.current_secret = None
        self.phonebook_entries = []
        self._connection_status = "Nicht verbunden"
        self._call_status = ""
        self._client_name = ""  # Korrektes privates Attribut
        self.client_name = ""   # Öffentliche Property
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

    @Property(list, notify=phonebookUpdated)
    def phonebookEntries(self):
        return self.phonebook_entries

    def _handle_standard_sip(self, sip_data):
        """Verarbeitet reguläre SIP-Nachrichten"""
        # Hier können andere SIP-Nachrichten behandelt werden
        print("[CLIENT] Handling standard SIP message: {}".format(sip_data))
        return True

    def send_client_secret(self):
        """Generiert und sendet das AES-Geheimnis an den Server"""
        try:
            # 1. Generiere 48-Byte Geheimnis (16 IV + 32 AES Key)
            secret = generate_secret()  # Ihre existierende Funktion
            
            # 2. Lade Server Public Key
            server_pubkey = RSA.load_pub_key_bio(
                BIO.MemoryBuffer(self.server_public_key.encode())
            )
            
            # 3. Verschlüssele das Geheimnis mit dem Server Public Key
            encrypted_secret = server_pubkey.public_encrypt(
                secret, 
                RSA.pkcs1_padding
            )
            
            # 4. Sende an Server
            request = self.build_sip_message(
                "MESSAGE",
                "server",
                {
                    "CLIENT_SECRET": base64.b64encode(encrypted_secret).decode('utf-8')
                }
            )
            self.client_socket.sendall(request.encode('utf-8'))
            
            # Speichere das Geheimnis für spätere Entschlüsselung
            self.encrypted_secret = encrypted_secret
            self.aes_iv = secret[:16]
            self.aes_key = secret[16:48]
            
        except Exception as e:
            print("Fehler beim Senden des Geheimnisses: {}".format(e))

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

    def update_phonebook(self, phonebook_data):
        """Aktualisiert das Telefonbuch für QML mit vollständiger Fehlerbehandlung
        
        Args:
            phonebook_data: Entschlüsselte Telefonbuchdaten (Liste von Dicts oder JSON-String)
        """
        print("\n=== UPDATING PHONEBOOK (QML) ===")
        
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
                    client_name = str(entry.get('name', 'Unnamed')).strip() or 'Unnamed'
                    client_ip = str(entry.get('ip', ''))
                    client_port = str(entry.get('port', ''))
                    public_key = str(entry.get('public_key', ''))
                    
                    # QML-kompatibles Dict erstellen
                    qml_entry = {
                        'id': client_id,
                        'name': client_name,
                        'ip': client_ip,
                        'port': client_port,
                        'publicKey': public_key,
                        'publicKeyShort': public_key[:20] + '...' if public_key else '',
                        'callable': bool(client_ip and client_port)
                    }
                    
                    valid_entries.append(qml_entry)
                    
                    print(f"[DEBUG] Added entry: {client_id} - {client_name}")
                    
                except Exception as e:
                    print(f"[WARNING] Invalid entry skipped: {str(e)}")
                    traceback.print_exc()
                    continue

            # 4. Debug-Ausgabe
            print(f"[DEBUG] Processed {len(valid_entries)} valid entries")
            if valid_entries:
                print("[DEBUG] First entry sample:", valid_entries[0])

            # 5. Update internal state without triggering signals
            if self.phonebook_entries != valid_entries:
                self.phonebook_entries = valid_entries
                self.phonebookUpdated.emit(valid_entries)
            
            # 6. Optional: Logging für erfolgreiche Aktualisierung
            print("[SUCCESS] Phonebook updated for QML")

        except Exception as e:
            error_msg = f"Critical phonebook update error: {str(e)}"
            print(error_msg)
            traceback.print_exc()
            
            # Fehler an QML melden
            if hasattr(self, 'show_error'):
                self.show_error(error_msg)

    @Slot(int)
    def on_entry_click(self, index):
        if 0 <= index < len(self.phonebook_entries):
            entry = self.phonebook_entries[index]
            print("Selected entry: {}: {}".format(entry['id'], entry['name']))
            self.initiate_call(entry)

    @Slot()
    def on_call_click(self):
        secret = generate_secret()
        seed = secret[:16]
        key = secret[16:]
        
        try:
            send_audio_stream(key, seed)
            receive_audio_stream(key, seed)
            self._call_status = "Anruf gestartet"
            self.callStatusChanged.emit(self._call_status)
        except Exception as e:
            self._call_status = "Anruf fehlgeschlagen: {}".format(e)
            self.callStatusChanged.emit(self._call_status)

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
    def handle_incoming_call(self, sip_data):
        """Verarbeitet eingehende Anrufe"""
        try:
            # 1. Extrahiere verschlüsseltes Geheimnis
            encrypted_secret = base64.b64decode(sip_data['custom_data']['ENCRYPTED_SECRET'])
            
            # 2. Entschlüssele mit eigenem privaten Schlüssel
            with open("private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
            
            decrypted = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            # 3. Überprüfe Overhead
            if not decrypted.startswith(b"+++secret+++"):
                raise ValueError("Ungültiges Geheimnis - Falscher Overhead")
                
            secret = decrypted[11:]  # 11 Bytes Overhead entfernen
            self.current_secret = secret
            self.secret_vault.store(secret)
            
            # 4. Extrahiere Anrufer-Daten
            caller_ip = sip_data['custom_data']['CALLER_IP']
            caller_port = int(sip_data['custom_data']['CALLER_PORT'])
            caller_name = sip_data['custom_data']['CALLER_NAME']
            
            # 5. Bestätige den Anruf
            response = self.build_sip_message(
                "200 OK",
                caller_name,
                {"STATUS": "ACCEPTED"}
            )
            self.client_socket.sendall(response.encode('utf-8'))
            
            # 6. Starte Audio-Streams
            iv = secret[:16]
            aes_key = secret[16:]
            start_audio_streams(caller_ip, caller_port, aes_key, iv)
            
            messagebox.showinfo("Anruf", "Verbunden mit {}".format(caller_name))

            
        except Exception as e:
            print("Fehler bei Anrufannahme: {}".format(e))
            if 'CALLER_NAME' in sip_data['custom_data']:
                # Sende Ablehnung
                response = self.build_sip_message(
                    "603 DECLINE",
                    sip_data['custom_data']['CALLER_NAME'],
                    {"STATUS": "REJECTED"}
                )
                self.client_socket.sendall(response.encode('utf-8'))
    def initiate_call(self, recipient):
        """Startet einen verschlüsselten Anruf zu einem anderen Client"""
        try:
            # 1. Generiere neues 48-Byte Geheimnis
            secret = generate_secret()  # Ihre existierende Funktion
            self.current_secret = secret
            
            # 2. Verschlüssele mit Public Key des Empfängers
            recipient_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(recipient['public_key'].encode()))
            
            # Mit Overhead verschlüsseln
            secret_with_overhead = b"+++secret+++" + secret
            encrypted_secret = recipient_pubkey.public_encrypt(
                secret_with_overhead, 
                RSA.pkcs1_padding
            )
            
            # 3. Sichere das Geheimnis lokal
            self.secret_vault.store(secret)
            
            # 4. Sende INVITE Nachricht
            request = self.build_sip_message(
                "INVITE",
                recipient['name'],
                {
                    "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode('utf-8'),
                    "CALLER_NAME": load_client_name(),
                    "CALLER_IP": socket.gethostbyname(socket.gethostname()),
                    "CALLER_PORT": str(PORT)  # Globaler Audio-Port
                }
            )
            self.client_socket.sendall(request.encode('utf-8'))
            
            # 5. Starte Audio-Streams
            iv = secret[:16]
            aes_key = secret[16:]
            start_audio_streams(recipient['ip'], recipient['port'], aes_key, iv)
            
            messagebox.showinfo("Anruf", "Verbinde mit {}...".format(recipient['name']))

            
        except Exception as e:
            messagebox.showerror("Anruf fehlgeschlagen", str(e))
            self.current_secret = None
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
        
        try:
            # Try to decode as UTF-8
            try:
                decoded = raw_data.decode('utf-8') if isinstance(raw_data, bytes) else str(raw_data)
            except UnicodeDecodeError:
                decoded = None
                print("[DEBUG] Message is not UTF-8, treating as binary")

            # Handle PING messages
            if decoded and "PING: true" in decoded:
                print("[DEBUG] Processing PING message")
                return self._handle_ping_message()
                
            # Handle SIP messages
            if decoded and decoded.startswith(('MESSAGE', 'SIP/2.0')):
                print("[DEBUG] Processing SIP message")
                sip_data = parse_sip_message(decoded)
                if sip_data:
                    # Route to the correct processing method
                    if 'ENCRYPTED_SECRET' in sip_data.get('custom_data', {}):
                        return self._process_encrypted_phonebook(sip_data)
                    return self._process_sip_message(sip_data)
            
            # Handle binary/raw encrypted data
            if isinstance(raw_data, bytes) and len(raw_data) >= 512:
                print("[DEBUG] Processing raw encrypted data")
                return self._process_encrypted_phonebook(raw_data)
                
            print("[ERROR] No valid message format detected")
            return False
                
        except Exception as e:
            print(f"[ERROR] Message handling failed: {str(e)}")
            return False
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
        """Handle PING messages by responding with PONG"""
        try:
            if hasattr(self, 'client_socket') and self.client_socket:
                pong_msg = build_sip_message(
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
    def _decrypt_phonebook_data(self, encrypted_data):
        """Main method for decrypting phonebook data with enhanced error handling"""
        print("\n=== DECRYPT PHONEBOOK DEBUG ===")
        
        try:
            # Debug input
            print(f"[DEBUG] Initial input type: {type(encrypted_data)}")
            
            # Parse SIP message if needed
            if isinstance(encrypted_data, bytes):
                try:
                    sip_msg = parse_sip_message(encrypted_data.decode('utf-8'))
                    if sip_msg and 'custom_data' in sip_msg:
                        print("[DEBUG] Extracted custom_data from SIP")
                        encrypted_data = sip_msg['custom_data']
                        print(f"[DEBUG] Custom data keys: {list(encrypted_data.keys())}")
                except Exception as e:
                    print(f"[DEBUG] SIP parse error: {str(e)}")

            # Process dictionary with encrypted parts
            if isinstance(encrypted_data, dict):
                print("[DEBUG] Processing encrypted dictionary")
                required_keys = ['encrypted_secret', 'encrypted_phonebook']
                if all(k in encrypted_data for k in required_keys):
                    try:
                        # Base64 decode with validation
                        secret = base64.b64decode(encrypted_data['encrypted_secret'])
                        phonebook = base64.b64decode(encrypted_data['encrypted_phonebook'])
                        print(f"[DEBUG] Decoded secret: {len(secret)} bytes (expected: 512)")
                        print(f"[DEBUG] Decoded phonebook: {len(phonebook)} bytes (expected: >=1040)")

                        if len(secret) != 512:
                            raise ValueError("Invalid secret length after base64 decode")

                        # RSA decrypt
                        private_key = load_privatekey()
                        if not private_key or not private_key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
                            raise ValueError("Invalid private key format")
                            
                        priv_key = RSA.load_key_string(private_key.encode())
                        decrypted_secret = priv_key.private_decrypt(secret, RSA.pkcs1_padding)
                        print(f"[DEBUG] RSA decrypted: {len(decrypted_secret)} bytes")
                        print(f"[DEBUG] First 32 bytes (hex): {binascii.hexlify(decrypted_secret[:32])}")

                        # Extract AES components with improved error handling
                        prefix = b"+++secret+++"
                        if prefix not in decrypted_secret:
                            raise ValueError("Secret prefix not found in decrypted data")
                            
                        secret_start = decrypted_secret.find(prefix) + len(prefix)
                        secret = decrypted_secret[secret_start:secret_start+48]
                        
                        if len(secret) != 48:
                            raise ValueError(f"Invalid secret length: {len(secret)} bytes (expected 48)")
                            
                        iv = secret[:16]
                        key = secret[16:48]
                        print("[DEBUG] AES components:")
                        print(f"IV (16 bytes): {binascii.hexlify(iv)}")
                        print(f"Key (32 bytes): {binascii.hexlify(key[:8])}...")

                        # AES decrypt with padding fallback
                        try:
                            cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=1)
                            decrypted = cipher.update(phonebook) + cipher.final()
                        except EVP.EVPError as e:
                            print(f"[WARNING] AES decrypt failed with padding, trying without: {str(e)}")
                            cipher = EVP.Cipher("aes_256_cbc", key, iv, 0, padding=0)
                            decrypted = cipher.update(phonebook) + cipher.final()

                        print(f"[DEBUG] Decrypted data length: {len(decrypted)} bytes")
                        print(f"[DEBUG] First 100 bytes (ascii): {decrypted[:100].decode('ascii', errors='replace')}")

                        # Parse JSON with validation
                        phonebook_data = json.loads(decrypted.decode('utf-8'))
                        if not isinstance(phonebook_data, dict):
                            raise ValueError("Decrypted data is not a valid JSON object")
                            
                        print(f"[DEBUG] Phonebook entries: {len(phonebook_data.get('clients', []))}")

                        # UI Update with thread safety
                        if hasattr(self, 'update_phonebook'):
                            self.update_phonebook(phonebook_data)
                            print("[DEBUG] UI update scheduled")
                        else:
                            print("[WARNING] update_phonebook method missing")
                        
                        return phonebook_data
                        
                    except Exception as e:
                        print(f"[DECRYPT ERROR] {str(e)}")
                        traceback.print_exc()
                        return None

            print("[ERROR] No valid encrypted data format detected")
            return None

        except Exception as e:
            print(f"[CRITICAL ERROR] {str(e)}")
            traceback.print_exc()
            return None                        
    def _decrypt_phonebook(self, encrypted_data):
        """Robuste Entschlüsselung mit korrekter Bytes/String-Handling"""
        try:
            # 1. Konvertiere Eingangsdaten falls nötig
            if isinstance(encrypted_data, bytes):
                try:
                    encrypted_data = encrypted_data.decode('utf-8')
                    encrypted_data = json.loads(encrypted_data)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ValueError("Invalid message format - expected JSON")

            # 2. Validierung der Felder
            if not isinstance(encrypted_data, dict):
                raise ValueError("Expected dictionary data")
                
            required_fields = ['ENCRYPTED_SECRET', 'ENCRYPTED_PHONEBOOK']
            if not all(field in encrypted_data for field in required_fields):
                raise ValueError(f"Missing required fields: {required_fields}")

            # 3. Base64 Decoding
            encrypted_secret = base64.b64decode(encrypted_data['ENCRYPTED_SECRET'])
            encrypted_phonebook = base64.b64decode(encrypted_data['ENCRYPTED_PHONEBOOK'])

            # 4. RSA Entschlüsselung
            priv_key = RSA.load_key_string(self.private_key.encode())
            decrypted = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            
            # 5. Padding Check (16 Bytes)
            padding = b"SECURE_v4_2024____"
            if not decrypted.startswith(padding):
                raise ValueError("Invalid padding - possible key mismatch")
                
            # 6. Extrahiere Schlüsselkomponenten
            secret = decrypted[len(padding):len(padding)+48]  # 48 Bytes
            if len(secret) != 48:
                raise ValueError("Invalid secret length")
                
            iv = secret[:16]
            aes_key = secret[16:48]
            
            # 7. AES Entschlüsselung
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
            decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
            
            # 8. JSON Parsing
            return json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            print(f"[DECRYPT ERROR] {str(e)}")
            traceback.print_exc()
            raise
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
    
    def _process_phonebook_update(self, message):
        """Verarbeitet Phonebook-Updates mit vollständiger Entschlüsselung und ausführlichem Debugging"""
        print("\n=== CLIENT PHONEBOOK UPDATE PROCESSING ===")
        
        try:
            # 1. Validierung der Eingangsdaten
            print("[DEBUG] Validating input message...")
            if not isinstance(message, dict):
                print("[ERROR] Invalid message format - not a dictionary")
                return False
    
            # 2. Extrahiere verschlüsselte Daten
            print("[DEBUG] Extracting encrypted data from message...")
            try:
                encrypted_secret = base64.b64decode(message['ENCRYPTED_SECRET'])
                encrypted_phonebook = base64.b64decode(message['ENCRYPTED_PHONEBOOK'])
                print("[DEBUG] Encrypted secret length: {}".format(len(encrypted_secret)))
                print("[DEBUG] Encrypted phonebook length: {}".format(len(encrypted_phonebook)))
            except KeyError as e:
                print("[ERROR] Missing required field: {}".format(str(e)))
                return False
            except binascii.Error as e:
                print("[ERROR] Base64 decoding failed: {}".format(str(e)))
                return False
    
            # 3. Entschlüssele das Geheimnis
            print("[DEBUG] Decrypting secret with private key...")
            try:
                with open("private_key.pem", "rb") as f:
                    priv_key = RSA.load_key_string(f.read())
                    print("[DEBUG] Private key loaded successfully")
                    
                decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
                print("[DEBUG] Decrypted secret (len={}): {}...".format(
                    len(decrypted_secret),
                    ''.join('{:02x}'.format(b) for b in decrypted_secret[:16])  # Hex conversion without .hex()
                ))            
            except Exception as e:
                print("[ERROR] Failed to decrypt secret: {}".format(str(e)))
                return False
    
            # 4. Validiere das Geheimnis
            print("[DEBUG] Validating decrypted secret...")
            if not decrypted_secret.startswith(b"+++secret+++"):
                print("[ERROR] Invalid secret format - missing overhead")
                return False
                
            secret = decrypted_secret[11:59]  # 48 Bytes
            iv = secret[:16]
            aes_key = secret[16:]
            print("[DEBUG] IV: {}".format(''.join('{:02x}'.format(b) for b in iv)))
            print("[DEBUG] AES Key: {}...".format(''.join('{:02x}'.format(b) for b in aes_key[:8])))
    
            # 5. Entschlüssele das Phonebook
            print("[DEBUG] Decrypting phonebook with AES...")
            try:
                cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
                decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
                
                print("[DEBUG] Decrypted data (len={}): {}...".format(
                    len(decrypted_data),
                    decrypted_data[:100].decode('utf-8', errors='replace')
                ))
            except EVP.EVPError as e:
                error_msg = "AES decryption failed: {}".format(str(e))
                print("[ERROR] {}".format(error_msg))
                logging.error(error_msg, exc_info=True)
                return False
            except Exception as e:
                error_msg = "Unexpected error during decryption: {}".format(str(e))
                print("[CRITICAL] {}".format(error_msg))
                logging.critical(error_msg, exc_info=True)
                return False
    
            # 6. Parse JSON-Daten
            print("[DEBUG] Parsing decrypted JSON data...")
            try:
                phonebook_data = json.loads(decrypted_data.decode('utf-8'))
                print("[DEBUG] Raw phonebook data: {}".format(phonebook_data))
            except json.JSONDecodeError as e:
                print("[ERROR] JSON decode failed: {}".format(str(e)))
                # Safe debug output for potentially sensitive data
                print("[DEBUG] Problematic data ({} bytes): {}".format(
                    len(decrypted_data),
                    repr(decrypted_data[:200].decode('utf-8', errors='replace'))
                ))
                return False
    
            # 7. Filtere gültige Einträge
            print("[DEBUG] Validating phonebook entries...")
            valid_entries = []
            for entry in phonebook_data:
                try:
                    if (isinstance(entry, dict) and 
                        str(entry.get('id', '')).isdigit() and 
                        entry.get('name')):
                        print("[DEBUG] Valid entry found: {}: {}".format(
                            entry['id'],
                            entry['name']
                        ))
                        valid_entries.append(entry)
                except Exception as e:
                    print("[WARNING] Invalid entry skipped: {}".format(str(e)))
    
            # 8. Aktualisiere UI
            if valid_entries:
                print("[DEBUG] Updating UI with {} valid entries".format(len(valid_entries)))
                self.phonebook_update_signal.emit(phonebook_data.get('clients', []))
                return True
            else:
                print("[ERROR] No valid entries found in phonebook")
                return False
                
        except Exception as e:
            print("[CRITICAL] Processing error: {}".format(str(e)))
            traceback.print_exc()
            return False
        finally:
            print("=== CLIENT PHONEBOOK UPDATE PROCESSING END ===")
    
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


def main():
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
