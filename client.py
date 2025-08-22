from access_monitor import SecurityMonitor
import socket
import threading
from M2Crypto import RSA, BIO, EVP, Rand
import hashlib
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
import re  # Für SIP-Header-Parsing
import tkinter as tk
import stun  # pip install pystun3
import struct
import ctypes
import platform
import mmap
import traceback
from typing import Optional, NoReturn, Tuple
import seccomp
from ctypes import CDLL, c_void_p, c_int, c_ubyte, byref, cast, POINTER, create_string_buffer, c_size_t, c_char_p
#fallback für bessere kompatibilität:
try:
    from tkinter import simpledialog
except AttributeError:
    import tkinter as tk
    import tkinter.simpledialog as simpledialog


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
PORT = 5060  # Port für die Übertragung





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
def send_frame(sock, data):
    """Compatible frame sender matching server implementation"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Prepend length header (4 bytes network byte order)
    header = struct.pack('!I', len(data))
    try:
        sock.sendall(header + data)
    except BrokenPipeError:
        raise ConnectionError("Connection broken during send")
    except socket.timeout:
        raise TimeoutError("Send operation timed out")

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

def test_key_pair():
    priv_key = RSA.load_key_string(private_key.encode())
    pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(public_key.encode()))
    
    test_data = b"Test message"
    encrypted = pub_key.public_encrypt(test_data, RSA.pkcs1_padding)
    decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
    
    assert decrypted == test_data, "Key pair mismatch"

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
    return hashlib.sha3_256(data.encode('utf-8')).hexdigest()

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
    # Verwende SHA-3, um eine schlüsselabhängige Padding-Länge zu generieren
    sha3 = hashlib.sha3_256()
    sha3.update(key)  # Der Schlüssel wird als Seed für SHA-3 verwendet
    padding_length = (sha3.digest()[0] % 16) + 1  # Mindestens 1 Byte, maximal 16 Bytes
    padding = bytes([padding_length] * padding_length)
    return padding

# Funktion zum Hinzufügen von dynamischem Padding
def add_dynamic_padding(data, key):
    # Dynamisches Padding generieren
    padding = generate_dynamic_padding(data, key)
    # Daten mit Padding kombinieren
    padded_data = data + padding
    return padded_data


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
def decrypt_audio_chunk(chunk, key, seed):
    # AES-Entschlüsselung mit M2Crypto
    cipher = EVP.Cipher('aes_256_cbc', key=key, iv=seed, op=0)  # op=0 für Entschlüsselung
    decrypted_data = cipher.update(encrypted_data) + cipher.final()
    # Dynamisches Padding entfernen
    original_data = remove_dynamic_padding(decrypted_data, key)
    return original_data


def encrypt_audio_chunk(chunk, key, seed):
    """
    Verschlüsselt einen Audio-Chunk mit AES-256 im CBC-Modus.
    :param chunk: Der Audio-Chunk (Bytes).
    :param key: Der AES-256-Schlüssel (32 Bytes).
    :param iv: Der Initialisierungsvektor (16 Bytes).
    :return: Verschlüsselter Chunk (Bytes).
    """
    chunk = add_dynamic_padding(chunk,key)
    cipher = EVP.Cipher(ENC_METHOD, key=key, iv=seed, op=1)  # op=1 für Verschlüsselung
    encrypted_chunk = cipher.update(chunk) + cipher.final()
    return encrypted_chunk


def load_privatekey():
    with open("private_key.pem", "rb") as privHandle:
        private_key = privHandle.read()
    return private_key.decode('utf-8')
def load_server_publickey():
    """Lädt den öffentlichen Server-Schlüssel aus der Datei"""
    if not os.path.exists("server_public_key.pem"):
        raise FileNotFoundError("Server public key file not found")
    
    with open("server_public_key.pem", "rb") as f:
        return f.read().decode('utf-8')
def send_audio_stream(key,seed):
    """
    Erfasst Audio vom Mikrofon, verschlüsselt es und sendet es über das Netzwerk.
    :param key: Der AES-256-Schlüssel (32 Bytes).
    """
    # Initialisiere PyAudio
    audio = pyaudio.PyAudio()

    # Öffne den Audio-Stream vom Mikrofon
    stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)

    # Erstelle einen Socket für die Netzwerkübertragung..tox
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        #TODO:
        #+++ asymmetrisch mit public key des clients +++ vorgang verstecken - Address Space Layout Randomization (ASLR)
        a_seed = seed# .encrypt
        a_key = key# .encrypt
        # Sende den IV zuerst
        s.sendall('SEED:' + a_seed)
        s.sendall('KEY' + a_key)

        print("Starte Audioübertragung...")

        try:
            while True:
                # Lies einen Audio-Chunk vom Mikrofon
                chunk = stream.read(CHUNK)

                # Verschlüssele den Chunk
                encrypted_chunk = encrypt_audio_chunk(chunk, key, seed)

                # Sende den verschlüsselten Chunk über das Netzwerk
                s.sendall(encrypted_chunk)
        except KeyboardInterrupt:
            print("Audioübertragung beendet.")
        finally:
            # Schliessee den Audio-Stream
            stream.stop_stream()
            stream.close()
            audio.terminate()



def receive_audio_stream(key,seed):
    """
    Empfängt verschlüsselte Audiodaten über das Netzwerk, entschlüsselt sie und gibt sie über die Lautspre>
    :param key: Der AES-256-Schlüssel (32 Bytes).
    """
    # Initialisiere PyAudio
    audio = pyaudio.PyAudio()

    # �^vffne den Audio-Stream für die Wiedergabe
    stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)

    # Erstelle einen Socket für die Netzwerkübertragung
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("Warte auf Verbindung...")
        conn, addr = s.accept()
        print(f"Verbunden mit {addr}")

        # Empfange den IV zuerst
        a_seed = conn.recv(SEED)
        a_key = conn.recv(KEY)
        #TODO:
        # +++ seed +++ key +++ entschlüsseln mit privaten schlüssel +++ vorgang verstecken: Address Space Layout Randomization (ASLR) 
        seed = a_seed# .decrypt mit privatem schlüssel
        key = a_key# decrypt mit privatem schlüssel
        print("Starte Audioempfang...")

        try:
            while True:
                # Empfange einen verschlüsselten Audio-Chunk
                encrypted_chunk = conn.recv(CHUNK + IV_LEN)  # Chunk + Padding
                if not encrypted_chunk:
                    break

                # Entschlüssele den Chunk
                decrypted_chunk = decrypt_audio_chunk(encrypted_chunk, key, seed)

                # Gib den entschlüsselten Chunk über die Lautsprecher aus
                stream.write(decrypted_chunk)
        except KeyboardInterrupt:
            print("Audioempfang beendet.")
        finally:
            # Schliesse den Audio-Stream
            stream.stop_stream()
            stream.close()
            audio.terminate()

@staticmethod
def build_sip_request(method, recipient, client_name, server_ip, server_port):
    """Generiert standardkonforme SIP-Nachrichten mit korrekten Port-Handlings"""
    local_ip = socket.gethostbyname(socket.gethostname())
    
    # Wichtige Änderungen:
    local_port = random.randint(32768, 60999)  # IANA empfohlener ephemeral port range
    call_id = f"{uuid.uuid4()}@{server_ip}"
    branch_id = f"z9hG4bK{random.randint(1000,9999)}"
    tag = random.randint(1000,9999)

    return (
        f"{method} sip:{recipient}@{server_ip}:{server_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};rport;branch={branch_id}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{client_name}@{server_ip}>;tag={tag}\r\n"
        f"To: <sip:{recipient}@{server_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Contact: <sip:{client_name}@{local_ip}:{local_port}>\r\n"
        f"Content-Length: 0\r\n\r\n"
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
            print(f"Fehler beim Senden von Audio: {e}")
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
            print(f"Fehler beim Empfangen von Audio: {e}")
        finally:
            stream.stop_stream()
            stream.close()
            audio.terminate()



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
        self.client_socket = None
        self.server_public_key = None
        self.encrypted_secret = None
        self.aes_iv = None
        self.aes_key = None
        self.title("PHONEBOOK, mein Telefonbuch")
        self.geometry("600x1000")
        self.configure(fg_color='black')
        ctk.set_appearance_mode("dark")
        self.secret_vault = SecureVault()  # Neue Instanz für Geheimnis-Speicherung
        self.current_secret = None  # Aktuelles 48-Byte-Geheimnis für laufende Kommunikation
        # Nur setup_ui aufrufen, nicht beide!
        self.setup_ui()
        self.selected_entry = None
        client_name = load_client_name()
        self._client_name = self.load_client_name()
        self.current_secret = None
        self.active_call = False
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
    def save_client_name(self, name):
        """Speichert den Client-Namen in client_name.txt"""
        try:
            with open("client_name.txt", "w") as file:
                file.write(name)
            self._client_name = name
            return True
        except Exception as e:
            print(f"Fehler beim Speichern des Namens: {e}")
            return False

    def load_client_name(self):
        """Lädt den Client-Namen aus client_name.txt oder gibt leeren String zurück"""
        try:
            if os.path.exists("client_name.txt"):
                with open("client_name.txt", "r") as file:
                    return file.read().strip()
        except Exception as e:
            print(f"Fehler beim Laden des Namens: {e}")
        return ""    
    def _handle_standard_sip(self, sip_data):
        """Verarbeitet reguläre SIP-Nachrichten"""
        # Hier können andere SIP-Nachrichten behandelt werden
        print(f"[CLIENT] Handling standard SIP message: {sip_data}")
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
            print(f"Fehler beim Senden des Geheimnisses: {e}")

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
        buttons = [
            ctk.CTkButton(self.phonebook_tab, text="Update", command=self.load_phonebook),
            ctk.CTkButton(self.phonebook_tab, text="Setup", command=self.create_settings),
            ctk.CTkButton(self.phonebook_tab, text="Hang Up", command=self.on_hangup_click),
            ctk.CTkButton(self.phonebook_tab, text="Call", command=self.on_call_click)
        ]
        
        # Platzierung der Buttons
        for i, button in enumerate(buttons):
            button.place(relx=i/4, rely=0.95, relwidth=0.25, relheight=0.05, anchor='sw')

    def create_settings(self):
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
        self.server_ip_input.pack(side='left', fill="x", expand=True, padx=10)

        # Port Frame
        self.port_frame = ctk.CTkFrame(self.connection_window, fg_color="red")
        self.port_frame.pack(pady=5)

        self.server_port_label = ctk.CTkLabel(self.port_frame, text="Port:")
        self.server_port_label.pack(side='left', fill="x", expand=True, padx=10)

        self.server_port_input = ctk.CTkEntry(self.port_frame)
        self.server_port_input.pack(side='left', fill="x", expand=True, padx=10)

        # Verbinden Button
        self.button_frame = ctk.CTkFrame(self.connection_window, fg_color="grey")
        self.button_frame.pack(pady=40)

        self.connect_button = ctk.CTkButton(self.button_frame, text="Verbinden", command=self.on_connect_click)
        self.connect_button.pack(side='left', fill="x", expand=True, padx=10)

    def cleanup_connection(self):
        """Clean up connection resources"""
        if hasattr(self, 'client_socket') and self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            finally:
                self.client_socket = None
    #threading
    def on_connect_click(self):
        if hasattr(self, 'client_socket') and self.client_socket:
            messagebox.showerror("Fehler", "Bereits verbunden")
            return
    
        server_ip = self.server_ip_input.get()
        server_port = self.server_port_input.get()
    
        try:
            # Validate inputs
            if not server_ip or not server_port:
                raise ValueError("Server-IP und Port müssen angegeben werden")
            
            port = int(server_port)
            if not (0 < port <= 65535):
                raise ValueError("Ungültiger Port")
    
            # Create and connect socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)  # 5 second timeout
            
            try:
                self.client_socket.connect((server_ip, port))
                
                # Store connection info
                self.server_ip = server_ip
                self.server_port = port
                
                # Start connection thread
                threading.Thread(
                    target=self.start_connection_wrapper,
                    daemon=True
                ).start()
                
                self.connection_window.destroy()
    
            except socket.timeout:
                messagebox.showerror("Fehler", "Verbindungstimeout - Server nicht erreichbar")
                self.cleanup_connection()
            except ConnectionRefusedError:
                messagebox.showerror("Fehler", "Verbindung abgelehnt - Server nicht erreichbar oder Port falsch")
                self.cleanup_connection()
            except OSError as e:
                messagebox.showerror("Fehler", f"Netzwerkfehler: {str(e)}")
                self.cleanup_connection()
    
        except ValueError as e:
            messagebox.showerror("Fehler", f"Ungültige Eingabe: {str(e)}")
            self.cleanup_connection()
        except Exception as e:
            messagebox.showerror("Fehler", f"Unerwarteter Fehler: {str(e)}")
            self.cleanup_connection()
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
        """Aktualisiert das Telefonbuch mit vollständiger Fehlerbehandlung
            
        Args:
            phonebook_data: Entschlüsselte Telefonbuchdaten (Liste von Dicts oder JSON-String)
        """
        print("\n=== UPDATING PHONEBOOK ===")
        
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

            # 5. UI aktualisieren
            self.update_phonebook_ui(valid_entries)
            
            # 6. Internen Zustand aktualisieren
            if self.phonebook_entries != valid_entries:
                self.phonebook_entries = valid_entries
            
            print("[SUCCESS] Phonebook updated")

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

    def load_phonebook(self):
        if not self.client_socket:
            messagebox.showerror("Fehler", "Keine Verbindung zum Server!")
            return
        
        try:
            # Anfrage an den Server senden
            request = build_sip_message(
                "GET",
                "server",
                {"REQUEST": "PHONEBOOK"}
            )
            self.client_socket.sendall(request.encode('utf-8'))
            
            # Antwort empfangen
            response = recv_frame(self.client_socket)
            if response:
                phonebook_data = json.loads(response)
                self.update_phonebook(phonebook_data)
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Laden des Telefonbuchs: {e}")

    def on_numpad_click(self, button):
        self.log_text.insert(tk.END, f"Nummernblock gedrückt: {button}\n")


    def on_call_click(self):
        """Handler für den Call-Button"""
        if self.active_call:
            self.end_current_call()
            return
        
        if not self.selected_entry:
            messagebox.showerror("Error", "Please select a contact first")
            return
        
        try:
            recipient = {
                'name': self.selected_entry['name'],
                'public_key': self.selected_entry['public_key'],
                'ip': self.selected_entry['ip'],
                'port': int(self.selected_entry['port'])
            }
            self.initiate_call(recipient)
            self.update_call_ui(active=True)
            
        except KeyError as e:
            messagebox.showerror("Missing Data", f"Contact missing required field: {str(e)}")
        except Exception as e:
            messagebox.showerror("Call Failed", f"Connection error: {str(e)}")
            self.cleanup_call_resources()

    def on_hangup_click(self):
        pass

    def open_keyboard_settings(self):
        messagebox.showinfo("Tastatur", "Tastatureinstellungen (nicht implementiert)")

    def open_language_settings(self):
        messagebox.showinfo("Sprache", "Spracheinstellungen (nicht implementiert)")

     
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
            self.secret_vault.store_secret_safely(secret, "session_key")
            
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
            
            messagebox.showinfo("Anruf", f"Verbunden mit {caller_name}")
            
        except Exception as e:
            print(f"Fehler bei Anrufannahme: {e}")
            if 'CALLER_NAME' in sip_data['custom_data']:
                # Sende Ablehnung
                response = self.build_sip_message(
                    "603 DECLINE",
                    sip_data['custom_data']['CALLER_NAME'],
                    {"STATUS": "REJECTED"}
                )
                self.client_socket.sendall(response.encode('utf-8'))
    def handle_incoming_call(self, sip_data):
        """Eingehenden Anruf bearbeiten"""
        if self.active_call:
            self.send_sip_response(sip_data, "603", "Busy")
            return
        
        try:
            # 1. Entschlüsselung
            encrypted = base64.b64decode(sip_data['custom_data']['ENCRYPTED_SECRET'])
            with open("private_key.pem", "rb") as f:
                decrypted = RSA.load_key_string(f.read()).private_decrypt(encrypted, RSA.pkcs1_padding)
            
            if not decrypted.startswith(b"+++secret+++"):
                raise ValueError("Invalid secret format")
                
            secret = decrypted[11:]
            self.current_secret = secret
            self.secret_vault.store(secret)
            
            # 2. Audio starten
            caller = sip_data['custom_data']
            start_audio_streams(caller['CALLER_IP'], int(caller['CALLER_PORT']), secret[16:], secret[:16])
            
            # 3. Bestätigung senden
            self.send_sip_response(sip_data, "200", "OK")
            self.update_call_ui(active=True, caller_name=caller['CALLER_NAME'])
            
        except Exception as e:
            self.send_sip_response(sip_data, "500", str(e))
            self.cleanup_call_resources()

    def end_current_call(self):
        """Anruf beenden"""
        try:
            stop_audio_streams()
            if self.current_secret:
                self.secret_vault.purge(self.current_secret)
        finally:
            self.cleanup_call_resources()
            self.update_call_ui(active=False)

    def update_call_ui(self, active, caller_name=None):
        """UI-Status aktualisieren"""
        self.active_call = active
        if active:
            self.call_button.configure(
                text=f"End Call ({caller_name if caller_name else 'Outgoing'})",
                fg_color="red"
            )
        else:
            self.call_button.configure(
                text="Call",
                fg_color="green"
            )

    def cleanup_call_resources(self):
        """Ressourcen bereinigen"""
        self.current_secret = None
        self.active_call = False                
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
            self.secret_vault.store_secret_safely(secret, "session_key")
            
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
            
            messagebox.showinfo("Anruf", f"Verbinde mit {recipient['name']}...")
            
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
        """Verarbeitet Nachrichten aus der Queue in der originalen Reihenfolge"""
        self._processing_queue = True
        result = True
        
        try:
            while self._message_queue:
                raw_data = self._message_queue.pop(0)
                
                # ORIGINALE LOGIK - unverändert
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
                        result = self._handle_ping_message()
                        continue
                        
                    # Handle SIP messages
                    if decoded and decoded.startswith(('MESSAGE', 'SIP/2.0')):
                        print("[DEBUG] Processing SIP message")
                        sip_data = parse_sip_message(decoded)
                        if sip_data:
                            # Route to the correct processing method
                            if 'ENCRYPTED_SECRET' in sip_data.get('custom_data', {}):
                                result = self._process_encrypted_phonebook(sip_data)
                                continue
                            result = self._process_sip_message(sip_data)
                            continue
                    
                    # Handle binary/raw encrypted data
                    if isinstance(raw_data, bytes) and len(raw_data) >= 512:
                        print("[DEBUG] Processing raw encrypted data")
                        result = self._process_encrypted_phonebook(raw_data)
                        continue
                        
                    print("[ERROR] No valid message format detected")
                    result = False
                        
                except Exception as e:
                    print(f"[ERROR] Message handling failed: {str(e)}")
                    result = False
                    
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            result = False
        finally:
            self._processing_queue = False
            
        return result

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
                print(encrypted_data)
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
                        secure_del(priv_key) # wipe all traces of private keys
                        # SICHERE Debug-Ausgabe (nur 3 Byte Prefix)
                        print(f"[DEBUG] RSA decrypted: {len(decrypted_secret)} bytes")
                        print(f"[DEBUG] Prefix (hex): {binascii.hexlify(decrypted_secret[:15]).decode()}...")  
                        # Nur 3 Bytes vom secret!
                        # Extract AES components with improved error handling
                        prefix = b"+++secret+++"
                        if prefix not in decrypted_secret:
                            raise ValueError("Secret prefix not found in decrypted data")
                            
                        secret_start = decrypted_secret.find(prefix) + len(prefix)
                        secret = decrypted_secret[secret_start:secret_start+48]
                        secure_del(decrypted_secret) #wipe all secret traces
                        if len(secret) != 48:
                            raise ValueError(f"Invalid secret length: {len(secret)} bytes (expected 48)")
                        self.secret_vault.store_secret_safely(secret, "server_key")
                        secure_del(secret) # wipe all secret traces   
                        iv, key = self.secret_vault.get_secret_parts("server_key")
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
                        secure_del(iv)
                        secure_del(key)
                        secure_del(cipher)
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
            decure_del(priv_key)
            # 5. Padding Check (16 Bytes)
            padding = b"SECURE_v4_2024____"
            if not decrypted.startswith(padding):
                raise ValueError("Invalid padding - possible key mismatch")
                
            # 6. Extrahiere Schlüsselkomponenten
            secret = decrypted[len(padding):len(padding)+48]  # 48 Bytes
            secure_del(decrypted)
            if len(secret) != 48:
                raise ValueError("Invalid secret length")
            self.secret_vault.store_secret_safely(secret, "server_key")
            secure_del(secret) # wipe all secret traces   
            iv, key = self.secret_vault.get_secret_parts("server_key")
            
            # 7. AES Entschlüsselung
            cipher = EVP.Cipher("aes_256_cbc", key, iv, 0)
            decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
            secure_del(iv)
            secure_del(key)
            secure_del(cipher)
            # 8. JSON Parsing
            return json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            print(f"[DECRYPT ERROR] {str(e)}")
            traceback.print_exc()
            raise
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
                secure_del(priv_key)
                print("[DEBUG] Decrypted secret (len={}): {}...".format(
                    len(decrypted_secret),
                    ''.join('{:02x}'.format(b) for b in decrypted_secret[:2])  # Hex conversion without .hex()
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
            secure_del(decrypted_secret)
            self.secret_vault.store_secret_safely(secret, "server_key")
            del secret # wipe all secret traces   
            iv, key = self.secret_vault.get_secret_parts("server_key")
            print("[DEBUG] IV: {}".format(''.join('{:02x}'.format(b) for b in iv)))
            print("[DEBUG] AES Key: {}...".format(''.join('{:02x}'.format(b) for b in aes_key[:8])))
    
            # 5. Entschlüssele das Phonebook
            print("[DEBUG] Decrypting phonebook with AES...")
            try:
                cipher = EVP.Cipher("aes_256_cbc", key, iv, 0)
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
            secure_del(iv)
            secure_del(key)
            secure_del(cipher)
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
                success = start_connection(
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
