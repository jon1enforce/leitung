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
    """Lädt den privaten Schlüssel - konsistent mit generate_keys()"""
    if not os.path.exists("client_private_key.pem"):
        # Generiere neuen RSA-Schlüssel
        bits = 4096
        new_key = RSA.gen_key(bits, 65537)

        # Speichere den privaten Schlüssel im PKCS#8 Format (konsistent mit generate_keys)
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
            
        return public_key_pem
        
    else:
        # Lade den privaten Schlüssel
        with open("client_private_key.pem", "rb") as f:
            private_key_data = f.read()
        
        # Validiere dass es ein privater Schlüssel ist (akzeptiere beide Formate)
        private_key_str = private_key_data.decode('utf-8')
        if not ('-----BEGIN PRIVATE KEY-----' in private_key_str):
            raise ValueError("Invalid private key format in file")
        
        return private_key_data.decode('utf-8')
def load_server_publickey():
    """Lädt den öffentlichen Server-Schlüssel aus der Datei"""
    if not os.path.exists("server_public_key.pem"):
        raise FileNotFoundError("Server public key file not found")
    
    with open("server_public_key.pem", "rb") as f:
        return f.read().decode('utf-8')






@staticmethod
def build_sip_request(method, recipient, client_name, server_ip, server_port):
    """Generiert standardkonforme SIP-Nachrichten mit korrekten Port-Handlings"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"  # Fallback
    
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
    """Erweitere SIP-Nachrichtenerstellung mit JSON-Unterstützung (standalone Version)"""
    # Entscheide ob Body JSON oder Key-Value sein soll
    if any(isinstance(v, (dict, list)) for v in custom_data.values()):
        body = json.dumps(custom_data, separators=(',', ':'))
        content_type = "application/json"
    else:
        body = "\r\n".join("{}: {}".format(k, v) for k, v in custom_data.items())
        content_type = "text/plain"
    
    # Absenderadresse bestimmen - FIXED VERSION
    if from_server:
        from_header = "<sip:server@{}>".format(host) if host else "<sip:server>"
        client_ip = host if host else "127.0.0.1"
    else:
        client_name = load_client_name()
        # Use a more reliable method to get local IP
        try:
            # Method 1: Connect to a known external service
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google DNS
            client_ip = s.getsockname()[0]
            s.close()
        except:
            try:
                # Method 2: Use hostname lookup
                client_ip = socket.gethostbyname(socket.gethostname())
            except:
                # Method 3: Fallback to localhost
                client_ip = "127.0.0.1"
        
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
    global connected
    connected = True
    print("[SETUP] connected = True")
    
    # Lokale IP ermitteln (korrigierte Version für OpenBSD)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_ip, 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"[DEBUG] Local IP for ping: {local_ip}")
    except Exception as ip_error:
        print(f"[WARNING] Could not determine local IP for ping: {ip_error}")
        local_ip = "127.0.0.1"  # Fallback
    
    client_name = load_client_name()
    
    while True:
        try:
            # Build ping message with corrected local IP
            ping_msg = (
                f"MESSAGE sip:{server_ip} SIP/2.0\r\n"
                f"From: <sip:{client_name}@{local_ip}>\r\n"  # KORRIGIERT
                f"To: <sip:{server_ip}>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: 10\r\n\r\n"
                f"PING: true"
            )
            
            # Send ping MIT FRAMING (KEIN FALLBACK!)
            send_frame(client_socket, ping_msg.encode('utf-8'))
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
        custom_data = sip_data['custom_data']
        if 'SERVER_PUBLIC_KEY' in custom_data:
            key = custom_data['SERVER_PUBLIC_KEY']
            # Remove any prefix like "SERVER_PUBLIC_KEY: "
            if ':' in key:
                key = key.split(':', 1)[1].strip()
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
                key = raw_response[key_start:key_end]
                # Remove any prefix if present
                if 'SERVER_PUBLIC_KEY:' in key:
                    key = key.replace('SERVER_PUBLIC_KEY:', '').strip()
                return key
    
    # Variante 3: Aus Header-Zeilen
    if isinstance(sip_data, dict) and sip_data.get('headers'):
        for header in sip_data['headers'].values():
            if '-----BEGIN PUBLIC KEY-----' in header:
                key_start = header.find('-----BEGIN PUBLIC KEY-----')
                key_end = header.find('-----END PUBLIC KEY-----', key_start)
                if key_end != -1:
                    key_end += len('-----END PUBLIC KEY-----')
                    key = header[key_start:key_end]
                    if 'SERVER_PUBLIC_KEY:' in key:
                        key = key.replace('SERVER_PUBLIC_KEY:', '').strip()
                    return key
    
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
        try:
            # Methode 1: Direkte Socket-Methode
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((server_ip, 80))  # Verbindung zu einem beliebigen Port
            local_ip = s.getsockname()[0]
            s.close()
        except:
            try:
                # Methode 2: Hostname-Lookup mit Fallback
                local_ip = socket.gethostbyname(socket.gethostname())
            except:
                # Methode 3: Localhost als Fallback
                local_ip = "127.0.0.1"
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




class WireGuardManager:
    def __init__(self):
        self.interface_name = "wg-phonebook"
        self.config_path = f"/etc/wireguard/{self.interface_name}.conf"
        self.debug_log = []
        self.peer_public_key = None
        self.my_private_key = None
        self.my_public_key = None

    def _log_debug(self, message):
        """Log debug messages"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        debug_message = f"[{timestamp}] {message}"
        self.debug_log.append(debug_message)
        print(debug_message)
        
    def generate_keypair(self):
        """Generiert ein WireGuard Schlüsselpaar"""
        try:
            # Private Key generieren
            private_key = subprocess.run(
                ["wg", "genkey"],
                capture_output=True, text=True, check=True
            ).stdout.strip()
            
            # Public Key aus Private Key ableiten
            public_key = subprocess.run(
                ["wg", "pubkey"],
                input=private_key, capture_output=True, text=True, check=True
            ).stdout.strip()
            
            self.my_private_key = private_key
            self.my_public_key = public_key
            
            return private_key, public_key
            
        except Exception as e:
            self._log_debug(f"Key generation failed: {e}")
            raise
    
    def create_interface_config(self, private_key, peer_public_key, peer_endpoint, my_ip):
        """Erstellt eine WireGuard Konfiguration"""
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {my_ip}/24
ListenPort = 51820

[Peer]
PublicKey = {peer_public_key}
AllowedIPs = 10.8.0.0/24
Endpoint = {peer_endpoint}
PersistentKeepalive = 25
"""
        return config
    
    def setup_wireguard_tunnel(self, config):
        """Richtet den WireGuard Tunnel ein"""
        try:
            # Konfiguration speichern
            with open(self.config_path, 'w') as f:
                f.write(config)
            
            # Interface starten
            result = subprocess.run(
                ["wg-quick", "up", self.config_path],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"WireGuard start failed: {result.stderr}")
            
            return True
            
        except Exception as e:
            self._log_debug(f"WireGuard setup failed: {e}")
            raise
    
    def get_wireguard_ip(self):
        """Ermittelt die WireGuard IP des Interfaces"""
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "dev", self.interface_name],
                capture_output=True, text=True, check=True
            )
            
            # Extrahiere die IP-Adresse aus der Ausgabe
            lines = result.stdout.split('\n')
            for line in lines:
                if 'inet ' in line:
                    ip = line.split()[1].split('/')[0]
                    return ip
            
            return None
            
        except Exception as e:
            self._log_debug(f"Failed to get WireGuard IP: {e}")
            return None

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

class PHONEBOOK(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Vorhandene Initialisierung...
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
        self.setup_ui()
        self.selected_entry = None
        client_name = load_client_name()
        self._client_name = self.load_client_name()
        self.current_secret = None
        self.active_call = False
        self.server_ip = "127.0.0.1"
        self._message_queue = []
        self._processing_queue = False
        self._queue_size_limit = 120
        self._last_minute_check = time.time()
        self._messages_this_minute = 0
        # WireGuard Integration
        self.wg_manager = WireGuardManager()
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
            ctk.CTkButton(self.phonebook_tab, text="Update", command=self.on_update_click),
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
        self.server_ip_input.insert(0, "sichereleitung.duckdns.org")  # ✅ Default Domain
        self.server_ip_input.pack(side='left', fill="x", expand=True, padx=10)

        # Port Frame
        self.port_frame = ctk.CTkFrame(self.connection_window, fg_color="red")
        self.port_frame.pack(pady=5)

        self.server_port_label = ctk.CTkLabel(self.port_frame, text="Port:")
        self.server_port_label.pack(side='left', fill="x", expand=True, padx=10)

        self.server_port_input = ctk.CTkEntry(self.port_frame)
        self.server_port_input.insert(0, "5061")  # ✅ Default Port
        self.server_port_input.pack(side='left', fill="x", expand=True, padx=10)

        # Verbinden Button
        self.button_frame = ctk.CTkFrame(self.connection_window, fg_color="grey")
        self.button_frame.pack(pady=40)

        self.connect_button = ctk.CTkButton(self.button_frame, text="Verbinden", command=self.on_connect_click)
        self.connect_button.pack(side='left', fill="x", expand=True, padx=10)

    def cleanup_connection(self):
        """Detailed connection cleanup with debugging"""
        print("[CLEANUP] Starting connection cleanup...")
        
        if hasattr(self, 'client_socket') and self.client_socket:
            try:
                print("[CLEANUP] Closing client socket...")
                self.client_socket.close()
                print("[CLEANUP] Socket closed successfully")
            except Exception as close_error:
                print(f"[CLEANUP] Error closing socket: {close_error}")
            finally:
                self.client_socket = None
                print("[CLEANUP] Socket reference cleared")
        
        # Additional cleanup if needed
        print("[CLEANUP] Cleanup completed")
    #threading
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
        """Handler für den Update-Button Click - Startet Identity Challenge für Phonebook Update"""
        global connected
        try:
            if not hasattr(self, 'client_socket') or not self.client_socket or not connected:
                messagebox.showerror("Fehler", "Nicht mit Server verbunden")
                print("[UPDATE ERROR] Nicht mit Server verbunden")
                return

            print("[CLIENT] Update-Button geklickt - Starte Identity Challenge Prozess")

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
                
                # Füge zur Queue für spätere Verarbeitung hinzu
                if not hasattr(self, '_message_queue'):
                    self._message_queue = []
                    
                self._message_queue.append({
                    'type': 'update_request_sent',
                    'message': update_msg,
                    'timestamp': time.time(),
                    'server_ip': self.server_ip
                })

                # Starte Queue-Verarbeitung falls nicht bereits aktiv
                if not hasattr(self, '_processing_queue') or not self._processing_queue:
                    self._process_queue()

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



    def end_current_call(self):
        """Beendet den aktuellen Anruf und bereinigt Ressourcen"""
        print("[CALL] Ending current call...")
        self.active_call = False
        
        # Bereinige Audio-Ressourcen
        try:
            # Stoppe alle Audio-Threads
            self.cleanup_call_resources()
        except Exception as e:
            print(f"[CALL CLEANUP ERROR] {e}")
        
        # UI zurücksetzen
        self.update_call_ui(active=False)
        print("[CALL] Call ended successfully")

    def on_call_click(self):
        """Handler für den Call-Button mit korrigiertem Protokoll und 120-Sekunden Timeout"""
        try:
            if self.active_call:
                self.end_current_call()
                return
            
            if not self.selected_entry:
                messagebox.showerror("Error", "Bitte wählen Sie zuerst einen Kontakt aus")
                return

            # Prüfe ob der Kontakt anrufbar ist
            if not self.selected_entry.get('callable', True):
                messagebox.showerror("Error", "Dieser Kontakt kann nicht angerufen werden")
                return

            print(f"[CALL] Initiating call to {self.selected_entry['name']} (ID: {self.selected_entry['id']})")

            # 1. Generiere WireGuard Schlüsselpaar
            try:
                wg_private_key, wg_public_key = self.wg_manager.generate_keypair()
                print(f"[CALL] WG keys generated - Public: {wg_public_key[:30]}...")
            except Exception as e:
                print(f"[CALL ERROR] WireGuard key generation failed: {str(e)}")
                messagebox.showerror("Error", "Konnte WireGuard Schlüssel nicht generieren")
                return

            # 2. Generiere AES Session Key (48 Bytes: 16 IV + 32 Key)
            session_secret = os.urandom(48)
            iv = session_secret[:16]
            aes_key = session_secret[16:48]
            print(f"[CALL] AES session key generated - IV: {binascii.hexlify(iv).decode()[:16]}..., Key: {binascii.hexlify(aes_key).decode()[:16]}...")

            # 3. Ermittle öffentliche IP
            try:
                public_ip = self._get_public_ip()
                print(f"[CALL] Public IP: {public_ip}")
            except Exception as e:
                print(f"[CALL WARNING] Could not determine public IP: {str(e)}")
                public_ip = "127.0.0.1"  # Fallback

            # 4. Bereite Call-Daten vor
            call_data = {
                "caller_name": self._client_name,
                "caller_wg_public_key": wg_public_key,
                "aes_iv": base64.b64encode(iv).decode('utf-8'),
                "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                "caller_ip": public_ip,
                "caller_wg_port": 51820,
                "timestamp": time.time(),
                "call_type": "wireguard_audio",
                "protocol_version": "1.0"
            }
            
            call_data_json = json.dumps(call_data, separators=(',', ':'))
            print(f"[CALL] Call data prepared: {len(call_data_json)} bytes")

            # 5. Verschlüssele mit öffentlichem Schlüssel des Empfängers
            try:
                # Validiere und bereinige den öffentlichen Schlüssel
                recipient_pubkey_str = self.selected_entry['public_key']
                if '\\n' in recipient_pubkey_str:
                    recipient_pubkey_str = recipient_pubkey_str.replace('\\n', '\n')
                
                recipient_pubkey = RSA.load_pub_key_bio(
                    BIO.MemoryBuffer(recipient_pubkey_str.encode()))
                
                encrypted_data = recipient_pubkey.public_encrypt(
                    call_data_json.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                print(f"[CALL] Data encrypted with recipient key: {len(encrypted_data)} bytes")
                
            except Exception as e:
                print(f"[CALL ERROR] Failed to encrypt with recipient key: {str(e)}")
                messagebox.showerror("Error", "Konnte nicht mit Empfänger-Schlüssel verschlüsseln")
                return
            
            # 6. Sende CALL_REQUEST an Server
            request_msg = build_sip_message("MESSAGE", "server", {
                "MESSAGE_TYPE": "CALL_REQUEST",
                "TARGET_CLIENT_ID": self.selected_entry['id'],
                "ENCRYPTED_CALL_DATA": base64.b64encode(encrypted_data).decode('utf-8'),
                "CALLER_NAME": self._client_name,
                "CALLER_CLIENT_ID": self._find_my_client_id(),
                "TIMESTAMP": int(time.time()),
                "TIMEOUT": 120  # 120 Sekunden Timeout
            })
            
            try:
                send_frame(self.client_socket, request_msg.encode('utf-8'))
                print(f"[CALL] Call request sent to server for client {self.selected_entry['id']}")
                
            except Exception as e:
                print(f"[CALL ERROR] Failed to send call request: {str(e)}")
                messagebox.showerror("Error", "Konnte Anrufanfrage nicht senden")
                return

            # 7. Speichere Session-Daten mit 120-Sekunden Timeout
            self.pending_call = {
                'recipient': self.selected_entry.copy(),
                'wg_private_key': wg_private_key,
                'wg_public_key': wg_public_key,
                'aes_iv': iv,
                'aes_key': aes_key,
                'status': 'request_sent',
                'start_time': time.time(),
                'timeout': 120,  # 120 Sekunden
                'call_id': f"{self._client_name}_{self.selected_entry['id']}_{int(time.time())}"
            }
            
            # 8. UI aktualisieren
            self.update_call_ui(active=True, status="requesting", caller_name=self.selected_entry['name'])
            
            # 9. Starte 120-Sekunden Timeout-Überwachung
            threading.Thread(
                target=self._call_timeout_watchdog, 
                daemon=True,
                name=f"CallTimeout-{self.selected_entry['id']}"
            ).start()
            
            print(f"[CALL] Call initiation complete - waiting for response (120s timeout)")
                
        except Exception as e:
            print(f"[CALL CLICK ERROR] {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Unerwarteter Fehler: {str(e)}")
            
            # Cleanup bei Fehler
            if hasattr(self, 'pending_call'):
                del self.pending_call

    def _call_timeout_watchdog(self):
        """Überwacht Call-Timeout von 120 Sekunden"""
        if not hasattr(self, 'pending_call'):
            return
            
        timeout = self.pending_call.get('timeout', 120)
        start_time = self.pending_call.get('start_time', time.time())
        call_id = self.pending_call.get('call_id', 'unknown')
        
        print(f"[CALL TIMEOUT] Starting watchdog for call {call_id}, timeout: {timeout}s")
        
        while (hasattr(self, 'pending_call') and 
               self.pending_call.get('status') == 'request_sent'):
            
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                print(f"[CALL TIMEOUT] Timeout reached after {elapsed:.1f}s for call {call_id}")
                
                # Sende Timeout-Benachrichtigung an UI
                self.after(0, lambda: messagebox.showinfo(
                    "Call Failed", 
                    f"Keine Antwort vom Empfänger nach {timeout} Sekunden"
                ))
                
                # Beende den Anruf
                self.end_current_call()
                break
                
            # Update UI mit verbleibender Zeit
            remaining = timeout - elapsed
            if remaining % 10 == 0:  # Alle 10 Sekunden loggen
                print(f"[CALL TIMEOUT] {remaining:.0f} seconds remaining for call {call_id}")
            
            time.sleep(1)
        
        print(f"[CALL TIMEOUT] Watchdog finished for call {call_id}")

    def _call_timeout_watchdog(self):
        """Überwacht Call-Timeout"""
        timeout = 30  # 30 Sekunden Timeout
        start_time = time.time()
        
        while hasattr(self, 'pending_call') and self.pending_call.get('status') == 'request_sent':
            if time.time() - start_time > timeout:
                print("[CALL] Timeout waiting for call response")
                self.end_current_call()
                messagebox.showinfo("Call Failed", "No response from recipient")
                break
            time.sleep(1)

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
        print(f"[DEBUG] Raw data: {raw_data[:100]}...")
        
        # Queue-Initialisierung mit DoS-Schutz - KORRIGIERTE VERSION
        if not hasattr(self, '_message_queue'):
            self._message_queue = []
        if not hasattr(self, '_processing_queue'):
            self._processing_queue = False
        if not hasattr(self, '_queue_size_limit'):
            self._queue_size_limit = 120
        if not hasattr(self, '_last_minute_check'):
            self._last_minute_check = time.time()
        if not hasattr(self, '_messages_this_minute'):
            self._messages_this_minute = 0
        
        # DoS-Schutz: Nachrichten pro Minute limitieren
        current_time = time.time()
        if current_time - self._last_minute_check >= 60:
            self._last_minute_check = current_time
            self._messages_this_minute = 0
        
        if self._messages_this_minute >= self._queue_size_limit:
            print(f"[DOS PROTECTION] Message limit reached ({self._queue_size_limit}/min) - dropping message")
            return False
        
        self._messages_this_minute += 1
        
        # Nachricht zur Queue hinzufügen
        self._message_queue.append(raw_data)
        
        # Verarbeitung starten falls nicht bereits aktiv
        if not self._processing_queue:
            return self._process_queue()
        return True
    def _handle_identity_challenge(self, message):
        """Verarbeitet Identity Challenge vom Server - KORRIGIERTE VERSION"""
        try:
            print("\n" + "="*60)
            print("[IDENTITY] START: Handling identity challenge from server")
            print("="*60)
            
            # 1. Parse SIP message als Key-Value (nicht JSON)
            print("[DEBUG] Step 1: Parsing SIP message as key-value")
            sip_data = parse_sip_message(message)
            if not sip_data:
                print("[IDENTITY ERROR] Invalid SIP message format")
                return False
            
            # 2. Extrahiere custom_data aus Body (Key-Value Format)
            body = sip_data.get('body', '')
            custom_data = {}
            for line in body.split('\n'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    custom_data[key.strip()] = value.strip()
            
            print(f"[DEBUG] Custom data extracted: {list(custom_data.keys())}")
            
            # 3. Extract challenge data
            encrypted_challenge_b64 = custom_data.get('ENCRYPTED_CHALLENGE')
            challenge_id = custom_data.get('CHALLENGE_ID')
            
            if not encrypted_challenge_b64 or not challenge_id:
                print("[IDENTITY ERROR] Missing challenge data in body")
                print(f"[DEBUG] Body content: {body}")
                return False
            
            # 4. Base64 decode
            print("[DEBUG] Base64 decoding challenge")
            try:
                encrypted_challenge = base64.b64decode(encrypted_challenge_b64)
                print(f"[DEBUG] Decoded challenge length: {len(encrypted_challenge)} bytes")
            except Exception as e:
                print(f"[IDENTITY ERROR] Base64 decode failed: {str(e)}")
                return False
            
            # 5. Decrypt with client private key
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
            
            # 6. Create response
            response_data = challenge + "VALIDATED"
            print(f"[DEBUG] Response data: {response_data}")
            
            # 7. Encrypt response with server public key
            print("[DEBUG] Encrypting with server public key")
            try:
                server_pubkey = load_server_publickey()
                # Bereinige den Key von literal \n Zeichen
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
            
            # 8. Send response back to server als Key-Value (nicht JSON)
            print("[DEBUG] Sending key-value response to server")
            
            response_body = (
                f"MESSAGE_TYPE: IDENTITY_RESPONSE\r\n"
                f"CHALLENGE_ID: {challenge_id}\r\n"
                f"ENCRYPTED_RESPONSE: {encrypted_response_b64}"
            )
            
            response_msg = (
                f"MESSAGE sip:server SIP/2.0\r\n"
                f"From: <sip:{self._client_name}@client>\r\n"
                f"To: <sip:server>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(response_body)}\r\n\r\n"
                f"{response_body}"
            )
            
            send_frame(self.client_socket, response_msg.encode('utf-8'))
            print("[IDENTITY] Response sent to server successfully!")
            
            return True
            
        except Exception as e:
            print(f"[IDENTITY ERROR] Challenge handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False


    def _handle_identity_verified(self, message):
        """Verarbeitet Identity Verification Bestätigung vom Server"""
        try:
            print("[IDENTITY] Received verification confirmation from server")
            
            sip_data = parse_sip_message(message)
            if not sip_data:
                print("[IDENTITY ERROR] Invalid SIP message format")
                return False
            
            custom_data = sip_data.get('custom_data', {})
            status = custom_data.get('STATUS')
            
            if status == 'IDENTITY_VERIFIED':
                print("[IDENTITY] Successfully verified by server!")
                # Hier könntest du weitere Aktionen nach erfolgreicher Verifizierung durchführen
                return True
            else:
                print(f"[IDENTITY] Verification failed: {custom_data.get('REASON', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Verification handling failed: {str(e)}")
            return False
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
    def _handle_session_key(self, msg):
        """Verarbeitet den Session Key für Audio-Verschlüsselung"""
        try:
            custom_data = msg.get('custom_data', {})
            encrypted_session = custom_data.get('ENCRYPTED_SESSION')
            
            if not encrypted_session:
                print("[CALL ERROR] No session key in message")
                return
            
            # Entschlüssele Session Key mit privatem Schlüssel
            private_key = load_privatekey()
            priv_key = RSA.load_key_string(private_key.encode())
            decrypted_session = priv_key.private_decrypt(
                base64.b64decode(encrypted_session), 
                RSA.pkcs1_padding
            )
            
            # Extrahiere den eigentlichen Session Key (48 Bytes)
            if decrypted_session.startswith(b"+++session_key+++"):
                session_secret = decrypted_session[len(b"+++session_key+++"):]
                if len(session_secret) == 48:
                    iv = session_secret[:16]
                    aes_key = session_secret[16:48]
                    
                    # Speichere Session Key für Audio-Übertragung
                    self.current_secret = session_secret
                    
                    if hasattr(self, 'pending_call'):
                        self.pending_call['aes_iv'] = iv
                        self.pending_call['aes_key'] = aes_key
                        self.pending_call['status'] = 'session_key_received'
                    
                    print("[CALL] Session key decrypted and stored")
                    
                    # Bestätigung an Server senden
                    ack_msg = self.build_sip_message("MESSAGE", "server", {
                        "MESSAGE_TYPE": "SESSION_KEY_ACK",
                        "CLIENT_ID": self._find_my_client_id(),
                        "TIMESTAMP": int(time.time())
                    })
                    send_frame(self.client_socket, ack_msg.encode('utf-8'))
                    
                else:
                    print(f"[CALL ERROR] Invalid session key length: {len(session_secret)}")
            else:
                print("[CALL ERROR] Invalid session key format")
                
        except Exception as e:
            print(f"[CALL ERROR] Failed to decrypt session key: {str(e)}")
    def _find_my_client_id(self):
        """Ermittelt die eigene Client-ID"""
        if hasattr(self, 'phonebook_entries'):
            for entry in self.phonebook_entries:
                if isinstance(entry, dict) and entry.get('name') == self._client_name:
                    return entry.get('id')
        return None

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

    def _call_timeout_watchdog(self):
        """Überwacht Call-Timeout"""
        timeout = 30  # 30 Sekunden Timeout
        start_time = time.time()
        
        while hasattr(self, 'pending_call') and self.pending_call.get('status') == 'request_sent':
            if time.time() - start_time > timeout:
                print("[CALL] Timeout waiting for call response")
                self.end_current_call()
                messagebox.showinfo("Call Failed", "Keine Antwort vom Empfänger")
                break
            time.sleep(1)    
    def _handle_incoming_call_notification(self, msg):
        """Handles incoming call notifications with 120-second timeout"""
        try:
            print("\n=== INCOMING CALL NOTIFICATION ===")
            
            # Extract from headers (not body)
            headers = msg.get('headers', {})
            caller_name = headers.get('CALLER_NAME')
            caller_id = headers.get('CALLER_CLIENT_ID')
            encrypted_call_data = headers.get('ENCRYPTED_CALL_DATA')
            
            if not all([caller_name, caller_id, encrypted_call_data]):
                print("[ERROR] Missing call information in headers")
                return
            
            print(f"[CALL] Incoming call from {caller_name} (ID: {caller_id})")
            
            # Store call context
            self.incoming_call = {
                'caller_name': caller_name,
                'caller_id': caller_id,
                'encrypted_data': encrypted_call_data,
                'received_time': time.time(),
                'status': 'pending'
            }
            
            # Show dialog with 120-second timeout
            def show_call_dialog():
                response = messagebox.askyesno(
                    "Eingehender Anruf", 
                    f"Eingehender Anruf von {caller_name}.\nAnnehmen?",
                    icon='question',
                    detail="Sie haben 120 Sekunden Zeit zu antworten",
                    timeout=120000  # 120 seconds in milliseconds
                )
                
                if response:
                    self._accept_incoming_call()
                else:
                    self._reject_incoming_call()
            
            # Run in main thread
            self.after(0, show_call_dialog)
            
        except Exception as e:
            print(f"[INCOMING CALL ERROR] {str(e)}")
            traceback.print_exc()

    def _accept_incoming_call(self):
        """Accept incoming call and setup WireGuard"""
        try:
            if not hasattr(self, 'incoming_call'):
                print("[ERROR] No incoming call to accept")
                return
            
            call_data = self.incoming_call
            
            # 1. Decrypt the call data with our private key
            private_key = load_privatekey()
            priv_key = RSA.load_key_string(private_key.encode())
            
            encrypted_data = base64.b64decode(call_data['encrypted_data'])
            decrypted_data = priv_key.private_decrypt(encrypted_data, RSA.pkcs1_padding)
            call_info = json.loads(decrypted_data.decode('utf-8'))
            
            print(f"[CALL] Decrypted call info: {call_info}")
            
            # 2. Generate WireGuard keypair
            wg_private_key, wg_public_key = self.wg_manager.generate_keypair()
            
            # 3. Setup WireGuard
            wg_config = self.wg_manager.create_interface_config(
                wg_private_key,
                call_info['caller_wg_public_key'],
                f"{call_info['caller_ip']}:{call_info['caller_wg_port']}",
                "10.8.0.2"  #Our IP in VPN
            )
            
            success = self.wg_manager.setup_wireguard_tunnel(wg_config)
            
            if success:
                # 4. Store call data
                self.pending_call = {
                    'caller_name': call_data['caller_name'],
                    'caller_id': call_data['caller_id'],
                    'wg_private_key': wg_private_key,
                    'wg_peer_key': call_info['caller_wg_public_key'],
                    'aes_iv': base64.b64decode(call_info['aes_iv']),
                    'aes_key': base64.b64decode(call_info['aes_key']),
                    'status': 'accepted'
                }
                
                # 5. Send acceptance to server
                response_msg = self.build_sip_message("MESSAGE", "server", {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "accepted",
                    "CALLER_CLIENT_ID": call_data['caller_id'],
                    "CALLEE_WG_PUBLIC_KEY": wg_public_key,
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(self.client_socket, response_msg.encode('utf-8'))
                
                # 6. Start audio
                self.current_secret = self.pending_call['aes_iv'] + self.pending_call['aes_key']
                self._start_audio_streams()
                
                # 7. Update UI
                self.update_call_ui(active=True, status="connected", caller_name=call_data['caller_name'])
                
                print("[CALL] Call accepted successfully")
                
            else:
                print("[CALL ERROR] WireGuard setup failed")
                self._reject_incoming_call()
                
        except Exception as e:
            print(f"[ACCEPT CALL ERROR] {str(e)}")
            self._reject_incoming_call()

    def _reject_incoming_call(self):
        """Reject incoming call"""
        try:
            if hasattr(self, 'incoming_call'):
                call_data = self.incoming_call
                
                reject_msg = self.build_sip_message("MESSAGE", "server", {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "rejected",
                    "CALLER_CLIENT_ID": call_data['caller_id'],
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(self.client_socket, reject_msg.encode('utf-8'))
                print("[CALL] Call rejected")
                
                # Cleanup
                if hasattr(self, 'incoming_call'):
                    del self.incoming_call
                    
        except Exception as e:
            print(f"[REJECT CALL ERROR] {str(e)}")
    def _setup_wireguard_with_timeout(self):
        """WireGuard setup with extended 120-second timeout"""
        timeout = 120  # 120 seconds timeout
        start_time = time.time()
        
        while (hasattr(self, 'pending_call') and 
               self.pending_call.get('status') == 'accepted' and
               time.time() - start_time < timeout):
            
            try:
                # Setup WireGuard
                public_ip = self._get_public_ip()
                wg_config = self.wg_manager.create_interface_config(
                    self.pending_call['wg_private_key'],
                    self.pending_call.get('recipient', {}).get('public_key', ''),
                    f"{public_ip}:51820", 
                    "10.8.0.2"  # Client IP im WG-Netzwerk
                )
                
                success = self.wg_manager.setup_wireguard_tunnel(wg_config)
                
                if success:
                    self.pending_call['status'] = 'wg_connected'
                    self.update_call_ui(active=True, status="connected", 
                                      caller_name=self.pending_call['recipient']['name'])
                    
                    # Send confirmation to server
                    ack_msg = build_sip_message("MESSAGE", "server", {
                        "MESSAGE_TYPE": "WG_CONNECTED",
                        "CLIENT_ID": self._find_my_client_id(),
                        "TIMESTAMP": int(time.time())
                    })
                    send_frame(self.client_socket, ack_msg.encode('utf-8'))
                    
                    # Start audio if session key is available
                    if hasattr(self, 'current_secret') and self.current_secret:
                        self._start_audio_streams()
                    return
                    
            except Exception as e:
                print(f"[WG SETUP ERROR] {str(e)}")
                time.sleep(2)  # Wait before retry
        
        # Timeout reached
        if hasattr(self, 'pending_call'):
            print("[CALL] WireGuard setup timeout")
            self.end_current_call()
            messagebox.showinfo("Call Failed", "Verbindungsaufbau fehlgeschlagen (Timeout)")                   
    def _handle_call_response(self, msg):
        """Verarbeitet Antwort auf Anrufanfrage"""
        try:
            custom_data = msg.get('custom_data', {})
            response = custom_data.get('RESPONSE')
            callee_wg_key = custom_data.get('CALLEE_WG_PUBLIC_KEY')
            
            if not hasattr(self, 'pending_call'):
                print("[CALL WARNING] Received response but no pending call")
                return
            
            if response == "accepted" and callee_wg_key:
                print("[CALL] Call accepted by recipient")
                
                # Setup WireGuard mit dem öffentlichen Schlüssel des Angerufenen
                public_ip = self._get_public_ip()
                wg_config = self.wg_manager.create_interface_config(
                    self.pending_call['wg_private_key'],
                    callee_wg_key,
                    f"{public_ip}:51820", 
                    "10.8.0.1"  # Anrufer IP im VPN
                )
                
                success = self.wg_manager.setup_wireguard_tunnel(wg_config)
                
                if success:
                    self.pending_call['status'] = 'accepted'
                    self.update_call_ui(active=True, status="connected", 
                                      caller_name=self.pending_call['recipient']['name'])
                    
                    # Starte Audio-Streams
                    self.current_secret = self.pending_call['aes_iv'] + self.pending_call['aes_key']
                    self._start_audio_streams()
                else:
                    print("[CALL ERROR] WireGuard setup failed")
                    self.end_current_call()
                    
            elif response == "rejected":
                print("[CALL] Call rejected by recipient")
                messagebox.showinfo("Call Rejected", "Der Empfänger hat Ihren Anruf abgelehnt")
                self.end_current_call()
                
            else:
                print(f"[CALL] Unknown response: {response}")
                self.end_current_call()
                
        except Exception as e:
            print(f"[CALL ERROR] Response handling failed: {str(e)}")
            self.end_current_call()
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
                        
                        # INCOMING_CALL Handling (Für angerufenen Client)
                        if message_type == 'INCOMING_CALL':
                            print("[CALL] Incoming call received")
                            self._handle_incoming_call_notification(msg)
                            continue
                        
                        # SESSION_KEY Handling (Für beide Clients)
                        elif message_type == 'SESSION_KEY':
                            print("[CALL] Received session key from server")
                            self._handle_session_key(msg)
                            continue
                        
                        # CALL_RESPONSE Handling (Für anrufenden Client)
                        elif message_type == 'CALL_RESPONSE':
                            print("[CALL] Received call response")
                            self._handle_call_response(msg)
                            continue
                        
                        # CALL_TIMEOUT Handling
                        elif message_type == 'CALL_TIMEOUT':
                            print("[CALL] Call timeout received from server")
                            if hasattr(self, 'pending_call'):
                                self.end_current_call()
                                messagebox.showinfo("Call Failed", "Der Empfänger hat nicht innerhalb von 120 Sekunden geantwortet")
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
                        self._handle_incoming_call_notification(queue_item)
                        continue
                        
                    try:
                        sip_data = parse_sip_message(queue_item)
                        if sip_data:
                            print("[CLIENT] Verarbeite SIP Nachricht aus String-Queue")
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
                with open("client_private_key.pem", "rb") as f:
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




    def initiate_call(self, recipient):
        """Initiiert einen Anruf mit korrigiertem Protokoll"""
        try:
            print(f"[CALL] Initiating call to {recipient['name']}")
            
            # 1. Generiere WireGuard Schlüsselpaar
            wg_private_key, wg_public_key = self.wg_manager.generate_keypair()
            
            # 2. Generiere AES Session Key (48 Bytes: 16 IV + 32 Key)
            session_secret = generate_secret()
            iv = session_secret[:16]
            aes_key = session_secret[16:48]
            
            # 3. Bereite Call-Daten vor
            call_data = {
                "caller_name": self._client_name,
                "caller_wg_public_key": wg_public_key,
                "aes_iv": base64.b64encode(iv).decode('utf-8'),
                "aes_key": base64.b64encode(aes_key).decode('utf-8'),
                "timestamp": time.time(),
                "call_type": "wireguard_audio"
            }
            
            call_data_json = json.dumps(call_data, separators=(',', ':'))
            
            # 4. Verschlüssele mit öffentlichem Schlüssel des Empfängers
            recipient_pubkey = RSA.load_pub_key_bio(
                BIO.MemoryBuffer(recipient['public_key'].encode()))
            
            encrypted_data = recipient_pubkey.public_encrypt(
                call_data_json.encode('utf-8'), 
                RSA.pkcs1_padding
            )
            
            # 5. Sende CALL_REQUEST an Server
            request_msg = self.build_sip_message("MESSAGE", "server", {
                "MESSAGE_TYPE": "CALL_REQUEST",
                "TARGET_CLIENT_ID": recipient['id'],
                "ENCRYPTED_CALL_DATA": base64.b64encode(encrypted_data).decode('utf-8'),
                "CALLER_NAME": self._client_name,
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(self.client_socket, request_msg.encode('utf-8'))
            print(f"[CALL] Call request sent to server for client {recipient['id']}")
            
            # Speichere Session-Daten für späteren Gebrauch
            self.current_call_data = {
                'recipient': recipient,
                'wg_private_key': wg_private_key,
                'wg_public_key': wg_public_key,
                'aes_iv': iv,
                'aes_key': aes_key,
                'status': 'pending'
            }
            
            # Setze UI auf "Warte auf Antwort"
            self.update_call_ui(active=True, status="waiting", caller_name=recipient['name'])
            
        except Exception as e:
            print(f"[CALL ERROR] Failed to initiate call: {str(e)}")
            messagebox.showerror("Call Failed", f"Could not initiate call: {str(e)}")
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
    def _handle_incoming_call(self, msg):
        """Verarbeitet eingehende Anrufe und fragt Benutzer ab"""
        try:
            custom_data = msg.get('custom_data', {})
            caller_name = custom_data.get('CALLER_NAME')
            caller_wg_key = custom_data.get('WG_PUBLIC_KEY')
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            if not all([caller_name, caller_wg_key, caller_client_id]):
                print("[CALL ERROR] Missing call data")
                self._send_call_response(msg, "rejected")
                return
            
            # Frage Benutzer ob Anruf angenommen werden soll
            accept = messagebox.askyesno("Incoming Call", 
                                        f"Incoming call from {caller_name}. Accept?")
            
            if accept:
                # Generiere eigenes WG Schlüsselpaar
                wg_private_key, wg_public_key = self.wg_manager.generate_keypair()
                
                # Setup WireGuard
                public_ip = self._get_public_ip()
                wg_config = self.wg_manager.create_interface_config(
                    wg_private_key,
                    caller_wg_key,
                    f"{public_ip}:51820",
                    "10.8.0.2"
                )
                
                # WireGuard Interface starten
                success = self.wg_manager.setup_wireguard_tunnel(wg_config)
                
                if success:
                    # Speichere Call-Daten
                    self.pending_call = {
                        'caller_name': caller_name,
                        'caller_client_id': caller_client_id,
                        'wg_private_key': wg_private_key,
                        'wg_peer_key': caller_wg_key,
                        'status': 'wg_connected'
                    }
                    
                    # Akzeptiere Anruf
                    self._send_call_response(msg, "accepted")
                    self.update_call_ui(active=True, status="connected", caller_name=caller_name)
                else:
                    print("[CALL ERROR] WireGuard setup failed")
                    self._send_call_response(msg, "error")
            else:
                # Lehne Anruf ab
                self._send_call_response(msg, "rejected")
                
        except Exception as e:
            print(f"[CALL ERROR] Incoming call handling failed: {str(e)}")
            self._send_call_response(msg, "error")
    def _setup_call(self, call_data, caller_name):
        """Richtet den Anruf ein"""
        try:
            # WireGuard Konfiguration
            wg_config = self.wg_manager.create_interface_config(
                self.wg_manager.generate_keypair()[0],  # Eigener private key
                call_data['caller_wg_public_key'],
                f"{self._get_public_ip()}:51820",  # Eigenes Endpoint
                "10.8.0.2"  # Eigene IP im VPN
            )
            
            self.wg_manager.setup_wireguard_tunnel(wg_config)
            
            # Audio Setup
            self.current_secret = base64.b64decode(call_data['aes_iv']) + base64.b64decode(call_data['aes_key'])
            
            # Starte Audio-Streams
            self._start_audio_streams()
            
            # UI aktualisieren
            self.active_call = True
            self.update_call_ui(active=True, caller_name=caller_name)
            
        except Exception as e:
            print(f"[CALL SETUP ERROR] {str(e)}")
            raise

    def _start_audio_streams(self):
        """Startet die Audio-Streams nur wenn WG verbunden ist"""
        if not (hasattr(self, 'pending_call') and 
                self.pending_call.get('status') == 'wg_connected' and
                hasattr(self, 'current_secret') and self.current_secret):
            print("[AUDIO] Cannot start audio - missing requirements")
            return
            
        try:
            print("[AUDIO] Starting audio streams...")
            
            # Extrahiere AES Parameter
            iv = self.current_secret[:16]
            key = self.current_secret[16:48]
            
            # Ziel-IP für Audio-Streaming
            target_ip = self.pending_call['recipient'].get('wg_ip', self.pending_call['recipient'].get('ip'))
            
            # Starte Audio-Streaming
            self.audio_threads = [
                threading.Thread(target=self.audio_stream_out, args=(target_ip, iv, key), daemon=True),
                threading.Thread(target=self.audio_stream_in, args=(iv, key), daemon=True)
            ]
            
            for thread in self.audio_threads:
                thread.start()
                
            print("[AUDIO] Audio streams started successfully")
            
        except Exception as e:
            print(f"[AUDIO ERROR] Failed to start audio streams: {str(e)}")          
    def _send_call_response(self, sip_data, response):
        """Sendet Antwort auf Anruf"""
        try:
            headers = sip_data.get('headers', {})
            from_header = headers.get('FROM', '')
            
            response_msg = self.build_sip_message("MESSAGE", "server", {
                "MESSAGE_TYPE": "CALL_RESPONSE",
                "RESPONSE": response,
                "ORIGINAL_CALL_ID": headers.get('CALL-ID', ''),
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(self.client_socket, response_msg.encode('utf-8'))
            
        except Exception as e:
            print(f"[CALL RESPONSE ERROR] {str(e)}")            
    def audio_stream_out(self, target_ip, iv, key):
        """Sendet Audio an Ziel-IP über WireGuard Interface"""
        try:
            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK
            )
            
            # Socket für Audio-Übertragung
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            print(f"[AUDIO OUT] Streaming to {target_ip}:{PORT}")
            
            while self.active_call:
                try:
                    # Audio-Daten lesen
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    
                    # Verschlüsseln
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 1)
                    encrypted_data = cipher.update(data) + cipher.final()
                    
                    # Senden
                    audio_socket.sendto(encrypted_data, (target_ip, PORT))
                    
                except Exception as e:
                    if self.active_call:  # Nur loggen wenn Call noch aktiv
                        print(f"[AUDIO OUT ERROR] {str(e)}")
                    break
                    
        except Exception as e:
            print(f"[AUDIO OUT SETUP ERROR] {str(e)}")
        finally:
            try:
                stream.stop_stream()
                stream.close()
                audio.terminate()
                audio_socket.close()
            except:
                pass

    def audio_stream_in(self, iv, key):
        """Empfängt Audio über WireGuard Interface"""
        try:
            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                frames_per_buffer=CHUNK
            )
            
            # Socket für Audio-Empfang
            audio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            audio_socket.bind(('0.0.0.0', PORT))
            audio_socket.settimeout(0.1)
            
            print("[AUDIO IN] Listening for audio...")
            
            while self.active_call:
                try:
                    # Audio-Daten empfangen
                    encrypted_data, addr = audio_socket.recvfrom(4096)
                    
                    # Entschlüsseln
                    cipher = EVP.Cipher("aes_256_cbc", key, iv, 0)
                    decrypted_data = cipher.update(encrypted_data) + cipher.final()
                    
                    # Abspielen
                    stream.write(decrypted_data)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.active_call:  # Nur loggen wenn Call noch aktiv
                        print(f"[AUDIO IN ERROR] {str(e)}")
                    break
                    
        except Exception as e:
            print(f"[AUDIO IN SETUP ERROR] {str(e)}")
        finally:
            try:
                stream.stop_stream()
                stream.close()
                audio.terminate()
                audio_socket.close()
            except:
                pass
    def cleanup_call_resources(self):
        """Bereinigt Anruf-Ressourcen inklusive WireGuard"""
        print("[CLEANUP] Cleaning up call resources including WireGuard...")
        self.active_call = False
        self.current_secret = None
        
        # WireGuard Interface herunterfahren
        try:
            if os.path.exists(self.wg_config_path):
                subprocess.run(["wg-quick", "down", self.wg_config_path], 
                             timeout=10, check=False)
                os.remove(self.wg_config_path)
                print("[CLEANUP] WireGuard interface stopped and config removed")
        except Exception as e:
            print(f"[CLEANUP WARNING] WireGuard cleanup failed: {str(e)}")
        
        # Secure Vault bereinigen
        if hasattr(self, 'secret_vault'):
            try:
                self.secret_vault.wipe()
                print("[CLEANUP] Vault wiped")
            except Exception as e:
                print(f"[CLEANUP WARNING] Vault cleanup failed: {str(e)}")
        
        # Audio-Threads stoppen
        if hasattr(self, 'audio_threads'):
            for thread in self.audio_threads:
                try:
                    if thread.is_alive():
                        # Thread beenden
                        pass
                except:
                    pass
            self.audio_threads = []
            print("[CLEANUP] Audio threads cleared")
        
        # UI zurücksetzen
        try:
            self.update_call_ui(active=False)
            print("[CLEANUP] UI updated")
        except Exception as e:
            print(f"[CLEANUP WARNING] UI update failed: {str(e)}")
        
        # WireGuard Variablen zurücksetzen
        self.wg_peer_ip = None
        self.wg_my_ip = None
        
        print("[CLEANUP] All call resources cleaned up successfully")

    def update_call_ui(self, active, status=None, caller_name=None):
        """Aktualisiert die UI für den Anrufstatus mit verbesserter Fehlerbehandlung"""
        try:
            self.active_call = active
            
            # Status-Text basierend auf aktivem Status und zusätzlichem Status-Parameter
            if active:
                if status == "requesting":
                    status_text = f"Anfrage an {caller_name}..." if caller_name else "Anrufanfrage wird gesendet..."
                elif status == "connected":
                    status_text = f"Verbunden mit: {caller_name}" if caller_name else "Aktiver Anruf"
                else:
                    status_text = f"Aktiver Anruf mit: {caller_name}" if caller_name else "Aktiver Anruf"
                
                call_button_text = "Beenden"
                call_button_color = "red"
                print(f"[CALL UI] {status_text}")
            else:
                status_text = "Bereit für Anrufe"
                call_button_text = "Anrufen"
                call_button_color = "#006400"  # Dunkelgrün
                print("[CALL UI] Anruf beendet")
            
            # UI-Elemente aktualisieren mit erweiterter Fehlerbehandlung
            try:
                # Status-Label aktualisieren (falls vorhanden)
                if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                    self.status_label.configure(text=status_text)
                else:
                    # Erstelle Status-Label falls nicht vorhanden
                    self.status_label = ctk.CTkLabel(
                        self.phonebook_tab,
                        text=status_text,
                        text_color="white",
                        font=("Helvetica", 14)
                    )
                    self.status_label.place(relx=0.5, rely=0.02, anchor="n")
                    print("[CALL UI] Status label created")
                
                # Call-Button aktualisieren
                if hasattr(self, 'call_button') and self.call_button.winfo_exists():
                    self.call_button.configure(
                        text=call_button_text,
                        fg_color=call_button_color
                    )
                
            except Exception as e:
                print(f"[UI UPDATE ERROR] {e}")
                
        except Exception as e:
            print(f"[CALL UI CRITICAL ERROR] {e}")

    def _disable_other_buttons(self, disable):
        """Hilfsfunktion zum Deaktivieren/Reaktivieren anderer Buttons"""
        buttons_to_disable = ['update_button', 'setup_button', 'hangup_button']
        
        for btn_name in buttons_to_disable:
            if hasattr(self, btn_name):
                button = getattr(self, btn_name)
                try:
                    if disable:
                        button.configure(state="disabled", fg_color="gray")
                    else:
                        button.configure(state="normal", fg_color="#006400")
                except Exception as e:
                    print(f"[UI WARNING] Could not update button {btn_name}: {str(e)}")
        if hasattr(self, 'callStatusChanged'):
            self.callStatusChanged.emit(status_text)    
    def setup_audio(self):
        """
        Audio-Initialisierung mit umfassender Fehlerbehandlung
        """
        audio = None
        stream_in = None
        stream_out = None
        
        try:
            audio = pyaudio.PyAudio()
            
            # Audio-Device Konfiguration mit Fehlerbehandlung
            try:
                # Versuche Standard-Devices
                stream_in = audio.open(
                    format=FORMAT, 
                    channels=CHANNELS,
                    rate=RATE, 
                    input=True,
                    frames_per_buffer=CHUNK,
                    input_device_index=None  # Auto-select
                )
                
                stream_out = audio.open(
                    format=FORMAT, 
                    channels=CHANNELS,
                    rate=RATE, 
                    output=True,
                    frames_per_buffer=CHUNK,
                    output_device_index=None  # Auto-select
                )
                
            except Exception as e:
                print(f"[AUDIO WARN] Standard audio failed: {e}")
                
                # Fallback: Suche nach verfügbaren Devices
                device_count = audio.get_device_count()
                for i in range(device_count):
                    device_info = audio.get_device_info_by_index(i)
                    print(f"[AUDIO DEBUG] Device {i}: {device_info['name']}, "
                          f"in: {device_info['maxInputChannels']}, "
                          f"out: {device_info['maxOutputChannels']}")
                    
                    if device_info['maxInputChannels'] > 0:
                        try:
                            stream_in = audio.open(
                                format=FORMAT,
                                channels=CHANNELS,
                                rate=RATE,
                                input=True,
                                frames_per_buffer=CHUNK,
                                input_device_index=i
                            )
                            print(f"[AUDIO INFO] Using input device: {device_info['name']}")
                            break
                        except Exception as e:
                            print(f"[AUDIO ERROR] Input device {i} failed: {e}")
                            continue
                
                for i in range(device_count):
                    device_info = audio.get_device_info_by_index(i)
                    if device_info['maxOutputChannels'] > 0:
                        try:
                            stream_out = audio.open(
                                format=FORMAT,
                                channels=CHANNELS,
                                rate=RATE,
                                output=True,
                                frames_per_buffer=CHUNK,
                                output_device_index=i
                            )
                            print(f"[AUDIO INFO] Using output device: {device_info['name']}")
                            break
                        except Exception as e:
                            print(f"[AUDIO ERROR] Output device {i} failed: {e}")
                            continue
                
                # Wenn immer noch keine Devices gefunden wurden
                if stream_in is None or stream_out is None:
                    print("[AUDIO WARN] No audio devices found, using dummy mode")
                    # Setze Streams auf None für Dummy-Modus
                    
        except Exception as e:
            print(f"[AUDIO ERROR] Audio setup failed: {e}")
            # Versuche es ohne Audio
            return None, None, None
            
        return audio, stream_in, stream_out                          
    def send_call_request(self, callee_id):
        request_msg = self.build_sip_message("MESSAGE", "server", {
            "CALL_TYPE": "REQUEST",
            "CALLEE_ID": callee_id,
            "TIMESTAMP": int(time.time())
        })
        send_frame(self.client_socket, request_msg.encode('utf-8'))


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
