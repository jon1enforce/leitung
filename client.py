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
import traceback
from typing import Optional
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



def verify_merkle_integrity(all_keys, received_root_hash):
    """Überprüft die Integrität aller Schlüssel mittels Merkle Tree"""
    print("\n=== CLIENT VERIFICATION ===")
    
    # 1. Deduplizierung der Schlüssel
    unique_keys = []
    seen_keys = set()
    for key in all_keys:
        normalized = normalize_key(key)
        if normalized and normalized not in seen_keys:
            seen_keys.add(normalized)
            unique_keys.append(key)
    
    print(f"[Client] Unique keys after deduplication: {len(unique_keys)}")
    
    # 2. Normalisierung und Validierung
    normalized_keys = []
    for key in unique_keys:
        normalized = normalize_key(key)
        if normalized:
            normalized_keys.append(normalized)
    
    if not normalized_keys:
        print("Error: No valid keys after normalization")
        return False

    # 3. Zusammenführung mit Trennzeichen
    merged = "|||".join(normalized_keys)
    print(f"[Client] Merged keys (len={len(merged)}): {merged[:100]}...")

    # 4. Merkle Root berechnen
    calculated_hash = build_merkle_tree([merged])
    print(f"[Client] Calculated hash: {calculated_hash}")
    print(f"Received hash:   {received_root_hash}")
    
    return calculated_hash == received_root_hash

def debug_print_key(key_type, key_data):
    """Print detailed key information"""
    print(f"\n=== {key_type.upper()} KEY DEBUG ===")
    print(f"Length: {len(key_data)} bytes")
    print(f"First 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[:32])}")
    print(f"First 32 bytes (ascii): {key_data[:32].decode('ascii', errors='replace')}")
    if len(key_data) > 32:
        print(f"Last 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[-32:])}")
    print("="*50)

def validate_key_pair(private_key, public_key):
    """Validate RSA key pair matches"""
    try:
        # Create test message
        test_msg = b"TEST_MESSAGE_" + os.urandom(16)
        
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
    """Decrypts phonebook data using private key"""
    try:
        if len(encrypted_data) < 512:
            raise ValueError("Data too short")
            
        # 1. Split into secret and phonebook
        encrypted_secret = encrypted_data[:512]
        encrypted_phonebook = encrypted_data[512:]
        
        # 2. Decrypt secret with private key
        priv_key = RSA.load_key_string(private_key_pem.encode())
        decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
        
        # 3. Validate secret structure
        if not decrypted_secret.startswith(b"+++secret+++"):
            raise ValueError("Invalid secret structure")
            
        secret = decrypted_secret[11:59]  # 48 bytes
        iv = secret[:16]
        aes_key = secret[16:]
        
        # 4. Decrypt phonebook
        cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
        decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
        
        # 5. Parse JSON
        return json.loads(decrypted_data.decode('utf-8'))
        
    except Exception as e:
        print(f"Decryption error: {e}")
        raise

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
        body = "\r\n".join(f"{k}: {v}" for k, v in custom_data.items())
        content_type = "text/plain"
    
    # Absenderadresse bestimmen
    if from_server:
        from_header = f"<sip:server@{host}>" if host else "<sip:server>"
    else:
        client_name = load_client_name()
        client_ip = socket.gethostbyname(socket.gethostname())
        from_header = f"<sip:{client_name}@{client_ip}>"
    
    return (
        f"{method} sip:{recipient} SIP/2.0\r\n"
        f"From: {from_header}\r\n"
        f"To: <sip:{recipient}>\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    )
def parse_sip_message(message):
    """Original-Implementierung mit Merkle-Tree-Support"""
    if isinstance(message, bytes):
        message = message.decode('utf-8')
    
    message = message.strip()
    if not message:
        return None
    
    lines = [line.strip() for line in message.replace('\r\n', '\n').split('\n') if line.strip()]
    result = {'headers': {}, 'custom_data': {}}
    
    # Erste Zeile (Request/Response-Line)
    first_line = lines[0]
    if first_line.startswith('SIP/2.0'):
        parts = first_line.split(maxsplit=2)
        if len(parts) >= 2:
            result['status_code'] = parts[1]
            if len(parts) > 2:
                result['status_message'] = parts[2]
    else:
        result['method'] = first_line.split()[0]
    
    # Header parsen
    for line in lines[1:]:
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip().upper()
            val = val.strip()
            
            if key == "CONTENT-LENGTH":
                try:
                    result['content_length'] = int(val)
                except ValueError:
                    pass
            elif key not in result['headers']:
                result['headers'][key] = val
    
    # Body verarbeiten (für MERKLE_ROOT und ALL_KEYS)
    if 'content_length' in result and result['content_length'] > 0:
        body_lines = lines[len(result['headers']) + 1:]
        body = '\n'.join(body_lines)
        
        try:
            result['custom_data'] = dict(
                line.split(':', 1)
                for line in body.splitlines()
                if ':' in line
            )
        except Exception:
            result['body'] = body
    
    return result if ('method' in result or 'status_code' in result) else None
def connection_loop(client_socket, server_ip, message_handler=None):
    """Original connection loop with fixed ping-pong"""
    ping_interval = 60
    last_ping_time = 0
    
    while True:
        try:
            # Send ping periodically
            if time.time() - last_ping_time > ping_interval:
                ping_msg = build_sip_message("MESSAGE", server_ip, {"PING": "1"})
                client_socket.sendall(ping_msg.encode('utf-8'))
                last_ping_time = time.time()
                print(f"[PING] Sent to server")
            
            # Wait for response with timeout
            client_socket.settimeout(70)  # Matches server's pong_timeout
            response = client_socket.recv(4096)
            
            if not response:
                print("Empty response from server")
                continue
                
            # Handle PING requests
            if b"PING" in response:
                pong_msg = build_sip_message("MESSAGE", server_ip, {"PONG": "1"})
                client_socket.sendall(pong_msg.encode('utf-8'))
                print(f"[PONG] Sent to server")
                continue
                
            # Forward other messages to handler
            if message_handler:
                try:
                    if isinstance(response, bytes):
                        response = response.decode('utf-8')
                    message_handler(response)
                except Exception as e:
                    print(f"Error in message handler: {str(e)}")
                    
        except socket.timeout:
            print("Timeout waiting for server response")
            continue
        except ConnectionError as e:
            print(f"Connection error: {str(e)}")
            break
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
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
    try:
        client_pubkey = load_publickey()
        print("+++client_pubkey+++")
        print(client_pubkey)
        # Sicherstellen, dass der Key vollständig ist
        if not client_pubkey or "-----END PUBLIC KEY-----" not in client_pubkey:
            raise ValueError("Invalid client public key format")

        # Key in den Body der Nachricht einfügen
        request = (
            f"REGISTER sip:{server_ip} SIP/2.0\r\n"
            f"From: <sip:{client_name}@{socket.gethostbyname(socket.gethostname())}>\r\n"
            f"To: <sip:{server_ip}>\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(client_pubkey)}\r\n\r\n"
            f"{client_pubkey}"  # Rohdaten ohne zusätzliche Formatierung
        )
        
        print(f"\n[Client] Sending full public key...")
        send_frame(client_socket, request)
        
        response = recv_frame(client_socket)
        if not response:
            raise ConnectionError("Empty response from server")

        print(f"\n[Client] Raw Server Response:\n{response}\n")
        
        sip_data = parse_sip_message(response)  # Diese Variable wird verwendet
        if not sip_data:
            raise ValueError("Invalid SIP response format")

        # Check if this is a 200 OK response
        if sip_data.get('status_code') != '200':
            raise ValueError(f"Server returned error: {sip_data.get('status_code', 'Unknown')}")

        # Extract server public key - KORREKTE Variablenverwendung
        server_public_key = extract_server_public_key(sip_data, response)  # sip_data statt sip_msg
        
        if not server_public_key or not server_public_key.startswith('-----BEGIN'):
            print(f"Invalid server key format: {server_public_key[:100]}...")
            raise ValueError("Invalid server public key format")

        print(f"\n[Client] Extracted Server Key:\n{server_public_key}")

        # Wait for Merkle root message with timeout
        try:
            merkle_response = recv_frame(client_socket)
            if not merkle_response:
                raise ConnectionError("Empty Merkle response from server")
        
            print(f"\n[Client] Raw Merkle Response:\n{merkle_response}\n")
        
            merkle_data = parse_sip_message(merkle_response)
# Nach dem Empfang der Merkle-Antwort:
            all_keys = []
            merkle_root = None
            
            if merkle_data and 'custom_data' in merkle_data:
                if 'ALL_KEYS' in merkle_data['custom_data']:
                    try:
                        all_keys = json.loads(merkle_data['custom_data']['ALL_KEYS'])
                        print(f"[Client] Received {len(all_keys)} keys from server")
                    except json.JSONDecodeError as e:
                        print(f"[Client] Error parsing keys: {e}")
            
                if 'MERKLE_ROOT' in merkle_data['custom_data']:
                    merkle_root = merkle_data['custom_data']['MERKLE_ROOT']
            
            # Keine zusätzlichen Keys mehr hinzufügen - vertraue der Server-Liste
            if not merkle_root:
                if '\r\n\r\n' in merkle_response:
                    body = merkle_response.split('\r\n\r\n')[1]
                    for line in body.split('\n'):
                        if line.startswith('MERKLE_ROOT:'):
                            merkle_root = line.split('MERKLE_ROOT:')[1].strip()
                            break
            
            if not merkle_root:
                raise ValueError("No Merkle root in response")
            
            # Direkte Verifikation ohne Modifikation der Key-Liste
            if not verify_merkle_integrity(all_keys, merkle_root):
                messagebox.showerror("Security Error", 
                    "Integrity check failed!\n"
                    "Possible key manipulation detected.\n"
                    "Connection terminated.")
                client_socket.close()
                return
        
            # Start main communication loop
            connection_loop(client_socket, server_ip, message_handler)
        
        except socket.timeout:
            print("Timeout waiting for Merkle root message")
            raise ConnectionError("Timeout waiting for Merkle verification")
            
    except Exception as e:
        print(f"[Client] Critical error: {str(e)}")
        if client_socket:
            client_socket.close()
        raise

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
    def __init__(self):
        self.lib = None
        self.vault = None
        self.gen_lib = None
        self._load_libraries()
        
    def _load_libraries(self):
        """Lädt alle benötigten Bibliotheken für die aktuelle Architektur mit erweiterter ARM64-Erkennung"""
        arch = platform.machine().lower()
        print(f"[DEBUG] Detected architecture: {arch}")  # Debug-Ausgabe
    
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
        print(f"[DEBUG] Normalized architecture: {normalized_arch}")
    
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
    
    def generate_secret(self) -> Optional[int]:
        """Generiert ein 48-Byte Geheimnis und gibt nur die Speicheradresse zurück"""
        if not self.gen_lib:
            return None
        buf = (ctypes.c_ubyte * 48)()
        self.gen_lib.generate_secret(buf)
        return ctypes.addressof(buf)
    
    def store(self, secret_ptr: int) -> bool:
        """Speichert ein Geheimnis (nur über Speicheradresse)"""
        if not self.vault or not secret_ptr:
            return False
        self.lib.vault_load(ctypes.c_void_p(self.vault), ctypes.c_void_p(secret_ptr))
        return True
    
    def retrieve(self) -> Optional[int]:
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
        self.secret_vault.create()
        self.current_secret = None  # Aktuelles 48-Byte-Geheimnis für laufende Kommunikation
        # Nur setup_ui aufrufen, nicht beide!
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
        
        # Beispiel-Daten (später durch echte Daten ersetzen)
        self.phonebook_entries = []
        
        # Phonebook Einträge erstellen
        self.entry_buttons = []
        for entry in self.phonebook_entries:
            btn = ctk.CTkButton(
                self.scrollable_frame,
                text=f"{entry['id']}: {entry['name']}",
                fg_color="#006400",  # Dunkelgrün
                text_color="white",
                font=("Helvetica", 14),
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

    def on_entry_click(self, entry):
        print(f"Selected entry: {entry['id']}: {entry['name']}")
        # Hier können Sie die Logik für den Anruf implementieren
        # Beispiel:
        # self.initiate_call(entry['id'], entry['name'])
    
    def update_phonebook(self, phonebook_data):
        """Aktualisiert die Phonebook-Anzeige mit Client-Daten"""
        print(f"\n[UI] Updating phonebook with {len(phonebook_data)} entries")
        print(f"Data received: {phonebook_data}")  # Debug-Ausgabe der empfangenen Daten
        
        # Lösche vorhandene Einträge (im Hauptthread)
        self.after(0, self._clear_phonebook_entries)
        
        # Erstelle Einträge für jeden gültigen Client
        for entry in phonebook_data:
            if not isinstance(entry, dict):
                continue
                
            client_id = entry.get('id', '')
            client_name = entry.get('name', '')
            
            if not client_id or not client_name:
                continue
                
            print(f"[UI] Adding client {client_id}: {client_name}")
            
            # Widget-Erstellung im Hauptthread
            self.after(0, lambda e=entry: self._add_phonebook_entry(e))
        
        # Canvas aktualisieren
        self.after(0, self._update_canvas_scrollregion)
    
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
        # Erzeuge das 48-Byte-Geheimnis
        secret = generate_secret()
        # Extrahiere Seed und Schlüssel
        seed = secret[:16]  # Erste 16 Bytes
        key = secret[16:]   # Letzte 32 Bytes
        #sende seed und key
        send_audio_stream(key,seed)
        # Starte den Audioempfang
        receive_audio_stream(key,seed)

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
    
    def handle_server_message(self, raw_data):
        """Verarbeitet eingehende Nachrichten mit verbessertem Debugging"""
        print("\n=== CLIENT MESSAGE HANDLING START ===")
        print(f"[DEBUG] Raw data type: {type(raw_data)}, length: {len(raw_data)}")
        
        try:
            # 1. Versuche als SIP-Nachricht zu parsen
            print("[DEBUG] Attempting to parse as SIP message...")
            try:
                message = raw_data.decode('utf-8')
                sip_data = parse_sip_message(message)
                
                if not sip_data:
                    print("[ERROR] Failed to parse SIP message structure")
                    return False
                    
                print(f"[DEBUG] Parsed SIP - Method: {sip_data.get('method')}, Status: {sip_data.get('status_code')}")
                
                # Phonebook Update behandeln
                if sip_data.get('custom_data', {}).get('MESSAGE_TYPE') == 'PHONEBOOK_UPDATE':
                    print("[DEBUG] Detected phonebook update message")
                    return self._process_phonebook_update(sip_data['custom_data'])
                    
                return self._handle_standard_sip(sip_data)
                
            except UnicodeDecodeError:
                print("[DEBUG] UTF-8 decode failed, trying binary processing")
                return self._process_binary_phonebook(raw_data)
                
        except Exception as e:
            print(f"[CRITICAL] Message handling failed: {str(e)}")
            traceback.print_exc()
            return False
        finally:
            print("=== CLIENT MESSAGE HANDLING END ===")

    
    def _process_encrypted_phonebook(self, encrypted_data):
        """Process encrypted phonebook data"""
        print("\n=== DECRYPTING PHONEBOOK DATA ===")
        
        try:
            # Validate minimum length
            if len(encrypted_data) < 512:
                print(f"[ERROR] Data too short ({len(encrypted_data)} bytes)")
                return False
                
            encrypted_secret = encrypted_data[:512]
            encrypted_phonebook = encrypted_data[512:]
            
            print(f"[DEBUG] Encrypted secret (512 bytes): {encrypted_secret[:16].hex(' ')}...")
            print(f"[DEBUG] Encrypted phonebook ({len(encrypted_phonebook)} bytes): {encrypted_phonebook[:16].hex(' ')}...")
    
            # Load private key
            with open("private_key.pem", "rb") as f:
                priv_key = RSA.load_key_string(f.read())
                
            # Decrypt secret
            decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
            if not decrypted_secret.startswith(b"+++secret+++"):
                print("[ERROR] Invalid secret format")
                return False
                
            secret = decrypted_secret[11:59]  # Skip overhead
            iv = secret[:16]
            aes_key = secret[16:48]
            
            # Decrypt phonebook
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
            decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
            
            # Parse phonebook
            phonebook_data = json.loads(decrypted_data.decode('utf-8'))
            print(f"[DEBUG] Received phonebook with {len(phonebook_data)} entries")
            
            # Update UI in main thread
            self.after(0, lambda: self.update_phonebook(phonebook_data))
            return True
            
        except Exception as e:
            print(f"[DECRYPTION ERROR] {str(e)}")
            traceback.print_exc()
            return False
    
    def _process_binary_phonebook(self, framed_data):
        """Process framed SIP messages with encrypted payload"""
        print("\n=== PROCESSING FRAMED SIP MESSAGE ===")
        print(f"[FRAME] Length: {len(framed_data)} bytes")
        
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
                        print(f"[ERROR] Base64 decode failed: {e}")
            
            # Fallback to direct processing if no SIP headers found
            if len(framed_data) >= 512:
                print("[DEBUG] Trying direct encrypted phonebook processing")
                return self._process_encrypted_phonebook(framed_data)
                
            print("[ERROR] No valid message format detected")
            return False
            
        except Exception as e:
            print(f"[CRITICAL ERROR] {str(e)}")
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
                print(f"[DEBUG] Encrypted secret length: {len(encrypted_secret)}")
                print(f"[DEBUG] Encrypted phonebook length: {len(encrypted_phonebook)}")
            except KeyError as e:
                print(f"[ERROR] Missing required field: {str(e)}")
                return False
            except binascii.Error as e:
                print(f"[ERROR] Base64 decoding failed: {str(e)}")
                return False
    
            # 3. Entschlüssele das Geheimnis
            print("[DEBUG] Decrypting secret with private key...")
            try:
                with open("private_key.pem", "rb") as f:
                    priv_key = RSA.load_key_string(f.read())
                    print("[DEBUG] Private key loaded successfully")
                    
                decrypted_secret = priv_key.private_decrypt(encrypted_secret, RSA.pkcs1_padding)
                print(f"[DEBUG] Decrypted secret (len={len(decrypted_secret)}): {decrypted_secret[:16].hex()}...")
            except Exception as e:
                print(f"[ERROR] Failed to decrypt secret: {str(e)}")
                return False
    
            # 4. Validiere das Geheimnis
            print("[DEBUG] Validating decrypted secret...")
            if not decrypted_secret.startswith(b"+++secret+++"):
                print("[ERROR] Invalid secret format - missing overhead")
                return False
                
            secret = decrypted_secret[11:59]  # 48 Bytes
            iv = secret[:16]
            aes_key = secret[16:]
            print(f"[DEBUG] IV: {iv.hex()}")
            print(f"[DEBUG] AES Key: {aes_key[:8].hex()}...")
    
            # 5. Entschlüssele das Phonebook
            print("[DEBUG] Decrypting phonebook with AES...")
            try:
                cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 0)
                decrypted_data = cipher.update(encrypted_phonebook) + cipher.final()
                print(f"[DEBUG] Decrypted data (len={len(decrypted_data)}): {decrypted_data[:100]}...")
            except Exception as e:
                print(f"[ERROR] AES decryption failed: {str(e)}")
                return False
    
            # 6. Parse JSON-Daten
            print("[DEBUG] Parsing decrypted JSON data...")
            try:
                phonebook_data = json.loads(decrypted_data.decode('utf-8'))
                print(f"[DEBUG] Raw phonebook data: {phonebook_data}")
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON decode failed: {str(e)}")
                print(f"[DEBUG] Problematic data: {decrypted_data[:200]}")
                return False
    
            # 7. Filtere gültige Einträge
            print("[DEBUG] Validating phonebook entries...")
            valid_entries = []
            for entry in phonebook_data:
                try:
                    if (isinstance(entry, dict) and 
                        str(entry.get('id', '')).isdigit() and 
                        entry.get('name')):
                        print(f"[DEBUG] Valid entry found: {entry['id']}: {entry['name']}")
                        valid_entries.append(entry)
                except Exception as e:
                    print(f"[WARNING] Invalid entry skipped: {str(e)}")
    
            # 8. Aktualisiere UI
            if valid_entries:
                print(f"[DEBUG] Updating UI with {len(valid_entries)} valid entries")
                self.after(0, lambda: self.update_phonebook(valid_entries))
                return True
            else:
                print("[ERROR] No valid entries found in phonebook")
                return False
                
        except Exception as e:
            print(f"[CRITICAL] Processing error: {str(e)}")
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
            print(f"Warnung: Geheimnis konnte nicht sicher gespeichert werden: {e}")
            # Fallback: Temporär in Memory behalten
            self.temp_secret = secret

    def start_connection_wrapper(self):
        """Wrapper für start_connection mit Message-Handler"""
        start_connection(
            self.server_ip,
            int(self.server_port),  # Use the stored value
            load_client_name(),
            self.client_socket,
            self.handle_server_message
    )

def main():
    global app
    app = PHONEBOOK()
    app_instance = threading.Thread(target=app.mainloop())
    app_instance.daemon = True
    app_instance.start()
if __name__ == "__main__":
    main()
