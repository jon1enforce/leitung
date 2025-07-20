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
from typing import Optional
from PySide2.QtCore import QObject, Signal, Slot, Property, QUrl
from PySide2.QtGui import QGuiApplication
from PySide2.QtQuick import QQuickView
from PySide2.QtQml import QQmlApplicationEngine
from PySide2.QtWidgets import QApplication, QMessageBox

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
        
        print("\n[FRAME DEBUG] Received {} bytes".format(length))
        print("First 32 bytes (hex): {}".format(' '.join('{:02x}'.format(b) for b in received[:32])))
        
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
    print("[Client] Merged keys (len={}): {}...".format(len(merged), merged[:100]))

    # 4. Merkle Root berechnen
    calculated_hash = build_merkle_tree([merged])
    print("[Client] Calculated hash: {}".format(calculated_hash))
    print("Received hash: {}".format(received_root_hash))
    
    return calculated_hash == received_root_hash

def debug_print_key(key_type, key_data):
    """Print detailed key information"""
    print("\n=== {} KEY DEBUG ===".format(key_type.upper()))
    print(f"Length: {len(key_data)} bytes")
    print(f"First 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[:32])}")
    print("[DEBUG] First 32 bytes (ascii): {}".format(key_data[:32].decode('ascii', errors='replace')))
    if len(key_data) > 32:
        print(f"Last 32 bytes (hex): {' '.join(f'{b:02x}' for b in key_data[-32:])}")
    print("="*50)

def validate_key_pair(private_key, public_key):
    """Validate RSA key pair matches"""
    try:
        # Create test message
        test_msg = b"TEST_MESSAGE_" + os.urandom(16)
        
        # Encrypt with public key
        # Für Python 3.5 mit M2Crypto 0.38.0:
        bio = BIO.MemoryBuffer(public_key)
        pub_key = RSA.load_pub_key_bio(bio._ptr())  # _ptr() gibt den internen BIO-Pointer zurück
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
        print("Decryption error: {}".format(e))
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
    """
    Erweiterte Verbindungsschleife mit:
    - Ping/Pong-Mechanismus (bestehende Funktionalität)
    - Nachrichtenweiterleitung an optionalen Handler
    """
    ping_interval = 60
    pong_timeout = 70
    
    while True:
        try:
            # 1. Ping senden (bestehende Logik)
            ping_msg = build_sip_message("MESSAGE", server_ip, {"PING": "true"})
            print(ping_msg)
            client_socket.sendall(ping_msg.encode('utf-8'))
            print("DEBUG:ping gesendet+++")
            
            # 2. Auf Antwort warten mit erweiterter Verarbeitung
            client_socket.settimeout(pong_timeout)
            try:
                response = client_socket.recv(4096)
                if not response:
                    print("Leere Antwort vom Server")
                    continue
                    
                # Falls ein Message-Handler existiert, Nachricht weiterleiten
                if message_handler:
                    message_handler(response)
                else:
                    # Originale Ping/Pong-Verarbeitung
                    pong_data = parse_sip_message(response)
                    if pong_data:
                        pong_value = (pong_data.get('custom_data', {}).get("PONG", "") or 
                                     pong_data.get('headers', {}).get("PONG", ""))
                        if str(pong_value).lower() in ("true", "1", "yes"):
                            print(f"Pong erhalten um {time.strftime('%H:%M:%S')}")
                            
            except socket.timeout:
                print(f"Timeout: Kein Pong innerhalb von {pong_timeout}s")
                
            time.sleep(ping_interval)
            
        except ConnectionError as e:
            print(f"Verbindungsfehler: {str(e)}")
            return False
        except Exception as e:
            print(f"Unerwarteter Fehler: {str(e)}")
            continue
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
                        print("[Client] Error parsing keys: {}".format(e))
            
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
        self.client_name = ""
        self.requestClientName.connect(self.handle_name_request)

        # QML Engine Setup
        self.engine = QQmlApplicationEngine()
        self.engine.rootContext().setContextProperty("phonebook", self)
        self.engine.load('Phonebook.qml')
        
        if not self.engine.rootObjects():
            raise RuntimeError("QML konnte nicht geladen werden")

    # Properties für QML
    requestClientName = Signal()
    clientNameChanged = Signal(str)
    connectionStatusChanged = Signal(str)
    callStatusChanged = Signal(str)
    phonebookUpdated = Signal(list)
    @Property(str, notify=clientNameChanged)
    def clientName(self):
        return self._client_name

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
            print("Fehler beim Senden des Geheimnisses: {}".format(e))

    @Slot(str, str)
    def on_connect_click(self, server_ip, server_port):
        if self.client_socket:
            self._connection_status = "Bereits verbunden"
            self.connectionStatusChanged.emit(self._connection_status)
            return
    
        try:
            if not server_ip or not server_port:
                raise ValueError("Server-IP und Port müssen angegeben werden")
            
            port = int(server_port)
            if not (0 < port <= 65535):
                raise ValueError("Ungültiger Port")
    
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            
            try:
                self.client_socket.connect((server_ip, port))
                self.server_ip = server_ip
                self.server_port = port
                
                self._connection_status = f"Verbunden mit {server_ip}:{port}"
                self.connectionStatusChanged.emit(self._connection_status)
                
                threading.Thread(
                    target=self.start_connection_wrapper,
                    daemon=True
                ).start()
    
            except socket.timeout:
                self._connection_status = "Verbindungstimeout - Server nicht erreichbar"
                self.connectionStatusChanged.emit(self._connection_status)
                self.cleanup_connection()
            except ConnectionRefusedError:
                self._connection_status = "Verbindung abgelehnt - Server nicht erreichbar oder Port falsch"
                self.connectionStatusChanged.emit(self._connection_status)
                self.cleanup_connection()
            except OSError as e:
                self._connection_status = f"Netzwerkfehler: {str(e)}"
                self.connectionStatusChanged.emit(self._connection_status)
                self.cleanup_connection()
    
        except ValueError as e:
            self._connection_status = f"Ungültige Eingabe: {str(e)}"
            self.connectionStatusChanged.emit(self._connection_status)
            self.cleanup_connection()
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
        valid_entries = []
        for entry in phonebook_data:
            if (isinstance(entry, dict) and 
                str(entry.get('id', '')).isdigit() and 
                entry.get('name')):
                valid_entries.append(entry)
        
        self.phonebook_entries = valid_entries
        self.phonebookUpdated.emit(valid_entries)

    @Slot(int)
    def on_entry_click(self, index):
        if 0 <= index < len(self.phonebook_entries):
            entry = self.phonebook_entries[index]
            print(f"Selected entry: {entry['id']}: {entry['name']}")
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
            
            messagebox.showinfo("Anruf", f"Verbunden mit {caller_name}")
            
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
        print("[DEBUG] Raw data type: {}, length: {}".format(type(raw_data), len(raw_data)))
        
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
                print("[ERROR] Data too short ({} bytes)".format(len(encrypted_data)))
                return False
                
            encrypted_secret = encrypted_data[:512]
            encrypted_phonebook = encrypted_data[512:]
            print("[DEBUG] Encrypted secret (512 bytes): {}...".format(' '.join('{:02x}'.format(b) for b in encrypted_secret[:16])))
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
                        print("[ERROR] Base64 decode failed: {}".format(e))

            
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
            print("[DEBUG] IV: {}".format(''.join('{:02x}'.format(b) for b in iv)))
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
                print("[ERROR] JSON decode failed: {}".format(str(e)))
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
            print("Warnung: Geheimnis konnte nicht sicher gespeichert werden: {0}".format(e))
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
    # Qt benötigt sys.argv für die Initialisierung
    import sys
    
    # QGuiApplication für Ubuntu Touch (oder QApplication für Desktop mit Widgets)
    from PySide2.QtGui import QGuiApplication
    from PySide2.QtQml import QQmlApplicationEngine
    
    # Qt Application erstellen
    app = QGuiApplication(sys.argv)
    
    # PHONEBOOK Instanz erstellen
    phonebook = PHONEBOOK()
    
    # QML Engine starten (wird bereits im PHONEBOOK-Konstruktor gemacht)
    # Hier führen wir einfach die Hauptschleife aus
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
