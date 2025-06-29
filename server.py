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
from typing import Optional
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
BUFFER_SIZE = 4096

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
    """Generiert Server-Schlüsselpaar falls nicht vorhanden"""
    if not os.path.exists("server_public_key.pem"):
        print("Generiere neue Server-Schlüssel...")
        key = RSA.gen_key(2048, 65537)
        
        # Speichere öffentlichen Schlüssel
        pub_bio = BIO.MemoryBuffer()
        key.save_pub_key_bio(pub_bio)
        with open("server_public_key.pem", "wb") as f:
            f.write(pub_bio.getvalue())
        
        # Speichere privaten Schlüssel
        priv_bio = BIO.MemoryBuffer()
        key.save_key_bio(priv_bio, cipher=None)
        with open("server_private_key.pem", "wb") as f:
            f.write(priv_bio.getvalue())

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
    """Baut einen Merkle Tree aus allen öffentlichen Schlüsseln"""
    print("\n[Server] Building Merkle Tree from all keys")
    
    # 1. Debug-Ausgabe der Rohkeys
    print("[Server] All keys for Merkle Tree:")
    for i, key in enumerate(all_keys):
        print(f"Key {i}: {key}" if key else f"Key {i}: None")

    # 2. Normalisierung aller Keys
    normalized_keys = []
    for key in all_keys:
        if not key or "-----BEGIN PUBLIC KEY-----" not in key:
            continue
        # Extrahiere nur den Base64-Teil zwischen den PEM-Markern
        normalized = "".join(
            key.split("-----BEGIN PUBLIC KEY-----")[1]
            .split("-----END PUBLIC KEY-----")[0]
            .strip().split()
        )
        if normalized:
            normalized_keys.append(normalized)
    
    if len(normalized_keys) < 1:
        raise ValueError("No valid keys found for Merkle tree")
    
    # 3. Zusammenführung mit Trennzeichen
    merged = "|||".join(normalized_keys)
    print(f"[Server] Merged keys (len={len(merged)}): {merged[:100]}...")
    
    # 4. Merkle Root berechnen
    merkle_root = build_merkle_tree([merged])
    print(f"[Server] Final Merkle Root: {merkle_root}")
    
    return merkle_root

    


@staticmethod
def handle_sip_message(raw_data):
    """Verarbeitet eingehende SIP-Nachrichten"""
    try:
        data = raw_data.decode()
        if not data:
            return None
            
        parts = data.split("\r\n\r\n", 1)
        headers = {}
        for line in parts[0].split("\r\n"):
            if ": " in line:
                key, val = line.split(": ", 1)
                headers[key.lower()] = val.strip()
        
        custom_data = {}
        if len(parts) > 1:
            for line in parts[1].split("\r\n"):
                if ": " in line:
                    key, val = line.split(": ", 1)
                    custom_data[key] = val.strip()

        return {
            "method": data.split()[0],
            "headers": headers,
            "custom_data": custom_data
        }
    except Exception as e:
        print(f"SIP-Parsingfehler: {e}")
        return None
def load_client_name():
    """Lädt den Client-Namen aus einer lokalen Datei oder fordert den Benutzer zur Eingabe auf."""
    if os.path.exists("client_name.txt"):
        with open("client_name.txt", "r") as file:
            return file.read().strip()
    
    # If we're not in the main thread, return a default name
    if threading.current_thread() is not threading.main_thread():
        return "default_client"
    
    # Only show dialog in main thread
    client_name = simpledialog.askstring("Name", "Gib deinen Namen ein:")
    if client_name:
        with open("client_name.txt", "w") as file:
            file.write(client_name)
        return client_name
    else:
        messagebox.showerror("Fehler", "Kein Name eingegeben. Abbruch.")
        return None
def encrypt_phonebook_data(phonebook_json, client_public_key_pem):
    """Encrypts phonebook data for a specific client"""
    try:
        # 1. Generate random secret (16 bytes IV + 32 bytes AES key)
        secret = generate_secret()
        if len(secret) != 48:
            raise ValueError("Invalid secret length")
            
        # 2. Encrypt secret with client's public key
        client_pubkey = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_public_key_pem.encode()))
        encrypted_secret = client_pubkey.public_encrypt(b"+++secret+++" + secret, RSA.pkcs1_padding)
        
        # 3. Prepare AES parameters
        iv = secret[:16]
        aes_key = secret[16:]
        
        # 4. Encrypt phonebook data
        plaintext = json.dumps(phonebook_json).encode('utf-8')
        cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
        encrypted_phonebook = cipher.update(plaintext) + cipher.final()
        
        # 5. Combine results
        return encrypted_secret + encrypted_phonebook
        
    except Exception as e:
        print(f"Encryption error: {e}")
        raise


class Server:
    def __init__(self, host='0.0.0.0', port=5060):
        print("init0")
        self.host = host
        self.port = port
        print("init1")
        self.clients = {}
        self.server_public_key = load_server_publickey()
        print("init2")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(("init3"))
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("init4")
        self.client_send_lock = Lock()  # Add this line for thread safety
    def debug_socket(self,sock):
        """Hilfsfunktion zur Socket-Diagnose"""
        if sock is None:
            print("Socket: None")
            return
        
        print(f"Socket Fileno: {sock.fileno()}")
        print(f"Socket Type: {sock.type}")
        print(f"Socket Timeout: {sock.gettimeout()}")
        try:
            print(f"Socket Addr: {sock.getsockname()}")
        except Exception as e:
            print(f"Socket Addr Error: {e}")
    def build_sip_message(self, method, recipient, custom_data={}):
        """Erweitere SIP-Nachrichtenerstellung mit JSON-Unterstützung"""
        # Entscheide ob Body JSON oder Key-Value sein soll
        if any(isinstance(v, (dict, list)) for v in custom_data.values()):
            body = json.dumps(custom_data, separators=(',', ':'))
            content_type = "application/json"
        else:
            body = "\r\n".join(f"{k}: {v}" for k, v in custom_data.items())
            content_type = "text/plain"
        
        return (
            f"{method} sip:{recipient} SIP/2.0\r\n"
            f"From: <sip:{'server' if hasattr(self, 'host') else load_client_name()}@"
            f"{self.host if hasattr(self, 'host') else socket.gethostbyname(socket.gethostname())}>\r\n"
            f"To: <sip:{recipient}>\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
            f"{body}"
        )
    def parse_sip_message(self, message):
        """
        Server-spezifischer Parser mit:
        - Strict SIP-Header-Validierung
        - Merkle-Tree- und Broadcast-Support
        - Automatischer Client-Registrierung
        """
        if isinstance(message, bytes):
            try:
                message = message.decode('utf-8')
            except UnicodeDecodeError:
                print("[SERVER] Invalid UTF-8 in SIP message")
                return None
    
        # Normalize line endings and split
        lines = [line.strip() for line in message.replace('\r\n', '\n').split('\n') if line.strip()]
        if not lines:
            return None
    
        result = {
            'method': None,
            'status_code': None,
            'headers': {},
            'custom_data': {},
            'client_info': None  # Server-spezifisch für Client-Registrierung
        }
    
        # Parse first line
        first_line = lines[0]
        if first_line.startswith('SIP/2.0'):
            parts = first_line.split(maxsplit=2)
            if len(parts) >= 2:
                result['status_code'] = parts[1]
                if len(parts) > 2:
                    result['status_message'] = parts[2]
        else:
            result['method'] = first_line.split()[0]
    
        # Parse headers (strict)
        body_start = len(lines)
        for i, line in enumerate(lines[1:]):
            if not line.strip():
                body_start = i + 1
                break
            if ': ' not in line:
                continue  # Skip malformed headers
            key, val = line.split(': ', 1)
            key = key.strip().upper()
            result['headers'][key] = val.strip()
    
            # Server-spezifisch: Client-Info aus From-Header
            if key == 'FROM' and 'sip:' in val:
                result['client_info'] = val.split('sip:')[1].split('@')[0]
    
        # Parse body (tolerant für Key-Value und JSON)
        if len(lines) > body_start:
            body = '\n'.join(lines[body_start:])
            if body:
                try:
                    # Versuche Key-Value-Parsing (für SIP-Standardbody)
                    result['custom_data'] = dict(
                        line.split(': ', 1) 
                        for line in body.split('\n') 
                        if ': ' in line
                    )
                    
                    # Falls kein Key-Value, versuche JSON (für Phonebook Updates)
                    if not result['custom_data']:
                        try:
                            result['custom_data'] = json.loads(body)
                        except json.JSONDecodeError:
                            result['body'] = body
                except Exception as e:
                    print(f"[SERVER] Body parsing warning: {str(e)}")
                    result['body'] = body
    
        # Server-spezifische Post-Processing
        if result.get('method') == 'REGISTER' and 'PUBLIC_KEY' in result.get('custom_data', {}):
            self._register_client(result)
    
        return result 
    def start(self):
        try:
            print(f"Starte Server auf {self.host}:{self.port}...")
            
            # Socket mit expliziten Parametern erstellen
            self.server_socket = socket.socket(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP
            )
            
            # Debug-Ausgabe vor der Bindung
            self.debug_socket(self.server_socket)
            
            # SO_REUSEADDR setzen
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bindung mit expliziter Prüfung
            try:
                self.server_socket.bind((self.host, self.port))
                print(f"Socket gebunden an {self.host}:{self.port}")
            except OSError as e:
                print(f"Bind-Fehler: {e}")
                raise
            
            # Listen muss unbedingt aufgerufen werden!
            self.server_socket.listen(5)
            print(f"Server lauscht (backlog=5)")
            
            # Debug-Ausgabe nach listen
            self.debug_socket(self.server_socket)
            
            while True:
                try:
                    print("Warte auf Verbindung...")
                    # Standard accept() ohne Flags verwenden
                    client_socket, addr = self.server_socket.accept()
                    print(f"Verbindung von {addr} angenommen")
                    
                    try:
                        self.handle_client(client_socket)
                    finally:
                        client_socket.close()
                        
                except KeyboardInterrupt:
                    print("\nServer-Shutdown")
                    break
                except OSError as e:
                    print(f"Accept-Fehler: {e}")
                    continue
                    
        except Exception as e:
            print(f"Kritischer Fehler: {e}")
        finally:
            # Beim Herunterfahren: Speichere nur noch aktive Clients
            active_clients = {
                k: v for k, v in self.clients.items()
                if v.get('socket') is not None
            }
            with open("active_clients.json", "w") as f:
                json.dump(active_clients, f)
            
            self.server_socket.close()
            print("Server beendet")
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
        iv_part1 = os.urandom(8)
        iv_part2 = self.get_disk_entropy(8)
        if not iv_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        iv = iv_part1 + iv_part2
        
        # Erzeuge den AES-Schlüssel (32 Bytes)
        key_part1 = os.urandom(16)
        key_part2 = self.get_disk_entropy(16)
        if not key_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        aes_key = key_part1 + key_part2
        
        # Kombiniere IV und Schlüssel (48 Bytes total)
        return iv + aes_key

    def generate_client_id(self):
        """Generiert sequentielle Client-IDs (0,1,2,...) mit Nachrücklogik"""
        if not self.clients:
            return "0"
        
        # Finde alle vorhandenen IDs
        existing_ids = sorted(int(k) for k in self.clients.keys() if k.isdigit())
        
        # Finde Lücken oder nächste freie ID
        for i, expected_id in enumerate(range(len(existing_ids) + 1)):
            if i >= len(existing_ids) or str(expected_id) != existing_ids[i]:
                return str(expected_id)
        
        return str(len(existing_ids))
    def save_active_clients(self):
        """Speichert NUR aktuell verbundene Clients auf Festplatte"""
        try:
            active_clients = {
                client_id: {
                    'name': data['name'],
                    'public_key': data['public_key'],
                    'ip': data['ip'],
                    'port': data['port']
                }
                for client_id, data in self.clients.items()
                if data.get('socket') is not None  # Nur Clients mit aktiver Verbindung
            }
            
            with open("active_clients.json", "w") as f:
                json.dump(active_clients, f)
        except Exception as e:
            print(f"Fehler beim Speichern aktiver Clients: {e}")
    
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
        """Entfernt Client und aktualisiert Speicher"""
        if client_id in self.clients:
            del self.clients[client_id]
            
            # Nachrücklogik für IDs
            sorted_ids = sorted(int(k) for k in self.clients.keys() if k.isdigit())
            self.clients = {
                str(new_id): self.clients[str(old_id)]
                for new_id, old_id in enumerate(sorted_ids)
            }
            
            self.save_active_clients()  # Sofort speichern


    def load_or_generate_server_publickey(self):
        """
        Lädt den öffentlichen Schlüssel des Servers aus einer Datei oder generiert einen neuen.
        """
        if os.path.exists("server_public_key.pem"):
            # Lade den öffentlichen Schlüssel aus der Datei
            with open("server_public_key.pem", "r") as pubHandle:
                return pubHandle.read()
        else:
            # Generiere einen neuen öffentlichen Schlüssel
            bits = 4096
            new_key = RSA.gen_key(bits, 65537)
            memory = BIO.MemoryBuffer()
            new_key.save_pub_key_bio(memory)
            public_key = memory.getvalue().decode('utf-8')

            # Speichere den öffentlichen Schlüssel in einer Datei
            with open("server_public_key.pem", "w") as pubHandle:
                pubHandle.write(public_key)

                return public_key

    def get_ordered_keys(self):
        """Gibt Server-Key + geordnete Client-Keys zurück"""
        server_key = self.server_public_key
        client_keys = [
            self.clients[client_id]['public_key']
            for client_id in sorted(self.clients.keys(), key=int)
            if 'public_key' in self.clients[client_id]
        ]
        return [server_key] + client_keys
    def process_merkle_tree(self, client_name, client_socket):
        """Verarbeitet Merkle Tree für Schlüsselverifikation"""
        try:
            # 1. Sammle alle Schlüssel und dedupliziere
            raw_keys = [self.server_public_key] + [
                c['public_key'] for c in self.clients.values() 
                if c.get('public_key')
            ]
            
            unique_keys = []
            seen_keys = set()
            for key in raw_keys:
                normalized = normalize_key(key)
                if normalized and normalized not in seen_keys:
                    seen_keys.add(normalized)
                    unique_keys.append(key)
            
            print(f"[Server] Unique keys for Merkle Tree: {len(unique_keys)}")
            
            # 2. Normalisierung
            normalized_keys = []
            for key in unique_keys:
                normalized = normalize_key(key)
                if normalized:
                    normalized_keys.append(normalized)
            
            if len(normalized_keys) < 1:
                raise ValueError("No valid keys found for Merkle tree")
            
            # 3. Zusammenführung mit Trennzeichen
            merged = "|||".join(normalized_keys)
            print(f"[Server] Merged keys (len={len(merged)}): {merged[:100]}...")
            
            # 4. Merkle Root berechnen
            merkle_root = build_merkle_tree([merged])
            print(f"[Server] Final Merkle Root: {merkle_root}")
            
            # 5. Nachricht senden
            merkle_msg = self.build_sip_message("MESSAGE", client_name, {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": json.dumps(unique_keys)  # Original unnormalisierte, aber deduplizierte Keys
            })
            send_frame(client_socket, merkle_msg)
    
        except Exception as e:
            print(f"Fehler beim Merkle-Tree: {str(e)}")
            raise
    
    def handle_communication_loop(self, client_name, client_socket):
        """Original implementation with reliable ping-pong"""
        client_id = next((k for k, v in self.clients.items() if v['name'] == client_name), None)
        if not client_id:
            print(f"Client {client_name} not found in registry")
            return
    
        while True:
            try:
                # Receive data with reasonable timeout
                client_socket.settimeout(60)  # 1 minute timeout
                data = recv_frame(client_socket)
                
                if not data:
                    print(f"Empty data from {client_name}, disconnecting")
                    break
    
                msg = self.parse_sip_message(data)
                if not msg:
                    continue
    
                # Handle PONG responses
                if msg.get('method') == "MESSAGE" and msg.get('custom_data', {}).get("PONG"):
                    self.clients[client_id]['last_pong'] = time.time()
                    print(f"Pong from {client_name}")
                    continue
    
                # Handle regular messages
                print(f"Message from {client_name}: {msg.get('method')}")
    
                # Send ping every 50 seconds if no activity
                if time.time() - self.clients[client_id].get('last_pong', 0) > 50:
                    ping_msg = self.build_sip_message("MESSAGE", client_name, {"PING": "1"})
                    with self.client_send_lock:
                        send_frame(client_socket, ping_msg)
                    print(f"Sent ping to {client_name}")
    
            except socket.timeout:
                print(f"No activity from {client_name} for 60s, disconnecting")
                break
            except ConnectionResetError:
                print(f"Connection reset by {client_name}")
                break
            except Exception as e:
                print(f"Error with {client_name}: {str(e)}")
                break
    
        # Cleanup
        self.remove_client(client_id)
        client_socket.close()
    def handle_client(self, client_socket):
        client_address = client_socket.getpeername()
        print(f"\n[Server] Neue Verbindung von {client_address}")
        
        try:
            client_socket.settimeout(300.0)
            register_data = recv_frame(client_socket)
            
            if not register_data:
                print("Empty frame received")
                return
    
            print(f"[DEBUG] Raw received data:\n{register_data[:500]}...")  # Begrenzte Ausgabe
    
            # Phase 1: SIP-Nachricht parsen
            sip_msg = self.parse_sip_message(register_data)
            if not sip_msg:
                print("Ungültige SIP-Nachricht")
                client_socket.close()
                return
    
            print(f"Geparste Nachricht:\nHeaders: {sip_msg.get('headers', {})}\nCustom Data: {sip_msg.get('custom_data', {})}")
    
            # Phase 2: Client-Name extrahieren
            from_header = sip_msg['headers'].get('FROM', '')
            client_name_match = re.search(r'<sip:(.*?)@', from_header)
            if not client_name_match:
                print("Kein Client-Name gefunden")
                client_socket.close()
                return
            client_name = client_name_match.group(1)
    
            # Phase 3: Public Key extrahieren (mit Prioritäten)
            client_pubkey = None
            
            # 1. Versuch: Aus custom_data
            if 'custom_data' in sip_msg:
                client_pubkey = sip_msg['custom_data'].get('PUBLIC_KEY', '').strip()
            
            # 2. Versuch: Rohe Extraktion aus Body
            if not client_pubkey or '-----END PUBLIC KEY-----' not in client_pubkey:
                key_start = register_data.find('-----BEGIN PUBLIC KEY-----')
                if key_start != -1:
                    key_end = register_data.find('-----END PUBLIC KEY-----', key_start)
                    if key_end != -1:
                        client_pubkey = register_data[key_start:key_end + len('-----END PUBLIC KEY-----')]
    
            # 3. Validierung
            if not client_pubkey or '-----END PUBLIC KEY-----' not in client_pubkey:
                print(f"[ERROR] Ungültiger Client-Key erhalten:\n{client_pubkey[:100]}...")
                client_socket.close()
                return
    
            print(f"[DEBUG] Validierter Client-Key (Länge: {len(client_pubkey)}):\n{client_pubkey[:50]}...")
    
            # Phase 4: Client-Registrierung
            client_id = self.generate_client_id()
            self.clients[client_id] = {
                'name': client_name,
                'public_key': client_pubkey,
                'socket': client_socket,
                'ip': client_address[0],
                'port': client_address[1]
            }
            self.save_active_clients()
    
            # Phase 5: Server-Antwort senden
            response = self.build_sip_message("SIP/2.0 200 OK", client_name, {
                "SERVER_PUBLIC_KEY": self.server_public_key,
                "CLIENT_ID": client_id
            })
                        
            send_frame(client_socket, response)
            
            # Phase 6: Merkle Tree verarbeiten (synchron)
            self.process_merkle_tree(client_name, client_socket)
            
            # Phase 7: Phonebook asynchron broadcasten (nicht blockierend)
            threading.Thread(target=self.broadcast_phonebook, daemon=True).start()
            
            # Phase 8: Hauptkommunikationsschleife starten (blockierend)
            self.handle_communication_loop(client_name, client_socket)

            
        except Exception as e:
            print(f"Fehler bei der Kommunikation mit {client_address}: {str(e)}")
        finally:
            client_socket.close()
        

    def update_phonebook(self):
        """Aktualisiert das Telefonbuch mit sortierten Client-Daten"""
        self.phonebook = sorted(
            [(int(cid), data) for cid, data in self.clients.items() if cid.isdigit()],
            key=lambda x: x[0]
        )
        print("Telefonbuch aktualisiert:")
        for cid, data in self.phonebook:
            print(f"{cid}: {data['name']}")
    
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
            with open("private_key.pem", "rb") as f:
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
    def broadcast_phonebook(self):
        """Broadcastet das aktuelle Phonebook an alle verbundenen Clients mit erweitertem Debugging und Fehlerbehandlung"""
        print("\n=== SERVER BROADCAST PHONEBOOK START ===")
        print(f"[DEBUG] Starting phonebook broadcast at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        def _broadcast_to_client(client_id, client_data, phonebook_data):
            """Hilfsfunktion für den Versand an einzelne Clients"""
            try:
                print(f"\n[DEBUG] Preparing broadcast for client {client_id} ({client_data.get('name', 'no-name')})")
                
                # 1. Validierung der Client-Daten
                if not client_data.get('public_key'):
                    print("[ERROR] Client has no public key")
                    return False
                    
                if not client_data.get('socket'):
                    print("[ERROR] Client has no active socket")
                    return False
    
                # 2. Generiere neues 48-Byte Geheimnis
                print("[DEBUG] Generating new secret...")
                try:
                    raw_secret = self.generate_secret()
                    if len(raw_secret) != 48:
                        print(f"[ERROR] Invalid secret length: {len(raw_secret)}")
                        return False
                    secret = b"+++secret+++" + raw_secret  # Now total is 59 bytes
                except Exception as e:
                    print(f"[ERROR] Secret generation failed: {str(e)}")
                    return False
    
                # 3. Lade Client Public Key
                print("[DEBUG] Loading client public key...")
                try:
                    client_pubkey = RSA.load_pub_key_bio(
                        BIO.MemoryBuffer(client_data['public_key'].encode()))
                    print("[DEBUG] Client public key loaded successfully")
                    
                    # Teste den Key mit einer kleinen Verschlüsselung
                    test_enc = client_pubkey.public_encrypt(b'test', RSA.pkcs1_padding)
                    if not test_enc:
                        print("[ERROR] Client public key test failed")
                        return False
                except Exception as e:
                    print(f"[ERROR] Failed to load/validate client public key: {str(e)}")
                    traceback.print_exc()
                    return False
    
                # 4. Verschlüssele das Secret
                print("[DEBUG] Encrypting secret with client public key...")
                try:
                    encrypted_secret = client_pubkey.public_encrypt(secret, RSA.pkcs1_padding)
                    if len(encrypted_secret) != 512:  # 4096-bit RSA sollte 512 Bytes ergeben
                        print(f"[ERROR] Invalid encrypted secret length: {len(encrypted_secret)}")
                        return False
                    print(f"[DEBUG] Secret encrypted (len={len(encrypted_secret)})")
                except Exception as e:
                    print(f"[ERROR] Secret encryption failed: {str(e)}")
                    return False
    
                # 5. Verschlüssele das Phonebook mit AES
                print("[DEBUG] Encrypting phonebook with AES...")
                try:
                    iv = secret[11:27]  # 16 Bytes IV (nach dem Header)
                    aes_key = secret[27:59]  # 32 Bytes AES-256 Schlüssel
                    
                    print(f"[DEBUG] AES IV: {iv.hex(' ')}")
                    print(f"[DEBUG] AES Key: {aes_key[:8].hex(' ')}...")
                    
                    cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
                    plaintext = json.dumps(phonebook_data).encode('utf-8')
                    print(f"[DEBUG] Plaintext (len={len(plaintext)}): {plaintext[:100]}...")
                    
                    encrypted_phonebook = cipher.update(plaintext) + cipher.final()
                    if not encrypted_phonebook:
                        print("[ERROR] Phonebook encryption returned empty result")
                        return False
                        
                    print(f"[DEBUG] Encrypted phonebook (len={len(encrypted_phonebook)})")
                except Exception as e:
                    print(f"[ERROR] Phonebook encryption failed: {str(e)}")
                    traceback.print_exc()
                    return False
    
                # 6. Baue SIP-Nachricht
                print("[DEBUG] Building SIP message...")
                try:
                    message_data = {
                        "MESSAGE_TYPE": "PHONEBOOK_UPDATE",
                        "TIMESTAMP": int(time.time()),
                        "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode('utf-8'),
                        "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode('utf-8'),
                        "CLIENT_ID": client_id
                    }
                    
                    response = self.build_sip_message(
                        "MESSAGE",
                        client_data['name'],
                        message_data
                    )
                    
                    print(f"[DEBUG] SIP message size: {len(response)} bytes")
                except Exception as e:
                    print(f"[ERROR] Message building failed: {str(e)}")
                    return False
    
                # 7. Sende Nachricht
                print("[DEBUG] Sending message to client...")
                try:
                    with self.client_send_lock:
                        client_socket = client_data['socket']
                        if client_socket:
                            client_socket.settimeout(10.0)
                            send_frame(client_socket, response)
                            print("[DEBUG] Message sent successfully")
                            return True
                        else:
                            print("[ERROR] Client socket not available")
                            return False
                except Exception as e:
                    print(f"[ERROR] Message sending failed: {str(e)}")
                    return False
                    
            except Exception as e:
                print(f"[CRITICAL] Broadcast to {client_id} failed: {str(e)}")
                traceback.print_exc()
                return False
    
        def _broadcast():
            """Haupt-Broadcast-Funktion"""
            try:
                print("\n[DEBUG] Starting broadcast process...")
                
                # 1. Aktive Clients filtern
                active_clients = {
                    cid: data for cid, data in self.clients.items() 
                    if data.get('socket') is not None and cid.isdigit()
                }
                
                print(f"[DEBUG] Found {len(active_clients)} active clients")
                
                if not active_clients:
                    print("[DEBUG] No active clients for broadcast")
                    return
                    
                # 2. Telefonbuchdaten vorbereiten
                print("[DEBUG] Preparing phonebook data...")
                phonebook_data = []
                for cid, data in sorted(active_clients.items(), key=lambda x: int(x[0])):
                    if not data.get('name') or data['name'].lower() == 'server':
                        continue
                        
                    print(f"[DEBUG] Adding client {cid}: {data['name']}")
                    
                    phonebook_data.append({
                        'id': cid,
                        'name': data['name'],
                        'ip': data['ip'],
                        'port': data['port'],
                        'public_key': shorten_public_key(data['public_key'])
                    })
                
                print(f"[DEBUG] Prepared phonebook with {len(phonebook_data)} entries")
                
                if not phonebook_data:
                    print("[DEBUG] No valid client entries to broadcast")
                    return
                
                # 3. Paralleler Versand mit Thread-Pool
                print("[DEBUG] Starting parallel broadcast...")
                success_count = 0
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = {
                        executor.submit(_broadcast_to_client, cid, data, phonebook_data): cid
                        for cid, data in active_clients.items()
                    }
                    
                    for future in as_completed(futures, timeout=15.0):
                        cid = futures[future]
                        try:
                            if future.result():
                                success_count += 1
                            else:
                                print(f"[WARNING] Failed to send to client {cid}")
                        except Exception as e:
                            print(f"[ERROR] Broadcast failed for {cid}: {str(e)}")
                            traceback.print_exc()
                
                print(f"[DEBUG] Broadcast completed - {success_count}/{len(active_clients)} successful")
                
            except Exception as e:
                print(f"[CRITICAL] Broadcast process failed: {str(e)}")
                traceback.print_exc()
    
        # Starte den Broadcast in einem neuen Thread
        print("[DEBUG] Starting broadcast thread...")
        threading.Thread(target=_broadcast, daemon=True).start()
        print("=== SERVER BROADCAST PHONEBOOK END ===")
def load_server_publickey():
    if not os.path.exists("server_public_key.pem"):
        bits = 4096
        new_key = RSA.gen_key(bits, 65537)
        memory = BIO.MemoryBuffer()
        new_key.save_pub_key_bio(memory)
        public_key = memory.getvalue()
        with open("server_public_key.pem", "wb") as pubHandle:
            pubHandle.write(public_key)
    else:
        with open("server_public_key.pem", "rb") as pubHandle:
            public_key = pubHandle.read()
    return public_key.decode('utf-8')


class SecureVault:
    def __init__(self):
        self.lib = None
        self.vault = None
        self.gen_lib = None
        self._load_libraries()
        
    def _load_libraries(self):
        """Lädt alle benötigten Bibliotheken für die aktuelle Architektur"""
        arch = platform.machine().lower()
        
        # Mapping für die Auslagerungsbibliotheken
        vault_lib_mapping = {
            ('x86_64', 'amd64'): "libauslagern_x86_64.so",
            ('aarch64', 'arm64'): "libauslagern_arm64.so",
            ('armv7l',): "libauslagern_armv7.so"
        }
        
        # Mapping für die Generierungsbibliotheken
        gen_lib_mapping = {
            ('x86_64', 'amd64'): "libsecuregen_x86_64.so",
            ('aarch64', 'arm64'): "libsecuregen_arm64.so",
            ('armv7l',): "libsecuregen_armv7.so"
        }
        
        # Lade Auslagerungsbibliothek
        for arch_patterns, lib_name in vault_lib_mapping.items():
            if arch in arch_patterns:
                try:
                    self.lib = ctypes.CDLL(f"./{lib_name}")
                    print(f"Successfully loaded vault lib: {lib_name}")
                    break
                except Exception as e:
                    print(f"Error loading vault lib {lib_name}: {str(e)}")
        else:
            raise RuntimeError(f"Unsupported architecture for vault: {arch}")
        
        # Lade Generierungsbibliothek
        for arch_patterns, lib_name in gen_lib_mapping.items():
            if arch in arch_patterns:
                try:
                    self.gen_lib = ctypes.CDLL(f"./{lib_name}")
                    print(f"Successfully loaded generator lib: {lib_name}")
                    break
                except Exception as e:
                    print(f"Error loading generator lib {lib_name}: {str(e)}")
        else:
            raise RuntimeError(f"Unsupported architecture for generator: {arch}")
        
        # Funktionen definieren
        self.lib.vault_create.restype = ctypes.c_void_p
        self.lib.vault_load.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.vault_retrieve.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.vault_wipe.argtypes = [ctypes.c_void_p]
        
        self.gen_lib.generate_secret.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        self.gen_lib.generate_secret.restype = None
    
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

if __name__ == "__main__":
    try:
        print("main0")
        server = Server()
        print("main1")
        server.start()
    except Exception as e:
        print(f"Kritischer Fehler: {e}")
