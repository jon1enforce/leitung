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
import select
import binascii
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




class Server:
    def __init__(self, host='0.0.0.0', port=5060):
        self.host = host
        self.port = port
        self.clients = {}
        self.client_secrets = {}
        self.server_public_key = load_server_publickey()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.all_public_keys = [self.server_public_key]
        self.client_send_lock = Lock()
        self.name_lock = Lock()
        self.key_lock = threading.Lock()
        
        # Neue Attribute hinzufügen
        self.merkle_lock = threading.Lock()  # Für Merkle Tree Operationen
        self.last_merkle_root = None
        self.last_merkle_calculation = 0
        self.phonebook = []  # Für Phonebook-Daten
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
    def get_merkle_root(self):
        """
        Gibt den aktuellen Merkle Root zurück
        Verwendet Caching für 60 Sekunden zur Performance-Optimierung
        """
        with self.merkle_lock:
            # Cache ist nur 60 Sekunden gültig
            current_time = time.time()
            if (current_time - self.last_merkle_calculation > 60) or not self.last_merkle_root:
                print("\n[Server] Calculating new Merkle Tree...")
                
                with self.key_lock:
                    current_keys = self.all_public_keys.copy()
                
                # Debug-Ausgabe
                print(f"Using {len(current_keys)} keys:")
                for i, key in enumerate(current_keys):
                    print(f"Key {i}: {shorten_public_key(key)[:30]}...")
                
                self.last_merkle_root = build_merkle_tree_from_keys(current_keys)
                self.last_merkle_calculation = current_time
                print(f"New Merkle Root: {self.last_merkle_root}")
            
            return self.last_merkle_root
    def update_key_list(self):
        """Aktualisiert die Liste aller öffentlichen Schlüssel"""
        with self.key_lock:
            # Server-Key bleibt immer an Position 0
            client_keys = [
                c['public_key'] for c in self.clients.values() 
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

    def build_sip_message(self, method, recipient, custom_data={}):
        """Ensure consistent key formatting in server responses"""
        # Convert ALL_KEYS to proper format if present
        if 'ALL_KEYS' in custom_data:
            keys = custom_data['ALL_KEYS']
            if isinstance(keys, list):
                # Ensure each key is properly formatted
                formatted_keys = []
                for key in keys:
                    if not isinstance(key, str):
                        key = str(key)
                    if not key.startswith('-----BEGIN PUBLIC KEY-----'):
                        key = f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"
                    formatted_keys.append(key)
                custom_data['ALL_KEYS'] = formatted_keys
        
        # Rest of the message building remains the same
        if any(isinstance(v, (dict, list)) for v in custom_data.values()):
            body = json.dumps(custom_data, separators=(',', ':'))
            content_type = "application/json"
        else:
            body = "\r\n".join(f"{k}: {v}" for k, v in custom_data.items())
            content_type = "text/plain"
        
        return (
            f"{method} sip:{recipient} SIP/2.0\r\n"
            f"From: <sip:server@{self.host}>\r\n"
            f"To: <sip:{recipient}>\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
            f"{body}"
        )

    def parse_sip_message(self, message):
        """Parse SIP-Nachrichten mit Header und Body"""
        if isinstance(message, bytes):
            try:
                message = message.decode('utf-8')
            except UnicodeDecodeError:
                return None

        message = message.strip()
        if not message:
            return None

        lines = [line.strip() for line in message.replace('\r\n', '\n').split('\n') if line.strip()]
        result = {'headers': {}, 'custom_data': {}}

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

        # Parse headers
        for line in lines[1:]:
            if ': ' in line:
                key, val = line.split(': ', 1)
                key = key.strip().upper()
                val = val.strip()
                
                if key == "CONTENT-LENGTH":
                    try:
                        result['content_length'] = int(val)
                    except ValueError:
                        pass
                elif key not in result['headers']:
                    result['headers'][key] = val

        # Parse body
        if 'content_length' in result and result['content_length'] > 0:
            body_lines = lines[len(result['headers']) + 1:]
            body = '\n'.join(body_lines)
            
            try:
                result['custom_data'] = dict(
                    line.split(': ', 1)
                    for line in body.splitlines()
                    if ': ' in line
                )
            except Exception:
                result['body'] = body

        return result if ('method' in result or 'status_code' in result) else None


    def _register_client(self, sip_data):
        """Registriert einen neuen Client"""
        try:
            client_name = sip_data['client_info']
            client_pubkey = sip_data['custom_data'].get('PUBLIC_KEY')
            
            if not client_name or not client_pubkey:
                return False
                
            if not self.validate_client_name(client_name):
                return False
                
            client_id = self.generate_client_id()
            self.clients[client_id] = {
                'name': client_name,
                'public_key': client_pubkey,
                'socket': None,
                'ip': None,
                'port': None,
                'login_time': time.time()
            }
            
            return True
        except Exception as e:
            print(f"Fehler bei Client-Registrierung: {e}")
            return False

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
            self.clients = self.load_active_clients()
            print(f"Geladene Clients: {len(self.clients)}")

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
                            args=(client_socket,),
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
            print("\nSpeichere Client-Daten...")
            active_clients = {
                cid: {k: v for k, v in data.items() if k != 'socket'} 
                for cid, data in self.clients.items() 
                if data.get('socket') is not None
            }
            
            try:
                with open("active_clients.json", "w") as f:
                    json.dump(active_clients, f, indent=2)
                print(f"{len(active_clients)} Clients gespeichert")
            except Exception as e:
                print(f"Fehler beim Speichern: {e}")
            
            print("Schließe Verbindungen...")
            for client_id, client_data in list(self.clients.items()):
                if client_data.get('socket'):
                    try:
                        client_data['socket'].close()
                    except:
                        pass
            
            for sock in [main_socket, alt_socket]:
                try:
                    sock.close()
                except:
                    pass
            
            print("Server beendet")

    # Weitere Methoden (generate_client_id, validate_client_name, handle_client, etc.) bleiben gleich
    # ...
    def generate_client_id(self):
        """Generiert sequentielle Client-IDs mit Nachrücklogik basierend auf Login-Zeit"""
        if not self.clients:
            return "0"
        
        # Finde alle vorhandenen IDs und sortiere nach Login-Zeit
        sorted_clients = sorted(
            (cid for cid in self.clients.keys() if cid.isdigit()),
            key=lambda x: self.clients[x].get('login_time', 0)
        )
        
        # Finde Lücken oder nächste freie ID
        for i, expected_id in enumerate(range(len(sorted_clients) + 1)):
            if i >= len(sorted_clients) or str(expected_id) != sorted_clients[i]:
                return str(expected_id)
        
        return str(len(sorted_clients))

    def validate_client_name(self, name):
        """Überprüft ob der Client-Name eindeutig ist"""
        if not name or len(name) < 2:
            return False
            
        with self.name_lock:
            return not any(
                c['name'].lower() == name.lower() 
                for c in self.clients.values()
            )

    def handle_client(self, client_socket):
        """Vollständige Client-Behandlung - Kompatibel mit start_connection"""
        client_address = client_socket.getpeername()
        print(f"\n[Server] Neue Verbindung von {client_address}")
        client_id = None
        client_name = None

        try:
            # 1. Registration empfangen (mit Timeout)
            client_socket.settimeout(30.0)
            print(f"[SERVER] Warte auf Registration von {client_address}")
            
            register_data = recv_frame(client_socket)
            if not register_data:
                print("[SERVER] Keine Registrierungsdaten empfangen")
                return

            print(f"[SERVER] Empfangene Daten: {len(register_data)} bytes")
            
            # 2. SIP-Nachricht parsen
            if isinstance(register_data, bytes):
                try:
                    register_data = register_data.decode('utf-8')
                    print("[SERVER] Daten als UTF-8 decodiert")
                except UnicodeDecodeError:
                    print("[SERVER] Konnte Daten nicht als UTF-8 decodieren")
                    return

            # 3. SIP-Nachricht parsen
            sip_msg = self.parse_sip_message(register_data)
            if not sip_msg:
                print("[SERVER] Ungültige SIP-Nachricht")
                return

            # 4. Client-Identifikation
            from_header = sip_msg['headers'].get('From', sip_msg['headers'].get('FROM', ''))
            client_name_match = re.search(r'<sip:(.*?)@', from_header)
            if not client_name_match:
                print(f"[SERVER] Kein Client-Name in FROM-Header: {from_header}")
                return
                
            client_name = client_name_match.group(1)
            print(f"[SERVER] Client-Name: {client_name}")

            # 5. Public Key extrahieren
            client_pubkey = None
            
            if 'content' in sip_msg and sip_msg['content']:
                client_pubkey = sip_msg['content'].strip()
            
            if not client_pubkey:
                key_match = re.search(r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', 
                                     register_data, re.DOTALL)
                if key_match:
                    client_pubkey = key_match.group(0).strip()

            if not client_pubkey or '-----BEGIN PUBLIC KEY-----' not in client_pubkey:
                print("[SERVER] Kein gültiger Public Key gefunden")
                return

            # 6. Client registrieren und ALLE Keys sammeln
            with self.key_lock:
                client_id = self.generate_client_id()
                self.clients[client_id] = {
                    'name': client_name,
                    'public_key': client_pubkey,
                    'socket': client_socket,
                    'ip': client_address[0],
                    'port': client_address[1],
                    'login_time': time.time(),
                    'last_update': time.time()
                }
                
                # ALLE Public Keys sammeln: Server + alle Clients
                all_public_keys = [self.server_public_key]  # Server Key zuerst
                for cid, client_info in self.clients.items():
                    all_public_keys.append(client_info['public_key'])
                
                self.all_public_keys = all_public_keys
                print(f"[SERVER] Gesamte Keys: {len(all_public_keys)} (Server + {len(self.clients)} Clients)")

            # 7. Merkle Root berechnen
            merkle_root = build_merkle_tree_from_keys(all_public_keys)
            print(f"[SERVER] Merkle Root: {merkle_root[:20]}...")

            # 8. ERSTE ANTWORT: Server Public Key und Client ID
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

            # 9. ZWEITE ANTWORT: Merkle Tree Daten
            second_response_data = {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": all_public_keys  # Liste aller Keys in Reihenfolge
            }
            
            second_response_msg = self.build_sip_message("200 OK", client_name, second_response_data)
            print(f"[SERVER] Sende zweite Antwort: {len(second_response_msg)} bytes")
            
            send_frame(client_socket, second_response_msg.encode('utf-8'))
            print("[SERVER] Zweite Antwort erfolgreich gesendet")
            # 10. Hauptkommunikationsschleife mit RAW Socket-Reading
            print(f"[SERVER] Starte Hauptloop für {client_name}")
            client_socket.settimeout(1.0)
            last_activity = time.time()
            
            # Puffer für teilweise empfangene Daten
            buffer = b''
            # Queue-Initialisierung mit DoS-Schutz
            if not hasattr(self, '_message_queue'):
                self._message_queue = []
                self._processing_queue = False
                self._queue_size_limit = 120  # Max 120 Nachrichten
                self._last_minute_check = time.time()
                self._messages_this_minute = 0
            while True:
                try:
                    # RAW Socket lesen (ohne Framing)
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            print(f"[SERVER] {client_name} hat Verbindung getrennt")
                            break
                        
                        last_activity = time.time()
                        buffer += data
                        
                        # Versuche, komplette Nachrichten aus dem Buffer zu parsen
                        while buffer:
                            # Prüfe auf Framing-Header (4 Bytes Länge)
                            if len(buffer) >= 4:
                                # Extrahiere Länge aus Header
                                length = struct.unpack('!I', buffer[:4])[0]
                                
                                # Sicherheitscheck
                                if length > 10 * 1024 * 1024:  # 10MB max
                                    print(f"[SECURITY] Frame zu groß: {length} bytes, verwerfe")
                                    buffer = b''  # Buffer leeren
                                    break
                                    
                                if len(buffer) >= 4 + length:
                                    # Vollständige Nachricht empfangen
                                    frame_data = buffer[4:4+length]
                                    buffer = buffer[4+length:]
                                    
                                    # DOS-Schutz: Prüfe auf zu viele Nachrichten
                                    current_time = time.time()
                                    if current_time - self._last_minute_check > 60:
                                        self._last_minute_check = current_time
                                        self._messages_this_minute = 0
                                    
                                    if self._messages_this_minute >= self._queue_size_limit:
                                        print(f"[SECURITY] Too many messages from {client_name}, ignoring")
                                        continue
                                    
                                    self._messages_this_minute += 1
                                    
                                    # Nachricht zur Queue hinzufügen
                                    self._message_queue.append({
                                        'type': 'frame_data',
                                        'data': frame_data,
                                        'client_socket': client_socket,
                                        'client_name': client_name
                                    })
                                    
                                    # Queue verarbeiten, falls nicht bereits in Bearbeitung
                                    if not self._processing_queue:
                                        self._process_queue()
                                    
                                else:
                                    # Noch nicht genug Daten für vollständigen Frame
                                    break
                            else:
                                # Noch nicht genug Daten für Header
                                break
                                
                    except socket.timeout:
                        # Timeout ist normal, prüfe auf Inaktivität
                        if time.time() - last_activity > 60:
                            print(f"[SERVER] {client_name} inaktiv, trenne Verbindung")
                            break
                        continue

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
            # Cleanup
            print(f"[SERVER] Cleanup für {client_name if client_name else 'unknown'}")
            
            if client_id and client_id in self.clients:
                with self.key_lock:
                    if client_id in self.clients:
                        del self.clients[client_id]
                        self.update_key_list()
            
            try:
                client_socket.close()
            except:
                pass
    def _process_queue(self):
        """Verarbeitet Nachrichten aus der Queue in der originalen Reihenfolge"""
        self._processing_queue = True
        
        try:
            while self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                if queue_item['type'] == 'frame_data':
                    frame_data = queue_item['data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    try:
                        # Versuche UTF-8 Decoding für SIP Nachrichten
                        try:
                            message = frame_data.decode('utf-8')
                            print(f"[SERVER] Empfangen von {client_name}: {len(message)} bytes")
                            
                            # Zeige nur die ersten 200 Zeichen für Debugging
                            debug_msg = message[:200] + "..." if len(message) > 200 else message
                            print(f"[SERVER] Nachricht von {client_name}:\n{debug_msg}")
                            
                            # Parse SIP Message
                            msg = self.parse_sip_message(message)
                            if msg:
                                # Ping Handling
                                if msg.get('headers', {}).get('PING') == 'true':
                                    print(f"[PING] Empfangen von {client_name}")
                                    # PONG zur Queue hinzufügen
                                    pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                                    self._message_queue.append({
                                        'type': 'send_response',
                                        'response': pong_response,
                                        'client_socket': client_socket,
                                        'client_name': client_name
                                    })
                                    continue
                                    
                                # ENCRYPTED_SECRET Handling (für verschlüsselte Telefonbücher)
                                if 'ENCRYPTED_SECRET' in msg.get('custom_data', {}):
                                    print(f"[ENCRYPTED] Empfangen von {client_name}")
                                    self._message_queue.append({
                                        'type': 'process_encrypted',
                                        'sip_data': msg,
                                        'client_socket': client_socket,
                                        'client_name': client_name
                                    })
                                    continue
                                    
                                # Normale SIP Nachrichten verarbeiten
                                if message.startswith(('MESSAGE', 'SIP/2.0')):
                                    self._message_queue.append({
                                        'type': 'process_sip',
                                        'message': message,
                                        'sip_data': msg,
                                        'client_socket': client_socket,
                                        'client_name': client_name
                                    })
                                    continue
                        
                        except UnicodeDecodeError:
                            print(f"[SERVER] Binärdaten von {client_name}: {len(frame_data)} bytes")
                            # Framed binary data (möglicherweise verschlüsselt)
                            if len(frame_data) >= 512:
                                self._message_queue.append({
                                    'type': 'process_encrypted_binary',
                                    'binary_data': frame_data,
                                    'client_socket': client_socket,
                                    'client_name': client_name
                                })
                            continue
                            
                    except Exception as e:
                        print(f"[QUEUE ERROR] Frame processing failed: {str(e)}")
                        import traceback
                        traceback.print_exc()
                
                elif queue_item['type'] == 'send_response':
                    # Antwort senden
                    response = queue_item['response']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item.get('client_name', 'unknown')
                    try:
                        send_frame(client_socket, response.encode('utf-8'))
                        if "PONG" in response:
                            print(f"[PONG] Gesendet an {client_name}")
                        elif "ENCRYPTED" in response:
                            print(f"[ENCRYPTED] Antwort gesendet an {client_name}")
                    except Exception as e:
                        print(f"[QUEUE ERROR] Send failed for {client_name}: {str(e)}")
                
                elif queue_item['type'] == 'process_sip':
                    # Normale SIP Nachricht verarbeiten
                    message = queue_item['message']
                    sip_data = queue_item['sip_data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    try:
                        # Client Secret Handling
                        if 'CLIENT_SECRET' in sip_data.get('custom_data', {}):
                            encrypted_secret = base64.b64decode(sip_data['custom_data']['CLIENT_SECRET'])
                            # Finde client_id basierend auf client_name
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                if self.store_client_secret(client_id, encrypted_secret):
                                    print(f"[SECRET] Erfolgreich gespeichert für {client_name}")
                                else:
                                    print(f"[SECRET] Fehler beim Speichern für {client_name}")
                        
                        # Call Setup Handling
                        elif 'CALL_SETUP' in sip_data.get('custom_data', {}):
                            call_data = sip_data['custom_data']
                            if call_data.get('CALL_SETUP') == 'request':
                                caller_id = call_data.get('CALLER_ID')
                                callee_id = call_data.get('CALLEE_ID')
                                if caller_id and callee_id:
                                    if self.initiate_call_between_clients(caller_id, callee_id):
                                        print(f"[CALL] Vermittelt zwischen {caller_id} und {callee_id}")
                                    else:
                                        print(f"[CALL] Fehler bei Vermittlung")
                        
                        # Phonebook Request Handling
                        elif 'PHONEBOOK_REQUEST' in sip_data.get('custom_data', {}):
                            # Finde client_id
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                # Sende Phonebook an Client
                                if self.send_phonebook(client_id):
                                    print(f"[PHONEBOOK] Gesendet an {client_name}")
                                else:
                                    print(f"[PHONEBOOK] Fehler beim Senden an {client_name}")
                        
                    except Exception as e:
                        print(f"[QUEUE ERROR] SIP processing failed for {client_name}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                
                elif queue_item['type'] == 'process_encrypted':
                    # Verschlüsselte SIP Nachricht verarbeiten
                    sip_data = queue_item['sip_data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    try:
                        # Verarbeite verschlüsselte Phonebook-Daten
                        if 'ENCRYPTED_SECRET' in sip_data.get('custom_data', {}) and 'ENCRYPTED_PHONEBOOK' in sip_data.get('custom_data', {}):
                            # Finde client_id für den Schlüssel
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id and client_id in self.client_secrets:
                                # Hier könntest du die entschlüsselten Daten verarbeiten
                                print(f"[ENCRYPTED] Empfangen von {client_name}, Client hat Secret")
                                
                                # Bestätigung senden
                                ack_msg = self.build_sip_message("200 OK", client_name, {
                                    "STATUS": "ENCRYPTED_DATA_RECEIVED",
                                    "TIMESTAMP": int(time.time())
                                })
                                self._message_queue.append({
                                    'type': 'send_response',
                                    'response': ack_msg,
                                    'client_socket': client_socket,
                                    'client_name': client_name
                                })
                        
                    except Exception as e:
                        print(f"[QUEUE ERROR] Encrypted processing failed for {client_name}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                
                elif queue_item['type'] == 'process_encrypted_binary':
                    # Framed binary data verarbeiten (könnte verschlüsselt sein)
                    binary_data = queue_item['binary_data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    try:
                        print(f"[BINARY] Empfangen {len(binary_data)} bytes von {client_name}")
                        
                        # Prüfe auf mögliche verschlüsselte Daten
                        if len(binary_data) >= 512:
                            # Könnte ein verschlüsseltes Secret sein
                            print(f"[BINARY] Möglicherweise verschlüsselte Daten von {client_name}")
                            
                            # Bestätigung senden
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "STATUS": "BINARY_DATA_RECEIVED",
                                "SIZE": len(binary_data),
                                "TIMESTAMP": int(time.time())
                            })
                            self._message_queue.append({
                                'type': 'send_response',
                                'response': ack_msg,
                                'client_socket': client_socket,
                                'client_name': client_name
                            })
                        
                    except Exception as e:
                        print(f"[QUEUE ERROR] Binary processing failed for {client_name}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                        
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self._processing_queue = False

    def prepare_phonebook_data(self):
        """Standardized phonebook data preparation"""
        with self.key_lock:
            return {
                'version': '2.0',
                'timestamp': int(time.time()),
                'merkle_root': self.get_merkle_root(),
                'clients': [
                    {
                        'id': cid,
                        'name': data['name'],
                        'public_key': data['public_key'],
                        'ip': data.get('ip', ''),
                        'port': data.get('port', 0),
                        'last_seen': data.get('login_time', 0)
                    }
                    for cid, data in sorted(self.clients.items(), key=lambda x: int(x[0]))
                    if 'public_key' in data
                ]
            }

    def broadcast_phonebook(self):
        """Sendet aktualisierte Phonebooks an alle verbundenen Clients"""
        try:
            # Berechne Merkle Root nur einmal
            merkle_root = self.get_merkle_root()
            phonebook_data = self.prepare_phonebook_data()
            
            success_count = 0
            total_clients = len(self.clients)
            
            print(f"\n[Broadcast] Starting for {total_clients} clients with Merkle Root: {merkle_root}")
            
            for client_id, client_data in list(self.clients.items()):
                if not client_data.get('socket'):
                    continue
                    
                try:
                    encrypted = self.encrypt_phonebook_data(
                        phonebook_data,
                        client_data['public_key']
                    )
                    
                    if 'error' in encrypted:
                        print(f"[WARNING] Encryption failed for {client_id}, sending plaintext")
                        message = self.build_sip_message(
                            "MESSAGE",
                            client_data['name'],
                            {
                                "status": "encryption_failed",
                                "data": phonebook_data,
                                "error": encrypted['error']
                            }
                        )
                    else:
                        message = self.build_sip_message(
                            "MESSAGE",
                            client_data['name'],
                            {
                                "encrypted_secret": encrypted['encrypted_secret'],
                                "encrypted_phonebook": encrypted['encrypted_phonebook'],
                                "merkle_root": merkle_root
                            }
                        )
                    
                    with self.client_send_lock:
                        send_frame(client_data['socket'], message)
                        success_count += 1
                        
                except Exception as e:
                    print(f"[ERROR] Failed to send to {client_id}: {str(e)}")
                    continue
                    
            print(f"[Broadcast] Completed - {success_count}/{total_clients} successful")
            return success_count
            
        except Exception as e:
            print(f"[CRITICAL] Broadcast failed: {str(e)}")
            traceback.print_exc()
            return 0

    def remove_client(self, client_id):
        """Entfernt Client und aktualisiert IDs mit Nachrücklogik"""
        if client_id not in self.clients:
            return
            
        # Client entfernen
        del self.clients[client_id]
        
        # IDs neu ordnen basierend auf Login-Zeit
        sorted_clients = sorted(
            self.clients.items(),
            key=lambda x: x[1].get('login_time', 0)
        )
        
        new_clients = {}
        for new_id, (old_id, client_data) in enumerate(sorted_clients):
            new_clients[str(new_id)] = client_data
            
        self.clients = new_clients
        self.save_active_clients()
        self.broadcast_phonebook()  # Aktualisiertes Phonebook senden

    def get_merkle_root(self):
        """
        Gibt den aktuellen Merkle Root zurück (mit Cache-Mechanismus)
        """
        with self.merkle_lock:
            # Cache ist nur 60 Sekunden gültig
            if (time.time() - self.last_merkle_calculation) > 60 or not self.last_merkle_root:
                print("\n[Server] Calculating new Merkle Tree...")
                with self.key_lock:
                    current_keys = self.all_public_keys.copy()
                
                # Debug-Ausgabe der Keys
                print(f"Using {len(current_keys)} keys for Merkle tree:")
                for i, key in enumerate(current_keys):
                    print(f"Key {i}: {shorten_public_key(key)[:30]}...")
                
                self.last_merkle_root = build_merkle_tree_from_keys(current_keys)
                self.last_merkle_calculation = time.time()
                print(f"New Merkle Root: {self.last_merkle_root}")
            
            return self.last_merkle_root
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
    def send_phonebook(self, client_id):
        """
        Sendet das verschlüsselte Phonebook an einen Client mit folgenden Schritten:
        1. Generiert ein neues 48-Byte Geheimnis mit Prefix '+++secret+++'
        2. Verschlüsselt das Geheimnis mit dem öffentlichen Schlüssel des Clients
        3. Verschlüsselt das Phonebook mit AES-256-CBC
        4. Sendet beides an den Client
        """
        try:
            with self.key_lock:
                client_data = self.clients.get(client_id)
                if not client_data or not client_data.get('socket'):
                    print(f"[ERROR] Client {client_id} nicht verbunden")
                    return False

                # 1. Generiere neues 48-Byte Geheimnis mit Prefix
                secret = b"+++secret+++" + self.generate_secret()
                if len(secret) != 60:  # 12 + 48 = 61 Bytes
                    raise ValueError("Invalid secret length")

                # 2. Verschlüssele Geheimnis mit Client Public Key
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_data['public_key'].encode()))
                encrypted_secret = pub_key.public_encrypt(secret, RSA.pkcs1_padding)

                # 3. Bereite Phonebook-Daten vor
                phonebook_data = {
                    'version': '2.0',
                    'timestamp': int(time.time()),
                    'merkle_root': self.get_merkle_root(),
                    'clients': [
                        {
                            'id': cid,
                            'name': data['name'],
                            'public_key': data['public_key'],
                            'ip': data.get('ip', ''),
                            'port': data.get('port', 0)
                        }
                        for cid, data in sorted(self.clients.items(), key=lambda x: int(x[0]))
                        if 'public_key' in data and cid != client_id
                    ]
                }

                # 4. AES Verschlüsselung mit dem Geheimnis (ohne Prefix)
                iv = secret[13:29]  # 16 Bytes IV
                aes_key = secret[29:61]  # 32 Bytes Key
                cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
                phonebook_str = json.dumps(phonebook_data, separators=(',', ':'))
                encrypted_phonebook = cipher.update(phonebook_str.encode()) + cipher.final()

                # 5. Nachricht erstellen
                message = self.build_sip_message(
                    "MESSAGE",
                    client_data['name'],
                    {
                        "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode(),
                        "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode(),
                        "CLIENT_ID": client_id,
                        "TIMESTAMP": phonebook_data['timestamp']
                    }
                )

                # 6. Speichere Geheimnis für diesen Client (ohne Prefix)
                self.client_secrets[client_id] = secret[13:]  # Nur die 48 Bytes

                # 7. Sende Nachricht
                with self.client_send_lock:
                    if client_data['socket'].fileno() == -1:
                        print(f"[ERROR] Socket geschlossen für Client {client_id}")
                        return False
                    
                    client_data['socket'].settimeout(10.0)
                    send_frame(client_data['socket'], message)
                    print(f"[SUCCESS] Phonebook an {client_data['name']} gesendet")
                    return True

        except Exception as e:
            print(f"[CRITICAL] Fehler in send_phonebook: {str(e)}")
            traceback.print_exc()
            return False

    def update_all_phonebooks(self):
        """
        Sendet aktualisierte Phonebooks an alle verbundenen Clients.
        Verwendet ThreadPool für parallele Verarbeitung.
        """
        with self.key_lock:
            client_ids = list(self.clients.keys())
        
        success_count = 0
        total_clients = len(client_ids)
        
        print(f"\n[UPDATE] Starting phonebook update for {total_clients} clients...")
        
        # Verwende ThreadPool für parallele Verarbeitung
        with ThreadPoolExecutor(max_workers=min(10, total_clients)) as executor:
            futures = {
                executor.submit(self.send_phonebook, cid): cid 
                for cid in client_ids
            }
            
            for future in as_completed(futures):
                client_id = futures[future]
                try:
                    if future.result():
                        success_count += 1
                except Exception as e:
                    print(f"[UPDATE ERROR] Client {client_id}: {str(e)}")
        
        print(f"[UPDATE] Completed - Success: {success_count}/{total_clients}")
        return success_count

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
                secret_buf[:] = os.urandom(48)
            
            # Speichere im Vault
            self.lib.vault_load(ctypes.c_void_p(self.vault), secret_buf)
            
            # Rückgabe als bytes
            return bytes(secret_buf)
        except Exception as e:
            print(f"Secret generation failed: {str(e)}")
            return None

    def retrieve_secret(self):
        """Holt das Geheimnis aus dem Vault"""
        try:
            buf = (ctypes.c_ubyte * 48)()
            self.lib.vault_retrieve(ctypes.c_void_p(self.vault), buf)
            return bytes(buf)
        except:
            return None

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
        print("main0")
        server = Server()
        print("main1")
        server.start()
    except Exception as e:
        print(f"Kritischer Fehler: {e}")
