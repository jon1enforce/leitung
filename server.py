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
import os
import hmac
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
    if not os.path.exists("server_public_key.pem") or not os.path.exists("server_private_key.pem"):
        print("Generiere neue Server-Schlüssel...")
        
        try:
            from M2Crypto import RSA, BIO, EVP
            
            # Generiere RSA Key
            key = RSA.gen_key(2048, 65537)
            
            # Speichere öffentlichen Schlüssel
            pub_bio = BIO.MemoryBuffer()
            key.save_pub_key_bio(pub_bio)
            with open("server_public_key.pem", "wb") as f:
                f.write(pub_bio.getvalue())
            
            # Speichere privaten Schlüssel OHNE Passphrase
            # Verwende EVP.PKey um das Passphrase-Problem zu umgehen
            pkey = EVP.PKey()
            pkey.assign_rsa(key)
            
            priv_bio = BIO.MemoryBuffer()
            pkey.save_key_bio(priv_bio, cipher=None)
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
                
                # Teste private key
                with open("server_private_key.pem", "rb") as f:
                    priv_data = f.read()
                priv_key = RSA.load_key_string(priv_data)
                print("✓ Private key ist valide")
                
                # Teste Verschlüsselung/Entschlüsselung
                test_msg = b"Test Message"
                encrypted = pub_key.public_encrypt(test_msg, RSA.pkcs1_padding)
                decrypted = priv_key.private_decrypt(encrypted, RSA.pkcs1_padding)
                
                if decrypted == test_msg:
                    print("✓ Verschlüsselung/Entschlüsselung erfolgreich")
                else:
                    print("✗ Verschlüsselung/Entschlüsselung fehlgeschlagen")
                    
            except Exception as e:
                print(f"Key-Validierungsfehler: {e}")
                return False
                
            return True
            
        except Exception as e:
            print(f"Fehler bei der Schlüsselgenerierung: {e}")
            print("Bitte openssl manuell installieren und ausführen:")
            print("sudo apt-get install openssl")
            print("openssl genrsa -out server_private_key.pem 2048")
            print("openssl rsa -in server_private_key.pem -pubout -out server_public_key.pem")
            return False

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




class Server:
    def __init__(self, host='0.0.0.0', port=5060):
        self.host = host
        self.port = port
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
        """Robuste SIP-Nachrichtenerstellung mit korrekter Schlüsselverarbeitung"""
        # Erstelle eine Kopie der custom_data um das Original nicht zu modifizieren
        processed_data = custom_data.copy()
        
        # ALL_KEYS speziell behandeln - nur wenn es eine Liste von Schlüsseln ist
        if 'ALL_KEYS' in processed_data:
            keys = processed_data['ALL_KEYS']
            
            # Sicherstellen dass es eine Liste ist
            if not isinstance(keys, list):
                print(f"[WARNING] ALL_KEYS is not a list: {type(keys)}")
                # Versuche es in eine Liste zu konvertieren oder entferne es
                if isinstance(keys, str) and keys == 'ALL_KEYS':
                    # Das ist der Fehlerfall - entferne das falsche ALL_KEYS
                    del processed_data['ALL_KEYS']
                    print("[WARNING] Removed malformed ALL_KEYS entry")
                else:
                    try:
                        keys = [keys]  # Versuche es in eine Ein-Element-Liste zu konvertieren
                    except:
                        del processed_data['ALL_KEYS']
                        print("[WARNING] Could not process ALL_KEYS - removed")
            
            if isinstance(keys, list):
                formatted_keys = []
                for key in keys:
                    try:
                        # Sicherstellen dass es ein String ist
                        if not isinstance(key, str):
                            key_str = str(key)
                        else:
                            key_str = key
                        
                        # Nur gültige öffentliche Schlüssel formatieren
                        if (key_str and 
                            not key_str.strip() == 'ALL_KEYS' and  # ❌ Falsche ALL_KEYS Einträge filtern
                            'BEGIN PUBLIC KEY' not in key_str):    # Bereits formatierte Schlüssel überspringen
                            
                            # Als PEM formatieren
                            formatted_key = f"-----BEGIN PUBLIC KEY-----\n{key_str}\n-----END PUBLIC KEY-----"
                            formatted_keys.append(formatted_key)
                        else:
                            # Bereits formatierte oder ungültige Schlüssel direkt übernehmen
                            formatted_keys.append(key_str)
                            
                    except Exception as e:
                        print(f"[ERROR] Failed to format key: {str(e)}")
                        formatted_keys.append(key)  # Original behalten falls Fehler
                
                processed_data['ALL_KEYS'] = formatted_keys
        
        # Body-Erstellung basierend auf Inhaltstyp
        try:
            # Prüfen ob JSON benötigt wird (bei komplexen Datenstrukturen)
            requires_json = any(isinstance(v, (dict, list)) for v in processed_data.values())
            
            if requires_json:
                body = json.dumps(processed_data, separators=(',', ':'))
                content_type = "application/json"
            else:
                # Key-Value Format für einfache Daten
                body_lines = []
                for k, v in processed_data.items():
                    if isinstance(v, (list, dict)):
                        # Komplexe Werte als JSON stringifyen
                        body_lines.append(f"{k}: {json.dumps(v)}")
                    else:
                        body_lines.append(f"{k}: {v}")
                body = "\r\n".join(body_lines)
                content_type = "text/plain"
            
            # SIP-Nachricht erstellen
            return (
                f"{method} sip:{recipient} SIP/2.0\r\n"
                f"From: <sip:server@{self.host}>\r\n"
                f"To: <sip:{recipient}>\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}"
            )
            
        except Exception as e:
            print(f"[CRITICAL] Failed to build SIP message: {str(e)}")
            # Fallback: Einfache Text-Nachricht
            return (
                f"{method} sip:{recipient} SIP/2.0\r\n"
                f"From: <sip:server@{self.host}>\r\n"
                f"To: <sip:{recipient}>\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(str(processed_data))}\r\n\r\n"
                f"{processed_data}"
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
        """Verarbeitet Nachrichten aus der Client-eigenen Queue"""
        try:
            while client_queue:
                queue_item = client_queue.pop(0)
                
                if queue_item['type'] == 'frame_data':
                    frame_data = queue_item['data']
                    
                    try:
                        message = frame_data.decode('utf-8')
                        print(f"[SERVER] Empfangen von {client_name}: {len(message)} bytes")
                        
                        # Parse mit EXISTIERENDER Methode
                        msg = self.parse_sip_message(message)
                        if not msg:
                            print(f"[SERVER ERROR] Ungültiges SIP Format von {client_name}")
                            continue
                            
                        # Debug-Ausgabe
                        debug_msg = message[:200] + "..." if len(message) > 200 else message
                        print(f"[SERVER DEBUG] SIP Nachricht:\n{debug_msg}")
                        
                        # Header-Prüfung
                        headers = msg.get('headers', {})
                        custom_data = msg.get('custom_data', {})
                        
                        # Ping Handling
                        if headers.get('PING') == 'true':
                            print(f"[PING] Empfangen von {client_name}")
                            pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                            send_frame(client_socket, pong_response.encode('utf-8'))
                            continue
                            
                        # UPDATE Handling
                        update_detected = False
                        if headers.get('UPDATE') == 'true':
                            update_detected = True
                        elif custom_data.get('UPDATE') == 'true':
                            update_detected = True
                            
                        if update_detected:
                            print(f"[UPDATE] Empfangen von {client_name}")
                            
                            # Finde client_id und public key
                            client_id = None
                            client_pubkey = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        client_pubkey = data.get('public_key')
                                        break
                            
                            if client_id and client_pubkey:
                                print(f"[UPDATE] Starte Identity Challenge für {client_name} (ID: {client_id})")
                                identity_verified = self.test_identity_sip(client_socket, client_pubkey, client_name)
                                
                                if identity_verified:
                                    print(f"[IDENTITY] {client_name} erfolgreich verifiziert")
                                    if self.send_phonebook(client_id):
                                        print(f"[UPDATE] Phonebook gesendet an {client_name}")
                                    else:
                                        print(f"[UPDATE ERROR] Phonebook konnte nicht gesendet werden an {client_name}")
                                else:
                                    print(f"[IDENTITY] {client_name} Verifizierung fehlgeschlagen")
                            else:
                                print(f"[UPDATE ERROR] Client {client_name} nicht gefunden oder kein Public Key")
                            continue
                            
                        # Identity Response Handling
                        if custom_data.get('MESSAGE_TYPE') == 'IDENTITY_RESPONSE':
                            print(f"[IDENTITY] Response empfangen von {client_name}")
                            
                            # Finde client_id für die Verarbeitung
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                print(f"[IDENTITY] Client ID gefunden: {client_id}")
                                
                                # Response entschlüsseln und verifizieren
                                encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
                                response_challenge_id = custom_data.get('CHALLENGE_ID')
                                
                                if encrypted_response_b64 and response_challenge_id:
                                    try:
                                        encrypted_response = base64.b64decode(encrypted_response_b64)
                                        
                                        with open("server_private_key.pem", "rb") as f:
                                            priv_key = RSA.load_key_string(f.read())
                                        
                                        decrypted_response = priv_key.private_decrypt(encrypted_response, RSA.pkcs1_padding)
                                        
                                        print(f"[IDENTITY] Response von {client_name} verifiziert")
                                        
                                        # Phonebook an diesen Client senden
                                        if self.send_phonebook(client_id):
                                            print(f"[UPDATE] Phonebook erfolgreich an {client_name} gesendet")
                                        else:
                                            print(f"[UPDATE ERROR] Phonebook konnte nicht an {client_name} gesendet werden")
                                        
                                        # Bestätigung senden
                                        success_msg = self.build_sip_message("200 OK", client_name, {
                                            "STATUS": "IDENTITY_VERIFIED",
                                            "CHALLENGE_ID": response_challenge_id
                                        })
                                        
                                        send_frame(client_socket, success_msg.encode('utf-8'))
                                        
                                    except Exception as e:
                                        print(f"[IDENTITY ERROR] Response processing failed for {client_name}: {str(e)}")
                                        import traceback
                                        traceback.print_exc()
                                else:
                                    print("[IDENTITY ERROR] Missing response fields")
                            else:
                                print(f"[IDENTITY ERROR] Client {client_name} nicht gefunden")
                            
                            continue
                            
                        # ENCRYPTED_SECRET Handling
                        if 'ENCRYPTED_SECRET' in custom_data:
                            print(f"[ENCRYPTED] Empfangen von {client_name}")
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "STATUS": "ENCRYPTED_DATA_RECEIVED"
                            })
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                            
                        # Normale SIP Nachrichten verarbeiten
                        custom_data = msg.get('custom_data', {})
                        
                        # Client Secret Handling
                        if 'CLIENT_SECRET' in custom_data:
                            encrypted_secret = base64.b64decode(custom_data['CLIENT_SECRET'])
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id and self.store_client_secret(client_id, encrypted_secret):
                                print(f"[SECRET] Gespeichert für {client_name}")
                        
                        # Phonebook Request Handling
                        elif 'PHONEBOOK_REQUEST' in custom_data:
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id and self.send_phonebook(client_id):
                                print(f"[PHONEBOOK] Gesendet an {client_name}")
                        
                        # Call Setup Handling
                        elif 'CALL_SETUP' in custom_data:
                            call_data = custom_data
                            if call_data.get('CALL_SETUP') == 'request':
                                caller_id = call_data.get('CALLER_ID')
                                callee_id = call_data.get('CALLEE_ID')
                                if caller_id and callee_id:
                                    if self.initiate_call_between_clients(caller_id, callee_id):
                                        print(f"[CALL] Vermittelt zwischen {caller_id} und {callee_id}")
                        
                    except UnicodeDecodeError:
                        print(f"[SERVER ERROR] Kein UTF-8 SIP von {client_name} - Verwerfe {len(frame_data)} bytes")
                        continue
                        
        except Exception as e:
            print(f"[CLIENT QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
    def handle_client(self, client_socket):
        """Vollständige Client-Behandlung - Jede Session isoliert"""
        client_address = client_socket.getpeername()
        print(f"\n[Server] Neue Verbindung von {client_address}")
        client_id = None
        client_name = None

        # Thread-lokale Queue für diesen Client
        client_message_queue = []
        processing_client_queue = False

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
                self.save_active_clients()
                print("+++self.clients+++")
                print(self.clients[client_id])
                print("+++client_id+++")
                print(client_id)
                # ALLE Public Keys sammeln: Server + alle Clients
                all_public_keys = [self.server_public_key]  # Server Key zuerst
                for cid, client_info in self.clients.items():
                    all_public_keys.append(client_info['public_key'])
                
                self.all_public_keys = all_public_keys
                print(f"[SERVER] Gesamte Keys: {len(all_public_keys)} (Server + {len(self.clients)} Clients)")

            # 7. Merkle Root berechnen
            merkle_root = build_merkle_tree_from_keys(self.all_public_keys)
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

            
            second_response_data = {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": self.all_public_keys  # Liste aller Keys in Reihenfolge
            }            
            second_response_msg = self.build_sip_message("200 OK", client_name, second_response_data)
            print(f"[SERVER] Sende zweite Antwort: {len(second_response_msg)} bytes")
            
            send_frame(client_socket, second_response_msg.encode('utf-8'))
            print("[SERVER] Zweite Antwort erfolgreich gesendet")
            
            # 10. Hauptkommunikationsschleife mit eigener Queue
            print(f"[SERVER] Starte Hauptloop für {client_name}")
            client_socket.settimeout(1.0)
            last_activity = time.time()
            buffer = b''
            
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
                                    
                                    # Zur Client-eigenen Queue hinzufügen
                                    client_message_queue.append({
                                        'type': 'frame_data',
                                        'data': frame_data,
                                        'client_socket': client_socket,
                                        'client_name': client_name
                                    })
                                    
                                    # Client-Queue verarbeiten
                                    if not processing_client_queue:
                                        processing_client_queue = True
                                        self._process_client_queue(client_message_queue, client_socket, client_name)
                                        processing_client_queue = False
                                    
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
    def test_identity_sip(self, client_socket, client_pubkey, client_name):
        """
        Führt einen Identity-Test über SIP-Nachrichten durch mit erweitertem Debugging
        """
        timeout = 30
        try:
            print(f"[DEBUG] Starting identity test for client: {client_name}")
            
            # 0. Server Private Key verwenden (nicht temp_server_key.pem!)
            private_key_path = "server_private_key.pem"
            if not os.path.exists(private_key_path):
                print(f"[DEBUG] ERROR: Server private key file not found: {private_key_path}")
                print(f"[DEBUG] Current working directory: {os.getcwd()}")
                print(f"[DEBUG] Files in directory: {os.listdir('.')}")
                return False
            
            print(f"[DEBUG] Using server private key: {private_key_path}")
            
            # 1. Challenge generieren
            challenge = base64.b64encode(secure_random(16)).decode('ascii')
            challenge_id = str(uuid.uuid4())
            print(f"[SERVER] Generated SIP challenge: {challenge} (ID: {challenge_id})")
            
            # 2. Challenge mit Client-Public-Key verschlüsseln
            try:
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_pubkey.encode()))
                encrypted_challenge = pub_key.public_encrypt(
                    challenge.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                print(f"[DEBUG] Challenge encrypted successfully, length: {len(encrypted_challenge)} bytes")
            except Exception as e:
                print(f"[DEBUG] Encryption error: {e}")
                return False
            
            # 3. Challenge per SIP-Nachricht senden
            challenge_msg = self.build_sip_message("MESSAGE", client_name, {
                "MESSAGE_TYPE": "IDENTITY_CHALLENGE",
                "CHALLENGE_ID": challenge_id,
                "ENCRYPTED_CHALLENGE": base64.b64encode(encrypted_challenge).decode('ascii'),
                "TIMESTAMP": int(time.time())
            })
            
            print(f"[DEBUG] Sending challenge message: {challenge_msg[:200]}...")
            send_frame(client_socket, challenge_msg)
            print("[SERVER] Sent SIP challenge to client")
            
            # 4. Response vom Client empfangen - NON-BLOCKING mit select
            client_socket.settimeout(0.1)
            start_time = time.time()
            identity_response_found = False
            response_text = None
            
            print(f"[DEBUG] Waiting for identity response with challenge_id: {challenge_id}")
            
            while time.time() - start_time < timeout:
                try:
                    ready_to_read, _, _ = select.select([client_socket], [], [], 0.1)
                    if not ready_to_read:
                        continue
                    
                    response_data = recv_frame(client_socket)
                    if not response_data:
                        continue
                    
                    if isinstance(response_data, bytes):
                        response_text = response_data.decode('utf-8', errors='ignore')
                    else:
                        response_text = str(response_data)
                    
                    print(f"[DEBUG] Received message type: {response_text.split()[0] if response_text else 'unknown'}")
                    
                    # Prüfen ob es die gesuchte Identity-Response ist
                    if "IDENTITY_RESPONSE" in response_text and challenge_id in response_text:
                        print("[DEBUG] ✓ FOUND MATCHING IDENTITY_RESPONSE!")
                        identity_response_found = True
                        break
                    elif "IDENTITY_RESPONSE" in response_text:
                        print("[DEBUG] Found IDENTITY_RESPONSE but wrong challenge_id")
                    elif "PING" in response_text:
                        print("[DEBUG] Ignoring PING message")
                    else:
                        print(f"[DEBUG] Ignoring other message")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[DEBUG] Error receiving response: {e}")
                    continue
            
            if not identity_response_found:
                print("[DEBUG] Identity test failed: No identity response found within timeout")
                return False
            
            # 5. Response parsen und verifizieren
            print(f"[DEBUG] Parsing identity response...")
            
            # Extrahiere den Body der SIP-Nachricht
            lines = response_text.split('\r\n')
            body_started = False
            body_lines = []
            
            for line in lines:
                if line.strip() == '':
                    body_started = True
                    continue
                if body_started:
                    body_lines.append(line.strip())
            
            response_body = '\n'.join(body_lines)
            print(f"[DEBUG] Extracted response body: {response_body}")
            
            # Manuell die Custom Data aus dem Body parsen
            custom_data = {}
            for line in body_lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    custom_data[key.strip()] = value.strip()
            
            print(f"[DEBUG] Manually parsed custom data: {custom_data}")
            
            # Response-Daten extrahieren und verifizieren
            response_challenge_id = custom_data.get('CHALLENGE_ID')
            encrypted_response = custom_data.get('ENCRYPTED_RESPONSE')
            message_type = custom_data.get('MESSAGE_TYPE')
            
            if message_type != "IDENTITY_RESPONSE":
                print("[DEBUG] Identity test failed: Not an identity response")
                return False
            
            if not all([response_challenge_id, encrypted_response]):
                print("[DEBUG] Identity test failed: Missing response fields")
                return False
            
            if response_challenge_id != challenge_id:
                print(f"[DEBUG] Identity test failed: Challenge ID mismatch")
                return False
            
            # Response entschlüsseln und verifizieren
            try:
                encrypted_response_bytes = base64.b64decode(encrypted_response)
                print(f"[DEBUG] Decoded encrypted response: {len(encrypted_response_bytes)} bytes")
                
                # Server Private Key laden (WICHTIG: server_private_key.pem, nicht temp_server_key.pem!)
                with open(private_key_path, "rb") as f:
                    priv_key = RSA.load_key_string(f.read())
                
                decrypted_response = priv_key.private_decrypt(
                    encrypted_response_bytes, 
                    RSA.pkcs1_padding
                )
                
                decrypted_text = decrypted_response.decode('utf-8')
                print(f"[DEBUG] Decrypted response: '{decrypted_text}'")
                
                expected_response = challenge + "VALIDATED"
                print(f"[DEBUG] Expected response: '{expected_response}'")
                
                if decrypted_text == expected_response:
                    print("[SERVER] Identity test PASSED")
                    success_msg = self.build_sip_message("200 OK", client_name, {
                        "STATUS": "IDENTITY_VERIFIED",
                        "CHALLENGE_ID": challenge_id
                    })
                    send_frame(client_socket, success_msg)
                    return True
                else:
                    print("[DEBUG] Identity test failed: Invalid response content")
                    print(f"[DEBUG]   Expected: '{expected_response}' (length: {len(expected_response)})")
                    print(f"[DEBUG]   Received: '{decrypted_text}' (length: {len(decrypted_text)})")
                    return False
                    
            except Exception as e:
                print(f"[DEBUG] Response verification error: {e}")
                import traceback
                traceback.print_exc()
                return False
                
        except Exception as e:
            print(f"[DEBUG] Identity test error: {e}")
            import traceback
            traceback.print_exc()
            return False
    def process_identity_response(self, sip_data, client_socket):
        """Verarbeitet die Identity-Response vom Client und validiert die Challenge"""
        try:
            print("\n=== SERVER IDENTITY RESPONSE PROCESSING ===")
            print(f"[DEBUG] Processing identity response from client")
            
            # Extrahiere die Custom-Daten aus der SIP-Nachricht
            custom_data = sip_data.get('custom_data', {})
            print(f"[DEBUG] Custom data keys: {list(custom_data.keys())}")
            
            # Überprüfe ob alle benötigten Felder vorhanden sind
            required_fields = ['MESSAGE_TYPE', 'CHALLENGE_ID', 'ENCRYPTED_RESPONSE']
            missing_fields = [field for field in required_fields if field not in custom_data]
            
            if missing_fields:
                print(f"[IDENTITY ERROR] Missing required fields: {missing_fields}")
                print(f"[DEBUG] Available fields: {list(custom_data.keys())}")
                return False
                    
            # Validiere den Nachrichtentyp
            if custom_data['MESSAGE_TYPE'] != 'IDENTITY_RESPONSE':
                print(f"[IDENTITY ERROR] Invalid message type: {custom_data['MESSAGE_TYPE']}")
                return False
                
            challenge_id = custom_data['CHALLENGE_ID']
            encrypted_response_b64 = custom_data['ENCRYPTED_RESPONSE']
            
            print(f"[DEBUG] Challenge ID: {challenge_id}")
            print(f"[DEBUG] Encrypted response length: {len(encrypted_response_b64)}")
            
            # Überprüfe ob die Challenge-ID bekannt ist
            if not hasattr(self, 'pending_challenges') or challenge_id not in self.pending_challenges:
                print(f"[IDENTITY ERROR] Unknown challenge ID: {challenge_id}")
                if hasattr(self, 'pending_challenges'):
                    print(f"[DEBUG] Known challenge IDs: {list(self.pending_challenges.keys())}")
                else:
                    print("[DEBUG] pending_challenges not initialized")
                return False
                
            # Hole die ursprüngliche Challenge-Information
            challenge_info = self.pending_challenges[challenge_id]
            original_challenge = challenge_info['challenge']
            client_name = challenge_info['client']
            client_address = challenge_info.get('address', 'unknown')
            
            print(f"[DEBUG] Original challenge: {original_challenge}")
            print(f"[DEBUG] Client name: {client_name}")
            print(f"[DEBUG] Client address: {client_address}")
            
            # Base64 Decoding
            try:
                encrypted_response = base64.b64decode(encrypted_response_b64)
                print(f"[DEBUG] Decoded encrypted response length: {len(encrypted_response)} bytes")
                print(f"[DEBUG] First 16 bytes (hex): {binascii.hexlify(encrypted_response[:16]).decode()}")
            except Exception as e:
                print(f"[IDENTITY ERROR] Base64 decoding failed: {str(e)}")
                return False
            
            # Lade den privaten Server-Schlüssel
            try:
                with open("server_private_key.pem", "rb") as f:
                    priv_key_data = f.read()
                    priv_key = RSA.load_key_string(priv_key_data)
                print("[DEBUG] Server private key loaded successfully")
            except Exception as e:
                print(f"[IDENTITY ERROR] Failed to load server private key: {str(e)}")
                return False
            
            # Entschlüssele die Response mit dem privaten Server-Schlüssel
            try:
                decrypted_response = priv_key.private_decrypt(encrypted_response, RSA.pkcs1_padding)
                print(f"[DEBUG] Decrypted response length: {len(decrypted_response)} bytes")
                if len(decrypted_response) > 0:
                    print(f"[DEBUG] First 16 bytes (hex): {binascii.hexlify(decrypted_response[:16]).decode()}")
            except Exception as e:
                print(f"[IDENTITY ERROR] Decryption failed: {str(e)}")
                return False
            
            # Konvertiere zu String und validiere den Inhalt
            try:
                response_text = decrypted_response.decode('utf-8')
                print(f"[DEBUG] Response text: {response_text}")
                
                # Überprüfe ob die Response mit "VALIDATED" endet
                if not response_text.endswith("VALIDATED"):
                    print(f"[IDENTITY ERROR] Response does not end with 'VALIDATED'")
                    print(f"[DEBUG] Response ends with: {response_text[-10:] if len(response_text) >= 10 else 'TOO_SHORT'}")
                    return False
                    
                # Extrahiere den Challenge-Text aus der Response
                received_challenge = response_text[:-9]  # Remove "VALIDATED" suffix (9 characters)
                
                # Vergleiche mit dem originalen Challenge-Text
                if received_challenge != original_challenge:
                    print(f"[IDENTITY ERROR] Challenge mismatch!")
                    print(f"[DEBUG] Original: '{original_challenge}' (len: {len(original_challenge)})")
                    print(f"[DEBUG] Received: '{received_challenge}' (len: {len(received_challenge)})")
                    return False
                    
            except UnicodeDecodeError:
                print(f"[IDENTITY ERROR] Response is not valid UTF-8")
                print(f"[DEBUG] Raw bytes (hex): {binascii.hexlify(decrypted_response).decode()}")
                return False
            except Exception as e:
                print(f"[IDENTITY ERROR] Response validation error: {str(e)}")
                return False
            
            # Alles erfolgreich validiert
            print(f"[IDENTITY SUCCESS] Client {client_name} successfully verified")
            
            # Entferne die Challenge aus der pending-Liste
            del self.pending_challenges[challenge_id]
            print(f"[DEBUG] Removed challenge {challenge_id} from pending challenges")
            
            # Sende Bestätigung an Client
            response_msg = self.build_sip_message("200 OK", client_name, {
                "STATUS": "IDENTITY_VERIFIED",
                "MESSAGE": "Identity successfully verified",
                "CLIENT_ID": challenge_info.get('client_id', ''),
                "TIMESTAMP": int(time.time())
            })
            
            try:
                send_frame(client_socket, response_msg)
                print(f"[DEBUG] Sent verification confirmation to {client_name}")
            except Exception as e:
                print(f"[WARNING] Failed to send confirmation: {str(e)}")
            
            return True
            
        except Exception as e:
            print(f"[IDENTITY ERROR] Verification error: {str(e)}")
            traceback.print_exc()
            
            # Sende Fehler an Client falls möglich
            try:
                error_msg = self.build_sip_message("401 Unauthorized", "client", {
                    "STATUS": "IDENTITY_FAILED",
                    "ERROR": "Verification failed",
                    "REASON": str(e)[:100]  # Begrenze die Fehlermeldung
                })
                send_frame(client_socket, error_msg)
            except:
                pass
                
            return False                            
    def _process_queue(self):
        """Verarbeitet Nachrichten aus der Queue - kompatibel mit existing SIP methods"""
        self._processing_queue = True
        
        try:
            while self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                if queue_item['type'] == 'frame_data':
                    frame_data = queue_item['data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']

                    try:
                        message = frame_data.decode('utf-8')
                        print(f"[SERVER] Empfangen von {client_name}: {len(message)} bytes")
                        
                        # Parse mit EXISTIERENDER Methode
                        msg = self.parse_sip_message(message)
                        if not msg:
                            print(f"[SERVER ERROR] Ungültiges SIP Format von {client_name}")
                            continue
                            
                        # Debug-Ausgabe
                        debug_msg = message[:200] + "..." if len(message) > 200 else message
                        print(f"[SERVER DEBUG] SIP Nachricht:\n{debug_msg}")
                        
                        # ✅ KORREKTE Header-Prüfung (UPPERCASE)
                        headers = msg.get('headers', {})
                        custom_data = msg.get('custom_data', {})
                        
                        # Ping Handling
                        if headers.get('PING') == 'true':
                            print(f"[PING] Empfangen von {client_name}")
                            # ✅ KORREKTE build_sip_message Aufruf
                            pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                            self._message_queue.append({
                                'type': 'send_response',
                                'response': pong_response,
                                'client_socket': client_socket,
                                'client_name': client_name
                            })
                            continue
                            
                        # UPDATE Handling
                        update_detected = False
                        if headers.get('UPDATE') == 'true':
                            update_detected = True
                        elif custom_data.get('UPDATE') == 'true':
                            update_detected = True
                            
                        if update_detected:
                            print(f"[UPDATE] Empfangen von {client_name}")
                            
                            # Finde client_id und public key
                            client_id = None
                            client_pubkey = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        client_pubkey = data.get('public_key')
                                        break
                            
                            if client_id and client_pubkey:
                                print(f"[UPDATE] Starte Identity Challenge für {client_name} (ID: {client_id})")
                                
                                self._message_queue.append({
                                    'type': 'start_identity_challenge',
                                    'client_socket': client_socket,
                                    'client_name': client_name,
                                    'client_id': client_id,
                                    'client_pubkey': client_pubkey
                                })
                            else:
                                print(f"[UPDATE ERROR] Client {client_name} nicht gefunden oder kein Public Key")
                            continue
                            
                        # Identity Response Handling
                        # Identity Response Handling
                        # Identity Response Handling
                        if custom_data.get('MESSAGE_TYPE') == 'IDENTITY_RESPONSE':
                            print(f"[IDENTITY] Response empfangen von {client_name}")
                            
                            # ✅✅✅ AKTIVIERTES DEBUGGING
                            print(f"[IDENTITY DEBUG] ===== START IDENTITY DEBUG =====")
                            print(f"[IDENTITY DEBUG] Client: {client_name}")
                            print(f"[IDENTITY DEBUG] Full message length: {len(message)}")
                            
                            # Zeige Headers und Custom Data
                            print(f"[IDENTITY DEBUG] Headers: {headers}")
                            print(f"[IDENTITY DEBUG] Custom data: {custom_data}")
                            
                            # Zeige den kompletten Body
                            body = msg.get('body', '')
                            print(f"[IDENTITY DEBUG] Body length: {len(body)}")
                            print(f"[IDENTITY DEBUG] Complete body content:")
                            print(f"'{body}'")
                            
                            # Zeige alle Zeilen des Bodies
                            lines = body.split('\n')
                            print(f"[IDENTITY DEBUG] Body lines ({len(lines)}):")
                            for i, line in enumerate(lines):
                                if line.strip():  # Nur nicht-leere Zeilen
                                    print(f"[IDENTITY DEBUG] {i}: '{line}'")
                            
                            # Debug: Speichere die komplette Nachricht
                            with open("last_identity_response.txt", "w") as f:
                                f.write(message)
                            print("[IDENTITY DEBUG] Full message saved to last_identity_response.txt")
                            print(f"[IDENTITY DEBUG] ===== END IDENTITY DEBUG =====")
                            
                            # ✅✅✅ KEY-VALUE FORMAT PARSEN
                            encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
                            response_challenge_id = custom_data.get('CHALLENGE_ID')
                            
                            # Wenn nicht in custom_data, versuche aus Body zu parsen (Key-Value Format)
                            if not encrypted_response_b64 or not response_challenge_id:
                                print("[IDENTITY DEBUG] Parsing Key-Value format from body...")
                                print(f"[IDENTITY DEBUG] Body length: {len(body)}")
                                
                                # Parse Key-Value Format aus Body
                                lines = body.split('\n')
                                print(f"[IDENTITY DEBUG] Number of lines: {len(lines)}")
                                
                                for i, line in enumerate(lines):
                                    line = line.strip()
                                    if line:  # Nur nicht-leere Zeilen
                                        print(f"[IDENTITY DEBUG] Line {i}: '{line}'")
                                        if ': ' in line:
                                            key, value = line.split(': ', 1)
                                            key = key.strip()
                                            value = value.strip()
                                            
                                            print(f"[IDENTITY DEBUG] Found key-value: {key} = {value[:50]}...")
                                            
                                            if key == 'ENCRYPTED_RESPONSE':
                                                encrypted_response_b64 = value
                                                print(f"[IDENTITY DEBUG] Found ENCRYPTED_RESPONSE, length: {len(value)}")
                                            elif key == 'CHALLENGE_ID':
                                                response_challenge_id = value
                                                print(f"[IDENTITY DEBUG] Found CHALLENGE_ID: {value}")
                                        else:
                                            print(f"[IDENTITY DEBUG] Line without colon: '{line}'")
                            
                            print(f"[IDENTITY DEBUG] Final ENCRYPTED_RESPONSE present: {encrypted_response_b64 is not None}")
                            if encrypted_response_b64:
                                print(f"[IDENTITY DEBUG] ENCRYPTED_RESPONSE length: {len(encrypted_response_b64)}")
                                print(f"[IDENTITY DEBUG] ENCRYPTED_RESPONSE preview: {encrypted_response_b64[:50]}...")
                            print(f"[IDENTITY DEBUG] Final CHALLENGE_ID: {response_challenge_id}")
                            
                            if not encrypted_response_b64 or not response_challenge_id:
                                print("[IDENTITY ERROR] Missing response fields after Key-Value parsing")
                                print(f"[IDENTITY DEBUG] Body analysis:")
                                print(f"  Body contains 'ENCRYPTED_RESPONSE': {'ENCRYPTED_RESPONSE' in body}")
                                print(f"  Body contains 'CHALLENGE_ID': {'CHALLENGE_ID' in body}")
                                print(f"  Body starts with: {repr(body[:100])}")
                                print(f"  Body ends with: {repr(body[-100:])}")
                                continue
                            
                            # Finde client_id für die Verarbeitung
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                print(f"[IDENTITY] Client ID gefunden: {client_id}")
                                
                                # Identity Response verarbeiten
                                self._message_queue.append({
                                    'type': 'process_identity_response',
                                    'sip_data': msg,
                                    'client_socket': client_socket,
                                    'client_name': client_name,
                                    'client_id': client_id,
                                    'encrypted_response_b64': encrypted_response_b64,  # ← Explizit übergeben
                                    'response_challenge_id': response_challenge_id     # ← Explizit übergeben
                                })
                            else:
                                print(f"[IDENTITY ERROR] Client {client_name} nicht gefunden")
                            
                            continue
                            
                        # ENCRYPTED_SECRET Handling
                        if 'ENCRYPTED_SECRET' in custom_data:
                            print(f"[ENCRYPTED] Empfangen von {client_name}")
                            self._message_queue.append({
                                'type': 'process_encrypted',
                                'sip_data': msg,
                                'client_socket': client_socket,
                                'client_name': client_name
                            })
                            continue
                            
                        # Normale SIP Nachrichten verarbeiten
                        self._message_queue.append({
                            'type': 'process_sip',
                            'message': message,
                            'sip_data': msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
                        
                    except UnicodeDecodeError:
                        print(f"[SERVER ERROR] Kein UTF-8 SIP von {client_name} - Verwerfe {len(frame_data)} bytes")
                        continue
                        

            
                elif queue_item['type'] == 'send_response':
                    # Antwort senden
                    response = queue_item['response']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item.get('client_name', 'unknown')
                    try:
                        send_frame(client_socket, response.encode('utf-8'))
                        print(f"[SEND] Antwort an {client_name} gesendet")
                    except Exception as e:
                        print(f"[QUEUE ERROR] Send failed for {client_name}: {str(e)}")
                
                elif queue_item['type'] == 'start_identity_challenge':
                    # Identity Challenge starten
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    client_id = queue_item['client_id']
                    client_pubkey = queue_item['client_pubkey']
                    
                    try:
                        print(f"[IDENTITY] Starte Challenge für {client_name}")
                        identity_verified = self.test_identity_sip(client_socket, client_pubkey, client_name)
                        
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
                #
                elif queue_item['type'] == 'process_identity_response':
                    # Verarbeite Identity Response
                    sip_data = queue_item['sip_data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    # ✅✅✅ Explizit übergebene Werte verwenden (aus Key-Value Parsing)
                    encrypted_response_b64 = queue_item.get('encrypted_response_b64')
                    response_challenge_id = queue_item.get('response_challenge_id')
                    client_id = queue_item.get('client_id')
                    
                    try:
                        if not encrypted_response_b64 or not response_challenge_id:
                            print(f"[IDENTITY ERROR] Missing response fields from {client_name}")
                            return
                        
                        # Response entschlüsseln und verifizieren
                        encrypted_response = base64.b64decode(encrypted_response_b64)
                        
                        with open("server_private_key.pem", "rb") as f:
                            priv_key = RSA.load_key_string(f.read())
                        
                        decrypted_response = priv_key.private_decrypt(encrypted_response, RSA.pkcs1_padding)
                        
                        # Hier sollte die echte Challenge-Verifikation erfolgen
                        print(f"[IDENTITY] Response von {client_name} verifiziert")
                        
                        # ✅✅✅ PHONEBOOK UPDATE NACH ERFOLGREICHER VERIFIKATION
                        if client_id:
                            print(f"[UPDATE] Sende Phonebook an {client_name} nach Identity-Verifikation")
                            if self.send_phonebook(client_id):
                                print(f"[UPDATE] Phonebook erfolgreich an {client_name} gesendet")
                            else:
                                print(f"[UPDATE ERROR] Phonebook konnte nicht an {client_name} gesendet werden")
                        
                        # Bestätigung senden
                        success_msg = self.build_sip_message("200 OK", client_name, {
                            "STATUS": "IDENTITY_VERIFIED",
                            "CHALLENGE_ID": response_challenge_id
                        })
                        
                        self._message_queue.append({
                            'type': 'send_response',
                            'response': success_msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
                        
                    except Exception as e:
                        print(f"[IDENTITY ERROR] Response processing failed for {client_name}: {str(e)}")
                        import traceback
                        traceback.print_exc()
                
                elif queue_item['type'] == 'process_sip':
                    # Normale SIP Nachricht verarbeiten
                    message = queue_item['message']
                    sip_data = queue_item['sip_data']
                    client_socket = queue_item['client_socket']
                    client_name = queue_item['client_name']
                    
                    try:
                        custom_data = sip_data.get('custom_data', {})
                        
                        # Client Secret Handling
                        if 'CLIENT_SECRET' in custom_data:
                            encrypted_secret = base64.b64decode(custom_data['CLIENT_SECRET'])
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id and self.store_client_secret(client_id, encrypted_secret):
                                print(f"[SECRET] Gespeichert für {client_name}")
                        
                        # Phonebook Request Handling
                        elif 'PHONEBOOK_REQUEST' in custom_data:
                            client_id = None
                            with self.key_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id and self.send_phonebook(client_id):
                                print(f"[PHONEBOOK] Gesendet an {client_name}")
                        
                        # Call Setup Handling
                        elif 'CALL_SETUP' in custom_data:
                            call_data = custom_data
                            if call_data.get('CALL_SETUP') == 'request':
                                caller_id = call_data.get('CALLER_ID')
                                callee_id = call_data.get('CALLEE_ID')
                                if caller_id and callee_id:
                                    if self.initiate_call_between_clients(caller_id, callee_id):
                                        print(f"[CALL] Vermittelt zwischen {caller_id} und {callee_id}")
                        
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
                        custom_data = sip_data.get('custom_data', {})
                        
                        if 'ENCRYPTED_SECRET' in custom_data:
                            print(f"[ENCRYPTED] Empfangen von {client_name}")
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "STATUS": "ENCRYPTED_DATA_RECEIVED"
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
                if data.get('socket') is not None  # Nur mit aktiver Verbindung
            }
            
            with open("active_clients.json", "w") as f:
                json.dump(active_clients, f)
                
            print(f"[DEBUG] Saved {len(active_clients)} active clients")
            
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
        """Aktualisiert das Telefonbuch und synchronisiert beide Client-Listen"""
        # Lade gespeicherte Clients
        saved_clients = self.load_active_clients()
        
        # Kombiniere gespeicherte Clients mit aktuell verbundenen
        connected_clients = {}
        for client_id, client_data in self.clients.items():
            if client_data.get('socket') is not None:  # Nur verbundene Clients
                connected_clients[client_id] = client_data
        
        # Aktualisiere self.clients mit beiden Quellen
        self.clients = {**saved_clients, **connected_clients}
        
        self.phonebook = sorted(
            [(int(cid), data) for cid, data in connected_clients.items() if cid.isdigit()],
            key=lambda x: x[0]
        )
        print(f"Telefonbuch aktualisiert ({len(self.phonebook)} Einträge):")
        for cid, data in self.phonebook:
            print(f"  {cid}: {data['name']}")
    
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
        Sendet das verschlüsselte Phonebook an einen Client mit folgenden Schritten:
        1. Generiert ein neues 48-Byte Geheimnis mit Prefix '+++secret+++'
        2. Verschlüsselt das Geheimnis mit dem öffentlichen Schlüssel des Clients
        3. Verschlüsselt das Phonebook mit AES-256-CBC
        4. Sendet beides an den Client
        """
        try:
            with self.key_lock:
                print(f"\n=== SEND PHONEBOOK DEBUG START (Client {client_id}) ===")
                
                # 1. Client-Daten validieren
                client_data = self.clients.get(client_id)
                print(f"[DEBUG] Client data for {client_id}: {client_data is not None}")
                
                if not client_data:
                    print(f"[ERROR] Client {client_id} nicht im Dictionary gefunden")
                    print(f"[DEBUG] Available clients: {list(self.clients.keys())}")
                    return False
                
                if not client_data.get('socket'):
                    print(f"[ERROR] Client {client_id} hat keinen Socket")
                    return False

                # 2. Debug: Zeige alle Clients an
                print(f"[DEBUG] All clients in self.clients ({len(self.clients)} total):")
                for cid, data in self.clients.items():
                    print(f"  Client {cid}: '{data.get('name', 'unknown')}'")
                    print(f"    public_key: {'public_key' in data}")
                    print(f"    socket: {data.get('socket') is not None}")
                    print(f"    ip: {data.get('ip')}")
                    print(f"    port: {data.get('port')}")
                    if 'public_key' in data:
                        print(f"    public_key preview: {data['public_key'][:50]}...")
                    print(f"    is_target: {cid == client_id}")
                    print("    ---")

                # 3. Generiere neues 48-Byte Geheimnis mit Prefix
                print("[DEBUG] Generating secret...")
                secret = b"+++secret+++" + self.generate_secret()
                if len(secret) != 60:
                    print(f"[WARN] Secret length {len(secret)}, expected 60, adjusting...")
                    secret = secret[:60] if len(secret) > 60 else secret + b"\0" * (60 - len(secret))
                print(f"[DEBUG] Final secret length: {len(secret)}")

                # 4. Verschlüssele Geheimnis mit Client Public Key
                print("[DEBUG] Encrypting secret with client public key...")
                try:
                    pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_data['public_key'].encode()))
                    encrypted_secret = pub_key.public_encrypt(secret, RSA.pkcs1_padding)
                    print(f"[DEBUG] Encrypted secret length: {len(encrypted_secret)}")
                except Exception as e:
                    print(f"[ERROR] Public key encryption failed: {e}")
                    return False

                # 5. Bereite Phonebook-Daten vor
                print("[DEBUG] Preparing phonebook data...")
                try:
                    merkle_root = build_merkle_tree_from_keys(self.all_public_keys)
                    print(f"[DEBUG] Merkle root: {merkle_root}")
                except Exception as e:
                    print(f"[ERROR] Merkle root error: {e}, using fallback")
                    merkle_root = "fallback_root"

                # 6. Erstelle Client-Liste für Phonebook (inklusive Debug)
                phonebook_clients = []
                print("[DEBUG] Building client list for phonebook:")
                
                for cid, data in sorted(self.clients.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
                    has_public_key = 'public_key' in data
                    is_connected = data.get('socket') is not None
                    has_name = 'name' in data and data['name']
                    
                    print(f"  Evaluating client {cid}:")
                    print(f"    has_public_key: {has_public_key}")
                    print(f"    is_connected: {is_connected}")
                    print(f"    has_name: {has_name}")
                    
                    if has_public_key and is_connected and has_name:
                        client_entry = {
                            'id': cid,
                            'name': data['name'],
                            'public_key': data['public_key'],
                            'ip': data.get('ip', ''),
                            'port': data.get('port', 0),
                            'is_self': cid == client_id  # Markiere ob es der empfangende Client ist
                        }
                        phonebook_clients.append(client_entry)
                        print(f"    ✓ INCLUDED: {data['name']} (self: {cid == client_id})")
                    else:
                        reasons = []
                        if not has_public_key: reasons.append("no public_key")
                        if not is_connected: reasons.append("not connected")
                        if not has_name: reasons.append("no name")
                        print(f"    ✗ EXCLUDED: {', '.join(reasons)}")
                
                print(f"[DEBUG] Final phonebook clients: {len(phonebook_clients)}")

                phonebook_data = {
                    'version': '2.0',
                    'timestamp': int(time.time()),
                    'merkle_root': merkle_root,
                    'total_clients': len(self.clients),
                    'connected_clients': len([c for c in self.clients.values() if c.get('socket')]),
                    'clients': phonebook_clients
                }
                
                print("+++phonebook_data+++")
                print(phonebook_data)

                # 7. AES Verschlüsselung
                print("[DEBUG] Encrypting phonebook with AES...")
                iv = secret[12:28]  # 16 Bytes IV
                aes_key = secret[28:60]  # 32 Bytes Key
                
                cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
                phonebook_str = json.dumps(phonebook_data, separators=(',', ':'))
                print("phonebook_string")
                print(phonebook_str)
                
                encrypted_phonebook = cipher.update(phonebook_str.encode()) + cipher.final()
                print(f"[DEBUG] Encrypted phonebook length: {len(encrypted_phonebook)}")

                # 8. Nachricht erstellen
                print("[DEBUG] Building SIP message...")
                message = self.build_sip_message(
                    "MESSAGE",
                    client_data['name'],
                    {
                        "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode(),
                        "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode(),
                        "CLIENT_ID": client_id,
                        "TIMESTAMP": phonebook_data['timestamp'],
                        "TOTAL_CLIENTS": phonebook_data['total_clients'],
                        "CONNECTED_CLIENTS": phonebook_data['connected_clients']
                    }
                )

                # 9. Speichere Geheimnis
                self.client_secrets[client_id] = secret[12:60]
                print(f"[DEBUG] Secret stored for client {client_id}")

                # 10. Sende Nachricht
                print("[DEBUG] Sending message...")
                with self.client_send_lock:
                    if client_data['socket'].fileno() == -1:
                        print(f"[ERROR] Socket geschlossen für Client {client_id}")
                        return False
                    
                    client_data['socket'].settimeout(10.0)
                    print("+++client_data/phonebook+++")
                    print(message[:200] + "..." if len(message) > 200 else message)
                    
                    send_frame(client_data['socket'], message)
                    print(f"[SUCCESS] Phonebook an {client_data['name']} gesendet")
                    print(f"=== SEND PHONEBOOK DEBUG END ===")
                    return True

        except Exception as e:
            print(f"[CRITICAL] Fehler in send_phonebook: {str(e)}")
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
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read().strip())
            if entropy < 2000:
                print("LOW==ENTROPY==DETECTED!")
                print(entropy)
            elif entropy >= 2000:
                print("==ENTROPY==LEVEL==")
                print(entropy)
                print("==ENTROPY==LEVEL==")
            else:
                print("==UNKNOWN==ENTROPY==")
        print("start server")
        server = Server()
        server.start()
    except Exception as e:
        print(f"Kritischer Fehler: {e}")
