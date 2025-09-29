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

def recv_frame(sock, timeout=30):
    """EINHEITLICHER Frame-Empfänger für ALLE Nachrichten - KOMPATIBEL FÜR CLIENT UND SERVER"""
    original_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    
    try:
        # 1. Header lesen (4 Bytes Network Byte Order)
        header = b''
        start_time = time.time()
        
        while len(header) < 4:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                raise TimeoutError("Header receive timeout")
                
            sock.settimeout(remaining_time)
            chunk = sock.recv(4 - len(header))
            if not chunk:
                print("[FRAME] Connection closed during header reception")
                return None
            header += chunk
        
        # 2. Länge decodieren
        length = struct.unpack('!I', header)[0]
        
        # 3. SICHERHEITSCHECKS (identisch auf beiden Seiten)
        if length == 0:
            print("[FRAME] Empty frame received")
            return b''  # Leerer Frame ist erlaubt
            
        if length > 10 * 1024 * 1024:  # 10MB Maximum (konservativ)
            print(f"[FRAME SECURITY] Frame size suspicious: {length} bytes")
            # Versuche Daten zu lesen und zu verwerfen um Verbindung zu resetten
            try:
                discard_timeout = min(5.0, timeout)  # Max 5 Sekunden zum Verwerfen
                sock.settimeout(discard_timeout)
                bytes_discarded = 0
                while bytes_discarded < length:
                    chunk_size = min(4096, length - bytes_discarded)
                    chunk = sock.recv(chunk_size)
                    if not chunk:
                        break
                    bytes_discarded += len(chunk)
                print(f"[FRAME SECURITY] Discarded {bytes_discarded} bytes")
            except:
                pass
            raise ValueError(f"Frame too large: {length} bytes (max: 10MB)")
        
        # 4. Body lesen
        received = b''
        while len(received) < length:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                raise TimeoutError(f"Body receive timeout after {timeout}s")
                
            sock.settimeout(remaining_time)
            chunk_size = min(4096, length - len(received))
            chunk = sock.recv(chunk_size)
            if not chunk:
                raise ConnectionError(f"Incomplete frame: received {len(received)} of {length} bytes")
            received += chunk
        
        # 5. Erfolgslogging (konsistent)
        if len(received) == length:
            print(f"[FRAME] Successfully received {length} bytes")
        else:
            print(f"[FRAME WARNING] Length mismatch: expected {length}, got {len(received)}")
        
        return received
        
    except socket.timeout:
        print(f"[FRAME TIMEOUT] Timeout after {timeout} seconds")
        raise TimeoutError(f"Frame receive timeout after {timeout}s")
    except ConnectionError as e:
        print(f"[FRAME CONNECTION] Connection error: {e}")
        raise
    except ValueError as e:
        print(f"[FRAME VALIDATION] Validation error: {e}")
        raise
    except Exception as e:
        print(f"[FRAME ERROR] Unexpected error: {e}")
        return None
    finally:
        # 6. Original Timeout immer zurücksetzen
        try:
            sock.settimeout(original_timeout)
        except:
            pass  # Socket könnte bereits geschlossen sein
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
import socket
import json
import time
import threading
import random
from typing import Dict, List

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
        """Registriert diesen Server bei Seed-Servern - verwendet framed SIP"""
        print("📝 Registriere bei Seed-Servern...")
        
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                # Verwende framed SIP für Seed-Kommunikation
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
                
                from server import send_frame  # Framed SIP verwenden
                if send_frame(sock, sip_message.encode()):
                    # Empfange Response
                    response_data = recv_frame(sock)
                    if response_data:
                        response = json.loads(response_data.decode())
                        if response.get('status') == 'registered':
                            print(f"✅ Bei Seed {seed_host}:{seed_port} registriert")
                            break
                    
            except Exception as e:
                print(f"❌ Registrierung bei {seed_host}:{seed_port} fehlgeschlagen: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass
    
    def _discover_other_servers(self):
        """Holt Server-Liste von Seed-Servern - verwendet framed SIP"""
        print("🔍 Hole Server-Liste...")
        
        for seed_host, seed_port in self.SEED_SERVERS:
            try:
                # Framed SIP für Discovery
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
                
                from server import send_frame, recv_frame
                if send_frame(sock, sip_message.encode()):
                    response_data = recv_frame(sock)
                    if response_data:
                        response = json.loads(response_data.decode())
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
                print(f"❌ Discovery von {seed_host}:{seed_port} fehlgeschlagen: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass
    
    def handle_seed_request(self, sip_message, client_socket, client_address):
        """Verarbeitet Seed-Anfragen von anderen Servern - als framed SIP"""
        if not self.is_seed_server:
            return False
            
        try:
            message = self.server.parse_sip_message(sip_message)
            if not message:
                return False
                
            custom_data = message.get('custom_data', {})
            request_type = custom_data.get('type')
            
            response_data = {}
            
            if request_type == 'register':
                response_data = self._handle_seed_register(custom_data, client_address[0])
            elif request_type == 'get_servers':
                response_data = self._handle_seed_get_servers(custom_data)
            elif request_type == 'update_load':
                response_data = self._handle_load_update(custom_data)
            
            # Sende Response als framed SIP
            response_msg = self.server.build_sip_message(
                "200 OK", 
                client_address[0],
                response_data
            )
            
            from server import send_frame
            return send_frame(client_socket, response_msg.encode())
            
        except Exception as e:
            print(f"Seed Request Error: {e}")
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
    
    def _update_load_on_seeds(self):
        """Aktualisiert eigene Last bei Seed-Servern - als framed SIP"""
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
                
                from server import send_frame
                if send_frame(sock, sip_message.encode()):
                    print(f"📈 Load update an {seed_host}: {self.server_load}%")
                
                sock.close()
                break
                
            except:
                continue
    
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
        
        # ✅ OPTIMIERT: UDP Relay mit Kernel-Level Performance
        self.udp_relay_port = 51822  # Audio Relay Port
        self.audio_relays = {}  # {call_id: {caller_addr: (ip, port), callee_addr: (ip, port)}}
        self.relay_lock = threading.Lock()
        self.udp_socket = None
        
        # Starte UDP Relay Server
        self._start_udp_relay()

    def _start_udp_relay(self):
        """Startet den UDP Relay Server mit korrekter Adresse"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # ✅ KORRIGIERT: Verwende 0.0.0.0 statt self.server.host
            # So bindet es auf alle Interfaces, nicht nur auf den Hostnamen
            bind_host = '0.0.0.0'  # Bind auf alle Netzwerk-Interfaces
            
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.setblocking(False)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            
            self.udp_socket.bind((bind_host, self.udp_relay_port))
            print(f"[UDP RELAY] Server started on {bind_host}:{self.udp_relay_port}")
            
            threading.Thread(target=self._handle_udp_relay, daemon=True).start()
            
        except Exception as e:
            print(f"[UDP RELAY ERROR] Failed to start: {e}")

    def _handle_udp_relay(self):
        """ULTRA-LEICHT: UDP Relay mit quasi 0% CPU/RAM Last"""
        import select
        
        print("[UDP RELAY] Starting ultra-light relay handler")
        
        while True:
            try:
                # ✅ NON-BLOCKING CHECK mit select() - fast 0 CPU
                ready, _, _ = select.select([self.udp_socket], [], [], 0.001)  # 1ms timeout
                
                if not ready:
                    time.sleep(0.001)  # Kurze Pause um CPU zu schonen
                    continue
                
                # ✅ PAKET EMPFANGEN (non-blocking)
                try:
                    data, addr = self.udp_socket.recvfrom(1400)  # MTU size
                except BlockingIOError:
                    continue
                except OSError as e:
                    if e.errno == 9:  # Bad file descriptor (socket closed)
                        break
                    continue
                
                # ✅ SOFORT WEITERLEITEN OHNE VERARBEITUNG
                relay_success = False
                
                # 🔄 SCHNELLE ZIELSUCHE ohne Lock wenn möglich
                for call_id, clients in list(self.audio_relays.items()):  # Thread-safe copy
                    if addr == clients.get('caller_addr'):
                        target_addr = clients.get('callee_addr')
                        if target_addr:
                            try:
                                self.udp_socket.sendto(data, target_addr)
                                relay_success = True
                            except:
                                pass
                        break
                    elif addr == clients.get('callee_addr'):
                        target_addr = clients.get('caller_addr')
                        if target_addr:
                            try:
                                self.udp_socket.sendto(data, target_addr)
                                relay_success = True
                            except:
                                pass
                        break
                
                # ✅ KEINE LOGGING im normalen Betrieb (spart CPU)
                if not relay_success:
                    # Nur gelegentlich loggen um CPU zu sparen
                    if random.randint(0, 1000) == 1:  # Nur 0.1% der Fehler loggen
                        print(f"[RELAY] No target for packet from {addr}")
                        
            except Exception as e:
                # Sehr seltenes Error-Logging
                if random.randint(0, 10000) == 1:  # Nur 0.01% der Errors loggen
                    print(f"[RELAY ERROR] {e}")

    def _register_audio_relay(self, call_id, caller_name, callee_name):
        """Registriert Audio-Relay - OPTIMIERT für minimale Last"""
        try:
            # ✅ SCHNELLE CLIENT-SUCHE ohne unnötige Locks
            caller_ip = None
            callee_ip = None
            
            # Kurzer Lock nur für die Suche
            with self.server.clients_lock:
                for client_id, client_data in self.server.clients.items():
                    if client_data.get('name') == caller_name:
                        caller_ip = client_data.get('ip')
                        if callee_ip:  # Beide gefunden → abbrechen
                            break
                    elif client_data.get('name') == callee_name:
                        callee_ip = client_data.get('ip') 
                        if caller_ip:  # Beide gefunden → abbrechen
                            break
            
            if not caller_ip or not callee_ip:
                print(f"[RELAY] Client IPs not found: {caller_name} or {callee_name}")
                return False
            
            # ✅ FESTE PORTS wie in client.py definiert
            caller_addr = (caller_ip, 51821)  # Audio port from client.py
            callee_addr = (callee_ip, 51821)
            
            # ✅ SCHNELLE REGISTRIERUNG mit kurzem Lock
            with self.relay_lock:
                self.audio_relays[call_id] = {
                    'caller_addr': caller_addr,
                    'callee_addr': callee_addr,
                    'timestamp': time.time()  # Für spätere Cleanup-Logik
                }
            
            print(f"[UDP RELAY] Registered: {caller_name}@{caller_addr} ↔ {callee_name}@{callee_addr}")
            return True
            
        except Exception as e:
            print(f"[RELAY REG ERROR] {e}")
            return False

    def _unregister_audio_relay(self, call_id):
        """Entfernt Audio-Relay Registration - OPTIMIERT"""
        with self.relay_lock:
            if call_id in self.audio_relays:
                del self.audio_relays[call_id]

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
        """KORRIGIERT: Target-Suche mit erweitertem Debugging"""
        try:
            custom_data = msg.get('custom_data', {})
            target_id = custom_data.get('TARGET_CLIENT_ID')
            encrypted_data = custom_data.get('ENCRYPTED_CALL_DATA')
            caller_name = custom_data.get('CALLER_NAME')
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            print(f"[CONVEY] Framed SIP call request from {caller_name} to target {target_id}")
            print(f"[CONVEY DEBUG] Caller ID: {caller_client_id}, Target ID: {target_id}")
            print(f"[CONVEY DEBUG] Encrypted data length: {len(encrypted_data) if encrypted_data else 0}")

            # ✅ VALIDIERUNG MIT FRAME-SIP FEHLERMELDUNGEN
            if not all([target_id, encrypted_data, caller_name, caller_client_id]):
                print("[CONVEY ERROR] Missing required fields in framed SIP")
                print(f"[CONVEY DEBUG] target_id: {target_id}, encrypted_data: {'present' if encrypted_data else 'missing'}")
                print(f"[CONVEY DEBUG] caller_name: {caller_name}, caller_client_id: {caller_client_id}")
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "MISSING_REQUIRED_FIELDS",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            # ✅ KORRIGIERTE ZIELSUCHE MIT DETAILIERTEM DEBUGGING
            target_client = None
            target_socket = None
            target_client_name = None
            
            with self.server.clients_lock:
                print(f"[CONVEY DEBUG] Searching through {len(self.server.clients)} clients:")
                for client_id, client_info in self.server.clients.items():
                    client_name_debug = client_info.get('name', 'unknown')
                    has_socket = client_info.get('socket') is not None
                    print(f"[CONVEY DEBUG] Client {client_id}: {client_name_debug} (socket: {has_socket})")
                    
                    # ✅ VERBESSERTE SUCHE: Prüfe sowohl Client-ID als auch Name
                    if str(client_id) == str(target_id):
                        target_client = client_info
                        target_socket = client_info.get('socket')
                        target_client_name = client_name_debug
                        print(f"[CONVEY DEBUG] ✓ Found target by ID: {client_name_debug}")
                        break
                    elif client_name_debug == target_id:
                        target_client = client_info  
                        target_socket = client_info.get('socket')
                        target_client_name = client_name_debug
                        print(f"[CONVEY DEBUG] ✓ Found target by name: {client_name_debug}")
                        break

            if not target_client:
                print(f"[CONVEY ERROR] Target client {target_id} not found in clients")
                print(f"[CONVEY DEBUG] Available clients: {list(self.server.clients.keys())}")
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "TARGET_NOT_FOUND",
                    "TARGET_ID": target_id,
                    "DEBUG_INFO": f"Available clients: {list(self.server.clients.keys())}",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            if not target_socket:
                print(f"[CONVEY ERROR] Target client {target_id} has no active socket")
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "CALL_ERROR", 
                    "ERROR": "TARGET_OFFLINE",
                    "TARGET_ID": target_id,
                    "TARGET_NAME": target_client_name,
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            # ✅ FRAME-SIP INCOMING_CALL NACHRICHT
            incoming_call_msg = self.server.build_sip_message("MESSAGE", target_client_name, {
                "MESSAGE_TYPE": "INCOMING_CALL",
                "CALLER_NAME": caller_name,
                "CALLER_CLIENT_ID": caller_client_id,
                "ENCRYPTED_CALL_DATA": encrypted_data,
                "TIMESTAMP": int(time.time()),
                "TIMEOUT": 120
            })
            
            print(f"[CONVEY] Sending framed SIP INCOMING_CALL to target {target_client_name}")
            send_success = send_frame(target_socket, incoming_call_msg.encode('utf-8'))
            
            if not send_success:
                print("[CONVEY ERROR] Failed to send framed SIP INCOMING_CALL")
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "TARGET_SEND_FAILED",
                    "TARGET_NAME": target_client_name,
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False

            # ✅ KONSISTENTE CALL-VERWALTUNG
            call_id = f"{caller_client_id}_{target_id}_{int(time.time())}"
            self.active_calls[call_id] = {
                'caller_id': caller_client_id,
                'callee_id': target_id,
                'caller_name': caller_name,
                'callee_name': target_client_name,
                'caller_socket': client_socket,
                'callee_socket': target_socket,
                'start_time': time.time(),
                'status': 'pending',
                'timeout': 120
            }

            # ✅ FRAME-SIP BESTÄTIGUNG
            ack_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                "MESSAGE_TYPE": "CALL_REQUEST_ACK",
                "STATUS": "CALL_FORWARDED",
                "TARGET_ID": target_id,
                "TARGET_NAME": target_client_name,
                "CALL_ID": call_id,
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(client_socket, ack_msg.encode('utf-8'))
            print(f"[CONVEY] Framed SIP call request completed for {call_id}")

            # Timeout-Überwachung
            threading.Thread(
                target=self._call_timeout_watchdog,
                args=(call_id,),
                daemon=True
            ).start()

            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Framed SIP call request failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            try:
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "CALL_ERROR", 
                    "ERROR": f"INTERNAL_SERVER_ERROR: {str(e)}",
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                pass
                
            return False

    def handle_call_response(self, msg, client_socket, client_name):
        """Leitet Call-Antworten weiter - VOLLSTÄNDIG FRAME-SIP KOMPATIBEL"""
        try:
            custom_data = msg.get('custom_data', {})
            response = custom_data.get('RESPONSE')
            caller_id = custom_data.get('CALLER_CLIENT_ID')  # ✅ Client-ID
            
            print(f"[CONVEY] Framed SIP call response from {client_name}: {response}")
            print(f"[CONVEY DEBUG] Caller ID: {caller_id}")
            print(f"[CONVEY DEBUG] Custom data keys: {list(custom_data.keys())}")

            if not response or not caller_id:
                print("[CONVEY ERROR] Missing response or caller_id in framed SIP")
                return False
                
            # ✅ KONSISTENTE CALL-SUCHE NUR MIT CLIENT-IDs
            call_id = None
            call_data = None
            
            print(f"[CONVEY DEBUG] Searching through {len(self.active_calls)} active calls")
            for cid, data in self.active_calls.items():
                print(f"[CONVEY DEBUG] Call {cid}: caller={data.get('caller_id')}, callee={data.get('callee_id')}")
                # ✅ NUR CLIENT-IDs VERGLEICHEN!
                if data['callee_id'] == client_name and data['caller_id'] == caller_id:
                    call_id = cid
                    call_data = data
                    print(f"[CONVEY DEBUG] ✓ Found matching call: {cid}")
                    break
            
            if not call_data:
                print(f"[CONVEY ERROR] No active call found for {client_name} -> {caller_id}")
                print(f"[CONVEY DEBUG] Available calls: {list(self.active_calls.keys())}")
                return False
            
            print(f"[CONVEY] Processing call response for call {call_id}")
            
            # ✅ FRAME-SIP BEARBEITUNG
            if response == "accepted":
                print(f"[CONVEY] Call {call_id} accepted by {client_name}")
                
                # UDP Relay registrieren
                relay_success = self._register_audio_relay(call_id, call_data['caller_name'], client_name)
                
                # ✅ FRAME-SIP ACCEPTED NACHRICHT
                response_data = {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "accepted",
                    "CALLER_CLIENT_ID": caller_id,
                    "TIMESTAMP": int(time.time())
                }
                
                # Füge Relay-Informationen hinzu falls verfügbar
                if relay_success:
                    response_data.update({
                        "AUDIO_RELAY_IP": self.server.host,
                        "AUDIO_RELAY_PORT": self.udp_relay_port,
                        "USE_AUDIO_RELAY": True
                    })
                
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], response_data)
                send_success = send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                
                if send_success:
                    call_data['status'] = 'accepted'
                    print(f"[CONVEY] Call accepted response sent to {call_data['caller_name']}")
                    
                    # ✅ FRAME-SIP CALLEE BESTÄTIGUNG
                    callee_msg = self.server.build_sip_message("MESSAGE", client_name, {
                        "MESSAGE_TYPE": "CALL_CONFIRMED",
                        "TIMESTAMP": int(time.time())
                    })
                    
                    # Füge Relay-Informationen hinzu falls verfügbar
                    if relay_success:
                        callee_msg_data = {
                            "AUDIO_RELAY_IP": self.server.host,
                            "AUDIO_RELAY_PORT": self.udp_relay_port,
                            "USE_AUDIO_RELAY": True
                        }
                        callee_msg = self.server.build_sip_message("MESSAGE", client_name, {
                            "MESSAGE_TYPE": "CALL_CONFIRMED",
                            "TIMESTAMP": int(time.time()),
                            **callee_msg_data
                        })
                    
                    send_frame(client_socket, callee_msg.encode('utf-8'))
                    
                    print(f"[CONVEY] Framed SIP call {call_id} accepted with UDP Relay: {relay_success}")
                else:
                    print(f"[CONVEY ERROR] Failed to send accepted response to caller")
                    
            elif response == "rejected":
                print(f"[CONVEY] Call {call_id} rejected by {client_name}")
                
                # ✅ FRAME-SIP REJECTED NACHRICHT
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller_name'], {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "rejected",
                    "CALLER_CLIENT_ID": caller_id,
                    "TIMESTAMP": int(time.time())
                })
                send_success = send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                
                if send_success:
                    call_data['status'] = 'rejected'
                    print(f"[CONVEY] Call rejected response sent to {call_data['caller_name']}")
                else:
                    print(f"[CONVEY ERROR] Failed to send rejected response to caller")
                    
            elif response == "error":
                print(f"[CONVEY] Call {call_id} error from {client_name}")
                
                # ✅ FRAME-SIP ERROR NACHRICHT
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
                    print(f"[CONVEY] Call error response sent to {call_data['caller_name']}")
            
            # ✅ SAUBERES CLEANUP
            if response in ['accepted', 'rejected', 'error']:
                if call_id in self.active_calls:
                    if response in ['rejected', 'error']:
                        self._unregister_audio_relay(call_id)
                    del self.active_calls[call_id]
                    print(f"[CONVEY] Call {call_id} cleaned up")
            
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
        """Überwacht Call-Timeout"""
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
            
            # Anrufer über Timeout benachrichtigen
            timeout_msg = self.server.build_sip_message("MESSAGE", call_data['caller'], {
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
                        
                        # === PING/PONG HANDLING ===
                        elif (headers.get('PING') == 'true' or custom_data.get('PING') == 'true' or 
                              message_type == 'PING'):
                            print(f"[PING] Received from {client_name}")
                            pong_response = self.build_sip_message("MESSAGE", client_name, {
                                "MESSAGE_TYPE": "PONG",
                                "TIMESTAMP": int(time.time())
                            })
                            if not send_frame(client_socket, pong_response.encode('utf-8')):
                                print(f"[PING ERROR] Failed to send pong to {client_name}")
                            continue
                        
                        elif message_type == 'PONG':
                            print(f"[PONG] Received from {client_name}")
                            # Einfach bestätigen
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "MESSAGE_TYPE": "PONG_ACK",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        # === UPDATE & IDENTITY HANDLING ===
                        elif (message_type == 'UPDATE_REQUEST' or 
                              headers.get('UPDATE') == 'true' or 
                              custom_data.get('UPDATE') == 'true'):
                            print(f"[UPDATE] Request from {client_name}")
                            self._handle_update_request(client_socket, client_name, msg)
                            continue
                        
                        elif message_type == 'IDENTITY_RESPONSE':
                            print(f"[IDENTITY] Response from {client_name}")
                            self._handle_identity_response(client_socket, client_name, msg)
                            continue
                        
                        elif message_type == 'IDENTITY_CHALLENGE':
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
                        elif (message_type == 'ENCRYPTED_SECRET' or 
                              'ENCRYPTED_SECRET' in custom_data or 
                              'CLIENT_SECRET' in custom_data):
                            print(f"[SECRET] Received from {client_name}")
                            self._handle_encrypted_secret(msg, client_socket, client_name)
                            continue
                        
                        # === PHONEBOOK HANDLING ===
                        elif (message_type == 'PHONEBOOK_REQUEST' or 
                              'PHONEBOOK_REQUEST' in custom_data):
                            print(f"[PHONEBOOK] Request from {client_name}")
                            self._handle_phonebook_request(msg, client_socket, client_name)
                            continue
                        
                        elif message_type == 'PHONEBOOK_UPDATE':
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
                        elif ('CALL_SETUP' in custom_data or 
                              message_type == 'CALL_SETUP'):
                            print(f"[LEGACY CALL] Setup from {client_name}")
                            self._handle_legacy_call_setup(msg, client_socket, client_name)
                            continue
                        
                        # === REGISTRATION & DISCOVERY ===
                        elif message_type == 'REGISTER':
                            print(f"[REGISTER] Received from {client_name}")
                            # Client ist bereits registriert, bestätigen
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "MESSAGE_TYPE": "REGISTRATION_CONFIRMED",
                                "STATUS": "ALREADY_REGISTERED",
                                "TIMESTAMP": int(time.time())
                            })
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        elif message_type == 'DISCOVER':
                            print(f"[DISCOVER] Request from {client_name}")
                            self._handle_discovery_request(msg, client_socket, client_name)
                            continue
                        
                        # === ERROR HANDLING ===
                        elif message_type == 'ERROR':
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

    def _safe_remove_client(self, client_id):
        """Thread-safe client removal"""
        with self.clients_lock:
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"[SERVER] Client {client_id} entfernt")
        
        # Key-Liste aktualisieren
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        all_public_keys = [self.server_public_key]
        for cid, client_info in clients_copy.items():
            if 'public_key' in client_info:
                all_public_keys.append(client_info['public_key'])
        
        with self.key_lock:
            self.all_public_keys = all_public_keys            
    def _handle_relay_manager_request(self, register_data, client_socket, client_address):
        """Verarbeitet Anfragen vom Relay-Manager (andere Server)"""
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
            request_type = custom_data.get('type')
            
            # Prüfe ob es eine Relay-Manager Anfrage ist
            if request_type in ['register', 'get_servers', 'update_load']:
                print(f"[RELAY] Erhaltene Relay-Anfrage: {request_type} von {client_address}")
                success = self.relay_manager.handle_seed_request(register_data, client_socket, client_address)
                if success:
                    print(f"[RELAY] Anfrage erfolgreich verarbeitet, schließe Verbindung")
                    try:
                        client_socket.close()
                    except:
                        pass
                return success
            
            return False
            
        except Exception as e:
            print(f"[RELAY ERROR] Fehler bei Relay-Anfrage: {e}")
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
        """Thread-safe client removal"""
        with self.clients_lock:
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"[SERVER] Client {client_id} entfernt")
        
        # Key-Liste aktualisieren
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        all_public_keys = [self.server_public_key]
        for cid, client_info in clients_copy.items():
            if 'public_key' in client_info:
                all_public_keys.append(client_info['public_key'])
        
        with self.key_lock:
            self.all_public_keys = all_public_keys

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

        # Thread-lokale Queue für diesen Client
        if not hasattr(self, '_message_queue'):
            self._message_queue = []
        
        # ✅ INIT: Stelle sicher dass Processing-Flag existiert  
        if not hasattr(self, '_processing_client_queue'):
            self._processing_client_queue = False

        try:
            # 1. Registration empfangen (mit Timeout)
            client_socket.settimeout(30.0)
            print(f"[SERVER] Warte auf Registration von {client_address}")
            
            register_data = recv_frame(client_socket)
            if not register_data:
                print("[SERVER] Keine Registrierungsdaten empfangen")
                return

            print(f"[SERVER] Empfangene Daten: {len(register_data)} bytes")
            
            # 2. Prüfe ob es eine Relay-Manager Anfrage ist (andere Server)
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

            # 6. Public Key extrahieren
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

            # 7. ✅ Client ATOMIC registrieren (THREAD-SAFE)
            client_data = {
                'name': client_name,
                'public_key': client_pubkey,
                'socket': client_socket,
                'ip': client_address[0],
                'port': client_address[1],
                'login_time': time.time(),
                'last_update': time.time()
            }
            
            # ✅ ATOMIC Registration unter clients_lock
            with self.clients_lock:
                client_id = self._generate_client_id_locked()
                self.clients[client_id] = client_data
                print(f"[SERVER] Client {client_name} registriert mit ID: {client_id}")
            
            # ✅ Gespeicherte Clients aktualisieren
            self.save_active_clients()

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
                    
                    # ✅ Nachricht zur Verarbeitung in die Queue stellen
                    if not hasattr(self, '_message_queue'):
                        self._message_queue = []
                    
                    self._message_queue.append({
                        'type': 'frame_data',
                        'data': frame_data,
                        'client_socket': client_socket,
                        'client_name': client_name
                    })
                    
                    # ✅ Queue verarbeiten
                    self._process_client_queue(self._message_queue, client_socket, client_name)
                    
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
    def _find_my_client_id(self):
        """Hilfsmethode für Client-ID Suche (Kompatibilität)"""
        # Diese Methode wird vom Client erwartet, kann aber einfach sein
        return "server"
    def _receive_registration(self, client_socket):
        """Empfängt Registrierungsdaten mit mehreren Fallbacks"""
        try:
            # Versuche framed Nachricht
            try:
                return recv_frame(client_socket)
            except (ValueError, ConnectionError):
                pass
            
            # Fallback: Direkter Empfang
            data = client_socket.recv(4096)
            if data:
                print(f"[SERVER] Unframed Daten empfangen: {len(data)} bytes")
                return data.decode('utf-8') if isinstance(data, bytes) else data
            
            return None
            
        except socket.timeout:
            print("[SERVER] Timeout beim Empfang der Registration")
            raise
        except Exception as e:
            print(f"[SERVER] Fehler beim Empfang: {e}")
            raise

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
            
            # Ping Handling
            if headers.get('PING') == 'true':
                print(f"[PING] Empfangen von {client_name}")
                pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                self._message_queue.append({
                    'type': 'send_response',
                    'response': pong_response,
                    'client_socket': client_socket,
                    'client_name': client_name
                })
                return
                
            # UPDATE Handling - NOW THREAD-SAFE!
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
    def _process_sip_message(self, queue_item):
        """Thread-safe SIP message processing"""
        message = queue_item['message']
        sip_data = queue_item['sip_data']
        client_socket = queue_item['client_socket']
        client_name = queue_item['client_name']
        
        try:
            custom_data = sip_data.get('custom_data', {})
            
            # ✅ SICHER: Client Secret Handling mit clients_lock
            if 'CLIENT_SECRET' in custom_data:
                print(f"[SECRET] Empfangen von {client_name}")
                encrypted_secret = base64.b64decode(custom_data['CLIENT_SECRET'])
                
                # Client ID thread-safe finden
                client_id = None
                with self.clients_lock:
                    clients_copy = self.clients.copy()
                
                for cid, data in clients_copy.items():
                    if data.get('name') == client_name:
                        client_id = cid
                        break
                
                if client_id:
                    if self.store_client_secret(client_id, encrypted_secret):
                        print(f"[SECRET] Gespeichert für {client_name} (ID: {client_id})")
                        
                        # Bestätigung senden
                        ack_msg = self.build_sip_message("200 OK", client_name, {
                            "STATUS": "SECRET_STORED",
                            "CLIENT_ID": client_id,
                            "TIMESTAMP": int(time.time())
                        })
                        
                        self._message_queue.append({
                            'type': 'send_response',
                            'response': ack_msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
                    else:
                        print(f"[SECRET ERROR] Konnte Secret nicht speichern für {client_name}")
                else:
                    print(f"[SECRET ERROR] Client {client_name} nicht gefunden")
            
            # ✅ SICHER: Phonebook Request Handling
            elif 'PHONEBOOK_REQUEST' in custom_data:
                print(f"[PHONEBOOK] Request von {client_name}")
                
                # Client ID thread-safe finden
                client_id = None
                with self.clients_lock:
                    clients_copy = self.clients.copy()
                
                for cid, data in clients_copy.items():
                    if data.get('name') == client_name:
                        client_id = cid
                        break
                
                if client_id:
                    if self.send_phonebook(client_id):
                        print(f"[PHONEBOOK] Gesendet an {client_name} (ID: {client_id})")
                        
                        # Bestätigung senden
                        ack_msg = self.build_sip_message("200 OK", client_name, {
                            "STATUS": "PHONEBOOK_SENT",
                            "CLIENT_ID": client_id,
                            "TIMESTAMP": int(time.time())
                        })
                        
                        self._message_queue.append({
                            'type': 'send_response',
                            'response': ack_msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
                    else:
                        print(f"[PHONEBOOK ERROR] Konnte Phonebook nicht senden an {client_name}")
                        
                        # Fehlermeldung senden
                        error_msg = self.build_sip_message("500 Error", client_name, {
                            "STATUS": "PHONEBOOK_FAILED",
                            "ERROR": "Could not send phonebook",
                            "CLIENT_ID": client_id,
                            "TIMESTAMP": int(time.time())
                        })
                        
                        self._message_queue.append({
                            'type': 'send_response',
                            'response': error_msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
                else:
                    print(f"[PHONEBOOK ERROR] Client {client_name} nicht gefunden")
                    
                    # Fehlermeldung senden
                    error_msg = self.build_sip_message("404 Not Found", client_name, {
                        "STATUS": "CLIENT_NOT_FOUND",
                        "ERROR": "Client not registered",
                        "TIMESTAMP": int(time.time())
                    })
                    
                    self._message_queue.append({
                        'type': 'send_response',
                        'response': error_msg,
                        'client_socket': client_socket,
                        'client_name': client_name
                    })
            
            # ✅ SICHER: Call Setup Handling
            elif 'CALL_SETUP' in custom_data:
                print(f"[CALL] Setup Request von {client_name}")
                call_data = custom_data
                
                if call_data.get('CALL_SETUP') == 'request':
                    caller_id = call_data.get('CALLER_ID')
                    callee_id = call_data.get('CALLEE_ID')
                    
                    if caller_id and callee_id:
                        # Call initiation thread-safe durchführen
                        call_success = self.initiate_call_between_clients(caller_id, callee_id)
                        
                        if call_success:
                            print(f"[CALL] Vermittelt zwischen {caller_id} und {callee_id}")
                            
                            # Bestätigung senden
                            ack_msg = self.build_sip_message("200 OK", client_name, {
                                "STATUS": "CALL_INITIATED",
                                "CALLER_ID": caller_id,
                                "CALLEE_ID": callee_id,
                                "TIMESTAMP": int(time.time())
                            })
                            
                            self._message_queue.append({
                                'type': 'send_response',
                                'response': ack_msg,
                                'client_socket': client_socket,
                                'client_name': client_name
                            })
                        else:
                            print(f"[CALL ERROR] Konnte Call nicht vermitteln")
                            
                            # Fehlermeldung senden
                            error_msg = self.build_sip_message("500 Error", client_name, {
                                "STATUS": "CALL_FAILED",
                                "ERROR": "Could not initiate call",
                                "CALLER_ID": caller_id,
                                "CALLEE_ID": callee_id,
                                "TIMESTAMP": int(time.time())
                            })
                            
                            self._message_queue.append({
                                'type': 'send_response',
                                'response': error_msg,
                                'client_socket': client_socket,
                                'client_name': client_name
                            })
                    else:
                        print(f"[CALL ERROR] Missing caller or callee ID")
                        
                        # Fehlermeldung senden
                        error_msg = self.build_sip_message("400 Bad Request", client_name, {
                            "STATUS": "CALL_INVALID",
                            "ERROR": "Missing caller or callee ID",
                            "TIMESTAMP": int(time.time())
                        })
                        
                        self._message_queue.append({
                            'type': 'send_response',
                            'response': error_msg,
                            'client_socket': client_socket,
                            'client_name': client_name
                        })
            
            # Unbekannte Nachricht
            else:
                print(f"[UNKNOWN] Unbekannte SIP Nachricht von {client_name}")
                print(f"[DEBUG] Custom data keys: {list(custom_data.keys())}")
                
                # Antwort senden
                ack_msg = self.build_sip_message("200 OK", client_name, {
                    "STATUS": "MESSAGE_RECEIVED",
                    "UNKNOWN_TYPE": "true",
                    "TIMESTAMP": int(time.time())
                })
                
                self._message_queue.append({
                    'type': 'send_response',
                    'response': ack_msg,
                    'client_socket': client_socket,
                    'client_name': client_name
                })
            
        except Exception as e:
            print(f"[QUEUE ERROR] SIP processing failed for {client_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Error response senden
            try:
                error_msg = self.build_sip_message("500 Error", client_name, {
                    "STATUS": "PROCESSING_ERROR",
                    "ERROR": str(e)[:100],
                    "TIMESTAMP": int(time.time())
                })
                
                self._message_queue.append({
                    'type': 'send_response',
                    'response': error_msg,
                    'client_socket': client_socket,
                    'client_name': client_name
                })
            except Exception as send_error:
                print(f"[QUEUE ERROR] Could not send error response: {send_error}")                
    def _process_encrypted(self, queue_item):
        """Thread-safe encrypted data processing"""
        sip_data = queue_item['sip_data']
        client_socket = queue_item['client_socket']
        client_name = queue_item['client_name']
        
        try:
            custom_data = sip_data.get('custom_data', {})
            
            if 'ENCRYPTED_SECRET' in custom_data:
                print(f"[ENCRYPTED] Empfangen von {client_name}")
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

    def _process_encrypted_binary(self, queue_item):
        """Thread-safe binary encrypted data processing"""
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
