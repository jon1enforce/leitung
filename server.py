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
BUFFER_SIZE = 4096

def send_frame(sock, data):
    """Verschickt Daten mit Längenprefix"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

def recv_frame(sock, timeout=30):
    """Empfängt einen Frame mit Längenprefix"""
    sock.settimeout(timeout)
    try:
        header = sock.recv(4)
        if not header: return None
        length = struct.unpack('!I', header)[0]
        
        chunks = []
        bytes_recd = 0
        while bytes_recd < length:
            chunk = sock.recv(min(length - bytes_recd, 4096))
            if not chunk: raise ConnectionError("Verbindung abgebrochen")
            chunks.append(chunk)
            bytes_recd += len(chunk)
        return b''.join(chunks).decode('utf-8')
    except socket.timeout:
        raise TimeoutError("Timeout beim Warten auf Frame")

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
    if not key or "-----BEGIN PUBLIC KEY-----" not in key:
        return None  # Statt leerem String None zurückgeben
    # Extrahiere nur den Base64-Inhalt zwischen den PEM-Markern
    key_content = "".join(
        key.split("-----BEGIN PUBLIC KEY-----")[1]
        .split("-----END PUBLIC KEY-----")[0]
        .strip().split()
    )
    return key_content if key_content else None


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
    
    # 1. Normalisierungsfunktion
    def normalize_key(key):
        if not key or "-----BEGIN PUBLIC KEY-----" not in key:
            return None
        # Extrahiere nur den Base64-Teil zwischen den PEM-Markern
        return "".join(
            key.split("-----BEGIN PUBLIC KEY-----")[1]
            .split("-----END PUBLIC KEY-----")[0]
            .strip().split()
        )
    
    # 2. Debug-Ausgabe der Rohkeys
    print("[Server] All keys for Merkle Tree:")
    for i, key in enumerate(all_keys):
        print(f"Key {i}: {key}" if key else f"Key {i}: None")

    # 3. Normalisierung aller Keys
    normalized_keys = []
    for key in all_keys:
        normalized = normalize_key(key)
        if normalized:
            normalized_keys.append(normalized)
    
    if len(normalized_keys) < 1:
        raise ValueError("No valid keys found for Merkle tree")
    
    # 4. Zusammenführung mit Trennzeichen
    merged = "|||".join(normalized_keys)
    print(f"[Server] Merged keys (len={len(merged)}): {merged[:100]}...")
    
    # 5. Merkle Root berechnen
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
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Wichtig für Port-Reuse
        print("init4")
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
        """Einfache SIP-Nachricht-Erstellung kompatibel zum Client"""
        body = "\r\n".join(f"{k}: {v}" for k, v in custom_data.items())
        return (
            f"{method} sip:{recipient} SIP/2.0\r\n"
            f"From: <sip:server@{self.host}>\r\n"
            f"To: <sip:{recipient}>\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
            f"{body}"
        )
    def parse_sip_message(self, message):
        """
        Korrigierte Version die SIP-Antworten richtig erkennt
        """
        if isinstance(message, bytes):
            message = message.decode('utf-8')
        
        message = message.strip()
        if not message:
            return None
    
        lines = [line.strip() for line in message.replace('\r\n', '\n').split('\n') if line.strip()]
        result = {'headers': {}, 'custom_data': {}}
        print(f"Original headers: {lines[1:]}")  # Zeigt die tatsächlich geparsten Header
        # Erste Zeile analysieren
        first_line = lines[0]
        if first_line.startswith(('SIP/2.0', 'REGISTER', 'INVITE', 'MESSAGE')):
            if first_line.startswith('SIP/2.0'):
                parts = first_line.split(maxsplit=2)
                if len(parts) >= 2:
                    result['status_code'] = parts[1]
                    if len(parts) > 2:
                        result['status_message'] = parts[2]
            else:
                result['method'] = first_line.split()[0]
        else:
            return None
    
        # Header parsen
        for line in lines[1:]:
            if ':' in line:
                key, sep, value = line.partition(':')
                key = key.strip().upper()
                value = value.strip()
                
                if not key:
                    continue
                if key == "CONTENT-LENGTH":
                    try:
                        result['content_length'] = int(value)
                    except ValueError:
                        pass
                elif key not in result['headers']:  # Nur ersten Header-Wert behalten
                    result['headers'][key] = value
        if 'content_length' in result and result['content_length'] > 0:
            body = '\n'.join(lines[len(result['headers'])+1:])
            if body:
                try:
                    result['custom_data'] = dict(
                        line.split(':', 1) 
                        for line in body.splitlines() 
                        if ':' in line
                    )
                except Exception:
                    result['custom_data'] = {}
        return result if ('method' in result or 'status_code' in result) else None     
    def start(self):
        print("start1")
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
        """
        Erzeuge ein 48-Byte-Geheimnis:
        - Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie.
        - Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festplatten-Entropi e.
        :return: 48-Byte-Geheimnis als Bytes.
        """
        # Erzeuge den Seed: 8 Bytes aus os.urandom + 8 Bytes aus der Festplatten-Entropie
        seed_part1 = os.urandom(8)  # 8 Bytes aus os.urandom
        seed_part2 = self.get_disk_entropy(8)  # 8 Bytes aus der Festplatten-Entropie
        if not seed_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        seed = seed_part1 + seed_part2  # 16 Bytes Seed

        # Erzeuge den Schlüssel: 16 Bytes aus os.urandom + 16 Bytes aus der Festpla tten-Entropie
        key_part1 = os.urandom(16)  # 16 Bytes aus os.urandom
        key_part2 = self.get_disk_entropy(16)  # 16 Bytes aus der Festplatten-Entropie
        if not key_part2:
            raise RuntimeError("Konnte die Festplatten-Entropie nicht lesen.")
        key = key_part1 + key_part2  # 32 Bytes Schlüssel

        # Kombiniere Seed und Schlüssel zu einem 48-Byte-Geheimnis
        secret = seed + key  # 16 + 32 = 48 Bytes
        return secret

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
        try:
            all_keys = [self.server_public_key] + [
                c['public_key'] for c in self.clients.values() 
                if c.get('public_key')
            ]
            
            if len(all_keys) < 2:
                print("Warnung: Nicht genug Keys für Merkle Tree")
                return
    
            normalized_keys = []
            for key in all_keys:
                normalized = normalize_key(key)
                if normalized:
                    normalized_keys.append(normalized)
                else:
                    print(f"Warnung: Key konnte nicht normalisiert werden: {key[:50]}...")
    
            if len(normalized_keys) < 2:
                normalized_keys.append(normalized_keys[0])  # Fallback
    
            merged = "|||".join(normalized_keys)
            merkle_root = build_merkle_tree([merged])
            
            merkle_msg = self.build_sip_message("MESSAGE", client_name, {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": json.dumps(all_keys)
            })
            send_frame(client_socket, merkle_msg)
    
        except Exception as e:
            print(f"Fehler beim Merkle-Tree: {str(e)}")
            raise
    
    def handle_communication_loop(self, client_name, client_socket):
        last_pong_time = 0
        pong_delay = 20
        
        while True:
            try:
                client_socket.settimeout(1.0)
                data = client_socket.recv(4096)
                
                if not data:
                    break
                    
                msg = self.parse_sip_message(data)
                if not msg:
                    continue
                    
                if msg.get('method') == "MESSAGE" and msg.get('custom_data', {}).get("PING"):
                    if time.time() - last_pong_time >= pong_delay:
                        pong_msg = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                        client_socket.sendall(pong_msg.encode('utf-8'))
                        last_pong_time = time.time()
                elif msg.get('custom_data', {}).get('CLIENT_SECRET'):
                    encrypted_secret = base64.b64decode(msg['custom_data']['CLIENT_SECRET'])
                    self.clients[client_id]['aes_secret'] = encrypted_secret
                        
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Kommunikationsfehler: {str(e)}")
                break
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
            # Phase 6: Merkle Tree verarbeiten
            self.process_merkle_tree(client_name, client_socket)
            time.sleep(0.1)
            self.broadcast_phonebook()  
            # Phase 7: Hauptkommunikationsschleife
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
        """Thread-sichere Version des Broadcasts"""
        def _broadcast():
            try:
                phonebook_data = [
                    {
                        'id': client_id,
                        'name': data['name'],
                        'ip': data['ip'],
                        'port': data['port'],
                        'public_key': data['public_key']
                    }
                    for client_id, data in sorted(self.clients.items(), key=lambda x: int(x[0]))
                    if data.get('socket') is not None
                ]
                
                for client_id, client_data in self.clients.items():
                    if not client_data.get('socket'):
                        continue
                    
                    try:
                        secret = self.generate_secret()
                        client_pubkey = RSA.load_pub_key_bio(
                            BIO.MemoryBuffer(client_data['public_key'].encode())
                        encrypted_secret = client_pubkey.public_encrypt(
                            b"+++secret+++" + secret,
                            RSA.pkcs1_padding
                        )
                        
                        iv = secret[:16]
                        aes_key = secret[16:]
                        cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
                        plaintext = json.dumps(phonebook_data).encode('utf-8')
                        encrypted_phonebook = cipher.update(plaintext) + cipher.final()
                        
                        response = self.build_sip_message(
                            "MESSAGE",
                            client_data['name'],
                            {
                                "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode(),
                                "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode()
                            }
                        )
                        send_frame(client_data['socket'], response)
                        
                    except Exception as e:
                        print(f"Broadcast error for client {client_id}: {str(e)}")
                        
            except Exception as e:
                print(f"Critical broadcast error: {str(e)}")
    
        # Starte den Broadcast in einem neuen Thread
        threading.Thread(target=_broadcast, daemon=True).start()
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

if __name__ == "__main__":
    try:
        print("main0")
        server = Server()
        print("main1")
        server.start()
    except Exception as e:
        print(f"Kritischer Fehler: {e}")
