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

BUFFER_SIZE = 4096
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

def merge_public_keys(keys):
    """Hilfsfunktion für Merkle-Root"""
    return ":".join([k.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "") for k in keys])

def shorten_public_key(key):
    """Kürzt die Darstellung des öffentlichen Schlüssels."""
    shortened = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    return shortened



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

def parse_multiline_headers(raw_data):
    """Hilfsfunktion zum Parsen von mehrzeiligen Headern"""
    headers = {}
    lines = raw_data.split('\n')
    for line in lines:
        if ': ' in line:
            key, val = line.split(': ', 1)
            headers[key.strip()] = val.strip()
    return headers

    
@staticmethod
def build_sip_message(method, recipient, custom_data={}):
    """Generiert SIP-Nachrichten mit Custom-Daten"""
    body = "\r\n".join(f"{k}: {v}" for k, v in custom_data.items())
    
    return (
        f"{method} sip:{recipient} SIP/2.0\r\n"
        f"From: <sip:server@{socket.gethostbyname(socket.gethostname())}>\r\n"
        f"To: <sip:{recipient}>\r\n"
        f"Call-ID: {uuid.uuid4()}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Content-Type: text/custom\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    )

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
        """Generiert eine eindeutige 3- oder 4-stellige ID für den Client."""
        while True:
            client_id = str(random.randint(100, 9999))  # 3- oder 4-stellige ID
            if client_id not in self.clients:
                return client_id

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
    def handle_client(self, client_socket):
        client_address = client_socket.getpeername()
        print(f"\n[Server] Neue Verbindung von {client_address}")
        client_name = None
        client_pubkey = None
        client_id = None
        try:
            client_socket.settimeout(300.0)
            print("Neue Client-Verbindung")
            register_data = client_socket.recv(4096)
            print(f"Vollständige empfangene Daten:\n{register_data.decode('utf-8')}")  # Debug
            
            if not register_data:
                print("Leere Anfrage - Verbindung geschlossen")
                client_socket.close()
                return
        
            sip_msg = self.parse_sip_message(register_data)
            print(f"Geparste Nachricht - Headers: {sip_msg.get('headers', {})}")  # Debug
            print(f"Geparste Nachricht - Custom Data: {sip_msg.get('custom_data', {})}")  # Debug
        

            # 2. Client-Daten verarbeiten
            # Extrahiere Body-Daten
            body_data = {}
            if '\r\n\r\n' in register_data.decode('utf-8'):
                body = register_data.decode('utf-8').split('\r\n\r\n')[1]
                body_data = parse_multiline_headers(body)
             
            # Kombiniere Header und Body-Daten
            client_name = (sip_msg['headers'].get('CLIENT_NAME') or 
                          sip_msg['custom_data'].get('CLIENT_NAME') or
                          body_data.get('CLIENT_NAME', ''))
             
            client_pubkey = extract_public_key(register_data)
             
            # Entferne eventuelle doppelten Zeilenumbrüche
            client_pubkey = re.sub(r'\n+', '\n', client_pubkey).strip()
             
            print(f"Extrahierter CLIENT_NAME: {client_name}")
            print(f"Extrahierter PUBLIC_KEY: {client_pubkey}")
            if not client_name or not client_pubkey:
                raise ValueError("Unvollständige Client-Daten")
    
            # 3. Client registrieren
            client_id = f"client_{len(self.clients)+1}"
            self.clients[client_id] = {
                'name': client_name,
                'public_key': client_pubkey,
                'socket': client_socket,
                'ip': client_address[0]
            }
    
            # 4. 200 OK mit Server-Key senden
            response = self.build_sip_message(
                "SIP/2.0 200 OK",
                client_name,
                {
                    "SERVER_PUBLIC_KEY": self.server_public_key,
                    "CLIENT_ID": client_id
                }
            )
            client_socket.send(response.encode('utf-8'))
            time.sleep(0.1)
    
            try:
                all_keys = [self.server_public_key] + [c['public_key'] for c in self.clients.values()]
                merkle_root = build_merkle_tree(merge_public_keys(all_keys))
        
                merkle_msg = self.build_sip_message(
                    "MESSAGE",
                    client_name,
                    {"MERKLE_ROOT": merkle_root}
                )
                client_socket.send(merkle_msg.encode('utf-8'))
            except Exception as e:
                print(f"Fehler beim Senden der Merkle-Root: {str(e)}")
    
            # 6. Hauptkommunikationsschleife
            last_pong_time = 0
            pong_delay = 60  # 60 Sekunden Verzögerung
            last_pong_sent = time.time()
            while True:
                time.sleep(1)
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
        
                    msg = self.parse_sip_message(data)
                    if not msg:
                        continue
        
                    if msg.get('method') == "MESSAGE":
                        custom_data = msg.get('custom_data', {})
                        if custom_data.get("PING"):
                            current_time = time.time()
                            if current_time - last_pong_sent >= pong_delay:
                                try:
                                    pong_msg = self.build_sip_message(
                                        "MESSAGE",
                                        client_name,
                                        {
                                            "PONG": "true",
                                            "CALL_ID": msg['headers'].get('CALL-ID', ''),
                                            "CSEQ": msg['headers'].get('CSEQ', '1')
                                        }
                                    )
                                    client_socket.sendall(pong_msg.encode('utf-8'))  # sendall statt send
                                    last_pong_sent = current_time
                                    print(f"[Server] PONG gesendet")
                                except Exception as e:
                                    print(f"[Server] Pong-Sendefehler: {str(e)}")
                            continue
        
                except Exception as e:
                    print(f"[Server] Fehler: {str(e)}")
                    break
        except Exception as e:
            print(f"Fehler bei der Kommunikation mit {client_address}: {e}")
        finally:
            client_socket.close()



    def update_phonebook(self):
        """Aktualisiert das Telefonbuch mit den aktuellen Client-Daten."""
        self.phonebook = [f"{data['name']}: {client_id}: {data['ip']}: {data['public_key']}" for client_id, data in self.clients.items()]
        print("Telefonbuch aktualisiert:", self.phonebook)

    def broadcast_phonebook(self,decrypted_secret):
        """Sendet das aktualisierte Telefonbuch an alle Clients."""
        clients_copy = self.clients.copy()
        for client_id, data in clients_copy.items():
            print("+++PUBLIC_KEY+++")
            print(data)
            print("+++OWNER+++")
            print(client_id)
            try:
                encrypted_phonebook = self.encrypt_phonebook(decrypted_secret)
                if encrypted_phonebook:
                    data["socket"].send(f"PHONEBOOK:{encrypted_phonebook}".encode('utf-8'))
                    #secret
                    time.sleep(1)
                    rsa_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(data["public_key"].encode('utf-8')))
                    secret = rsa_key.public_encrypt(decrypted_secret, RSA.pkcs1_padding).hex()
                    print(secret)
                    data["socket"].send(f"SECRET:{secret}".encode('utf-8'))
            except Exception as e:
                print(f"Fehler beim Senden des Telefonbuchs an {data['name']} (ID: {client_id}): {e}")
                if client_id in self.clients:
                    del self.clients[client_id]
                    self.update_phonebook()

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
