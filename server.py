import socket
import threading
from M2Crypto import RSA, BIO, EVP
import hashlib
import json
import os
import random
import time

BUFFER_SIZE = 4096
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
        self.host = host
        self.port = port
        self.clients = {}
        try:
            self.server_public_key = load_server_publickey()
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as e:
            print(f"Initialisierungsfehler: {e}")
            raise

    def start(self):
        try:
            print(f"Starte Server auf {self.host}:{self.port}...")
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Server lauscht auf Port {self.port}")

            while True:
                client_sock, addr = self.server_socket.accept()
                print(f"Neue Verbindung von {addr}")
                threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr),
                    daemon=True
                ).start()

        except PermissionError:
            print(f"FEHLER: Port {self.port} benötigt Root-Rechte (sudo)")
        except Exception as e:
            print(f"Serverfehler: {e}")
        finally:
            self.server_socket.close()
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
    
def handle_client(self, client_socket, client_address):
    print(f"\n[Server] Neue Verbindung von {client_address}")
    try:
        client_socket.settimeout(30.0)
            
            # 1. Client-Registrierung
        data = client_socket.recv(BUFFER_SIZE).decode()
        if not data.startswith("REGISTER"):
            raise ValueError("Keine REGISTER-Nachricht")
        # 1. SIP-REGISTER empfangen
        register_data = client_socket.recv(BUFFER_SIZE)
        sip_msg = self.parse_sip_message(register_data)
        
        if not sip_msg or sip_msg['method'] != "REGISTER":
            client_socket.send(b"SIP/2.0 400 Invalid Request\r\n\r\n")
            return

        client_name = sip_msg['custom_data'].get("CLIENT_NAME")
        public_key = sip_msg['custom_data'].get("PUBLIC_KEY")
        
        # 2. Client registrieren
        client_id = f"client_{len(self.clients)+1}"
        self.clients[client_id] = {
            'name': client_name,
            'public_key': public_key,
            'socket': client_socket
        }

        # 3. Server-Antwort senden (200 OK + Server-Key)
        response = self.build_sip_message(
            "SIP/2.0 200 OK",
            client_name,
            {"SERVER_PUBLIC_KEY": self.server_public_key}
        )
        client_socket.send(response.encode())

        # 4. Merkle-Root senden
        merkle_root = self.calculate_merkle_root(client_id)
        merkle_msg = self.build_sip_message(
            "MESSAGE",
            client_name,
            {"MERKLE_ROOT": merkle_root}
        )
        client_socket.send(merkle_msg.encode())

        # 5. Hauptkommunikationsschleife
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data: break
            
            msg = self.parse_sip_message(data)
            if msg and msg.get('custom_data', {}).get("PING"):
                pong = self.build_sip_message(
                    "MESSAGE",
                    client_name,
                    {"PONG": "true"}
                )
                client_socket.send(pong.encode())
    except socket.timeout:
        print(f"Timeout mit {client_address}")
    except Exception as e:
        print(f"Client-Fehler {client_address}: {str(e)}")
    finally:
        client_socket.close()
        print(f"Verbindung zu {client_address} geschlossen")





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

    def start(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

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
        server = Server()
        server.start()
    except Exception as e:
        print(f"Kritischer Fehler: {e}")
