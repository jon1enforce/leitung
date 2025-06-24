import socket
import threading
from M2Crypto import RSA, BIO, EVP
import hashlib
import json
import os
import random
import time

BUFFER_SIZE = 4096


def shorten_public_key(key):
    """Kürzt die Darstellung des öffentlichen Schlüssels."""
    shortened = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
    return shortened

def merge_public_keys(keys):
    """Führt eine Liste von öffentlichen Schlüsseln in einem String zusammen."""
    # Kürze jeden Schlüssel und füge sie mit einem Trennzeichen zusammen
    shortened_keys = [shorten_public_key(key) for key in keys]
    return ":".join(shortened_keys)



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

    
def handle_sip_message(raw_data):
    """Verarbeitet ALLE SIP-Nachrichten und gibt Typ/Header/Body zurück"""
    try:
        data = raw_data.decode()
        lines = data.split('\r\n')
        
        # Start-Line parsen (z.B. "REGISTER sip:server.com SIP/2.0")
        start_line = lines[0]
        method = start_line.split()[0] if ' ' in start_line else None
        
        # Header extrahieren
        headers = {}
        body = ""
        header_mode = True
        
        for line in lines[1:]:
            if not line.strip():
                header_mode = False  # Leerzeile markiert Body-Start
                continue
                
            if header_mode and ': ' in line:
                key, val = line.split(': ', 1)
                headers[key.lower()] = val.strip()
            elif not header_mode:
                body += line + '\r\n'

        # Ihre Protokoll-Labels extrahieren (MERKLE_ROOT: etc.)
        custom_data = {}
        for line in body.split('\r\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                custom_data[key.strip()] = val.strip()

        return {
            'method': method,
            'headers': headers,
            'body': body.strip(),
            'custom_data': custom_data  # Enthält MERKLE_ROOT/public_key etc.
        }

    except Exception as e:
        print(f"SIP-Parsingfehler: {e}")
        return None
        return b"SIP/2.0 400 Bad Request\r\n\r\n"


class Server:
    def __init__(self):
        self.clients = {}  # {client_id: {"name": str, "public_key": str, "socket": socket, "ip": str}}
        self.server_public_key = self.load_or_generate_server_publickey()
        self.phonebook = []  # Liste der Clients im Telefonbuch
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', 5060))
        self.server_socket.listen(5)
        print("Server lauscht auf Port 5060...")
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
        print(f"Verbindung hergestellt mit {client_address}")

        try:
            decrypted_secret = self.generate_secret()
            # Empfange den Client-Namen
            client_name = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            print(f"Client {client_name} verbunden.")
            # Empfange den öffentlichen Schlüssel des Clients
            public_key = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            client_id = str(len(self.clients) + 1)  # Generiere eine Client-ID
            self.clients[client_id] = {"name": client_name, "public_key": public_key, "socket": client_socket, "ip": client_address[0]}
            print(f"Öffentlicher Schlüssel von {client_name} empfangen.")
            # Sende den öffentlichen Schlüssel des Servers an den Client
            client_socket.send(f"SERVER_PUBLIC_KEY:{self.server_public_key}".encode('utf-8'))

            # Sende die öffentlichen Schlüssel aller Clients an den neuen Client
            client_public_keys = []
            for client in self.clients.values():
                if client["public_key"] != public_key:  # Sende nicht den eigenen Schlüssel
                    client_socket.send(f"CLIENT_PUBLIC_KEY:{client['public_key']}:{client['ip']}".encode('utf-8'))
                    client_public_keys.append(client["public_key"])
            client_socket.send("END_OF_KEYS".encode('utf-8'))  # Signalisiere das Ende der Schlüssel       
            public_keys_list = []
            public_keys_list.append(self.server_public_key)#.decode('utf-8'))
            for key0 in client_public_keys:
                public_keys_list.append(key0)
            key_string = merge_public_keys(public_keys_list)
            # Generiere und sende den Merkle Root Hash an alle Clients
            merkle_root = build_merkle_tree(key_string)
            print("+++STRING+++")
            print(key_string)
            print("+++STRING+++")
            time.sleep(1)
            client_socket.send(f"MERKLE_ROOT:{merkle_root}".encode('utf-8'))
            time.sleep(1)
            # Sende die Client-ID an den Client
            client_socket.send(f"CLIENT_ID:{client_id}".encode('utf-8'))   
                    # Schleife zum Empfangen und Verarbeiten von Nachrichten
            time.sleep(1)
            self.update_phonebook()
            self.broadcast_phonebook(decrypted_secret)
            time.sleep(5)
            client_socket.send(f"PING".encode("utf-8"))
            while True:
                time.sleep(1)
                message = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                print(f"Empfangene Nachricht: {message}")  # Debug-Ausgabe

                if message.startswith("CALL_ID:"):
                    # Verarbeite die Client-ID
                    client_id = message.split(":")[1]
                    save_client_id(client_id)
                    print(f"Empfangene Client-ID: {client_id}")

                elif message.startswith("CALL_PUBLIC_KEY:"):
                    # Verarbeite den öffentlichen Schlüssel des Servers
                    client_public_key = message.split(":")[1]
                    print(f"Empfangener öffentlicher Schlüssel des Anrufers: {client_public_key}")
                    client_socket.send(f"CALL_PUBLIC_KEY:{client_public_key}".encode('utf-8'))
                elif message.startswith("PONG"):
                    client_socket.send(f"PING".encode('utf-8'))
                else:
                    # Unbekannte Nachricht
                    print(f"Unbekannte Nachricht empfangen: {message}")
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
    server = Server()
    server.start()
