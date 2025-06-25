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

def get_public_ip():
    nat_type, public_ip, public_port = stun.get_ip_info()
    return public_ip, public_port  # Für SIP-Contact-Header


def shorten_public_key(key):
    """Kürzt die Darstellung des öffentlichen Schlüssels."""
    shortened = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("END_OF_KEYS","").replace("\n", "")
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




def verify_merkle_integrity(server_public_key, client_public_keys, received_root_hash):
    """
    Überprüft die Integrität der Datenblöcke, indem der Merkle Root-Hash berechnet
    und mit dem empfangenen Hash verglichen wird.
    """
    # Füge die öffentlichen Schlüssel in der festgelegten Reihenfolge zusammen
    public_key_list = []
    public_key_list.append(server_public_key)
    for key0 in client_public_keys:
        public_key_list.append(key0)
    data_blocks = merge_public_keys(public_key_list)#key_string
            # Generiere und sende den Merkle Root Hash an alle Clients
            
    # Berechne den Merkle Root-Hash
    calculated_root_hash = build_merkle_tree(data_blocks)
    print('+++STRING+++')
    print(data_blocks)

    # Vergleiche die Hash-Werte
    if calculated_root_hash == received_root_hash:
        print("Integrität der Daten bestätigt: Die Daten sind unverändert.")
        return True
    else:
        print("Integritätsprüfung fehlgeschlagen: Die Daten wurden manipuliert.")
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

def build_sip_message(method, recipient, custom_data={}):
    """Baut eine vollständige SIP-Nachricht mit Custom-Daten"""
    local_ip = socket.gethostbyname(socket.gethostname())
    body = "\r\n".join(f"{k}: {json.dumps(v) if isinstance(v, (dict, list)) else v}" for k, v in custom_data.items())
    
    return (
        f"{method} sip:{recipient} SIP/2.0\r\n"
        f"From: <sip:{load_client_name()}@{local_ip}>\r\n"
        f"To: <sip:{recipient}>\r\n"
        f"Call-ID: {uuid.uuid4()}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Content-Type: application/sip-custom\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    )
def parse_sip_message(message):
    """Korrigierte SIP-Nachrichtenparser-Funktion"""
    if isinstance(message, bytes):
        message = message.decode('utf-8')
    
    if not message.strip():
        return None

    lines = [line.strip() for line in message.splitlines() if line.strip()]
    result = {'headers': {}, 'custom_data': {}}
    
    # Erste Zeile analysieren
    first_line = lines[0]
    if first_line.startswith('SIP/2.0'):
        parts = first_line.split()
        if len(parts) >= 2:
            result['status_code'] = parts[1]  # Statuscode (200, 400 etc.)
            if len(parts) > 2:
                result['status_message'] = ' '.join(parts[2:])
    elif first_line in ["REGISTER", "INVITE", "MESSAGE"]:
        result['method'] = first_line
    else:
        return None  # Ungültige Nachricht

    # Header parsen
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().upper()
            value = value.strip()
            
            if key == "CUSTOM-DATA":
                try:
                    result['custom_data'] = json.loads(value)
                except json.JSONDecodeError:
                    result['custom_data'] = {}
            else:
                result['headers'][key] = value
    
    return result if ('method' in result or 'status_code' in result) else None
def start_connection(server_ip, server_port, client_name, client_socket):
    try:
        client_socket.settimeout(10.0)
        
        # 1. REGISTER senden
        pubkey = load_publickey()
        if isinstance(pubkey, bytes):
            pubkey = pubkey.decode('utf-8')
        client_socket.settimeout(10.0)  # Timeout setzen
        print(f"Verbinde zu {server_ip}:{server_port}...")  # Debug
        register_msg = build_sip_message(
            "REGISTER",
            server_ip,
            {
                "CLIENT_NAME": client_name,
                "PUBLIC_KEY": pubkey,  # Als String
                "VERSION": "1.0"       # Neu: Protokollversion
            }
        )
        pubkey = load_publickey()
        print(f"Sende Registrierung mit: Name={client_name}, Key={pubkey[:20]}...")
        print(f"Sende Registrierung: {register_msg[:200]}...")  # Debug
        client_socket.send(register_msg.encode('utf-8'))
        for attempt in range(3):  # Wiederholungsversuche
            try:
                response = client_socket.recv(4096)
                if response:
                    print(f"Serverantwort: {response[:200]}...")  # Debug
                    sip_data = parse_sip_message(response)
                    break
            except socket.timeout:
                print(f"Timeout Versuch {attempt+1}/3")
                continue
    
        if not response:
            raise ValueError("Keine Serverantwort (Timeout)")
        if not sip_data or 'status_code' not in sip_data:
            raise ValueError("Ungültiges Protokollformat")
        if sip_data['status_code'] != "200":
            error_details = sip_data.get('custom_data', {})
            raise ValueError(f"Serverfehler {sip_data['status_code']}: {error_details.get('ERROR','')}")

        # 3. Server-Key speichern
        # Extrahiere den Key aus dem Body der Nachricht
        server_public_key = None
        merkle_root = None
        if '\r\n\r\n' in response.decode('utf-8'):
            body = response.decode('utf-8').split('\r\n\r\n')[1]
            for line in body.split('\n'):
                if line.startswith('SERVER_PUBLIC_KEY:'):
                    server_public_key = line.split('SERVER_PUBLIC_KEY:')[1].strip()

        if not server_public_key:
            raise ValueError("Kein Server-Key erhalten")
        try:
            client_socket.settimeout(5.0)  # Timeout für Merkle-Root
            merkle_response = client_socket.recv(4096)
            if not merkle_response:
                raise ValueError("Keine Merkle-Root Antwort erhalten")
                
    
            if '\r\n\r\n' in merkle_response.decode('utf-8'):
                body = merkle_response.decode('utf-8').split('\r\n\r\n')[1]
                for line in body.split('\n'):
                    if line.startswith('MERKLE_ROOT:'):
                        merkle_root = line.split('MERKLE_ROOT:')[1].strip()
            
            if not merkle_root:
                raise ValueError("Keine Merkle-Root in der Antwort")
                
            print(f"Merkle-Root erhalten: {merkle_root}")
            
        except socket.timeout:
            raise ValueError("Timeout beim Warten auf Merkle-Root")

        # 5. Hauptkommunikationsschleife
        while True:
            try:
                # Ping-Pong Mechanismus
                ping_msg = build_sip_message(
                    "MESSAGE",
                    self.server_ip,
                    {"PING": "true", "TIMESTAMP": str(time.time())}
                )
                self.sock.send(ping_msg.encode('utf-8'))
    
                # Pong-Antwort empfangen und verarbeiten
            
                pong_response = self.sock.recv(4096)
                if not pong_response:
                    raise ValueError("Keine Pong-Antwort erhalten")
                    
                pong_data = self.parse_sip_message(pong_response)
                if not pong_data:
                    raise ValueError("Ungültiges Pong-Nachrichtenformat")
                    
                pong = pong_data.get('custom_data', {}).get("PONG")
                if pong != "true":
                    raise ValueError("Ungültige Pong-Antwort")
                    
                print("Ping-Pong erfolgreich")
            
            except socket.timeout:
                raise ValueError("Timeout bei Pong-Antwort")

    except Exception as e:
        print(f"[Client] Fehler: {str(e)}")
        raise
    finally:
        client_socket.close()
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

        # Speichere den öffentlichen Schlüssel
        pub_memory = BIO.MemoryBuffer()
        new_key.save_pub_key_bio(pub_memory)
        public_key = pub_memory.getvalue()

        with open("public_key.pem", "wb") as pubHandle:
            pubHandle.write(public_key)

        # Speichere den privaten Schlüssel
        priv_memory = BIO.MemoryBuffer()
        new_key.save_key_bio(priv_memory, cipher=None)
        private_key = priv_memory.getvalue()

        with open("private_key.pem", "wb") as privHandle:
            privHandle.write(private_key)
    else:
        # Lade den öffentlichen Schlüssel
        with open("public_key.pem", "rb") as load_pub_key:
            public_key = load_pub_key.read()

    return public_key.decode('utf-8')  # Rückgabe als String


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

class PHONEBOOK(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.title("PHONEBOOK, mein Telefonbuch")
        self.geometry("600x1000")
        self.configure(fg_color='black')
        ctk.set_appearance_mode("dark")
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
        self.phonebook_tab = ctk.CTkFrame(self.notebook,fg_color='black')
        self.notebook.add(self.phonebook_tab, text="Telefonbuch")
        self.create_phonebook_tab()

    def create_phonebook_tab(self):
        # Listbox für das Telefonbuch
        self.phonebook_listbox = tk.Listbox(self.phonebook_tab, bg='darkgray', fg='black')
        self.phonebook_listbox.pack(fill='both', expand=True, padx=10, pady=10)

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





#threading
    def on_connect_click(self):
        if self.client_socket:
            messagebox.showerror("Fehler", "Es besteht bereits eine Verbindung zum Server.")
            return

        server_ip = self.server_ip_input.get()
        server_port = self.server_port_input.get()
        client_name = load_client_name()
        if not server_ip or not server_port or not client_name:
            messagebox.showerror("Fehler", "Keine Server-IP, Port oder Name angegeben.")
            return

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((server_ip, int(server_port)))
            # Starte den Thread korrekt
            message_thread = threading.Thread(target=start_connection, args=(server_ip, server_port, client_name, self.client_socket))
            message_thread.daemon = True  # Daemon-Thread, damit er beendet wird, wenn das Hauptprogramm endet
            message_thread.start()  # Starte den Thread
            self.connection_window.after(1000,self.connection_window.destroy)            
            
        except Exception as e:
            messagebox.showerror("Fehler", f"Verbindung zum Server fehlgeschlagen: {e}")
            self.client_socket = None
        return


    def update_phonebook(self, phonebook):
        self.phonebook_listbox.delete(0, tk.END)
        for entry in phonebook.split("\n"):
            self.phonebook_listbox.insert(tk.END, entry)
            print('phonebook updated')
        # Speichere das Telefonbuch lokal
        with open("phonebook.json", "w") as f:
            json.dump(phonebook, f)

    def load_phonebook(self):
        # Lade das Telefonbuch vom Server
        pass

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

def main():
    global app
    app = PHONEBOOK()
    app_instance = threading.Thread(target=app.mainloop())
    app_instance.daemon = True
    app_instance.start()
if __name__ == "__main__":
    main()
