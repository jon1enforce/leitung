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
    """Frame receiver with increased size limit for RSA keys"""
    sock.settimeout(timeout)
    try:
        # Read header
        header = sock.recv(4)
        if len(header) != 4:
            return None
            
        length = struct.unpack('!I', header)[0]
        # ✅ ERHÖHT auf 64KB für RSA Public Keys (4096-bit Keys sind ~800 bytes)
        if length > 65536:  # 64KB max (statt 10MB)
            print(f"[FRAME ERROR] Frame too large: {length} bytes")
            raise ValueError(f"Frame too large: {length} bytes")
        
        # Read body
        received = bytearray()
        while len(received) < length:
            chunk = sock.recv(min(length - len(received), 4096))
            if not chunk:
                raise ConnectionError("Connection closed prematurely")
            received.extend(chunk)
        
        print(f"[FRAME DEBUG] Received {length} bytes frame")
        
        # Try UTF-8 decode for SIP messages
        try:
            return received.decode('utf-8')
        except UnicodeDecodeError:
            return bytes(received)
            
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
class CONVEY:
    def __init__(self, server_instance):
        self.server = server_instance
        self.active_calls = {}
        self.call_lock = threading.RLock()  # Lock für Thread-Sicherheit


    def handle_get_public_key(self, msg, client_socket, client_name):
        """Verbesserte Public-Key-Handling - VOLLSTÄNDIG KORRIGIERT"""
        try:
            custom_data = msg.get('custom_data', {})
            body = msg.get('body', '')
            
            print(f"[CONVEY DEBUG] Custom data: {custom_data}")
            print(f"[CONVEY DEBUG] Body: '{body}'")
            
            # ✅ VERBESSERT: Zuerst Body als JSON parsen
            target_id = None
            caller_name = None
            body_data = {}
            
            if body and body.strip():
                try:
                    body_data = json.loads(body)
                    print(f"[CONVEY DEBUG] Body parsed as JSON: {body_data}")
                except json.JSONDecodeError:
                    print("[CONVEY DEBUG] Body is not JSON, trying key-value")
                    # Fallback: Key-Value Parsing
                    for line in body.split('\n'):
                        line = line.strip()
                        if line and ': ' in line:
                            key, value = line.split(': ', 1)
                            body_data[key.strip()] = value.strip()
            
            # ✅ Daten aus allen Quellen sammeln (Body hat Priorität)
            target_id = body_data.get('TARGET_CLIENT_ID') or custom_data.get('TARGET_CLIENT_ID')
            caller_name = body_data.get('CALLER_NAME') or custom_data.get('CALLER_NAME') or client_name
                
            if not target_id:
                print(f"[CONVEY ERROR] Missing target client ID after parsing")
                print(f"[CONVEY DEBUG] Body data: {body_data}")
                print(f"[CONVEY DEBUG] Custom data: {custom_data}")
                
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "TARGET_NOT_FOUND",
                    "TARGET_ID": "unknown",
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False
                
            print(f"[CONVEY] Public key request from {caller_name} for client {target_id}")
            
            # Thread-sichere Client-Suche
            target_client = None
            with self.server.clients_lock:
                for client_id, client_info in self.server.clients.items():
                    if str(client_id) == str(target_id):
                        target_client = client_info
                        break
            
            if not target_client or 'public_key' not in target_client:
                print(f"[CONVEY ERROR] Target client {target_id} not found or no public key")
                
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "TARGET_NOT_FOUND",
                    "TARGET_ID": target_id,
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False
            
            # Public Key senden
            response_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                "MESSAGE_TYPE": "PUBLIC_KEY_RESPONSE", 
                "TARGET_CLIENT_ID": target_id,
                "PUBLIC_KEY": target_client['public_key'],
                "CALLER_NAME": caller_name,
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(client_socket, response_msg.encode('utf-8'))
            print(f"[CONVEY] Sent public key for client {target_id} to {caller_name}")
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Public key handling failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            # Fehlermeldung senden
            try:
                error_msg = self.server.build_sip_message("MESSAGE", client_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "INTERNAL_ERROR",
                    "REASON": str(e)[:100],
                    "TIMESTAMP": int(time.time())
                })
                send_frame(client_socket, error_msg.encode('utf-8'))
            except:
                pass
                
            return False
    def handle_call_request(self, msg, client_socket, client_name):
        """Vermittelt Call-Requests zwischen Clients"""
        try:
            custom_data = msg.get('custom_data', {})
            target_id = custom_data.get('TARGET_CLIENT_ID')
            encrypted_data = custom_data.get('ENCRYPTED_CALL_DATA')
            caller_name = custom_data.get('CALLER_NAME')
            caller_client_id = custom_data.get('CALLER_CLIENT_ID')
            
            if not all([target_id, encrypted_data, caller_name, caller_client_id]):
                print("[CONVEY ERROR] Missing required call data")
                return False
                
            print(f"[CONVEY] Call request from {caller_name} to {target_id}")
            
            # Ziel-Client finden
            target_client = None
            with self.server.clients_lock:
                for client_id, client_info in self.server.clients.items():
                    if str(client_id) == str(target_id):
                        target_client = client_info
                        break
            
            if not target_client or not target_client.get('socket'):
                print(f"[CONVEY ERROR] Target client {target_id} not found or offline")
                
                error_msg = self.server.build_sip_message("MESSAGE", caller_name, {
                    "MESSAGE_TYPE": "CALL_ERROR",
                    "ERROR": "TARGET_OFFLINE",
                    "TARGET_ID": target_id,
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(client_socket, error_msg.encode('utf-8'))
                return False
            
            # INCOMING_CALL an Ziel senden
            incoming_call_msg = self.server.build_sip_message("MESSAGE", target_client['name'], {
                "MESSAGE_TYPE": "INCOMING_CALL",
                "CALLER_NAME": caller_name,
                "CALLER_CLIENT_ID": caller_client_id,
                "ENCRYPTED_CALL_DATA": encrypted_data,
                "TIMESTAMP": int(time.time()),
                "TIMEOUT": 120
            })
            
            send_frame(target_client['socket'], incoming_call_msg.encode('utf-8'))
            
            # Call-Kontext speichern
            call_id = f"{caller_client_id}_{target_id}_{int(time.time())}"
            self.active_calls[call_id] = {
                'caller_id': caller_client_id,
                'callee_id': target_id,
                'caller': caller_name,
                'callee': target_client.get('name', 'Unknown'),
                'caller_socket': client_socket,
                'callee_socket': target_client['socket'],
                'start_time': time.time(),
                'status': 'pending',
                'timeout': 120
            }
            
            # Timeout-Überwachung starten
            threading.Thread(
                target=self._call_timeout_watchdog,
                args=(call_id,),
                daemon=True
            ).start()
            
            print(f"[CONVEY] Call request forwarded to {target_client.get('name', 'Unknown')}")
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Call request handling failed: {str(e)}")
            return False
    # Füge diese Methode zur CONVEY-Klasse hinzu
    def generate_wireguard_keypair(self):
        """Generiert ein WireGuard Schlüsselpaar"""
        try:
            # Private Key generieren
            private_key = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
            private_key = private_key.stdout.strip()
            
            # Public Key aus Private Key ableiten
            public_key = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True, check=True)
            public_key = public_key.stdout.strip()
            
            return private_key, public_key
        except Exception as e:
            print(f"[WIREGUARD ERROR] Key generation failed: {str(e)}")
            # Fallback: Generiere zufällige Keys
            import secrets
            private_key = secrets.token_hex(32)
            public_key = secrets.token_hex(32)
            return private_key, public_key
    def handle_call_response(self, msg, client_socket, client_name):
        """Leitet Call-Antworten weiter"""
        try:
            custom_data = msg.get('custom_data', {})
            response = custom_data.get('RESPONSE')
            caller_id = custom_data.get('CALLER_CLIENT_ID')
            callee_wg_key = custom_data.get('CALLEE_WG_PUBLIC_KEY')
            
            if not response or not caller_id:
                print("[CONVEY ERROR] Missing response data")
                return False
                
            print(f"[CONVEY] Call response from {client_name}: {response}")
            
            # Call-Kontext finden
            call_id = None
            call_data = None
            
            for cid, data in self.active_calls.items():
                if (data['callee_id'] == client_name and data['caller_id'] == caller_id) or \
                   (data['caller_id'] == client_name and data['callee_id'] == caller_id):
                    call_id = cid
                    call_data = data
                    break
            
            if not call_data:
                print(f"[CONVEY ERROR] No active call found for response")
                return False
            
            # Antwort an anderen Client weiterleiten
            if response == "accepted" and callee_wg_key:
                # An Anrufer senden
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller'], {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "accepted",
                    "CALLEE_WG_PUBLIC_KEY": callee_wg_key,
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                call_data['status'] = 'accepted'
                
            elif response == "rejected":
                # An Anrufer senden
                response_msg = self.server.build_sip_message("MESSAGE", call_data['caller'], {
                    "MESSAGE_TYPE": "CALL_RESPONSE",
                    "RESPONSE": "rejected",
                    "TIMESTAMP": int(time.time())
                })
                
                send_frame(call_data['caller_socket'], response_msg.encode('utf-8'))
                call_data['status'] = 'rejected'
                
            elif response == "error":
                call_data['status'] = 'error'
            
            # Call-Kontext bereinigen wenn abgeschlossen
            if response in ['accepted', 'rejected', 'error']:
                if call_id in self.active_calls:
                    del self.active_calls[call_id]
            
            print(f"[CONVEY] Call response forwarded: {response}")
            return True
            
        except Exception as e:
            print(f"[CONVEY ERROR] Call response handling failed: {str(e)}")
            return False

    def handle_call_end(self, msg, client_socket, client_name):
        """Verarbeitet Call-Ende Nachrichten"""
        try:
            custom_data = msg.get('custom_data', {})
            reason = custom_data.get('REASON', 'unknown')
            
            print(f"[CONVEY] Call end from {client_name}, reason: {reason}")
            
            # Aktive Calls für diesen Client finden und beenden
            calls_to_remove = []
            
            for call_id, call_data in self.active_calls.items():
                if call_data['caller_id'] == client_name or call_data['callee_id'] == client_name:
                    calls_to_remove.append(call_id)
                    
                    # Anderen Client benachrichtigen
                    other_client = call_data['callee_id'] if call_data['caller_id'] == client_name else call_data['caller_id']
                    other_socket = call_data['callee_socket'] if call_data['caller_id'] == client_name else call_data['caller_socket']
                    
                    end_msg = self.server.build_sip_message("MESSAGE", other_client, {
                        "MESSAGE_TYPE": "CALL_END",
                        "REASON": "remote_hangup",
                        "TIMESTAMP": int(time.time())
                    })
                    
                    try:
                        send_frame(other_socket, end_msg.encode('utf-8'))
                    except:
                        pass
            
            # Calls entfernen
            for call_id in calls_to_remove:
                if call_id in self.active_calls:
                    del self.active_calls[call_id]
            
            # Bestätigung senden
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
            
            del self.active_calls[call_id]

    def cleanup_client_calls(self, client_name):
        """Bereinigt alle Calls eines Clients bei Disconnect"""
        calls_to_remove = []
        
        for call_id, call_data in self.active_calls.items():
            if call_data['caller_id'] == client_name or call_data['callee_id'] == client_name:
                calls_to_remove.append(call_id)
                
                # Anderen Client benachrichtigen
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
        
        for call_id in calls_to_remove:
            if call_id in self.active_calls:
                del self.active_calls[call_id]
        
        if calls_to_remove:
            print(f"[CONVEY] Cleaned up {len(calls_to_remove)} calls for disconnected client {client_name}")



class Server:
    def __init__(self, host='0.0.0.0', port=5060):
        self.convey_manager = CONVEY(self)
        # Interaktive Host-Abfrage
        change_host = input("Set host-ip? y/n -> ").lower().strip()
        if change_host == 'y':
            new_host = input("New default host ip: ").strip()
            if new_host:  # Nur ändern wenn nicht leer
                host = new_host
                print(f"Host changed to: {host}")
            else:
                print("Keeping default host")
        self.active_calls = {}  # Aktive Calls verwalten
        self.call_timeout = 30  # Timeout in Sekunden
    
        # Lock für Thread-sicheren Zugriff auf active_calls
        self.call_lock = threading.RLock()
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
        self.clients_lock = threading.RLock()
        
        print(f"Server configured with: {self.host}:{self.port}")
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
            print("\nSpeichere Client-Daten...")
            with self.clients_lock:
                clients_copy = self.clients.copy()

            active_clients = {
                cid: {k: v for k, v in data.items() if k != 'socket'} 
                for cid, data in clients_copy.items() 
                if data.get('socket') is not None
            }
            
            try:
                with open("active_clients.json", "w") as f:
                    json.dump(active_clients, f, indent=2)
                print(f"{len(active_clients)} Clients gespeichert")
            except Exception as e:
                print(f"Fehler beim Speichern: {e}")
            
            print("Schließe Verbindungen...")
            with self.clients_lock:
                clients_copy = self.clients.copy()

            # ✅ SICHER: Dann mit der Kopie arbeiten
            for client_id, client_data in clients_copy.items():
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
        """Verarbeitet Nachrichten aus der Client-eigenen Queue - VOLLSTÄNDIG KORRIGIERT"""
        try:
            # VERBESSERT: Rekursionsschutz hinzufügen
            if hasattr(self, '_processing_client_queue') and self._processing_client_queue:
                return
            self._processing_client_queue = True
            
            while client_queue:
                queue_item = client_queue.pop(0)
                
                if queue_item.get('type') == 'frame_data':  # VERBESSERT: .get() für Sicherheit
                    frame_data = queue_item.get('data')
                    if not frame_data:
                        continue
                        
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
                        
                        # Header und Custom Data
                        headers = msg.get('headers', {})
                        custom_data = msg.get('custom_data', {})
                        body = msg.get('body', '')  # ✅ NEU: Body für Key-Value Parsing
                        
                        # ✅ ERWEITERTE MESSAGE_TYPE ERKENNUNG - Key-Value aus Body
                        message_type = None
                        if 'MESSAGE_TYPE' in custom_data:
                            message_type = custom_data['MESSAGE_TYPE']
                            print(f"[DEBUG] Found MESSAGE_TYPE in custom_data: {message_type}")
                        elif 'MESSAGE_TYPE' in headers:
                            message_type = headers['MESSAGE_TYPE']
                            print(f"[DEBUG] Found MESSAGE_TYPE in headers: {message_type}")
                        else:
                            # ✅ NEU: Key-Value Parsing aus Body für GET_PUBLIC_KEY
                            for line in body.split('\n'):
                                if 'MESSAGE_TYPE: ' in line:
                                    message_type = line.split('MESSAGE_TYPE: ')[1].strip()
                                    print(f"[DEBUG] Found MESSAGE_TYPE in body: {message_type}")
                                    break
                        
                        # ✅ CALL-bezogene Nachrichten an CONVEY MANAGER delegieren
                        if message_type in ['GET_PUBLIC_KEY', 'CALL_REQUEST', 'CALL_RESPONSE', 'CALL_END']:
                            if hasattr(self, 'convey_manager'):
                                print(f"[CALL] Delegating {message_type} to convey manager")
                                
                                # ✅ NEU: Body-Daten zu custom_data hinzufügen falls nötig
                                if body and message_type == 'GET_PUBLIC_KEY':
                                    body_data = {}
                                    for line in body.split('\n'):
                                        line = line.strip()
                                        if line and ': ' in line:  # ✅ VERBESSERT: Leerzeilen ignorieren
                                            key, value = line.split(': ', 1)
                                            body_data[key.strip()] = value.strip()
                                    # Füge Body-Daten zu custom_data hinzu (nur falls nicht vorhanden)
                                    for key, value in body_data.items():
                                        if key not in custom_data:  # ✅ VERBESSERT: Nur hinzufügen falls nicht schon da
                                            custom_data[key] = value
                                    msg['custom_data'] = custom_data
                                
                                if message_type == 'GET_PUBLIC_KEY':
                                    self.convey_manager.handle_get_public_key(msg, client_socket, client_name)
                                elif message_type == 'CALL_REQUEST':
                                    self.convey_manager.handle_call_request(msg, client_socket, client_name)
                                elif message_type == 'CALL_RESPONSE':
                                    self.convey_manager.handle_call_response(msg, client_socket, client_name)
                                elif message_type == 'CALL_END':
                                    self.convey_manager.handle_call_end(msg, client_socket, client_name)
                            else:
                                print(f"[CALL ERROR] No convey manager available for {message_type}")
                            continue
                        
                        # ✅ SESSION_KEY Handling
                        if message_type == 'SESSION_KEY':
                            print(f"[CALL] Session key received from {client_name}")
                            self._handle_session_key(msg, client_socket, client_name)
                            continue
                        
                        # ✅ INCOMING_CALL Response Handling
                        if message_type == 'INCOMING_CALL_RESPONSE':
                            print(f"[CALL] Incoming call response from {client_name}")
                            if hasattr(self, 'convey_manager'):
                                self.convey_manager.handle_call_response(msg, client_socket, client_name)
                            continue
                        
                        # ✅ Ping Handling
                        if headers.get('PING') == 'true' or custom_data.get('PING') == 'true':
                            print(f"[PING] Empfangen von {client_name}")
                            pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                            send_frame(client_socket, pong_response.encode('utf-8'))
                            continue
                        
                        # ✅ UPDATE Handling
                        update_detected = False
                        if headers.get('UPDATE') == 'true':
                            update_detected = True
                        elif custom_data.get('UPDATE') == 'true':
                            update_detected = True
                        elif message_type == 'UPDATE_REQUEST':
                            update_detected = True
                        
                        if update_detected:
                            print(f"[UPDATE] Empfangen von {client_name}")
                            
                            # Finde client_id und public key
                            client_id = None
                            client_pubkey = None
                            with self.clients_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        client_pubkey = data.get('public_key')
                                        break
                            
                            if client_id and client_pubkey:
                                print(f"[UPDATE] Starte Identity Challenge für {client_name} (ID: {client_id})")
                                identity_verified, challenge_id = self.test_identity_sip(client_socket, client_pubkey, client_name)
                                
                                if identity_verified:
                                    print(f"[IDENTITY] {client_name} erfolgreich verifiziert")
                                    if self.send_phonebook(client_id):
                                        print(f"[UPDATE] Phonebook gesendet an {client_name}")
                                    else:
                                        print(f"[UPDATE ERROR] Phonebook konnte nicht gesendet werden an {client_name}")
                                else:
                                    print(f"[IDENTITY] {client_name} Verifizierung fehlgeschlagen")
                                        
                                    error_msg = self.build_sip_message("401 Unauthorized", client_name, {
                                        "STATUS": "IDENTITY_VERIFICATION_FAILED",
                                        "REASON": "Challenge response invalid",
                                        "TIMESTAMP": int(time.time())
                                    })
                                    send_frame(client_socket, error_msg.encode('utf-8'))
                            else:
                                print(f"[UPDATE ERROR] Client {client_name} nicht gefunden oder kein Public Key")    
                                error_msg = self.build_sip_message("404 Not Found", client_name, {
                                        "STATUS": "CLIENT_NOT_FOUND",
                                        "ERROR": "Client not registered or missing public key",
                                        "TIMESTAMP": int(time.time())
                                    })
                                send_frame(client_socket, error_msg.encode('utf-8'))
                            continue
                        
                        # ✅ Identity Response Handling
                        if message_type == 'IDENTITY_RESPONSE':
                            print(f"[IDENTITY] Response empfangen von {client_name}")
                            self._handle_identity_response(client_socket, client_name, msg)
                            continue
                        
                        # ✅ ENCRYPTED_SECRET Handling
                        if 'ENCRYPTED_SECRET' in custom_data:
                            print(f"[ENCRYPTED] Empfangen von {client_name}")
                            
                            # Finde client_id
                            client_id = None
                            with self.clients_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                try:
                                    encrypted_secret = base64.b64decode(custom_data['ENCRYPTED_SECRET'])
                                    if self.store_client_secret(client_id, encrypted_secret):
                                        ack_msg = self.build_sip_message("200 OK", client_name, {
                                            "STATUS": "SECRET_STORED",
                                            "CLIENT_ID": client_id,
                                            "TIMESTAMP": int(time.time())
                                        })
                                        print(f"[SECRET] Gespeichert für {client_name}")
                                    else:
                                        ack_msg = self.build_sip_message("500 Error", client_name, {
                                            "STATUS": "SECRET_STORAGE_FAILED",
                                            "ERROR": "Failed to store secret",
                                            "TIMESTAMP": int(time.time())
                                        })
                                        print(f"[SECRET ERROR] Konnte Secret nicht speichern für {client_name}")
                                except Exception as e:
                                    ack_msg = self.build_sip_message("500 Error", client_name, {
                                        "STATUS": "PROCESSING_ERROR",
                                        "ERROR": str(e)[:100],
                                        "TIMESTAMP": int(time.time())
                                    })
                                    print(f"[SECRET ERROR] Fehler bei Secret-Verarbeitung: {str(e)}")
                            else:
                                ack_msg = self.build_sip_message("404 Not Found", client_name, {
                                    "STATUS": "CLIENT_NOT_FOUND",
                                    "ERROR": "Client not registered",
                                    "TIMESTAMP": int(time.time())
                                })
                                print(f"[SECRET ERROR] Client {client_name} nicht gefunden")
                            
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        # ✅ PHONEBOOK_REQUEST Handling
                        if message_type == 'PHONEBOOK_REQUEST' or 'PHONEBOOK_REQUEST' in custom_data:
                            print(f"[PHONEBOOK] Request von {client_name}")
                            
                            # Finde client_id
                            client_id = None
                            with self.clients_lock:
                                for cid, data in self.clients.items():
                                    if data.get('name') == client_name:
                                        client_id = cid
                                        break
                            
                            if client_id:
                                if self.send_phonebook(client_id):
                                    ack_msg = self.build_sip_message("200 OK", client_name, {
                                        "STATUS": "PHONEBOOK_SENT",
                                        "CLIENT_ID": client_id,
                                        "TIMESTAMP": int(time.time())
                                    })
                                    print(f"[PHONEBOOK] Gesendet an {client_name}")
                                else:
                                    ack_msg = self.build_sip_message("500 Error", client_name, {
                                        "STATUS": "PHONEBOOK_FAILED",
                                        "ERROR": "Could not send phonebook",
                                        "CLIENT_ID": client_id,
                                        "TIMESTAMP": int(time.time())
                                    })
                                    print(f"[PHONEBOOK ERROR] Konnte Phonebook nicht senden an {client_name}")
                            else:
                                ack_msg = self.build_sip_message("404 Not Found", client_name, {
                                    "STATUS": "CLIENT_NOT_FOUND",
                                    "ERROR": "Client not registered",
                                    "TIMESTAMP": int(time.time())
                                })
                                print(f"[PHONEBOOK ERROR] Client {client_name} nicht gefunden")
                            
                            send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        # ✅ CALL_SETUP Handling (Legacy)
                        if 'CALL_SETUP' in custom_data:
                            call_data = custom_data
                            if call_data.get('CALL_SETUP') == 'request':
                                caller_id = call_data.get('CALLER_ID')
                                callee_id = call_data.get('CALLEE_ID')
                                if caller_id and callee_id:
                                    if self.initiate_call_between_clients(caller_id, callee_id):
                                        ack_msg = self.build_sip_message("200 OK", client_name, {
                                            "STATUS": "CALL_INITIATED",
                                            "CALLER_ID": caller_id,
                                            "CALLEE_ID": callee_id,
                                            "TIMESTAMP": int(time.time())
                                        })
                                        print(f"[CALL] Vermittelt zwischen {caller_id} und {callee_id}")
                                    else:
                                        ack_msg = self.build_sip_message("500 Error", client_name, {
                                            "STATUS": "CALL_FAILED",
                                            "ERROR": "Could not initiate call",
                                            "CALLER_ID": caller_id,
                                            "CALLEE_ID": callee_id,
                                            "TIMESTAMP": int(time.time())
                                        })
                                        print(f"[CALL ERROR] Konnte Call nicht vermitteln")
                                    
                                    send_frame(client_socket, ack_msg.encode('utf-8'))
                            continue
                        
                        # ✅ Unbekannte Nachricht - Standardantwort
                        print(f"[UNKNOWN] Unbekannte Nachricht von {client_name}: {message_type}")
                        print(f"[DEBUG] Custom data keys: {list(custom_data.keys())}")
                        
                        # Standard Bestätigung senden
                        ack_msg = self.build_sip_message("200 OK", client_name, {
                                "STATUS": "MESSAGE_RECEIVED",
                                "MESSAGE_TYPE": message_type or "UNKNOWN",
                                "TIMESTAMP": int(time.time())
                            })
                        
                        send_frame(client_socket, ack_msg.encode('utf-8'))
                        
                    except UnicodeDecodeError:
                        print(f"[SERVER ERROR] Kein UTF-8 SIP von {client_name} - Verwerfe {len(frame_data)} bytes")
                        continue
                        
        except Exception as e:
            print(f"[CLIENT QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            # VERBESSERT: Flag immer zurücksetzen
            if hasattr(self, '_processing_client_queue'):
                self._processing_client_queue = False
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
    def handle_client(self, client_socket, client_address):
        """Vollständige Client-Behandlung - Jede Session isoliert"""
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

            # 6. ✅ Client ATOMIC registrieren (THREAD-SAFE)
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

            # 9. ZWEITE ANTWORT: Merkle Root und alle Keys
            second_response_data = {
                "MERKLE_ROOT": merkle_root,
                "ALL_KEYS": all_public_keys  # ✅ Lokale Variable verwenden
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
            # ✅ Cleanup (THREAD-SAFE)
            print(f"[SERVER] Cleanup für {client_name if client_name else 'unknown'}")
            
            if client_id:
                self._safe_remove_client(client_id)
            
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
        Normalisiert einen Client Public Key für M2Crypto mit erweitertem Debugging
        """
        if not key or not isinstance(key, str):
            print("[DEBUG] Key is None or not a string")
            return None
        
        key = key.strip()
        print(f"[DEBUG] Original key length: {len(key)}")
        print(f"[DEBUG] Key starts with: {repr(key[:50])}")
        print(f"[DEBUG] Key ends with: {repr(key[-50:])}")
        
        # Fall 1: Bereits korrektes PEM Format
        if key.startswith('-----BEGIN PUBLIC KEY-----') and key.endswith('-----END PUBLIC KEY-----'):
            print("[DEBUG] Key is already in PEM format")
            return key
        
        # Fall 2: Base64 content ohne PEM Header
        try:
            # Entferne eventuelle Prefixe wie "SERVER_PUBLIC_KEY: "
            if ':' in key:
                key = key.split(':', 1)[1].strip()
            
            # Teste ob es Base64 ist
            import re
            # Entferne alle Whitespace Zeichen
            clean_key = re.sub(r'\s+', '', key)
            base64.b64decode(clean_key)
            
            # Wrap in PEM headers
            pem_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----"
            print("[DEBUG] Successfully converted Base64 to PEM format")
            return pem_key
            
        except Exception as e:
            print(f"[DEBUG] Key is not valid Base64: {e}")
        
        # Fall 3: Key enthält literal \n Zeichen
        if '\\n' in key:
            print("[DEBUG] Key contains literal \\n characters, replacing...")
            key = key.replace('\\n', '\n')
            if key.startswith('-----BEGIN PUBLIC KEY-----') and key.endswith('-----END PUBLIC KEY-----'):
                return key
        
        print("[DEBUG] Key format could not be normalized")
        return None             
    def test_identity_sip(self, client_socket, client_pubkey, client_name):
        """
        Führt einen Identity-Test über SIP-Nachrichten durch mit erweitertem Debugging
        """
        timeout = 45
        challenge_id = None
        
        try:
            print(f"[DEBUG] Starting identity test for client: {client_name}")
            
            # 0. Server Private Key verwenden
            private_key_path = "server_private_key.pem"
            if not os.path.exists(private_key_path):
                print(f"[DEBUG] ERROR: Server private key file not found: {private_key_path}")
                return False, None
            
            print(f"[DEBUG] Using server private key: {private_key_path}")
            
            # 1. Private Key laden und validieren
            try:
                with open(private_key_path, "rb") as f:
                    priv_key_data = f.read()
                    priv_key = RSA.load_key_string(priv_key_data)
                
                # Teste ob der private Schlüssel funktioniert
                test_data = b"test_message_123"
                encrypted_test = priv_key.public_encrypt(test_data, RSA.pkcs1_padding)
                decrypted_test = priv_key.private_decrypt(encrypted_test, RSA.pkcs1_padding)
                
                if decrypted_test != test_data:
                    print("[DEBUG] ERROR: Private key test failed - decryption mismatch")
                    print(f"Expected: {test_data}")
                    print(f"Got: {decrypted_test}")
                    return False, None
                else:
                    print("[DEBUG] Private key test PASSED")
                    
            except Exception as e:
                print(f"[DEBUG] ERROR: Private key test failed: {e}")
                import traceback
                traceback.print_exc()
                return False, None
            
            # 2. Challenge generieren
            challenge = base64.b64encode(secure_random(16)).decode('ascii')
            challenge_id = str(uuid.uuid4())
            print(f"[SERVER] Generated SIP challenge: {challenge} (ID: {challenge_id})")
            
            # 3. Challenge mit Client-Public-Key verschlüsseln
            try:
                if '\\n' in client_pubkey:
                    print("[DEBUG] Replacing literal \\n with actual newlines")
                    client_pubkey = client_pubkey.replace('\\n', '\n')
                
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(client_pubkey.encode()))
                encrypted_challenge = pub_key.public_encrypt(
                    challenge.encode('utf-8'), 
                    RSA.pkcs1_padding
                )
                print(f"[DEBUG] Challenge encrypted successfully, length: {len(encrypted_challenge)} bytes")
            except Exception as e:
                print(f"[DEBUG] Encryption error: {e}")
                import traceback
                traceback.print_exc()
                return False, challenge_id
            
            # 4. Challenge senden
            challenge_msg = self.build_sip_message("MESSAGE", client_name, {
                "MESSAGE_TYPE": "IDENTITY_CHALLENGE",
                "CHALLENGE_ID": challenge_id,
                "ENCRYPTED_CHALLENGE": base64.b64encode(encrypted_challenge).decode('ascii'),
                "TIMESTAMP": int(time.time())
            })
            
            send_frame(client_socket, challenge_msg.encode('utf-8'))
            print("[SERVER] Sent SIP challenge to client")
            
            # 5. Response empfangen
            client_socket.settimeout(5.0)
            start_time = time.time()
            response_text = None
            
            while time.time() - start_time < timeout:
                try:
                    response_data = recv_frame(client_socket)
                    if not response_data:
                        continue
                    
                    if isinstance(response_data, bytes):
                        response_text = response_data.decode('utf-8', errors='ignore')
                    else:
                        response_text = str(response_data)
                    
                    # Ping handling
                    if "PING" in response_text:
                        pong_response = self.build_sip_message("MESSAGE", client_name, {"PONG": "true"})
                        send_frame(client_socket, pong_response.encode('utf-8'))
                        continue
                    
                    # Identity Response check
                    if "IDENTITY_RESPONSE" in response_text and challenge_id in response_text:
                        print("[DEBUG] ✓ FOUND MATCHING IDENTITY_RESPONSE!")
                        break
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[DEBUG] Error receiving response: {e}")
                    continue
            else:
                print("[DEBUG] Identity test failed: Timeout")
                return False, challenge_id
            
            # 6. Response parsen
            lines = response_text.split('\r\n')
            body_started = False
            body_lines = []
            
            for line in lines:
                if line.strip() == '':
                    body_started = True
                    continue
                if body_started:
                    body_lines.append(line.strip())
            
            # Custom Data parsen
            custom_data = {}
            for line in body_lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    custom_data[key.strip()] = value.strip()
            
            response_challenge_id = custom_data.get('CHALLENGE_ID')
            encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
            
            if not all([response_challenge_id, encrypted_response_b64]):
                print("[DEBUG] Identity test failed: Missing response fields")
                return False, challenge_id
            
            if response_challenge_id != challenge_id:
                print("[DEBUG] Identity test failed: Challenge ID mismatch")
                return False, challenge_id
            
            # 7. Response entschlüsseln
            try:
                encrypted_response_bytes = base64.b64decode(encrypted_response_b64)
                print(f"[DEBUG] Decoded encrypted response: {len(encrypted_response_bytes)} bytes")
                
                decrypted_response = priv_key.private_decrypt(encrypted_response_bytes, RSA.pkcs1_padding)
                
                if decrypted_response is None:
                    print("[DEBUG] Identity test FAILED: Decryption returned None")
                    return False, challenge_id
                    
                if len(decrypted_response) == 0:
                    print("[DEBUG] Identity test FAILED: Decryption returned empty data")
                    return False, challenge_id
                
                # Decoding versuchen
                try:
                    decrypted_text = decrypted_response.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        decrypted_text = decrypted_response.decode('latin-1')
                    except:
                        print("[DEBUG] Identity test FAILED: Could not decode response")
                        return False, challenge_id
                
                expected_response = challenge + "VALIDATED"
                
                if decrypted_text == expected_response:
                    print("[SERVER] Identity test PASSED")
                    success_msg = self.build_sip_message("200 OK", client_name, {
                        "STATUS": "IDENTITY_VERIFIED",
                        "CHALLENGE_ID": challenge_id
                    })
                    send_frame(client_socket, success_msg.encode('utf-8'))
                    return True, challenge_id
                else:
                    print("[DEBUG] Identity test FAILED: Response mismatch")
                    print(f"Expected: {expected_response}")
                    print(f"Got: {decrypted_text}")
                    return False, challenge_id
                    
            except Exception as e:
                print(f"[DEBUG] Identity test FAILED: Decryption error: {e}")
                import traceback
                traceback.print_exc()
                return False, challenge_id
                
        except Exception as e:
            print(f"[DEBUG] Identity test FAILED: {e}")
            import traceback
            traceback.print_exc()
            return False, challenge_id
    def _process_identity_response(self, sip_data, raw_data):
        """Verarbeitet Identity Response - KORRIGIERT FÜR KEY-VALUE"""
        try:
            print("[DEBUG] ✓ FOUND MATCHING IDENTITY_RESPONSE!")
            
            # Extrahiere Body und parse als Key-Value
            body = sip_data.get('body', '')
            custom_data = {}
            for line in body.split('\n'):
                line = line.strip()
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    custom_data[key] = value
            
            challenge_id = custom_data.get('CHALLENGE_ID')
            encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
            
            if not challenge_id or not encrypted_response_b64:
                print("[ERROR] Missing fields in identity response")
                return False
            
            # Überprüfe ob Challenge ID existiert
            if challenge_id not in self.active_challenges:
                print(f"[ERROR] Unknown challenge ID: {challenge_id}")
                return False
            
            original_challenge = self.active_challenges[challenge_id]
            
            # Entschlüssele die Response
            try:
                encrypted_response = base64.b64decode(encrypted_response_b64)
                decrypted_response = self.private_key.private_decrypt(
                    encrypted_response, RSA.pkcs1_padding
                ).decode('utf-8')
                
                print(f"[DEBUG] Decrypted response: {decrypted_response}")
                print(f"[DEBUG] Expected: {original_challenge}VALIDATED")
                
                # Validiere die Response
                if decrypted_response == original_challenge + "VALIDATED":
                    print(f"[IDENTITY] {sip_data['from_user']} erfolgreich verifiziert")
                    del self.active_challenges[challenge_id]
                    return True
                else:
                    print("[IDENTITY] Verification failed - response mismatch")
                    return False
                    
            except Exception as e:
                print(f"[IDENTITY ERROR] Decryption failed: {str(e)}")
                return False
                
        except Exception as e:
            print(f"[IDENTITY ERROR] Processing failed: {str(e)}")
            return False                       
    def _process_queue(self):
        """Thread-safe message processing with proper locking"""
        self._processing_queue = True
        
        try:
            while self._message_queue:
                queue_item = self._message_queue.pop(0)
                
                if queue_item['type'] == 'frame_data':
                    self._process_frame_data(queue_item)#1
                    
                elif queue_item['type'] == 'send_response':
                    self._process_send_response(queue_item)
                    
                elif queue_item['type'] == 'start_identity_challenge':
                    self._process_start_identity_challenge(queue_item)
                    
                elif queue_item['type'] == 'process_identity_response':
                    self._process_identity_response(queue_item)
                    
                elif queue_item['type'] == 'process_sip':
                    self._process_sip_message(queue_item)
                    
                elif queue_item['type'] == 'process_encrypted':
                    self._process_encrypted(queue_item)
                    
                elif queue_item['type'] == 'process_encrypted_binary':
                    self._process_encrypted_binary(queue_item)
                            
        except Exception as e:
            print(f"[QUEUE ERROR] {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self._processing_queue = False


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
        """Thread-safe update request handling"""
        # ✅ SICHER: Client suchen mit clients_lock
        client_id = None
        client_pubkey = None
        
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        for cid, data in clients_copy.items():
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
            # Debug output
            with self.clients_lock:
                print(f"[DEBUG] Available clients: {list(self.clients.keys())}")
                for cid, data in self.clients.items():
                    print(f"  {cid}: {data.get('name')} - pubkey: {'public_key' in data}")

    def _handle_identity_response(self, client_socket, client_name, msg):
        """Thread-safe identity response handling - MINIMAL KORRIGIERT"""
        # Extrahiere Daten aus der Nachricht
        custom_data = msg.get('custom_data', {})
        body = msg.get('body', '')
        
        encrypted_response_b64 = custom_data.get('ENCRYPTED_RESPONSE')
        response_challenge_id = custom_data.get('CHALLENGE_ID')
        
        # ✅ ERWEITERT: Key-Value Parsing falls nicht in custom_data
        if not encrypted_response_b64 or not response_challenge_id:
            for line in body.split('\n'):
                line = line.strip()
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    if key == 'ENCRYPTED_RESPONSE':
                        encrypted_response_b64 = value.strip()
                    elif key == 'CHALLENGE_ID':
                        response_challenge_id = value.strip()
        
        if not encrypted_response_b64 or not response_challenge_id:
            print("[IDENTITY ERROR] Missing response fields after body parsing")
            return
        
        # ✅ SICHER: Client ID finden mit clients_lock
        client_id = None
        with self.clients_lock:
            clients_copy = self.clients.copy()
        
        for cid, data in clients_copy.items():
            if data.get('name') == client_name:
                client_id = cid
                break
        
        if client_id:
            print(f"[IDENTITY] Client ID gefunden: {client_id}")
            
            self._message_queue.append({
                'type': 'process_identity_response',
                'sip_data': msg,
                'client_socket': client_socket,
                'client_name': client_name,
                'client_id': client_id,
                'encrypted_response_b64': encrypted_response_b64,
                'response_challenge_id': response_challenge_id
            })
        else:
            print(f"[IDENTITY ERROR] Client {client_name} nicht gefunden")

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
            identity_verified, challenge_id = self.test_identity_sip(client_socket, client_pubkey, client_name)
            
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
        Sendet das verschlüsselte Phonebook an einen Client
        """
        try:
            print(f"\n=== SEND PHONEBOOK DEBUG START (Client {client_id}) ===")
            
            # 1. ✅ ZIEL Client-Daten validieren (EINZELNER Client)
            target_client_data = self.get_client(client_id)  # ← RICHTIG!
            if not target_client_data:
                print(f"[ERROR] Client {client_id} nicht gefunden")
                return False
                
            if not target_client_data.get('socket'):
                print(f"[ERROR] Client {client_id} hat keinen Socket")
                return False

            # 2. ✅ ALLE Clients fürs Phonebook holen
            all_clients_data = self.get_all_clients()  # ← Dictionary aller Clients
            print(f"[DEBUG] Total clients for phonebook: {len(all_clients_data)}")

            # 3. Phonebook-Liste erstellen
            phonebook_clients = []
            for cid, data in all_clients_data.items():
                has_public_key = 'public_key' in data and data['public_key']
                has_name = 'name' in data and data['name']
                
                if has_public_key and has_name:
                    client_entry = {
                        'id': cid,
                        'name': data['name'],
                        'public_key': data['public_key'],
                        'ip': data.get('ip', ''),
                        'port': data.get('port', 0),
                        'is_self': cid == client_id,
                        'online': data.get('socket') is not None
                    }
                    phonebook_clients.append(client_entry)

            # 4. Phonebook-Daten vorbereiten
            phonebook_data = {
                'version': '2.0',
                'timestamp': int(time.time()),
                'merkle_root': build_merkle_tree_from_keys(self.all_public_keys),
                'total_clients': len(all_clients_data),
                'connected_clients': sum(1 for c in all_clients_data.values() if c.get('socket')),
                'clients': phonebook_clients
            }

            # 5. ✅ Verschlüsselung mit ZIEL Client Public Key
            print("[DEBUG] Encrypting secret with TARGET client public key...")
            try:
                pub_key = RSA.load_pub_key_bio(BIO.MemoryBuffer(target_client_data['public_key'].encode()))
                secret = b"+++secret+++" + self.generate_secret()
                encrypted_secret = pub_key.public_encrypt(secret, RSA.pkcs1_padding)
            except Exception as e:
                print(f"[ERROR] Public key encryption failed: {e}")
                return False

            # 6. AES Verschlüsselung
            iv = secret[12:28]  # 16 Bytes IV
            aes_key = secret[28:60]  # 32 Bytes Key
            
            cipher = EVP.Cipher("aes_256_cbc", aes_key, iv, 1)
            phonebook_str = json.dumps(phonebook_data, separators=(',', ':'))
            encrypted_phonebook = cipher.update(phonebook_str.encode()) + cipher.final()

            # 7. Nachricht erstellen und senden
            message = self.build_sip_message(
                "MESSAGE",
                target_client_data['name'],  # ← ZIEL Client Name
                {
                    "ENCRYPTED_SECRET": base64.b64encode(encrypted_secret).decode(),
                    "ENCRYPTED_PHONEBOOK": base64.b64encode(encrypted_phonebook).decode(),
                    "CLIENT_ID": client_id,
                    "TIMESTAMP": phonebook_data['timestamp']
                }
            )

            # 8. Senden
            with self.client_send_lock:
                if target_client_data['socket'].fileno() == -1:
                    return False
                    
                send_frame(target_client_data['socket'], message)
                print(f"[SUCCESS] Phonebook an {target_client_data['name']} gesendet")
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
        # Entropy check
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read().strip())
            if entropy < 2000:
                print("LOW ENTROPY DETECTED!")
            print(f"Entropy level: {entropy}")
        
        print("Starting server...")
        server = Server()
        server.start()
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
