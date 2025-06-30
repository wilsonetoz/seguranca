import socket
import threading
import os
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_ssh_private_key


FIXED_DH_PARAMETERS_PEM = b"""-----BEGIN DH PARAMETERS-----
MIGHAoGBAIw8OqcQG5UziSsa92WZo6VhLEQBHEdBY+ofV24omMRZlqft9FiGjhm6
sXNd4OksNbu6kByl3HCH1a0E25k8Ge8VJ+pdTcx3rui4YEvGQYRcVoY8FZoqTCv4
MQNe8Dh2ZwUx4IUnrBBjmaLP2CwOZGOwuMf4XTYJK/jvv6OwZmw3AgEC
-----END DH PARAMETERS-----
"""

DH_PARAMETERS = serialization.load_pem_parameters(FIXED_DH_PARAMETERS_PEM, backend=default_backend())

SERVER_USERNAME = "wilsonetoz"
SERVER_PRIVATE_KEY_FILE = "servidor_key" 

# Configurações para derivação de chaves (PBKDF2)
PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16

AES_KEY_LENGTH = 32
HMAC_KEY_LENGTH = 32
HMAC_TAG_LEN = 32
IV_AES_LEN = 16

def send_prefixed_data(sock, data):
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big') + data)

def recv_prefixed_data(sock):
    raw_length = sock.recv(4)
    if not raw_length:
        return None
    length = int.from_bytes(raw_length, 'big')
    
    data = b''
    bytes_received = 0
    while bytes_received < length:
        chunk = sock.recv(min(4096, length - bytes_received))
        if not chunk:
            return None
        data += chunk
        bytes_received += len(chunk)
    return data

def get_public_key_from_github(username):
    public_keys = []
    try:
        response = requests.get(f"https://github.com/{username}.keys")
        response.raise_for_status()
        
        key_lines = response.text.strip().split('\n')
        for line in key_lines:
            if line.strip():
                try:
                    public_key = load_ssh_public_key(line.encode('utf-8'), backend=default_backend())
                    print(f"DEBUG: Chave pública para '{username}' analisada com sucesso: {line.strip()[:50]}...")
                    public_keys.append(public_key)
                except Exception as e:
                    print(f"DEBUG: Falha ao analisar linha como SSH public key: {e}. Tentando próxima linha...")
        
        if not public_keys:
            print(f"ERRO: Nenhuma chave pública SSH analisável encontrada para '{username}' no GitHub.")
            return []
        return public_keys
    except requests.exceptions.RequestException as e:
        print(f"ERRO: Falha ao buscar chave pública para '{username}' no GitHub: {e}")
        return []
    except Exception as e:
        print(f"ERRO: Ocorreu um erro inesperado ao buscar/analisar a chave pública para '{username}': {e}")
        return []

def send_secure_message(sock, message, key_aes, key_hmac):
    message_bytes = message.encode('utf-8')
    iv_aes = os.urandom(IV_AES_LEN)

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv_aes), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    h = hmac.HMAC(key_hmac, hashes.SHA256(), backend=default_backend())
    h.update(iv_aes + encrypted_message)
    hmac_tag = h.finalize()

    full_packet = hmac_tag + iv_aes + encrypted_message
    
    send_prefixed_data(sock, full_packet)
    print("DEBUG_SEND: Mensagem segura enviada.")

def receive_secure_message(sock, key_aes, key_hmac):
    try:
        full_packet = recv_prefixed_data(sock)
        if full_packet is None:
            return None

        if len(full_packet) < HMAC_TAG_LEN + IV_AES_LEN:
            print(f"ERRO_RECV: Pacote recebido muito curto. Esperado pelo menos {HMAC_TAG_LEN + IV_AES_LEN}, obtido {len(full_packet)}.")
            return "[PACOTE_CURTO]"

        received_hmac_tag = full_packet[:HMAC_TAG_LEN]
        received_iv_aes = full_packet[HMAC_TAG_LEN : HMAC_TAG_LEN + IV_AES_LEN]
        encrypted_message = full_packet[HMAC_TAG_LEN + IV_AES_LEN :]
        
        h = hmac.HMAC(key_hmac, hashes.SHA256(), backend=default_backend())
        h.update(received_iv_aes + encrypted_message)
        expected_hmac_tag = h.finalize()

        if expected_hmac_tag == received_hmac_tag:
            cipher = Cipher(algorithms.AES(key_aes), modes.CBC(received_iv_aes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

            padding_length = decrypted_padded_message[-1]
            if padding_length > len(decrypted_padded_message) or padding_length == 0:
                print(f"ERRO_RECV: Comprimento de padding inválido detectado: {padding_length}. Possível corrupção ou ataque.")
                return "[PADDING_INVALIDO]"

            decrypted_message = decrypted_padded_message[:-padding_length].decode('utf-8')
            print("DEBUG_RECV: Mensagem descriptografada com sucesso.")
            return decrypted_message
        else:
            print(f"ERRO_RECV: Falha na verificação de HMAC! Integridade ou autenticidade comprometida.")
            return "[HMAC_INVALIDO]"
    except Exception as e:
        print(f"ERRO_RECV: Erro durante recepção/descriptografia da mensagem: {e}")
        return None

def handle_client_communication(conn, key_aes, key_hmac):
    print("[*] Iniciando thread de recebimento para o cliente.")
    while True:
        message = receive_secure_message(conn, key_aes, key_hmac)
        if message is None:
            print("[-] Conexão com o cliente perdida.")
            break
        elif message == "[HMAC_INVALIDO]":
            print("[RECEBIDO] Mensagem rejeitada: Falha na verificação.")
        elif message == "[PACOTE_CURTO]":
            print("[RECEBIDO] Mensagem rejeitada: Pacote recebido muito curto.")
        elif message == "[PADDING_INVALIDO]":
            print("[RECEBIDO] Mensagem rejeitada: Padding inválido.")
        else:
            print(f"[RECEBIDO] {message}")

def run_server():
    HOST = '127.0.0.1'
    PORT = 65432

    try:
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as key_file:
            server_private_key_ecdsa = load_ssh_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        print(f"[+] Chave privada ECDSA do servidor carregada de '{SERVER_PRIVATE_KEY_FILE}'.")
    except FileNotFoundError:
        print(f"ERRO: Arquivo da chave privada do servidor '{SERVER_PRIVATE_KEY_FILE}' não encontrado.")
        return
    except Exception as e:
        print(f"ERRO: Falha ao carregar a chave privada do servidor: {e}. Certifique-se de que é uma chave SSH válida e senha.")
        return
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Servidor rodando em {HOST}:{PORT}")
        print("[*] Aguardando conexão do cliente...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Cliente conectado de {addr}")

            # 2- Handshake Diffie-Hellman e Autenticação
            print("[*] Iniciando Handshake DH e Autenticação com cliente...")

            client_dh_public_bytes = recv_prefixed_data(conn)
            client_signature_bytes = recv_prefixed_data(conn)
            client_username_bytes = recv_prefixed_data(conn)

            if any(x is None for x in [client_dh_public_bytes, client_signature_bytes, client_username_bytes]):
                print("ERRO: Falha ao receber todos os componentes do handshake do cliente. Abortando.")
                return

            client_username = client_username_bytes.decode('utf-8')
            print(f"[*] Recebido do cliente: Chave DH Pública, Assinatura, Usuário ({client_username}).")

            client_public_keys_from_github = get_public_key_from_github(client_username)
            if not client_public_keys_from_github:
                print(f"ERRO: Nenhuma chave publica valida encontrada para '{client_username}' no GitHub. Abortando.")
                return
            
            # Verifica a assinatura do cliente, tentando com todas as chaves
            signature_verified = False
            data_to_verify = client_dh_public_bytes + client_username_bytes
            for pub_key in client_public_keys_from_github:
                try:
                    pub_key.verify(client_signature_bytes, data_to_verify)
                    print(f"[+] Assinatura do cliente verificada com sucesso usando uma das chaves do '{client_username}'.")
                    signature_verified = True
                    break
                except Exception:
                    pass
            
            if not signature_verified:
                print(f"ERRO: Falha na verificação da assinatura do cliente. Nenhuma das chaves públicas do '{client_username}' no GitHub correspond.")
                return

            # Gera o par de chaves DH do servidor
            server_private_dh_key = DH_PARAMETERS.generate_private_key()
            server_public_dh_key = server_private_dh_key.public_key()
            server_public_dh_bytes = server_public_dh_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Assina a chave DH pública e o username do servidor com a chave privada
            data_to_sign = server_public_dh_bytes + SERVER_USERNAME.encode('utf-8')
            server_signature = server_private_key_ecdsa.sign(data_to_sign)

            # Servidor envia sua chave DH pública, assinatura e username.
            send_prefixed_data(conn, server_public_dh_bytes)
            send_prefixed_data(conn, server_signature)
            send_prefixed_data(conn, SERVER_USERNAME.encode('utf-8'))
            print("[*] Chave DH Pública, Assinatura e Usuário do servidor enviados ao cliente.")

            # Calcula o segredo compartilhado (S)
            client_peer_public_numbers = serialization.load_pem_public_key(
                client_dh_public_bytes,
                backend=default_backend()
            ).public_numbers()
            
            client_peer_public_key = dh.DHPublicNumbers(client_peer_public_numbers.y, DH_PARAMETERS.parameter_numbers()).public_key(default_backend())
            
            shared_secret = server_private_dh_key.exchange(client_peer_public_key)
            hasher_secret = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher_secret.update(shared_secret)
            print(f"DEBUG: Shared Secret Hash (Server/Client): {hasher_secret.finalize().hex()}")

            print("[+] Segredo compartilhado (DH) calculado.")

            # --- 3. Derivação de chaves (PBKDF2) ---
            print("[*] Derivando chaves AES e HMAC (PBKDF2)...")
            salt = os.urandom(SALT_SIZE)
            conn.sendall(salt)
            print("[*] Salt enviado ao cliente.")

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_LENGTH + HMAC_KEY_LENGTH,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            derived_key = kdf.derive(shared_secret)
            key_aes = derived_key[:AES_KEY_LENGTH]
            key_hmac = derived_key[AES_KEY_LENGTH:]
            hasher_hmac = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher_hmac.update(key_hmac)
            print(f"DEBUG: HMAC Key Hash (Server/Client): {hasher_hmac.finalize().hex()}")

            print("[+] Chaves AES e HMAC derivadas usando PBKDF2.")

            # --- 4. Troca de Mensagens Seguras ---
            receive_thread = threading.Thread(target=handle_client_communication, args=(conn, key_aes, key_hmac))
            receive_thread.daemon = True
            receive_thread.start()
            
            while True:
                message_to_send = input("Digite sua mensagem para o cliente (ou 'sair' para encerrar): ")
                if message_to_send.lower() == 'sair':
                    print("[-] Encerrando conexão...")
                    break
                send_secure_message(conn, message_to_send, key_aes, key_hmac)
        
        print("[*] Servidor encerrado.")

if __name__ == "__main__":
    run_server()
