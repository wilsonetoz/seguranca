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

# --- Constantes de Configuração ---
# Parâmetros Diffie-Hellman: Devem ser os mesmos para cliente e servidor
# IMPORTANTE: Estes parâmetros DH devem ser os MESMOS para cliente e servidor.
# Eles foram gerados uma única vez e estão fixos aqui.
FIXED_DH_PARAMETERS_PEM = b"""-----BEGIN DH PARAMETERS-----
MIGHAoGBAO94ys5raCTmERuOSAkplAq6e8a72gUdz4mZAMZQQi2P1xCUGcn+TN2w
bnJlb11+K64eKQhshPG9+JQL+Y2maD6+2GEm9cN/SIkAXM1zto4SuMve78DqyMBN
Uj25Vh0MEX/Tx61seN3eNMpvP/3WtQxD3A5H/qp3dxAF27qhr64fAgEC
-----END DH PARAMETERS-----"""

DH_PARAMETERS = serialization.load_pem_parameters(FIXED_DH_PARAMETERS_PEM, backend=default_backend())
# Nome de usuário do GitHub do cliente para autenticação (substitua pelo seu)
CLIENT_USERNAME = "wilsonetoz" # SEU USUARIO GITHUB
# Nome do arquivo da chave privada ECDSA do cliente (gerado manualmente)
CLIENT_PRIVATE_KEY_FILE = "cliente_key" 

# Configurações para Derivação de Chaves (PBKDF2)
PBKDF2_ITERATIONS = 100000 # Número de iterações para PBKDF2 (maior = mais seguro, mais lento)
SALT_SIZE = 16 # Tamanho do salt em bytes

# Comprimentos das chaves e tags (AES-256 e HMAC-SHA256)
AES_KEY_LENGTH = 32 # 256 bits
HMAC_KEY_LENGTH = 32 # 256 bits
HMAC_TAG_LEN = 32 # Tamanho da saída do SHA256
IV_AES_LEN = 16 # Tamanho do IV para AES (128 bits)

# --- Funções Auxiliares de Comunicação de Socket ---
def send_prefixed_data(sock, data):
    """Envia dados prefixados com seu comprimento de 4 bytes."""
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big') + data)

def recv_prefixed_data(sock):
    """Recebe dados prefixados com seu comprimento de 4 bytes."""
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

# --- Funções Criptográficas ---
def get_public_key_from_github(username):
    public_keys = [] # Mude para uma lista para armazenar todas as chaves
    try:
        response = requests.get(f"https://github.com/{username}.keys")
        response.raise_for_status()
        
        key_lines = response.text.strip().split('\n')
        for line in key_lines:
            if line.strip():
                try:
                    # Tenta carregar a chave e adicioná-la à lista
                    public_key = load_ssh_public_key(line.encode('utf-8'), backend=default_backend())
                    print(f"DEBUG: Chave pública para '{username}' analisada com sucesso: {line.strip()[:50]}...") # Adicionado snippet para depuração
                    public_keys.append(public_key)
                except Exception as e:
                    print(f"DEBUG: Falha ao analisar linha como SSH public key: {e}. Tentando próxima linha...")
        
        if not public_keys: # Se nenhuma chave foi analisada com sucesso
            print(f"ERRO: Nenhuma chave pública SSH analisável encontrada para '{username}' no GitHub.")
            return [] # Retorna uma lista vazia
        return public_keys # Retorna a lista de todas as chaves públicas encontradas
    except requests.exceptions.RequestException as e:
        print(f"ERRO: Falha ao buscar chave pública para '{username}' no GitHub: {e}")
        return [] # Retorna uma lista vazia em caso de erro
    except Exception as e:
        print(f"ERRO: Ocorreu um erro inesperado ao buscar/analisar a chave pública para '{username}': {e}")
        return [] # Retorna uma lista vazia em caso de erro

def send_secure_message(sock, message, key_aes, key_hmac):
    """Criptografa, gera HMAC e envia uma mensagem."""
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
    """Recebe, verifica HMAC e descriptografa uma mensagem."""
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

def handle_server_communication(sock, key_aes, key_hmac):
    """Gerencia a comunicação contínua com o servidor em uma thread separada."""
    print("[*] Iniciando thread de recebimento do servidor.")
    while True:
        message = receive_secure_message(sock, key_aes, key_hmac)
        if message is None:
            print("[-] Conexão com o servidor perdida.")
            break
        elif message == "[HMAC_INVALIDO]":
            print("[RECEBIDO] Mensagem rejeitada: Falha na verificação de integridade/autenticidade.")
        elif message == "[PACOTE_CURTO]":
            print("[RECEBIDO] Mensagem rejeitada: Pacote recebido muito curto.")
        elif message == "[PADDING_INVALIDO]":
            print("[RECEBIDO] Mensagem rejeitada: Padding inválido.")
        else:
            print(f"[RECEBIDO] {message}")

def run_client():
    HOST = '127.0.0.1'
    PORT = 65432

    # --- CARREGAR A CHAVE PRIVADA ECDSA DO CLIENTE DE UM ARQUIVO ---
    try:
        with open(CLIENT_PRIVATE_KEY_FILE, "rb") as key_file:
            client_private_key_ecdsa = load_ssh_private_key(
                key_file.read(),
                password=None, # Mude para b"sua_senha" se a chave tiver uma senha
                backend=default_backend()
            )
        print(f"[+] Chave privada ECDSA do cliente carregada de '{CLIENT_PRIVATE_KEY_FILE}'.")
    except FileNotFoundError:
        print(f"ERRO: Arquivo da chave privada do cliente '{CLIENT_PRIVATE_KEY_FILE}' não encontrado. Certifique-se de que ele está na mesma pasta e você o gerou.")
        return
    except Exception as e:
        print(f"ERRO: Falha ao carregar a chave privada do cliente: {e}. Certifique-se de que é uma chave SSH válida e sem senha (ou com a senha correta).")
        return
    # --- FIM DO CARREGAMENTO DA CHAVE PRIVADA ---

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"[+] Conectado ao servidor em {HOST}:{PORT}")

            # --- 2. Handshake Diffie-Hellman e Autenticação (Cliente) ---
            print("[*] Iniciando Handshake DH com servidor...")

            # Gera o par de chaves DH do cliente
            client_private_dh_key = DH_PARAMETERS.generate_private_key()
            client_public_dh_key = client_private_dh_key.public_key()
            client_public_dh_bytes = client_public_dh_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Assina a chave DH pública e o username do cliente
            data_to_sign = client_public_dh_bytes + CLIENT_USERNAME.encode('utf-8')
            client_signature = client_private_key_ecdsa.sign(data_to_sign)

            # Envia chave DH pública, assinatura e username do cliente
            send_prefixed_data(s, client_public_dh_bytes)
            send_prefixed_data(s, client_signature)
            send_prefixed_data(s, CLIENT_USERNAME.encode('utf-8'))
            print("[*] Chave DH Pública, Assinatura e Usuário do cliente enviados ao servidor.")

            # Recebe chave DH pública, assinatura e username do servidor.
            server_dh_public_bytes = recv_prefixed_data(s)
            server_signature_bytes = recv_prefixed_data(s)
            server_username_bytes = recv_prefixed_data(s)

            if any(x is None for x in [server_dh_public_bytes, server_signature_bytes, server_username_bytes]):
                print("ERRO: Falha ao receber todos os componentes do handshake do servidor. Abortando.")
                return

            server_username = server_username_bytes.decode('utf-8')
            print(f"[*] Recebido do servidor: Chave DH Pública, Assinatura, Usuário ({server_username}).")

           # BUSCA AS CHAVES PÚBLICAS ECDSA DO SERVIDOR NO GITHUB PARA VERIFICAR A ASSINATURA
            server_public_keys_from_github = get_public_key_from_github(server_username)
            if not server_public_keys_from_github:
                print(f"ERRO: Nenhuma chave pública válida encontrada para '{server_username}' no GitHub. Abortando.")
                return

            # Verifica a assinatura do servidor, tentando com todas as chaves encontradas
            signature_verified = False
            data_to_verify = server_dh_public_bytes + server_username_bytes
            for pub_key in server_public_keys_from_github:
                try:
                    pub_key.verify(server_signature_bytes, data_to_verify)
                    print(f"[+] Assinatura do servidor verificada com sucesso usando uma das chaves do '{server_username}'.")
                    signature_verified = True
                    break # Se a verificação for bem-sucedida, não precisamos tentar com as outras chaves
                except Exception:
                    # Se falhar, tentamos a próxima chave
                    pass
            
            if not signature_verified:
                print(f"ERRO: Falha na verificação da assinatura do servidor. Nenhuma das chaves públicas do '{server_username}' no GitHub corresponde à assinatura.")
                return

            # Calcula o segredo compartilhado (S)
            server_peer_public_numbers = serialization.load_pem_public_key(
                server_dh_public_bytes,
                backend=default_backend()
            ).public_numbers()
            
            # CORREÇÃO AQUI: Passa o objeto DHParameterNumbers completo
            server_peer_public_key = dh.DHPublicNumbers(server_peer_public_numbers.y, DH_PARAMETERS.parameter_numbers()).public_key(default_backend())
            
            shared_secret = client_private_dh_key.exchange(server_peer_public_key)
            hasher_secret = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher_secret.update(shared_secret)
            print(f"DEBUG: Shared Secret Hash (Server/Client): {hasher_secret.finalize().hex()}")

            print("[+] Segredo compartilhado (DH) calculado.")

            # --- 3. Derivação de Chaves (PBKDF2) ---
            print("[*] Derivando chaves AES e HMAC (PBKDF2)...")
            
            # Cliente recebe o salt do servidor, garantindo que todos os bytes sejam lidos
            received_salt = b''
            bytes_received_salt = 0
            while bytes_received_salt < SALT_SIZE:
                chunk = s.recv(SALT_SIZE - bytes_received_salt)
                if not chunk:
                    print("ERRO: Conexão encerrada inesperadamente antes de receber o salt completo.")
                    return # Encerra a função se a conexão for perdida
                received_salt += chunk
                bytes_received_salt += len(chunk)
            salt = received_salt # Usa o salt completo e garantido
            print("[*] Salt recebido do servidor.")

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_LENGTH + HMAC_KEY_LENGTH,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            derived_key = kdf.derive(shared_secret)
            key_aes = derived_key[:AES_KEY_LENGTH]
            key_hmac = derived_key[AES_KEY_LENGTH:] # Corrected line
            print(f"DEBUG: HMAC Key Hash (Server/Client): {hashes.Hash(hashes.SHA256(), backend=default_backend()).update(key_hmac), hashes.Hash(hashes.SHA256(), backend=default_backend()).finalize().hex()}")
            hasher_hmac = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hasher_hmac.update(key_hmac)
            print(f"DEBUG: HMAC Key Hash (Server/Client): {hasher_hmac.finalize().hex()}")
            print("[+] Chaves AES e HMAC derivadas usando PBKDF2.")

            # --- 4. Troca de Mensagens Seguras ---
            receive_thread = threading.Thread(target=handle_server_communication, args=(s, key_aes, key_hmac))
            receive_thread.daemon = True
            receive_thread.start()
            
            while True:
                message_to_send = input("Digite sua mensagem (ou 'sair' para encerrar): ")
                if message_to_send.lower() == 'sair':
                    print("[-] Encerrando conexão...")
                    break
                send_secure_message(s, message_to_send, key_aes, key_hmac)

        except ConnectionRefusedError:
            print(f"[-] Conexão recusada. Verifique se o servidor está rodando em {HOST}:{PORT}")
        except Exception as e:
            print(f"[-] Ocorreu um erro: {e}")

if __name__ == "__main__":
    run_client()