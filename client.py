import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib

HOST = '127.0.0.1'
PORT = 8080

def generate_rsa_keypair():
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext_bytes):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext_bytes)

def rsa_decrypt(private_key, ciphertext_bytes):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext_bytes)

def sha256_digest(data_bytes):
    h = SHA256.new(data_bytes)
    return h.digest()

def main():
    print("Starting client...")
    
    # Generate RSA key pair
    print("Creating RSA keypair")
    client_private, client_public = generate_rsa_keypair()
    print("RSA keypair created")
    
    # Create control socket
    print("Creating client socket")
    control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to server
        print("Connecting to server")
        control_socket.connect((HOST, PORT))
        
        # Send CONNECT command
        control_socket.sendall("CONNECT\n".encode("utf-8"))
        
        # Receive data port from server
        response = control_socket.recv(1024).decode("utf-8").strip()
        
        if response.startswith("DATA_PORT"):
            data_port = int(response.split()[1])
            print("Creating data socket")
        else:
            print(f"Unexpected response: {response}")
            return
        
        # Create data socket and connect to data port
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.connect((HOST, data_port))
        
        # TUNNEL command - exchange public keys
        print("Requesting tunnel")
        data_socket.sendall("TUNNEL\n".encode("utf-8"))
        
        # Receive server's public key
        server_public_key_bytes = data_socket.recv(4096)
        server_public = RSA.import_key(server_public_key_bytes)
        print("Server public key received")
        
        # Send client's public key
        client_public_key_bytes = client_public.export_key()
        data_socket.sendall(client_public_key_bytes)
        print("Tunnel established")
        
        # Get message from user
        message = input("Encrypting message: ").strip()
        if not message:
            message = "Hello"
        
        message_bytes = message.encode("utf-8")
        print(f"Encrypting message: {message}")
        
        # Encrypt message with server's public key
        encrypted_message = rsa_encrypt(server_public, message_bytes)
        print(f"Sending encrypted message: {encrypted_message.hex()[:50]}...")
        
        # Send POST command
        data_socket.sendall("POST\n".encode("utf-8"))
        
        # Send encrypted message size and then the message
        data_socket.sendall(len(encrypted_message).to_bytes(4, byteorder='big'))
        data_socket.sendall(encrypted_message)
        
        # Receive encrypted hash size and then the hash
        size_bytes = data_socket.recv(4)
        hash_size = int.from_bytes(size_bytes, byteorder='big')
        
        encrypted_hash = b""
        while len(encrypted_hash) < hash_size:
            chunk = data_socket.recv(min(1024, hash_size - len(encrypted_hash)))
            if not chunk:
                break
            encrypted_hash += chunk
        
        print("Received hash")
        
        # Decrypt the hash
        decrypted_hash = rsa_decrypt(client_private, encrypted_hash)
        received_hash = decrypted_hash.decode("utf-8")
        
        # Calculate hash of original message
        print("Computing hash")
        local_hash = hashlib.sha256(message_bytes).hexdigest()
        
        # Compare hashes
        if local_hash == received_hash:
            print("Secure")
        else:
            print("Compromised")
        
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        control_socket.close()
        if 'data_socket' in locals():
            data_socket.close()

if __name__ == "__main__":
    main()