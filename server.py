import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib

HOST = "127.0.0.1"
CONTROL_PORT = 8080

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

def handle_client(control_conn, addr, server_private, server_public):
    print(f"Connection requested. Creating data socket")
    print(f"Control connection from {addr}")
    
    # Create data socket on random port
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_sock.bind((HOST, 0))  # 0 means random port will be chosen
    data_sock.setblocking(True) #Socket will wait for data
    data_sock.listen(1)
    data_port = data_sock.getsockname()[1]  # retrieve random port from data_socket
    
    # Send data port to client
    port_message = f"DATA_PORT {data_port}\n"
    control_conn.sendall(port_message.encode("utf-8"))
    print(f"Sent data port: {data_port}")
    
    # Accept data connection
    print(f"Awaiting data connection on port {data_port}...")
    data_conn, data_addr = data_sock.accept()
    print(f"Data connection established from {data_addr}")
    
    try:
        # Handle TUNNEL command
        tunnel_cmd = data_conn.recv(1024).decode("utf-8").strip()
        if tunnel_cmd == "TUNNEL":
            print("Tunnel requested. Sending public key")
            # Send server's public key
            server_public_key_bytes = server_public.export_key()
            data_conn.sendall(server_public_key_bytes)
            
            # Receive client's public key
            client_public_key_bytes = data_conn.recv(4096)
            client_public = RSA.import_key(client_public_key_bytes)
            print("Client public key received")
            print("Tunnel established")
        else:
            print(f"Expected TUNNEL command, got: {tunnel_cmd}")
            return
        
        # Handle POST command
        post_cmd = data_conn.recv(1024).decode("utf-8").strip()
        if post_cmd == "POST":
            print("Post requested")
            
            # Receive encrypted message size first
            size_bytes = data_conn.recv(4)
            message_size = int.from_bytes(size_bytes, byteorder='big')
            
            # Receive encrypted message
            encrypted_message = b""
            while len(encrypted_message) < message_size:
                chunk = data_conn.recv(min(1024, message_size - len(encrypted_message)))
                if not chunk:
                    break
                encrypted_message += chunk
            
            print(f"Received encrypted message: {encrypted_message.hex()[:50]}...")
            
            # Decrypt the message
            decrypted_message = rsa_decrypt(server_private, encrypted_message)
            print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
            
            # Calculate SHA256 hash of original message
            message_hash = hashlib.sha256(decrypted_message).hexdigest()
            print("Computing hash")
            
            # Encrypt the hash with client's public key
            encrypted_hash = rsa_encrypt(client_public, message_hash.encode('utf-8'))
            
            # Send encrypted hash back to client
            data_conn.sendall(len(encrypted_hash).to_bytes(4, byteorder='big'))
            data_conn.sendall(encrypted_hash)
            print(f"Responding with hash: {message_hash}")
        else:
            print(f"Expected POST command, got: {post_cmd}")
            
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        data_conn.close()
        data_sock.close()

def main():
    print("Starting server...")
    print("Creating RSA keypair")
    server_private, server_public = generate_rsa_keypair()
    print("RSA keypair created")
    
    print("Creating server socket")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, CONTROL_PORT))
        s.listen(1)
        print("Awaiting connections...")
        
        while True:
            try:
                conn, addr = s.accept()
                with conn:
                    # Handle CONNECT command
                    connect_cmd = conn.recv(1024).decode("utf-8").strip()
                    if connect_cmd == "CONNECT":
                        handle_client(conn, addr, server_private, server_public)
                    else:
                        print(f"Expected CONNECT command, got: {connect_cmd}")
                    break  # For single client handling
            except KeyboardInterrupt:
                print("\nServer shutting down...")
                break
            except Exception as e:
                print(f"Server error: {e}")

if __name__ == "__main__":
    main()