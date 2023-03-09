import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

# Set up the server address and port
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 12345        # Port to listen on (non-privileged ports are > 1023)

def handle_client_request(conn):
    # Generate an RSA key pair for the server
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Send the public key to the client
    conn.sendall(public_key)
    client_public_key_pem = conn.recv(4096)

    # Loop for continuously receiving queries from the client
    while True:
        # Receive the encrypted query from the client
        query_encrypted = conn.recv(4096)
        if not query_encrypted:
            break

        # Decrypt the query using the server's private key
        cipher_rsa = PKCS1_OAEP.new(key)
        query_decrypted = cipher_rsa.decrypt(query_encrypted).decode()

        # Look up the IP address for the domain name
        ip_address = socket.gethostbyname(query_decrypted)

        # Encrypt the IP address using the client's public key
        client_public_key = RSA.import_key(client_public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        ip_address_encrypted = cipher_rsa.encrypt(ip_address.encode())

        # Compute the hash value of the IP address
        hash_value = hashlib.sha512(ip_address.encode()).hexdigest()

        # Encrypt the hash value using the client's public key
        hash_value_encrypted = cipher_rsa.encrypt(hash_value.encode())

        # Send the encrypted IP address and hash value to the client
        conn.sendall(ip_address_encrypted)
        conn.sendall(hash_value_encrypted)

    # Close the connection with the client
    conn.close()


# Set up a socket and bind it to the address and port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    # Wait for clients to connect
    print("Waiting for clients to connect...")
    while True:
        conn, addr = s.accept()
        print(f"Client connected: {addr}")

        # Start a new thread to handle the client request
        threading.Thread(target=handle_client_request, args=(conn,)).start()

