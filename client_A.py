import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

# Generate an RSA key pair for the client
# Encryption is for Data Confidentiality
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Set up the server address and port
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 12345        # The port used by the server

# Set up a socket and connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Send the public key to the server
    s.sendall(public_key)
    server_public_key_pem = s.recv(4096)


    # Loop for continuously sending queries to the server
    while True:
        # Get the domain name from the user
        domain_name = input("Enter the domain name (or type 'quit' to exit): ")

        # Exit the loop if the user types 'quit'
        if domain_name == 'quit':
            break

        # Encrypt the domain name using the server's public key
        server_public_key = RSA.import_key(server_public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        domain_name_encrypted = cipher_rsa.encrypt(domain_name.encode())

        # Send the encrypted query to the server
        s.sendall(domain_name_encrypted)

        # Receive the encrypted response and hash value from the server
        response_encrypted = s.recv(4096)
        hash_value_encrypted = s.recv(4096)

        # Decrypt the response using the client's private key
        cipher_rsa = PKCS1_OAEP.new(key)
        response_decrypted = cipher_rsa.decrypt(response_encrypted).decode()

        # Verify the integrity of the data by computing the hash value
        hash_value = hashlib.sha512(response_decrypted.encode()).hexdigest()

        # Decrypt the hash value using the client's private key
        hash_value_decrypted = cipher_rsa.decrypt(hash_value_encrypted).decode()

        # Check that the decrypted hash value matches the computed hash value
        # Data Integrity and Data Confidentiality
        if hash_value == hash_value_decrypted:
            print("Response:", response_decrypted)
        else:
            print("Error: data has been tampered with")
